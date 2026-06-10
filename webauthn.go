package main

// WebAuthn passkey registration and authentication ceremony handlers.
//
// Endpoints:
//   POST /auth/register/begin   — returns PublicKeyCredentialCreationOptions
//   POST /auth/register/finish  — verifies + stores credential, returns 201
//   POST /auth/login/begin      — returns PublicKeyCredentialRequestOptions
//   POST /auth/login/finish     — verifies + mints session JWT, sets cookie
//
// The login endpoints support two flows:
//
//  1. Explicit: contact_id is provided. The server loads the principal's
//     credentials and returns allowCredentials=[(those IDs)].
//
//  2. Discoverable (conditional mediation): contact_id is empty. The server
//     calls BeginDiscoverableLogin (allowCredentials=[]) and returns an
//     aithne_session token alongside publicKey. The client passes this token as
//     ?session=<id> on finish; the server uses the assertion's userHandle to
//     identify the principal without a contact_id.
//
// See ADR-0001 §2 for the design: RP ID = l42.eu (registrable parent so the
// login origin can move freely within the domain without invalidating passkeys).
//
// Security rules enforced here per the lucos-security comment on #6:
//   1. Sign-count replay protection (FIDO2 §6.1.3): reject if asserted count ≤
//      stored count (and stored count is non-zero). The library sets
//      Credential.Authenticator.CloneWarning = true in this case; we check it.
//   2. Credential BLOB validation: required fields checked before CreateCredential.
//   3. Ghost-principal: GetPrincipalByExternalID called before login/begin to
//      distinguish "no credentials" from "principal not found".

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	gwebauthn "github.com/go-webauthn/webauthn/webauthn"
	"lucos_aithne/store"
	"lucos_aithne/token"
)

// challengeTTL is the maximum gap allowed between begin and finish steps.
// 60 seconds is generous for any human interacting with a passkey prompt.
const challengeTTL = 60 * time.Second

// --- In-memory challenge store ---

// ceremonyStore holds pending WebAuthn session data (challenges) between the
// begin and finish steps. In-memory is intentional: challenges are ephemeral
// and a restart invalidating pending ceremonies is acceptable (user retries).
type ceremonyStore struct {
	mu      sync.Mutex
	entries map[string]*ceremonyEntry
	enrol   map[string]*enrolCeremonyEntry
}

type ceremonyEntry struct {
	data      *gwebauthn.SessionData
	expiresAt time.Time
}

// enrolCeremonyEntry holds session data for the invite-gated enrolment flow.
// It carries the contactID from the invite so that /enrol/finish can derive it
// server-side rather than trusting a client-supplied parameter.
type enrolCeremonyEntry struct {
	data      *gwebauthn.SessionData
	contactID string
	expiresAt time.Time
}

func newCeremonyStore() *ceremonyStore {
	return &ceremonyStore{
		entries: make(map[string]*ceremonyEntry),
		enrol:   make(map[string]*enrolCeremonyEntry),
	}
}

// put stores session data under key. Overwrites any prior entry (new begin
// invalidates a previous pending ceremony for the same user+type).
func (cs *ceremonyStore) put(key string, data *gwebauthn.SessionData) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.entries[key] = &ceremonyEntry{data: data, expiresAt: time.Now().Add(challengeTTL)}
	// Opportunistic cleanup of expired entries to avoid unbounded growth.
	now := time.Now()
	for k, e := range cs.entries {
		if now.After(e.expiresAt) {
			delete(cs.entries, k)
		}
	}
}

// take retrieves and deletes session data under key (one-time use).
// Returns nil, false if the key does not exist or has expired.
func (cs *ceremonyStore) take(key string) (*gwebauthn.SessionData, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	e, ok := cs.entries[key]
	if !ok {
		return nil, false
	}
	delete(cs.entries, key)
	if time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.data, true
}

// putEnrol stores an enrolment ceremony session keyed by tokenHash.
// contactID is the contact the invite was issued for; it is retrieved at
// finish time so the server never trusts a client-supplied contact_id.
func (cs *ceremonyStore) putEnrol(tokenHash string, data *gwebauthn.SessionData, contactID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.enrol[tokenHash] = &enrolCeremonyEntry{
		data:      data,
		contactID: contactID,
		expiresAt: time.Now().Add(challengeTTL),
	}
	// Opportunistic cleanup.
	now := time.Now()
	for k, e := range cs.enrol {
		if now.After(e.expiresAt) {
			delete(cs.enrol, k)
		}
	}
}

// takeEnrol retrieves and deletes an enrolment ceremony session (one-time use).
// Returns (nil, "", false) if the key does not exist or has expired.
func (cs *ceremonyStore) takeEnrol(tokenHash string) (*gwebauthn.SessionData, string, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	e, ok := cs.enrol[tokenHash]
	if !ok {
		return nil, "", false
	}
	delete(cs.enrol, tokenHash)
	if time.Now().After(e.expiresAt) {
		return nil, "", false
	}
	return e.data, e.contactID, true
}

// --- webAuthnUser wraps store.Principal + credentials for the library ---

type webAuthnUser struct {
	principal   *store.Principal
	credentials []gwebauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                          { return []byte(u.principal.ID) }
func (u *webAuthnUser) WebAuthnName() string                        { return u.principal.ExternalID }
func (u *webAuthnUser) WebAuthnDisplayName() string                 { return u.principal.ExternalID }
func (u *webAuthnUser) WebAuthnCredentials() []gwebauthn.Credential { return u.credentials }

// loadWebAuthnUser loads a principal by (class=human, externalID=contactID) and
// deserialises all its WebAuthn credentials for the library.
// Returns ErrNotFound if the principal does not exist.
// Returns an empty credential slice (not an error) if the principal exists but
// has no credentials registered yet.
func loadWebAuthnUser(s *store.Store, contactID string) (*webAuthnUser, error) {
	p, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID)
	if err != nil {
		return nil, err
	}
	return loadWebAuthnUserByPrincipal(s, p)
}

// loadWebAuthnUserByPrincipal is the inner loader used when the principal is
// already known (e.g. resolved from the assertion's userHandle in the
// discoverable login path).
func loadWebAuthnUserByPrincipal(s *store.Store, p *store.Principal) (*webAuthnUser, error) {
	creds, err := s.ListCredentialsByPrincipal(p.ID)
	if err != nil {
		return nil, err
	}
	var webCreds []gwebauthn.Credential
	for _, c := range creds {
		if c.Type != store.CredentialTypeWebAuthn {
			continue
		}
		wc, err := store.UnmarshalWebAuthnCredential(c.Data)
		if err != nil {
			log.Printf("loadWebAuthnUser: skip credential %s: %v", c.ID, err)
			continue
		}
		webCreds = append(webCreds, *wc)
	}
	return &webAuthnUser{principal: p, credentials: webCreds}, nil
}

// --- Authentication ceremony ---

type loginBeginRequest struct {
	ContactID string `json:"contact_id"`
}

func handleLoginBegin(s *store.Store, wa *gwebauthn.WebAuthn, cs *ceremonyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var req loginBeginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "400 Bad Request — invalid JSON", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if req.ContactID == "" {
			// Discoverable login (conditional mediation): no contact_id supplied.
			// The browser will offer any registered passkey for the RP ID.
			// We return an aithne_session token alongside publicKey; the client
			// must pass it as ?session=<token> on the finish request so we can
			// match the session data without a contact_id.
			assertion, sessionData, err := wa.BeginDiscoverableLogin()
			if err != nil {
				log.Printf("login/begin: BeginDiscoverableLogin: %v", err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			sessionID := uuid.New().String()
			cs.put("login:disco:"+sessionID, sessionData)

			// Embed the session ID into the response alongside the standard
			// publicKey field so the JS can echo it back on finish.
			assertionJSON, err := json.Marshal(assertion)
			if err != nil {
				log.Printf("login/begin: marshal discoverable assertion: %v", err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var respMap map[string]json.RawMessage
			if err := json.Unmarshal(assertionJSON, &respMap); err != nil {
				log.Printf("login/begin: unmarshal discoverable assertion: %v", err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			sessionIDJSON, _ := json.Marshal(sessionID) // uuid.New().String() is always valid JSON
			respMap["aithne_session"] = sessionIDJSON
			if err := json.NewEncoder(w).Encode(respMap); err != nil {
				log.Printf("login/begin: encode discoverable options: %v", err)
			}
			return
		}

		// Explicit login: contact_id is provided.
		// Distinguish ghost-principal from no-credentials (security rule #3).
		// Both cases return the same client-facing 404 to prevent enumeration;
		// the distinction is logged server-side.
		user, err := loadWebAuthnUser(s, req.ContactID)
		if errors.Is(err, store.ErrNotFound) {
			log.Printf("login/begin: principal not found for contact %q", req.ContactID)
			http.Error(w, "404 Not Found — no passkey registered for this contact ID", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("login/begin: load user %q: %v", req.ContactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if len(user.credentials) == 0 {
			log.Printf("login/begin: principal exists but has no credentials for contact %q", req.ContactID)
			http.Error(w, "404 Not Found — no passkey registered for this contact ID", http.StatusNotFound)
			return
		}

		assertion, sessionData, err := wa.BeginLogin(user)
		if err != nil {
			log.Printf("login/begin: BeginLogin %q: %v", req.ContactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		cs.put("login:"+req.ContactID, sessionData)

		if err := json.NewEncoder(w).Encode(assertion); err != nil {
			log.Printf("login/begin: encode options: %v", err)
		}
	}
}

func handleLoginFinish(s *store.Store, wa *gwebauthn.WebAuthn, cs *ceremonyStore, issuer, environment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		contactID := r.URL.Query().Get("contact_id")
		sessionID := r.URL.Query().Get("session")

		if contactID == "" && sessionID == "" {
			http.Error(w, "400 Bad Request — contact_id or session query param required", http.StatusBadRequest)
			return
		}

		var user *webAuthnUser
		var sessionData *gwebauthn.SessionData
		var updatedCred *gwebauthn.Credential

		if sessionID != "" {
			// Discoverable login path: look up session by token, then identify
			// the principal from the assertion's userHandle after verification.
			var ok bool
			sessionData, ok = cs.take("login:disco:" + sessionID)
			if !ok {
				http.Error(w, "400 Bad Request — no pending authentication (expired or not started)", http.StatusBadRequest)
				return
			}

			// Build a DiscoverableUserHandler that resolves the principal from
			// the userHandle embedded in the assertion (set as principal ID at
			// registration time via webAuthnUser.WebAuthnID()).
			var handlerErr error
			handler := func(rawID, userHandle []byte) (gwebauthn.User, error) {
				principalID := string(userHandle)
				p, err := s.GetPrincipalByID(principalID)
				if err != nil {
					handlerErr = err
					return nil, err
				}
				u, err := loadWebAuthnUserByPrincipal(s, p)
				if err != nil {
					handlerErr = err
					return nil, err
				}
				user = u
				return u, nil
			}

			var err error
			updatedCred, err = wa.FinishDiscoverableLogin(handler, *sessionData, r)
			if err != nil {
				if handlerErr != nil {
					if errors.Is(handlerErr, store.ErrNotFound) {
						http.Error(w, "404 Not Found — principal not found", http.StatusNotFound)
					} else {
						log.Printf("login/finish: discoverable user lookup: %v", handlerErr)
						http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					}
				} else {
					log.Printf("login/finish: FinishDiscoverableLogin: %v", err)
					http.Error(w, "401 Unauthorized — authentication failed", http.StatusUnauthorized)
				}
				return
			}
			if user == nil {
				// Handler was not called — malformed assertion; library should have errored but be safe.
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
		} else {
			// Explicit login path: principal identified by contact_id.
			var ok bool
			sessionData, ok = cs.take("login:" + contactID)
			if !ok {
				http.Error(w, "400 Bad Request — no pending authentication (expired or not started)", http.StatusBadRequest)
				return
			}

			var err error
			user, err = loadWebAuthnUser(s, contactID)
			if errors.Is(err, store.ErrNotFound) {
				http.Error(w, "404 Not Found — principal not found", http.StatusNotFound)
				return
			}
			if err != nil {
				log.Printf("login/finish: load user %q: %v", contactID, err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}

			updatedCred, err = wa.FinishLogin(user, *sessionData, r)
			if err != nil {
				log.Printf("login/finish: FinishLogin %q: %v", contactID, err)
				http.Error(w, "401 Unauthorized — authentication failed", http.StatusUnauthorized)
				return
			}
		}

		// Sign-count replay protection (FIDO2 §6.1.3, security rule #1).
		// The library sets CloneWarning=true when the asserted sign count is ≤
		// the stored count and the stored count is non-zero.
		if updatedCred.Authenticator.CloneWarning {
			log.Printf("login/finish: sign-count clone warning for principal %s — rejecting", user.principal.ID)
			http.Error(w, "403 Forbidden — authenticator clone detected (sign count regression)", http.StatusForbidden)
			return
		}

		// Persist the updated sign count so replay protection works on the next auth.
		storeCredID, newData := findAndUpdateSignCount(s, user, updatedCred)
		if storeCredID != "" && newData != nil {
			if err := s.UpdateCredentialData(storeCredID, newData); err != nil {
				// Non-fatal: log and continue. The session is still valid; the
				// sign count update failing means the next auth is slightly less
				// protected but not broken.
				log.Printf("login/finish: update sign count for principal %s: %v", user.principal.ID, err)
			}
		}

		// Mint session JWT with the principal's active scopes.
		scopes, err := s.GetActiveScopes(user.principal.ID, environment)
		if err != nil {
			log.Printf("login/finish: get active scopes for principal %s: %v", user.principal.ID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		signingKey, err := s.GetOrCreateActiveSigningKey()
		if err != nil {
			log.Printf("login/finish: get signing key: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		tok, err := token.MintSession(user.principal, scopes, signingKey, issuer, "l42.eu", token.DefaultSessionTTL)
		if err != nil {
			log.Printf("login/finish: mint session for principal %s: %v", user.principal.ID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		token.SetSessionCookie(w, tok)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}

// findAndUpdateSignCount finds the store.Credential row matching the returned
// credential and returns its ID + updated data bytes.
// Returns ("", nil) if the credential cannot be found — caller logs and continues.
func findAndUpdateSignCount(s *store.Store, user *webAuthnUser, updated *gwebauthn.Credential) (string, []byte) {
	creds, err := s.ListCredentialsByPrincipal(user.principal.ID)
	if err != nil {
		return "", nil
	}
	for _, c := range creds {
		if c.Type != store.CredentialTypeWebAuthn {
			continue
		}
		wc, err := store.UnmarshalWebAuthnCredential(c.Data)
		if err != nil {
			continue
		}
		// Match by credential ID.
		if string(wc.ID) == string(updated.ID) {
			wc.Authenticator.SignCount = updated.Authenticator.SignCount
			newData, err := store.MarshalWebAuthnCredential(wc)
			if err != nil {
				return "", nil
			}
			return c.ID, newData
		}
	}
	return "", nil
}
