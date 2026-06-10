package main

// WebAuthn passkey registration and authentication ceremony handlers.
//
// Endpoints:
//   POST /auth/register/begin   — returns PublicKeyCredentialCreationOptions
//   POST /auth/register/finish  — verifies + stores credential, returns 201
//   POST /auth/login/begin      — returns PublicKeyCredentialRequestOptions
//   POST /auth/login/finish     — verifies + mints session JWT, sets cookie
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
}

type ceremonyEntry struct {
	data      *gwebauthn.SessionData
	expiresAt time.Time
}

func newCeremonyStore() *ceremonyStore {
	return &ceremonyStore{entries: make(map[string]*ceremonyEntry)}
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

// --- Registration ceremony ---

type registerBeginRequest struct {
	ContactID string `json:"contact_id"`
	Label     string `json:"label"` // human-readable device label, e.g. "MacBook Touch ID"
}

func handleRegisterBegin(s *store.Store, wa *gwebauthn.WebAuthn, cs *ceremonyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var req registerBeginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "400 Bad Request — invalid JSON", http.StatusBadRequest)
			return
		}
		if req.ContactID == "" {
			http.Error(w, "400 Bad Request — contact_id is required", http.StatusBadRequest)
			return
		}

		// Get or create the human principal for this contact ID.
		p, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, req.ContactID)
		if errors.Is(err, store.ErrNotFound) {
			p, err = s.CreatePrincipal(store.PrincipalClassHuman, req.ContactID)
			if err != nil {
				log.Printf("register/begin: create principal %q: %v", req.ContactID, err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
		} else if err != nil {
			log.Printf("register/begin: lookup principal %q: %v", req.ContactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Load all existing credentials to exclude them from the new registration
		// (prevents registering the same authenticator twice).
		existingCreds, _ := s.ListCredentialsByPrincipal(p.ID)
		var excludeList []gwebauthn.Credential
		for _, c := range existingCreds {
			if c.Type != store.CredentialTypeWebAuthn {
				continue
			}
			wc, err := store.UnmarshalWebAuthnCredential(c.Data)
			if err != nil {
				continue
			}
			excludeList = append(excludeList, *wc)
		}
		user := &webAuthnUser{principal: p, credentials: excludeList}

		creation, sessionData, err := wa.BeginRegistration(user)
		if err != nil {
			log.Printf("register/begin: BeginRegistration %q: %v", req.ContactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Stash session data; key = "register:<contactID>" for one-time take.
		cs.put("register:"+req.ContactID, sessionData)

		// Return the options JSON to the browser.
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(creation); err != nil {
			log.Printf("register/begin: encode options: %v", err)
		}
	}
}

type registerFinishRequest struct {
	ContactID string `json:"contact_id"`
	Label     string `json:"label"` // stored as credentials.label
}

func handleRegisterFinish(s *store.Store, wa *gwebauthn.WebAuthn, cs *ceremonyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// The contact_id and label are passed as query parameters so the body
		// can carry the raw WebAuthn credential JSON as expected by the library.
		contactID := r.URL.Query().Get("contact_id")
		label := r.URL.Query().Get("label")
		if contactID == "" {
			http.Error(w, "400 Bad Request — contact_id query param required", http.StatusBadRequest)
			return
		}

		sessionData, ok := cs.take("register:" + contactID)
		if !ok {
			http.Error(w, "400 Bad Request — no pending registration (expired or not started)", http.StatusBadRequest)
			return
		}

		p, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID)
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "404 Not Found — principal not found (register/begin not called?)", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("register/finish: lookup principal %q: %v", contactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		user := &webAuthnUser{principal: p}

		credential, err := wa.FinishRegistration(user, *sessionData, r)
		if err != nil {
			log.Printf("register/finish: FinishRegistration %q: %v", contactID, err)
			http.Error(w, "400 Bad Request — registration verification failed: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Validate + serialise credential data before storing (security rule #2).
		data, err := store.MarshalWebAuthnCredential(credential)
		if err != nil {
			log.Printf("register/finish: marshal credential: %v", err)
			http.Error(w, "400 Bad Request — invalid credential structure", http.StatusBadRequest)
			return
		}

		if label == "" {
			label = "passkey"
		}
		if _, err := s.CreateCredential(p.ID, store.CredentialTypeWebAuthn, data, label); err != nil {
			log.Printf("register/finish: store credential %q: %v", contactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
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
		if req.ContactID == "" {
			http.Error(w, "400 Bad Request — contact_id is required", http.StatusBadRequest)
			return
		}

		// Explicit principal check to distinguish ghost-principal from no-credentials
		// (security rule #3). Both cases result in the same client-facing 404 to
		// avoid contact-ID enumeration; the distinction is logged.
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
			log.Printf("login/begin: BeginAuthentication %q: %v", req.ContactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		cs.put("login:"+req.ContactID, sessionData)

		w.Header().Set("Content-Type", "application/json")
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
		if contactID == "" {
			http.Error(w, "400 Bad Request — contact_id query param required", http.StatusBadRequest)
			return
		}

		sessionData, ok := cs.take("login:" + contactID)
		if !ok {
			http.Error(w, "400 Bad Request — no pending authentication (expired or not started)", http.StatusBadRequest)
			return
		}

		user, err := loadWebAuthnUser(s, contactID)
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "404 Not Found — principal not found", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("login/finish: load user %q: %v", contactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		updatedCred, err := wa.FinishLogin(user, *sessionData, r)
		if err != nil {
			log.Printf("login/finish: FinishAuthentication %q: %v", contactID, err)
			http.Error(w, "401 Unauthorized — authentication failed", http.StatusUnauthorized)
			return
		}

		// Sign-count replay protection (FIDO2 §6.1.3, security rule #1).
		// The library sets CloneWarning=true when the asserted sign count is ≤
		// the stored count and the stored count is non-zero.
		if updatedCred.Authenticator.CloneWarning {
			log.Printf("login/finish: sign-count clone warning for contact %q — rejecting", contactID)
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
				log.Printf("login/finish: update sign count for %q: %v", contactID, err)
			}
		}

		// Mint session JWT with the principal's active scopes.
		scopes, err := s.GetActiveScopes(user.principal.ID, environment)
		if err != nil {
			log.Printf("login/finish: get active scopes %q: %v", contactID, err)
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
			log.Printf("login/finish: mint session for %q: %v", contactID, err)
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
