package main

// Admin-invite enrolment flow (lucos_aithne#10).
//
// templateFS is declared in main.go (via //go:embed templates) and referenced
// here in renderTemplate — both are in the same package.
//
// An admin (aithne:admin scope) generates a single-use invite URL via the
// admin enrolment page or the POST /admin/invites API. The invitee opens the
// URL, and the server validates the invite, fetches their display name from
// lucos_contacts, and renders an enrolment page. The invitee completes the
// passkey ceremony; on success all existing passkeys for that contact are
// wiped and replaced with the new one, and the invite is consumed — all in
// a single atomic transaction.
//
// Endpoints:
//   GET  /admin/enrol        — admin invite-generation page (aithne:admin)
//   POST /admin/invites      — create invite, returns JSON {invite_url, expires_at}
//   GET  /enrol?token=X      — invitee enrolment page (server-rendered Go template)
//   POST /enrol/begin?token=X — begin WebAuthn registration ceremony
//   POST /enrol/finish?token=X — finish ceremony + atomic credential replace + invite consume
//
// Security properties per lucos-security review on #6:
//   - Invite token is never stored; only SHA-256(token) lives in the DB.
//   - contact_id binding is server-enforced via the ceremony session (never
//     read from a client-supplied field at finish time).
//   - Re-enrolment atomically wipes old credentials + registers new + consumes invite.
//   - Invite is consumed at FinishRegistration (not Begin) so a browser crash
//     between begin and finish does not permanently burn the invite.

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	gwebauthn "github.com/go-webauthn/webauthn/webauthn"
	"lucos_aithne/store"
	"lucos_aithne/token"
)

// --- Contacts API client ---

// contactsClient verifies and fetches contact metadata from lucos_contacts.
type contactsClient struct {
	origin string
	key    string
	client *http.Client
}

func newContactsClient(origin, key string) *contactsClient {
	return &contactsClient{
		origin: strings.TrimRight(origin, "/"),
		key:    key,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// contactInfo holds the data fetched from lucos_contacts for a contact.
type contactInfo struct {
	DisplayName string
}

// Get fetches contact info from lucos_contacts.
// Returns ErrNotFound (from store) if the contact does not exist (404).
// Returns an error for any other non-200 status.
func (c *contactsClient) Get(contactID string) (*contactInfo, error) {
	url := fmt.Sprintf("%s/agents/%s", c.origin, contactID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("contacts: build request: %w", err)
	}
	req.Header.Set("Authorization", "key "+c.key)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacts: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, resp.Body)
		return nil, store.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("contacts: unexpected status %d for contact %q", resp.StatusCode, contactID)
	}

	// Parse the response JSON. We only care about the display name.
	// The contacts API returns an object; we fish out the name field.
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("contacts: decode response: %w", err)
	}

	name, _ := payload["name"].(string)
	if name == "" {
		// Fall back to the contact ID if no name is available.
		name = contactID
	}
	return &contactInfo{DisplayName: name}, nil
}

// --- Go templates ---

// enrolPageData is the data passed to templates/enrol.html.
type enrolPageData struct {
	Token       string // raw invite token (for JS to read)
	ContactID   string
	DisplayName string
	IsRecovery  bool // true if the principal already has at least one passkey
}

// enrolErrorPageData is the data passed to templates/enrol_error.html.
type enrolErrorPageData struct {
	Reason string // "not_found", "expired", or "used"
}

// adminEnrolPageData is the data passed to templates/admin_enrol.html.
// Currently empty — the page is fully client-driven (calls POST /admin/invites).
type adminEnrolPageData struct{}

// renderTemplate parses and executes a named template from the binary, writing
// the result to w. On error it writes a plain 500 response.
func renderTemplate(w http.ResponseWriter, name string, data any) {
	t, err := template.ParseFS(templateFS, "templates/"+name)
	if err != nil {
		log.Printf("renderTemplate %q: parse: %v", name, err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		// Headers already sent; log only.
		log.Printf("renderTemplate %q: execute: %v", name, err)
	}
}

// --- Admin enrolment page ---

// handleAdminEnrolPage serves GET /admin/enrol — the admin invite-generation page.
func handleAdminEnrolPage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		renderTemplate(w, "admin_enrol.html", adminEnrolPageData{})
	}
}

// --- POST /admin/invites ---

// createInviteRequest is the JSON body for POST /admin/invites.
type createInviteRequest struct {
	ContactID string `json:"contact_id"`
}

// createInviteResponse is returned on success.
type createInviteResponse struct {
	InviteURL string `json:"invite_url"`
	ExpiresAt string `json:"expires_at"`
}

// handleAdminInvites handles POST /admin/invites.
// The handler expects the request context to carry *token.SessionClaims (injected
// by requireAdminScope) for audit attribution.
func handleAdminInvites(s *store.Store, contacts *contactsClient, appOrigin string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var req createInviteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "400 Bad Request — invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.ContactID == "" {
			http.Error(w, "400 Bad Request — contact_id is required", http.StatusBadRequest)
			return
		}

		// Verify the contact exists in lucos_contacts.
		if _, err := contacts.Get(req.ContactID); errors.Is(err, store.ErrNotFound) {
			http.Error(w, "422 Unprocessable Entity — contact_id not found in lucos_contacts", http.StatusUnprocessableEntity)
			return
		} else if err != nil {
			log.Printf("admin/invites: contacts lookup %q: %v", req.ContactID, err)
			http.Error(w, "503 Service Unavailable — could not verify contact", http.StatusServiceUnavailable)
			return
		}

		// Get or create the human principal for this contact. This is safe to do
		// here so the principal exists when begin is called later.
		_, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, req.ContactID)
		if errors.Is(err, store.ErrNotFound) {
			if _, err = s.CreatePrincipal(store.PrincipalClassHuman, req.ContactID); err != nil {
				log.Printf("admin/invites: create principal %q: %v", req.ContactID, err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
		} else if err != nil {
			log.Printf("admin/invites: lookup principal %q: %v", req.ContactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Generate a cryptographically random UUID invite token.
		rawToken := uuid.New().String()

		// Attribution is read from the verified JWT claims injected by requireAdminScope.
		claims := r.Context().Value(claimsContextKey).(*token.SessionClaims)

		inv, err := s.CreateInvite(rawToken, req.ContactID, claims.Subject)
		if err != nil {
			log.Printf("admin/invites: create invite for %q: %v", req.ContactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		inviteURL := fmt.Sprintf("%s/enrol?token=%s", strings.TrimRight(appOrigin, "/"), rawToken)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createInviteResponse{
			InviteURL: inviteURL,
			ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
		})
	}
}

// --- Enrolment page ---

// handleEnrolPage serves GET /enrol?token=X.
// It validates the token server-side and renders a personalised enrolment page
// via a Go template. Invalid/expired/used tokens render a full error page.
func handleEnrolPage(s *store.Store, contacts *contactsClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		rawToken := r.URL.Query().Get("token")
		if rawToken == "" {
			http.Error(w, "400 Bad Request — invite token is required", http.StatusBadRequest)
			return
		}

		inv, err := s.GetInviteByRawToken(rawToken)
		if errors.Is(err, store.ErrNotFound) {
			renderTemplate(w, "enrol_error.html", enrolErrorPageData{Reason: "not_found"})
			return
		}
		if errors.Is(err, store.ErrInviteExpired) {
			renderTemplate(w, "enrol_error.html", enrolErrorPageData{Reason: "expired"})
			return
		}
		if errors.Is(err, store.ErrInviteUsed) {
			renderTemplate(w, "enrol_error.html", enrolErrorPageData{Reason: "used"})
			return
		}
		if err != nil {
			log.Printf("enrol: get invite: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Fetch display name from lucos_contacts.
		info, err := contacts.Get(inv.ContactID)
		if err != nil {
			log.Printf("enrol: contacts lookup %q: %v", inv.ContactID, err)
			// Non-fatal: render with contact ID as fallback name.
			info = &contactInfo{DisplayName: inv.ContactID}
		}

		// Check whether this is a re-enrolment (principal already has passkeys).
		p, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, inv.ContactID)
		isRecovery := false
		if err == nil {
			creds, err2 := s.ListCredentialsByPrincipal(p.ID)
			if err2 == nil {
				for _, c := range creds {
					if c.Type == store.CredentialTypeWebAuthn {
						isRecovery = true
						break
					}
				}
			}
		}

		renderTemplate(w, "enrol.html", enrolPageData{
			Token:       rawToken,
			ContactID:   inv.ContactID,
			DisplayName: info.DisplayName,
			IsRecovery:  isRecovery,
		})
	}
}

// --- Enrolment ceremony ---

// handleEnrolBegin handles POST /enrol/begin?token=X.
// It validates the invite (but does NOT consume it — that happens at finish),
// begins the WebAuthn registration ceremony, and stores the session with the
// contact_id so finish can derive it server-side.
func handleEnrolBegin(s *store.Store, wa *gwebauthn.WebAuthn, cs *ceremonyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		rawToken := r.URL.Query().Get("token")
		if rawToken == "" {
			http.Error(w, "400 Bad Request — token query param required", http.StatusBadRequest)
			return
		}

		// Validate the invite (does not consume it).
		inv, err := s.GetInviteByRawToken(rawToken)
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInviteExpired) || errors.Is(err, store.ErrInviteUsed) {
			http.Error(w, "401 Unauthorized — invite not found, expired, or already used", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Printf("enrol/begin: get invite: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Load the principal for this contact (created at invite-generation time).
		p, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, inv.ContactID)
		if errors.Is(err, store.ErrNotFound) {
			// Principal should have been created at admin/invites time; log and surface.
			log.Printf("enrol/begin: principal not found for contact %q", inv.ContactID)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err != nil {
			log.Printf("enrol/begin: lookup principal %q: %v", inv.ContactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// For re-enrolment: pass an empty exclude list so the ceremony always
		// completes. The old credentials will be atomically wiped at finish time.
		user := &webAuthnUser{principal: p, credentials: nil}

		creation, sessionData, err := wa.BeginRegistration(user)
		if err != nil {
			log.Printf("enrol/begin: BeginRegistration %q: %v", inv.ContactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Store session keyed by token hash, carrying the contact_id.
		tokenHash := store.HashToken(rawToken)
		cs.putEnrol(tokenHash, sessionData, inv.ContactID)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(creation); err != nil {
			log.Printf("enrol/begin: encode options: %v", err)
		}
	}
}

// handleEnrolFinish handles POST /enrol/finish?token=X.
// It retrieves the ceremony session (which carries the contact_id from begin),
// completes the WebAuthn registration, then atomically:
//   - wipes all existing WebAuthn credentials for the principal, and
//   - inserts the new credential, and
//   - marks the invite as used.
func handleEnrolFinish(s *store.Store, wa *gwebauthn.WebAuthn, cs *ceremonyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		rawToken := r.URL.Query().Get("token")
		label := r.URL.Query().Get("label")
		if rawToken == "" {
			http.Error(w, "400 Bad Request — token query param required", http.StatusBadRequest)
			return
		}
		if label == "" {
			label = "passkey"
		}

		// Retrieve and consume the ceremony session.
		tokenHash := store.HashToken(rawToken)
		sessionData, contactID, ok := cs.takeEnrol(tokenHash)
		if !ok {
			http.Error(w, "400 Bad Request — no pending enrolment (expired or begin not called)", http.StatusBadRequest)
			return
		}

		// Load the principal — the contact_id comes from our session, not the client.
		p, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID)
		if errors.Is(err, store.ErrNotFound) {
			log.Printf("enrol/finish: principal not found for contact %q", contactID)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err != nil {
			log.Printf("enrol/finish: lookup principal %q: %v", contactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		user := &webAuthnUser{principal: p}

		// Complete the WebAuthn ceremony.
		credential, err := wa.FinishRegistration(user, *sessionData, r)
		if err != nil {
			log.Printf("enrol/finish: FinishRegistration %q: %v", contactID, err)
			http.Error(w, "400 Bad Request — registration verification failed", http.StatusBadRequest)
			return
		}

		// Validate + serialise the credential (security rule #2).
		data, err := store.MarshalWebAuthnCredential(credential)
		if err != nil {
			log.Printf("enrol/finish: marshal credential: %v", err)
			http.Error(w, "400 Bad Request — invalid credential structure", http.StatusBadRequest)
			return
		}

		// Atomic: wipe old creds + register new + consume invite.
		if _, err := s.ReplaceWebAuthnCredentialAndConsumeInvite(p.ID, rawToken, data, label); err != nil {
			log.Printf("enrol/finish: replace credential for %q: %v", contactID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}
