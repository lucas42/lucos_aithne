package main

// Machine/agent authentication via OAuth2 client-credentials (lucos_aithne#8).
//
// Per ADR-0001 §5, non-human principals (AI agents) authenticate non-interactively
// via the OAuth2 client-credentials grant. The long-lived machine key lives in
// lucos_creds (per-env, rotatable); it is exchanged at runtime for a short-lived
// signed JWT. The session is never stored in creds — so there is no runtime creds
// dependency on the hot path.
//
// The machine key format used here is a shared-secret bearer credential:
//   - client_id  = agent slug (externally meaningful identity, per ADR §4)
//   - client_secret = raw high-entropy string (UUID v4 — no special characters,
//     compatible with lucos_creds storage)
//
// Only the SHA-256 hash of the raw secret is stored in the credential data BLOB
// (same pattern as enrolment invite tokens — the raw secret is returned once at
// provisioning time and never persisted in the DB).
//
// Endpoints:
//   POST /oauth2/token           — client-credentials grant (RFC 6749)
//   POST /admin/machine-keys     — provision a new machine key (aithne:admin)

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"lucos_aithne/store"
	"lucos_aithne/token"
)

// machineKeyHashLen is the expected byte-length of the data BLOB for a
// machine_key credential: 64 hex characters = 32 bytes SHA-256 digest.
const machineKeyHashLen = 64

// hashMachineKey returns the hex-encoded SHA-256 of the raw secret.
// This is the value stored in credentials.data for machine_key credentials.
func hashMachineKey(rawSecret string) string {
	sum := sha256.Sum256([]byte(rawSecret))
	return hex.EncodeToString(sum[:])
}

// --- OAuth2 token endpoint ---

// tokenSuccessResponse is the RFC 6749 §5.1 success payload.
// Scope echoes the effective scope list (space-delimited per RFC 6749 §3.3).
// It is included whenever a scope was issued, and required by §5.1 when the
// issued set differs from the requested set.
type tokenSuccessResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// tokenErrorResponse is the RFC 6749 §5.2 error payload.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeTokenError writes an RFC 6749 §5.2 JSON error response.
// status should be 400 (invalid_request, unsupported_grant_type) or
// 401 (invalid_client). For 401, WWW-Authenticate is required by the spec.
func writeTokenError(w http.ResponseWriter, status int, errCode, description string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="aithne"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(tokenErrorResponse{
		Error:            errCode,
		ErrorDescription: description,
	})
}

// handleOAuth2Token serves POST /oauth2/token.
// It dispatches between the supported grant types:
//   - client_credentials (RFC 6749 §4.4): agent/machine principals via machine_key
//   - authorization_code (RFC 6749 §4.1): human principals via OIDC authorization flow
func handleOAuth2Token(s *store.Store, issuer, environment string, tokenLimiter *keyedLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
			return
		}

		grantType := r.FormValue("grant_type")
		switch grantType {
		case "client_credentials":
			handleClientCredentialsGrant(s, issuer, environment, tokenLimiter, w, r)
		case "authorization_code":
			handleAuthCodeGrant(s, issuer, environment, w, r)
		default:
			writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type",
				fmt.Sprintf("unsupported grant_type %q; supported: client_credentials, authorization_code", grantType))
		}
	}
}

// handleClientCredentials wraps handleClientCredentialsGrant as an http.HandlerFunc,
// enforcing POST method and grant_type=client_credentials before delegating.
// Retained for use in tests that exercise the client_credentials path directly.
func handleClientCredentials(s *store.Store, issuer, environment string, tokenLimiter *keyedLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
			return
		}
		grantType := r.FormValue("grant_type")
		if grantType != "client_credentials" {
			writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type",
				fmt.Sprintf("unsupported grant_type %q; only client_credentials is supported", grantType))
			return
		}
		handleClientCredentialsGrant(s, issuer, environment, tokenLimiter, w, r)
	}
}

// parseScopeParam splits an OAuth2 scope string (space-delimited per RFC 6749 §3.3)
// into a deduplicated, order-preserved slice of non-empty scope tokens.
// Returns nil when s is empty or whitespace-only (treated as "scope omitted").
func parseScopeParam(s string) []string {
	parts := strings.Fields(s) // splits on any whitespace, drops empty tokens
	if len(parts) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// toSet converts a string slice to a set (map[string]bool) for O(1) membership tests.
func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// handleClientCredentialsGrant implements the client_credentials grant.
// Called after grant_type has been confirmed; r.ParseForm() must have run.
func handleClientCredentialsGrant(s *store.Store, issuer, environment string, tokenLimiter *keyedLimiter, w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" || clientSecret == "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client",
			"client_id and client_secret are required")
		return
	}

	// Per-client-ID rate limiting applied before any credential lookup, so
	// repeated failures from the same client don't trigger full DB work.
	// Fall back to IP when client_id is absent (already caught above, but guard
	// here in case this function is called via a future path without that check).
	limitKey := clientID
	if limitKey == "" {
		limitKey = clientIP(r)
	}
	if ok, count := tokenLimiter.Allow(limitKey); !ok {
		reqLogger(r).Printf("rate limit exceeded: %s client_id=%q count=%d window=%s", r.URL.Path, clientID, count, tokenEndpointWindow)
		w.Header().Set("Retry-After", "60")
		writeTokenError(w, http.StatusTooManyRequests, "rate_limited",
			"too many authentication attempts for this client — retry after 60 seconds")
		return
	}

	// Look up the agent principal by slug. Call GetPrincipalByExternalID first
	// to distinguish "unknown client" from "no machine_key credential" — both
	// return invalid_client to the caller (no information leak) but the
	// distinction avoids the ghost-principal ambiguity noted by lucos-security.
	principal, err := s.GetPrincipalByExternalID(store.PrincipalClassAgent, clientID)
	if err != nil {
		// ErrNotFound or any other error: do not reveal which case it is.
		writeTokenError(w, http.StatusUnauthorized, "invalid_client",
			"invalid client_id or client_secret")
		return
	}

	// List machine_key credentials and look for a hash match.
	creds, err := s.ListCredentialsByPrincipal(principal.ID)
	if err != nil {
		reqLogger(r).Printf("handleClientCredentialsGrant: list credentials for %s: %v", principal.ID, err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	secretHash := hashMachineKey(clientSecret)
	var matched bool
	for _, c := range creds {
		if c.Type != store.CredentialTypeMachineKey {
			continue
		}
		if c.RevokedAt != nil {
			continue // skip revoked keys — revocation is enforced here
		}
		if subtle.ConstantTimeCompare(c.Data, []byte(secretHash)) == 1 {
			matched = true
			break
		}
	}
	if !matched {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client",
			"invalid client_id or client_secret")
		return
	}

	// Collect active scopes for this principal in the current environment.
	granted, err := s.GetActiveScopes(principal.ID, environment)
	if err != nil {
		reqLogger(r).Printf("handleClientCredentialsGrant: get scopes for %s: %v", principal.ID, err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Honour the optional RFC 6749 §4.4 scope parameter.
	// If omitted/empty: issue the full granted set (backwards-compatible).
	// If present: intersect with granted; reject any scope not in the granted set.
	effective := granted
	if requested := parseScopeParam(r.FormValue("scope")); len(requested) > 0 {
		grantedSet := toSet(granted)
		for _, sc := range requested {
			if !grantedSet[sc] {
				writeTokenError(w, http.StatusBadRequest, "invalid_scope",
					fmt.Sprintf("scope %q is not granted to this principal in %s", sc, environment))
				return
			}
		}
		effective = requested
	}

	// Obtain the active signing key.
	signingKey, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		reqLogger(r).Printf("handleClientCredentialsGrant: get signing key: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Mint a short-lived session JWT — identical format to the human login path.
	tokenStr, err := token.MintSession(principal, effective, signingKey, issuer, "l42.eu", 0)
	if err != nil {
		reqLogger(r).Printf("handleClientCredentialsGrant: mint session: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenSuccessResponse{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		ExpiresIn:   int(token.DefaultSessionTTL.Seconds()),
		Scope:       strings.Join(effective, " "),
	})
}

// --- Admin machine-key provisioning endpoint ---

type createMachineKeyRequest struct {
	AgentSlug string `json:"agent_slug"`
}

type createMachineKeyResponse struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	PrincipalID  string    `json:"principal_id"`
	CredentialID string    `json:"credential_id"`
	CreatedAt    time.Time `json:"created_at"`
	Note         string    `json:"note"`
}

// handleAdminMachineKeys serves POST /admin/machine-keys.
// It provisions a new machine_key credential for an agent principal.
// The raw secret is returned once — only its SHA-256 hash is stored in the DB.
// Callers must save the secret immediately to lucos_creds.
func handleAdminMachineKeys(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var req createMachineKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "400 Bad Request: invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.AgentSlug == "" {
			http.Error(w, "400 Bad Request: agent_slug is required", http.StatusBadRequest)
			return
		}

		// Find or create the agent principal.
		principal, err := s.GetPrincipalByExternalID(store.PrincipalClassAgent, req.AgentSlug)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				reqLogger(r).Printf("handleAdminMachineKeys: get principal %q: %v", req.AgentSlug, err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			// Principal doesn't exist — create it.
			principal, err = s.CreatePrincipal(store.PrincipalClassAgent, req.AgentSlug)
			if err != nil {
				reqLogger(r).Printf("handleAdminMachineKeys: create principal %q: %v", req.AgentSlug, err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
		}

		// Generate raw secret (UUID v4 — no special chars, safe for lucos_creds storage).
		rawSecret := uuid.New().String()

		// Validate the hash we're about to store: confirm it's 64 hex characters.
		secretHash := hashMachineKey(rawSecret)
		if len(secretHash) != machineKeyHashLen {
			// This would be a bug — SHA-256 always produces 32 bytes → 64 hex chars.
			reqLogger(r).Printf("handleAdminMachineKeys: unexpected hash length %d", len(secretHash))
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Store only the hash — raw secret never touches the DB.
		label := fmt.Sprintf("machine_key:%s", req.AgentSlug)
		cred, err := s.CreateCredential(principal.ID, store.CredentialTypeMachineKey, []byte(secretHash), label)
		if err != nil {
			reqLogger(r).Printf("handleAdminMachineKeys: create credential for %q: %v", req.AgentSlug, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(createMachineKeyResponse{
			ClientID:     req.AgentSlug,
			ClientSecret: rawSecret,
			PrincipalID:  principal.ID,
			CredentialID: cred.ID,
			CreatedAt:    cred.CreatedAt,
			Note:         "Store client_secret in lucos_creds immediately — it is shown only once and not stored by aithne.",
		})
	}
}

// handleAdminMachineKeyByID dispatches DELETE for /admin/machine-keys/{id}.
// Revokes the identified machine_key credential (soft-revoke, keeping the row
// for audit). Mirrors handleGrantByID. Must be wrapped in requireAdminScope.
func handleAdminMachineKeyByID(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract the credential ID from the path: /admin/machine-keys/{id}
		id := strings.TrimPrefix(r.URL.Path, "/admin/machine-keys/")
		if id == "" {
			http.Error(w, "400 Bad Request — credential ID required", http.StatusBadRequest)
			return
		}

		// Attribution is read from the verified JWT claims injected by
		// requireAdminScope — never from a client-supplied header.
		claims := r.Context().Value(claimsContextKey).(*token.SessionClaims)
		revokedBy := claims.Subject

		err := s.RevokeCredential(id, revokedBy)
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
		if errors.Is(err, store.ErrCredentialRevoked) {
			http.Error(w, "409 Conflict — credential is already revoked", http.StatusConflict)
			return
		}
		if err != nil {
			reqLogger(r).Printf("revokeCredential: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
