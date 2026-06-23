package main

// handleReMint serves POST /auth/remint — the silent re-mint endpoint from ADR-0003 §2.
//
// # Purpose
//
// Given a valid IdP-session cookie, re-issues a fresh 15-minute aithne_session via
// Set-Cookie and returns 200. No WebAuthn ceremony is required. The shared navbar
// calls this endpoint in the background every N minutes (N < 15) and on focus events
// so the principal's access token stays fresh while they work.
//
// # CSRF safety — "harmless-if-forged" design
//
// The endpoint is a POST, not a GET. With SameSite=None a forged cross-origin
// trigger *can* send the aithne_idp_session cookie to this endpoint (since
// SameSite=None sends cookies on all same-site+cross-site requests), but the
// consequence is null:
//
//   - The attacker cannot read the response (HttpOnly cookie + CORS blocks the body).
//   - The only outcome is refreshing the victim's own session — the victim's cookie
//     is replaced with an equally-valid new one. This gives the attacker nothing.
//
// This rationale is documented here so that future contributors do not add a
// side-effect (e.g. "log the IP" or "issue a machine key") to this endpoint without
// also adding a CSRF token. The endpoint must remain "re-issue existing session only"
// for this reasoning to hold.
//
// # CORS allow-list — *.l42.eu origin glob + dev-localhost (ADR-0003 §2, amended 2026-06-23)
//
// Production: any HTTPS origin matching the *.l42.eu suffix (e.g. https://arachne.l42.eu,
// https://photos.l42.eu) is allowed to make credentialed cross-site fetch() calls
// to this endpoint.
//
// Development (ENVIRONMENT=development): additionally accepts http://localhost:<port>
// and http://127.0.0.1:<port>. A port is required in CORS origins (browsers include
// it for non-default ports; portless http://localhost:80 is never sent in practice).
//
// The matched origin is always echoed in Access-Control-Allow-Origin (required by
// the CORS spec when credentials are involved; a static "*" is spec-invalid with
// credentials per WHATWG Fetch §3.2.5).
//
// This glob is safe ONLY because the endpoint is "harmless-if-forged" (see CSRF
// section above). If any future change adds a readable response body, a side-effect
// beyond re-issuing the caller's own session, or any capability the attacker could
// extract across the CORS boundary, the allow-list MUST be tightened BEFORE that
// change ships. Do not widen or preserve the glob on a changed endpoint design
// without a fresh threat-model review.
//
// Non-l42.eu cross-origin requests are still 403'd. Same-origin requests (no
// Origin header, or Origin == APP_ORIGIN) bypass the check entirely.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"

	"lucos_aithne/store"
	"lucos_aithne/token"
)

// l42euOriginRe matches any https://*.l42.eu origin (scheme + valid hostname ending in .l42.eu).
// The regex requires "https://" and at least one label before ".l42.eu"; labels may contain
// ASCII letters, digits, and hyphens (RFC 1123); uppercase not expected (origins are lowercased
// by browsers) but the regex is case-sensitive for simplicity — production origins are lowercase.
var l42euOriginRe = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*\.l42\.eu$`)

// handleReMint returns an http.HandlerFunc for POST /auth/remint.
// appOrigin is APP_ORIGIN (used for same-origin CORS bypass).
func handleReMint(s *store.Store, issuer, environment, appOrigin string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Handle CORS preflight (OPTIONS) before method check so browsers can
		// complete the preflight without a 405.
		if r.Method == http.MethodOptions {
			handleReMintPreflight(w, r, environment)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Apply CORS headers for the actual request (cross-origin fetch).
		// setCORSHeaders returns false and writes 403 if the Origin is present but
		// not matched by the allow-list — in that case we must not proceed.
		if !setCORSHeaders(w, r, appOrigin, environment) {
			return
		}

		// --- IdP session validation ---

		cookie, err := r.Cookie(token.IdPSessionCookieName)
		if err != nil {
			// No IdP session cookie present — user hasn't logged in via WebAuthn.
			http.Error(w, "401 Unauthorized — no IdP session", http.StatusUnauthorized)
			return
		}

		sess, err := s.GetIDPSessionByToken(cookie.Value)
		if errors.Is(err, store.ErrIDPSessionRevoked) {
			// Session was explicitly revoked (e.g. credential-compromise runbook).
			http.Error(w, "401 Unauthorized — IdP session revoked", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, store.ErrIDPSessionExpired) {
			// Session has passed its 72-hour cap — new WebAuthn ceremony required.
			http.Error(w, "401 Unauthorized — IdP session expired", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			// Token doesn't exist in the DB (e.g. tampered cookie).
			http.Error(w, "401 Unauthorized — IdP session not found", http.StatusUnauthorized)
			return
		}
		if err != nil {
			reqLogger(r).Printf("handleReMint: get idp session: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// --- Synchronous principal re-validation (HARD requirement per ADR-0003 §2) ---
		//
		// Re-validating the principal on every re-mint is the revocation lever for
		// this session layer. If it is skipped or async-cached, a revoked principal
		// can keep minting fresh access tokens until the IdP session cap (72 h).
		// This MUST remain a synchronous DB read on every call.

		p, err := s.GetPrincipalByID(sess.PrincipalID)
		if errors.Is(err, store.ErrNotFound) {
			// Principal was deleted — refuse new tokens.
			http.Error(w, "401 Unauthorized — principal not found", http.StatusUnauthorized)
			return
		}
		if err != nil {
			reqLogger(r).Printf("handleReMint: get principal %s: %v", sess.PrincipalID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Verify the principal still has at least one active WebAuthn credential.
		// A fully-revoked principal (all credentials revoked) must not receive new tokens.
		creds, err := s.ListCredentialsByPrincipal(p.ID)
		if err != nil {
			reqLogger(r).Printf("handleReMint: list credentials for principal %s: %v", p.ID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		hasActiveCredential := false
		for _, c := range creds {
			if c.Type == store.CredentialTypeWebAuthn && c.IsActive() {
				hasActiveCredential = true
				break
			}
		}
		if !hasActiveCredential {
			// All WebAuthn credentials revoked — principal is effectively suspended.
			reqLogger(r).Printf("handleReMint: principal %s has no active WebAuthn credentials — denying re-mint", p.ID)
			http.Error(w, "401 Unauthorized — no active credential", http.StatusUnauthorized)
			return
		}

		// --- Mint fresh access token with current active scopes ---
		//
		// Re-fetching scopes on every re-mint ensures that a revoked scope takes
		// effect within one re-mint interval (N < 15 min). No caching.

		scopes, err := s.GetActiveScopes(p.ID, environment)
		if err != nil {
			reqLogger(r).Printf("handleReMint: get active scopes for principal %s: %v", p.ID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		signingKey, err := s.GetOrCreateActiveSigningKey()
		if err != nil {
			reqLogger(r).Printf("handleReMint: get signing key: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		tok, err := token.MintSession(p, scopes, signingKey, issuer, "l42.eu", token.DefaultSessionTTL)
		if err != nil {
			reqLogger(r).Printf("handleReMint: mint session for principal %s: %v", p.ID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		token.SetSessionCookie(w, tok, environment)

		reqLogger(r).Printf("handleReMint: re-minted session for principal %s", p.ID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

// handleReMintPreflight handles the OPTIONS preflight request for /auth/remint.
// The browser sends OPTIONS before the credentialed cross-origin POST;
// we must respond with the CORS allow headers for the browser to proceed.
func handleReMintPreflight(w http.ResponseWriter, r *http.Request, environment string) {
	appOrigin := "" // preflight doesn't need app-origin bypass
	if !setCORSHeaders(w, r, appOrigin, environment) {
		return // setCORSHeaders already wrote 403
	}
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

// setCORSHeaders inspects the Origin request header and, if the origin is
// allowed, sets the CORS response headers and returns true.
// If Origin is absent or equals appOrigin (same-origin), no headers are set and
// true is returned (non-cross-origin requests proceed without CORS headers).
// If Origin is present but not in the allow-list, 403 is written and false returned.
//
// Allow-list:
//   - Production: any https://*.l42.eu origin (l42euOriginRe).
//   - Development: additionally http://localhost:<port> and http://127.0.0.1:<port>
//     (isDevLocalhostURL from redirect.go, same package; port required for CORS).
//
// Safe to use a glob because /auth/remint is harmless-if-forged — see the
// package-level CORS comment above for the threat-model rationale and the
// explicit warning about future footguns.
func setCORSHeaders(w http.ResponseWriter, r *http.Request, appOrigin, environment string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == appOrigin {
		// No Origin header (non-browser / same-origin) — proceed without CORS headers.
		return true
	}

	if l42euOriginRe.MatchString(origin) {
		// Per-request origin echo required by the CORS spec when using
		// Access-Control-Allow-Credentials: true. A static "*" is spec-invalid
		// with credentials (WHATWG Fetch §3.2.5).
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
		return true
	}

	// Dev-environment: accept http://localhost:<port> and http://127.0.0.1:<port>.
	// Port is required — browsers always include it for non-default ports, and
	// portless http://localhost (port 80) is never used in practice for dev services.
	if environment == "development" {
		if u, err := url.Parse(origin); err == nil && u.Port() != "" && isDevLocalhostURL(u) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
			return true
		}
	}

	// Origin does not match the allow-list — reject the cross-origin request.
	http.Error(w, "403 Forbidden — origin not allowed", http.StatusForbidden)
	return false
}
