package main

// OIDC/OAuth2 protocol endpoints (lucos_aithne#7).
//
// Per ADR-0001 §1, lucos_aithne is a full OpenID Provider from day one.
// This file implements:
//
//   GET  /.well-known/openid-configuration — OIDC discovery document
//   GET  /oauth2/authorize                 — authorization-code flow
//   GET  /oauth2/userinfo                  — OIDC userinfo endpoint
//
// OIDC client registration is not an HTTP endpoint (ADR-0004 §5 removed the
// admin POST/GET/DELETE /admin/oidc-clients handler): clients are declared in
// the committed oidc_clients.json manifest and reconciled into the store at
// startup — see reconcileOIDCClients in main.go.
//
// The /oauth2/token endpoint is handled in machine_credentials.go and dispatches
// to handleAuthCodeGrant (defined here) for the authorization_code grant type.
//
// Authorization-code flow sequence:
//  1. RP → GET /oauth2/authorize?response_type=code&client_id=X&redirect_uri=Y&scope=openid&state=Z&nonce=N
//  2. Server validates client_id and redirect_uri (errors here are NOT redirected).
//  3. If no valid aithne_session cookie → redirect to /auth/login?next=<current URL>.
//  4. After login, the login page JS calls safeRedirect() which returns the browser here.
//  5. Server validates remaining params, generates authorization code, redirects to
//     redirect_uri?code=<code>&state=<state>.
//  6. RP → POST /oauth2/token with code, client_id, client_secret, redirect_uri.
//  7. Server returns access_token (session JWT, aud=l42.eu) + id_token (OIDC, aud=client_id).

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"lucos_aithne/store"
	"lucos_aithne/token"
)

// authCodeTTL is the maximum lifetime of an authorization code.
// OIDC Core §10.5 recommends a short lifetime; 5 minutes is conventional.
const authCodeTTL = 5 * time.Minute

// oidcScopes lists the OIDC-defined scopes advertised in the discovery document.
// These are separate from the aithne authorisation scopes stored in grants.
var oidcScopes = []string{"openid", "profile", "email"}

// oidcDiscovery is the OpenID Provider metadata per OIDC Discovery 1.0.
// Fields are a struct rather than map[string]any to ensure stable serialisation.
type oidcDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSUri                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// handleOpenIDConfiguration serves GET /.well-known/openid-configuration.
// The response is derived from APP_ORIGIN (issuer) and is otherwise static.
func handleOpenIDConfiguration(issuer string) http.HandlerFunc {
	doc := oidcDiscovery{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oauth2/authorize",
		TokenEndpoint:         issuer + "/oauth2/token",
		UserinfoEndpoint:      issuer + "/oauth2/userinfo",
		JWKSUri:               issuer + "/.well-known/jwks.json",
		ScopesSupported:       oidcScopes,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		ClaimsSupported:                   []string{"iss", "sub", "aud", "exp", "iat", "jti", "nonce", "principal_class", "name", "email", "scopes"},
	}
	b, _ := json.Marshal(doc) // static; marshal once at construction

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(b)
	}
}

// handleAuthorize serves GET /oauth2/authorize.
// It implements the OIDC authorization-code flow entry point.
func handleAuthorize(s *store.Store, issuer, environment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		q := r.URL.Query()
		clientID := q.Get("client_id")
		redirectURIStr := q.Get("redirect_uri")
		responseType := q.Get("response_type")
		scopeStr := q.Get("scope")
		state := q.Get("state")
		nonce := q.Get("nonce")

		// serverError renders the generic "something went wrong, try again"
		// page for the internal (non-config) failures below — none of these
		// are the user's fault or fixable by them, and a retry may genuinely
		// succeed a moment later.
		serverError := func() {
			renderErrorPage(w, http.StatusInternalServerError,
				"Something went wrong",
				"We couldn't complete your sign-in just then.",
				retryTransient)
		}

		// --- Phase 1: validate client_id and redirect_uri ---
		// These errors are NOT forwarded to the redirect_uri (prevents open redirect).
		// They're also not the user's fault or fixable by them — they mean the app
		// that sent them here is missing or misconfigured, so the copy points at the
		// administrator rather than suggesting the user do something differently.

		if clientID == "" {
			renderErrorPage(w, http.StatusBadRequest,
				"Sign-in link incomplete",
				"This sign-in link is missing information it needs to continue.",
				retryUnlikely)
			return
		}

		client, err := s.GetOIDCClient(clientID)
		if errors.Is(err, store.ErrNotFound) {
			renderErrorPage(w, http.StatusBadRequest,
				"App not recognised",
				"This app isn't registered to sign in with lucOS.",
				retryUnlikely)
			return
		}
		if err != nil {
			reqLogger(r).Printf("handleAuthorize: get client %q: %v", clientID, err)
			serverError()
			return
		}

		if redirectURIStr == "" {
			renderErrorPage(w, http.StatusBadRequest,
				"Sign-in link incomplete",
				"This sign-in link is missing information it needs to continue.",
				retryUnlikely)
			return
		}
		if !client.HasRedirectURI(redirectURIStr) {
			renderErrorPage(w, http.StatusBadRequest,
				"App configuration mismatch",
				"This app is registered with lucOS, but tried to send you back to an address lucOS doesn't recognise for it.",
				retryUnlikely)
			return
		}

		// Helper: redirect to redirect_uri with an OAuth2 error code.
		redirectError := func(errCode, errDescription string) {
			v := url.Values{}
			v.Set("error", errCode)
			if errDescription != "" {
				v.Set("error_description", errDescription)
			}
			if state != "" {
				v.Set("state", state)
			}
			http.Redirect(w, r, redirectURIStr+"?"+v.Encode(), http.StatusFound)
		}

		// --- Phase 2: validate remaining params (errors redirect to redirect_uri) ---

		if responseType != "code" {
			redirectError("unsupported_response_type",
				"only response_type=code is supported")
			return
		}

		if !slices.Contains(parseScopeParam(scopeStr), "openid") {
			redirectError("invalid_scope", "scope must include openid")
			return
		}

		// --- Phase 3: check session cookie ---

		cookie, err := r.Cookie("aithne_session")
		if err != nil {
			// No cookie — redirect to login; on success the login page JS
			// will call safeRedirect() which brings the browser back here.
			http.Redirect(w, r,
				"/auth/login?next="+url.QueryEscape(r.URL.RequestURI()),
				http.StatusFound)
			return
		}

		keys, err := s.ListVerificationKeys(token.VerificationWindow)
		if err != nil {
			reqLogger(r).Printf("handleAuthorize: list verification keys: %v", err)
			serverError()
			return
		}
		keySet, err := token.BuildVerificationKeySet(keys)
		if err != nil {
			reqLogger(r).Printf("handleAuthorize: build key set: %v", err)
			serverError()
			return
		}

		claims, err := token.ParseSession(cookie.Value, keySet, issuer, "l42.eu")
		if err != nil {
			// Cookie is invalid or expired — redirect to login.
			http.Redirect(w, r,
				"/auth/login?next="+url.QueryEscape(r.URL.RequestURI()),
				http.StatusFound)
			return
		}

		// --- Phase 4: generate authorization code and redirect ---

		// Look up the principal by external identity to get the internal ID.
		principal, err := s.GetPrincipalByExternalID(claims.PrincipalClass, claims.Subject)
		if errors.Is(err, store.ErrNotFound) {
			reqLogger(r).Printf("handleAuthorize: principal not found for %s %q", claims.PrincipalClass, claims.Subject)
			redirectError("server_error", "principal not found")
			return
		}
		if err != nil {
			reqLogger(r).Printf("handleAuthorize: get principal: %v", err)
			serverError()
			return
		}

		rawCode, err := store.GenerateRawCode()
		if err != nil {
			reqLogger(r).Printf("handleAuthorize: generate code: %v", err)
			serverError()
			return
		}

		expiresAt := time.Now().Add(authCodeTTL)
		if err := s.CreateOIDCAuthCode(rawCode, clientID, principal.ID, redirectURIStr, scopeStr, nonce, expiresAt); err != nil {
			reqLogger(r).Printf("handleAuthorize: create auth code: %v", err)
			serverError()
			return
		}

		v := url.Values{}
		v.Set("code", rawCode)
		if state != "" {
			v.Set("state", state)
		}
		http.Redirect(w, r, redirectURIStr+"?"+v.Encode(), http.StatusFound)
	}
}

// handleAuthCodeGrant implements the authorization_code grant for handleOAuth2Token.
// It is called after the grant_type has been confirmed to be "authorization_code".
func handleAuthCodeGrant(s *store.Store, issuer, environment string, tokenLimiter *keyedLimiter, contacts *contactsClient, w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")

	// Accept client credentials via HTTP Basic Auth ("client_secret_basic",
	// RFC 6749 §2.3.1) in addition to the form-body method above
	// ("client_secret_post") — the discovery document now advertises both
	// (see oidcDiscovery.TokenEndpointAuthMethodsSupported). Some OIDC relying
	// parties (e.g. BookStack, used by lucos_worlds) always send credentials
	// via Basic Auth regardless of what the discovery document advertises.
	// This is a genuine aithne conformance gap, not a posture choice: RFC 6749
	// §2.3.1 makes client_secret_basic the mandatory baseline method — aithne
	// only supported the optional client_secret_post one (lucas42/lucos_aithne#295,
	// lucos-architect review).
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		// RFC 6749 §2.3: a client MUST NOT use more than one authentication
		// method in a single request. Reject outright rather than silently
		// preferring one source — a request presenting both is malformed,
		// not a client we should guess at.
		if clientID != "" || clientSecret != "" {
			writeTokenError(w, http.StatusBadRequest, "invalid_request",
				"client credentials must be sent via either HTTP Basic Auth or the request body, not both")
			return
		}

		// RFC 6749 §2.3.1 technically specifies the client_id/client_secret in
		// the Basic Auth header should each be application/x-www-form-urlencoded
		// before being combined and base64-encoded — but real clients don't
		// reliably follow this. Verified directly against the library BookStack
		// (lucos_worlds) uses: league/oauth2-client's HttpBasicAuthOptionProvider
		// does `base64_encode(sprintf('%s:%s', $client_id, $client_secret))` —
		// raw, no urlencode step, despite its own docblock citing this RFC
		// section. So URL-decoding here would be actively wrong for our actual
		// client: any client_secret containing '+' or '%' would be silently
		// mangled ('+' -> space, or a decode error on '%'), a latent regression
		// waiting for a future secret rotation to trigger. #296 merged and
		// deployed with this bug before lucos-architect's review caught it;
		// this is the fix-forward (#297). Use the raw r.BasicAuth() values as-is.
		clientID = basicID
		clientSecret = basicSecret
	}

	if code == "" || clientID == "" || clientSecret == "" || redirectURI == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request",
			"code, client_id, client_secret, and redirect_uri are required")
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
		retryAfter := fmt.Sprintf("%d", int(tokenEndpointWindow.Seconds()))
		w.Header().Set("Retry-After", retryAfter)
		writeTokenError(w, http.StatusTooManyRequests, "rate_limited",
			"too many authentication attempts for this client — retry after "+retryAfter+" seconds")
		return
	}

	// Verify the OIDC client.
	client, err := s.GetOIDCClient(clientID)
	if errors.Is(err, store.ErrNotFound) {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client_id or client_secret")
		return
	}
	if err != nil {
		reqLogger(r).Printf("handleAuthCodeGrant: get client %q: %v", clientID, err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Constant-time comparison of the OIDC client secret hash (prevents timing attacks).
	secretHash := hashOIDCSecret(clientSecret)
	if subtle.ConstantTimeCompare([]byte(secretHash), []byte(client.SecretHash)) != 1 {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client_id or client_secret")
		return
	}

	// Validate the auth code (read-only) BEFORE consuming it.
	// Per RFC 6749 §4.1.3, validation failures must NOT consume the code — the
	// legitimate client holder must be able to retry with the correct parameters.
	pendingCode, err := s.GetOIDCAuthCode(code)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "unknown authorization code")
		return
	case errors.Is(err, store.ErrAuthCodeExpired):
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code has expired")
		return
	case errors.Is(err, store.ErrAuthCodeUsed):
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code has already been used")
		return
	case err != nil:
		reqLogger(r).Printf("handleAuthCodeGrant: get auth code: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Validate client_id and redirect_uri match what was stored at authorization time.
	if pendingCode.ClientID != clientID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	if pendingCode.RedirectURI != redirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Validation passed — atomically consume the code (marks used_at, double-checks expiry/used).
	authCode, err := s.ConsumeOIDCAuthCode(code)
	switch {
	case errors.Is(err, store.ErrAuthCodeExpired):
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code has expired")
		return
	case errors.Is(err, store.ErrAuthCodeUsed):
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code has already been used")
		return
	case err != nil:
		reqLogger(r).Printf("handleAuthCodeGrant: consume auth code: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Load the principal to mint tokens.
	principal, err := s.GetPrincipalByID(authCode.PrincipalID)
	if errors.Is(err, store.ErrNotFound) {
		reqLogger(r).Printf("handleAuthCodeGrant: principal %q not found", authCode.PrincipalID)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "principal not found")
		return
	}
	if err != nil {
		reqLogger(r).Printf("handleAuthCodeGrant: get principal %q: %v", authCode.PrincipalID, err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Collect active scopes (aithne authorisation scopes, not OIDC scopes).
	granted, err := s.GetActiveScopes(principal.ID, environment)
	if err != nil {
		reqLogger(r).Printf("handleAuthCodeGrant: get scopes for %s: %v", principal.ID, err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Narrow the token's scopes to the subset the client actually requested at
	// /oauth2/authorize (RFC 6749 §3.3, OIDC Core §5.4), rather than always
	// stamping the principal's full granted set. OIDC-protocol scopes such as
	// "openid"/"profile"/"email" are never present in the grant store, so they
	// drop out of this intersection naturally — no special-casing required.
	grantedSet := toSet(granted)
	requestedScopes := parseScopeParam(authCode.Scope)
	effectiveScopes := make([]string, 0, len(requestedScopes))
	for _, sc := range requestedScopes {
		if grantedSet[sc] {
			effectiveScopes = append(effectiveScopes, sc)
		}
	}

	// Separately track which *OIDC-protocol* scopes (openid/profile/email)
	// were requested, restricted to the advertised set — this is deliberately
	// NOT folded into effectiveScopes/ClaimScopes above (several tests assert
	// OIDC scopes never appear there). It exists purely to gate scope-
	// conditional claims like "email" (lucos_aithne#299): embedded on the
	// access token via ClaimOIDCScopes for handleUserinfo, and resolved here
	// directly for the id_token.
	oidcScopeSet := toSet(oidcScopes)
	requestedOIDCScopes := make([]string, 0, len(requestedScopes))
	for _, sc := range requestedScopes {
		if oidcScopeSet[sc] {
			requestedOIDCScopes = append(requestedOIDCScopes, sc)
		}
	}

	// Resolve the primary_email claim value (ADR-0003 / lucos_aithne#299):
	// only for human principals who requested the "email" scope, and only if
	// lucos_contacts actually has a primary email on file. Best-effort, like
	// the equivalent lookup in handleUserinfo — a contacts outage must not
	// fail the token exchange, it just omits the claim.
	var email string
	if principal.Class == store.PrincipalClassHuman && contacts != nil && slices.Contains(requestedOIDCScopes, "email") {
		info, err := contacts.Get(principal.ExternalID)
		if err == nil {
			email = info.PrimaryEmail
		} else if !errors.Is(err, store.ErrNotFound) {
			reqLogger(r).Printf("handleAuthCodeGrant: contacts lookup for %q: %v", principal.ExternalID, err)
		}
	}

	signingKey, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		reqLogger(r).Printf("handleAuthCodeGrant: get signing key: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Mint the access token — same session JWT format as all other flows
	// (audience "l42.eu"), carrying the effective (narrowed) scope set plus
	// the requested OIDC scopes (for handleUserinfo's claim gating).
	accessToken, err := token.MintSession(principal, effectiveScopes, signingKey, issuer, "l42.eu", 0, requestedOIDCScopes...)
	if err != nil {
		reqLogger(r).Printf("handleAuthCodeGrant: mint access token: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Mint the OIDC ID token — audience is the client_id, nonce forwarded.
	// Carries the same effective (narrowed) scope set as the access token, so a
	// generic OIDC RP (which authenticates off the id_token, not the access
	// token) has something to gate on (lucos_aithne#277), plus the
	// already-resolved, already scope-gated email claim (lucos_aithne#299).
	idToken, err := token.MintIDToken(principal, clientID, authCode.Nonce, effectiveScopes, email, signingKey, issuer, 0)
	if err != nil {
		reqLogger(r).Printf("handleAuthCodeGrant: mint id_token: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   int(token.DefaultSessionTTL.Seconds()),
	})
}

// handleUserinfo serves GET /oauth2/userinfo.
// The caller must present a valid session JWT as Bearer token.
// Returns OIDC claims for the authenticated principal.
func handleUserinfo(s *store.Store, issuer string, contacts *contactsClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract Bearer token.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="aithne"`)
			http.Error(w, "401 Unauthorized — missing Bearer token", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		keys, err := s.ListVerificationKeys(token.VerificationWindow)
		if err != nil {
			reqLogger(r).Printf("handleUserinfo: list verification keys: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		keySet, err := token.BuildVerificationKeySet(keys)
		if err != nil {
			reqLogger(r).Printf("handleUserinfo: build key set: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		claims, err := token.ParseSession(tokenStr, keySet, issuer, "l42.eu")
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="aithne", error="invalid_token"`)
			http.Error(w, "401 Unauthorized — invalid or expired token", http.StatusUnauthorized)
			return
		}

		// claims.Scopes is already the requested-∩-granted effectiveScopes set —
		// ParseSession extracts it from the access token's own "scopes" claim
		// (stamped by MintSession in handleAuthCodeGrant/handleClientCredentialsGrant),
		// so no re-derivation is needed here (lucos_aithne#277).
		resp := map[string]any{
			"sub":             claims.Subject,
			"principal_class": string(claims.PrincipalClass),
			"scopes":          claims.Scopes,
		}

		// Attempt to enrich with profile data from lucos_contacts for human principals.
		if claims.PrincipalClass == store.PrincipalClassHuman && contacts != nil {
			info, err := contacts.Get(claims.Subject)
			if err == nil {
				// name is gated on the "profile" OIDC scope having been
				// requested at /oauth2/authorize, mirroring the email gating
				// below (lucos_aithne#301).
				if slices.Contains(claims.OIDCScopes, "profile") && info.DisplayName != "" {
					resp["name"] = info.DisplayName
				}
				// email is gated on the "email" OIDC scope having been
				// requested at /oauth2/authorize (ClaimOIDCScopes, stamped
				// onto the access token by handleAuthCodeGrant) — omit
				// entirely rather than emitting an empty claim if the person
				// has no primary email set (lucos_aithne#299, ADR-0003).
				if slices.Contains(claims.OIDCScopes, "email") && info.PrimaryEmail != "" {
					resp["email"] = info.PrimaryEmail
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				// Log but don't fail — contacts lookup is best-effort.
				reqLogger(r).Printf("handleUserinfo: contacts lookup for %q: %v", claims.Subject, err)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// hashOIDCSecret returns the hex-encoded SHA-256 of the raw OIDC client secret.
// Used both by the (removed) admin registration path's successor — the startup
// manifest reconcile in main.go — to hash the CLIENT_KEYS-delivered secret.
func hashOIDCSecret(rawSecret string) string {
	sum := sha256.Sum256([]byte(rawSecret))
	return hex.EncodeToString(sum[:])
}
