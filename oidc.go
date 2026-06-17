package main

// OIDC/OAuth2 protocol endpoints (lucos_aithne#7).
//
// Per ADR-0001 §1, lucos_aithne is a full OpenID Provider from day one.
// This file implements:
//
//   GET  /.well-known/openid-configuration — OIDC discovery document
//   GET  /oauth2/authorize                 — authorization-code flow
//   GET  /oauth2/userinfo                  — OIDC userinfo endpoint
//   POST /admin/oidc-clients               — register an OIDC relying party (admin)
//   GET  /admin/oidc-clients               — list registered clients (admin)
//   DELETE /admin/oidc-clients/{id}        — remove a client (admin)
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
	"net/http"
	"net/url"
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
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		ClaimsSupported:                   []string{"iss", "sub", "aud", "exp", "iat", "jti", "nonce", "principal_class", "name"},
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

		// --- Phase 1: validate client_id and redirect_uri ---
		// These errors are NOT forwarded to the redirect_uri (prevents open redirect).

		if clientID == "" {
			http.Error(w, "400 Bad Request — client_id is required", http.StatusBadRequest)
			return
		}

		client, err := s.GetOIDCClient(clientID)
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "400 Bad Request — unknown client_id", http.StatusBadRequest)
			return
		}
		if err != nil {
			reqLogger(r).Printf("handleAuthorize: get client %q: %v", clientID, err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		if redirectURIStr == "" {
			http.Error(w, "400 Bad Request — redirect_uri is required", http.StatusBadRequest)
			return
		}
		if !client.HasRedirectURI(redirectURIStr) {
			http.Error(w, "400 Bad Request — redirect_uri not registered for this client", http.StatusBadRequest)
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

		if !strings.Contains(scopeStr, "openid") {
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
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		keySet, err := token.BuildVerificationKeySet(keys)
		if err != nil {
			reqLogger(r).Printf("handleAuthorize: build key set: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
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
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		rawCode, err := store.GenerateRawCode()
		if err != nil {
			reqLogger(r).Printf("handleAuthorize: generate code: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		expiresAt := time.Now().Add(authCodeTTL)
		if err := s.CreateOIDCAuthCode(rawCode, clientID, principal.ID, redirectURIStr, scopeStr, nonce, expiresAt); err != nil {
			reqLogger(r).Printf("handleAuthorize: create auth code: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
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
func handleAuthCodeGrant(s *store.Store, issuer, environment string, w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" || clientID == "" || clientSecret == "" || redirectURI == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request",
			"code, client_id, client_secret, and redirect_uri are required")
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
	scopes, err := s.GetActiveScopes(principal.ID, environment)
	if err != nil {
		reqLogger(r).Printf("handleAuthCodeGrant: get scopes for %s: %v", principal.ID, err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	signingKey, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		reqLogger(r).Printf("handleAuthCodeGrant: get signing key: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Mint the access token — same session JWT format as all other flows
	// (audience "l42.eu", carries aithne scopes from the grant store).
	accessToken, err := token.MintSession(principal, scopes, signingKey, issuer, "l42.eu", 0)
	if err != nil {
		reqLogger(r).Printf("handleAuthCodeGrant: mint access token: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Mint the OIDC ID token — audience is the client_id, nonce forwarded.
	idToken, err := token.MintIDToken(principal, clientID, authCode.Nonce, signingKey, issuer, 0)
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

		resp := map[string]any{
			"sub":             claims.Subject,
			"principal_class": string(claims.PrincipalClass),
		}

		// Attempt to enrich with profile data from lucos_contacts for human principals.
		if claims.PrincipalClass == store.PrincipalClassHuman && contacts != nil {
			info, err := contacts.Get(claims.Subject)
			if err == nil && info.DisplayName != "" {
				resp["name"] = info.DisplayName
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				// Log but don't fail — contacts lookup is best-effort.
				reqLogger(r).Printf("handleUserinfo: contacts lookup for %q: %v", claims.Subject, err)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// --- Admin OIDC client management ---

type createOIDCClientRequest struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
}

type createOIDCClientResponse struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	RedirectURIs []string  `json:"redirect_uris"`
	ClientName   string    `json:"client_name"`
	CreatedAt    time.Time `json:"created_at"`
	Note         string    `json:"note"`
}

type oidcClientJSON struct {
	ClientID     string    `json:"client_id"`
	RedirectURIs []string  `json:"redirect_uris"`
	ClientName   string    `json:"client_name"`
	CreatedAt    time.Time `json:"created_at"`
}

// handleAdminOIDCClients serves GET and POST /admin/oidc-clients, and DELETE /admin/oidc-clients/{id}.
func handleAdminOIDCClients(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if this is /admin/oidc-clients/{id} (DELETE).
		path := strings.TrimPrefix(r.URL.Path, "/admin/oidc-clients")
		path = strings.TrimPrefix(path, "/")
		if path != "" {
			// Sub-resource: /admin/oidc-clients/{id}
			if r.Method != http.MethodDelete {
				http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			err := s.DeleteOIDCClient(path)
			if errors.Is(err, store.ErrNotFound) {
				http.Error(w, "404 Not Found", http.StatusNotFound)
				return
			}
			if err != nil {
				reqLogger(r).Printf("handleAdminOIDCClients: delete %q: %v", path, err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		switch r.Method {
		case http.MethodGet:
			listOIDCClients(s, w, r)
		case http.MethodPost:
			createOIDCClient(s, w, r)
		default:
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

func listOIDCClients(s *store.Store, w http.ResponseWriter, r *http.Request) {
	clients, err := s.ListOIDCClients()
	if err != nil {
		reqLogger(r).Printf("listOIDCClients: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	result := make([]oidcClientJSON, 0, len(clients))
	for _, c := range clients {
		result = append(result, oidcClientJSON{
			ClientID:     c.ID,
			RedirectURIs: c.RedirectURIs,
			ClientName:   c.ClientName,
			CreatedAt:    c.CreatedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func createOIDCClient(s *store.Store, w http.ResponseWriter, r *http.Request) {
	var req createOIDCClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "400 Bad Request — invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.ClientID == "" {
		http.Error(w, "400 Bad Request — client_id is required", http.StatusBadRequest)
		return
	}
	if len(req.RedirectURIs) == 0 {
		http.Error(w, "400 Bad Request — at least one redirect_uri is required", http.StatusBadRequest)
		return
	}
	for _, uri := range req.RedirectURIs {
		parsed, err := url.ParseRequestURI(uri)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			http.Error(w, "400 Bad Request — redirect_uris must be valid http/https URLs", http.StatusBadRequest)
			return
		}
	}

	// Generate a raw secret; only the hash is stored.
	rawSecret, err := store.GenerateRawCode()
	if err != nil {
		reqLogger(r).Printf("createOIDCClient: generate secret: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	secretHash := hashOIDCSecret(rawSecret)

	client, err := s.CreateOIDCClient(req.ClientID, secretHash, req.ClientName, req.RedirectURIs)
	if errors.Is(err, store.ErrDuplicate) {
		http.Error(w, "409 Conflict — client_id already registered", http.StatusConflict)
		return
	}
	if err != nil {
		reqLogger(r).Printf("createOIDCClient: create: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(createOIDCClientResponse{
		ClientID:     client.ID,
		ClientSecret: rawSecret,
		RedirectURIs: client.RedirectURIs,
		ClientName:   client.ClientName,
		CreatedAt:    client.CreatedAt,
		Note:         "Store client_secret immediately — it is shown only once and not stored by aithne.",
	})
}

// hashOIDCSecret returns the hex-encoded SHA-256 of the raw OIDC client secret.
func hashOIDCSecret(rawSecret string) string {
	sum := sha256.Sum256([]byte(rawSecret))
	return hex.EncodeToString(sum[:])
}
