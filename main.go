// lucos_aithne — Passkey-based OpenID Provider for the lucOS estate.
//
// See ADR-0001 for the full design:
// https://github.com/lucas42/lucos_aithne/blob/main/docs/adr/0001-foundational-design.md
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	gwebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lucos_aithne/store"
	"lucos_aithne/token"
)

// contextKey is a private type for context keys in this package, preventing
// collisions with other packages that also store values in request contexts.
type contextKey int

const (
	claimsContextKey   contextKey = iota
	rawTokenContextKey            // raw JWT string, set by requireAdminScopeFromCookie
)

// scopes.yaml is embedded at build time.
// The file is NOT committed — run scripts/fetch-scopes.sh (or `go generate ./...`)
// to populate it locally before building or testing.
// In CI the fetch-scopes job writes scopes.yaml to the workspace before `go test`;
// the Dockerfile fetches it independently via the `COPY --from=scopes` instruction.
//
//go:generate ./scripts/fetch-scopes.sh
//go:embed scopes.yaml
var scopesYAML []byte

// staticFS embeds the static/ directory so the HTML login page
// is served by the single binary (required for the scratch runtime image).
//
//go:embed static
var staticFS embed.FS

// templateFS embeds the templates/ directory for server-rendered Go templates.
//
//go:embed templates
var templateFS embed.FS

const healthcheckTimeout = 5 * time.Second

// signingKeyRotationInterval is the maximum age of a signing key before it is
// rotated at startup. 30 days is well within industry norms for short-lived
// signing keys on an auth service.
const signingKeyRotationInterval = 30 * 24 * time.Hour

// infoResponse is the `/_info` payload (Tier 1 + Tier 2 fields).
// Tier 3 fields (icon, show_on_homepage, etc.) are omitted — this is an API-only service.
type infoResponse struct {
	System  string         `json:"system"`
	Checks  map[string]any `json:"checks"`
	Metrics map[string]any `json:"metrics"`
	CI      *ciInfo        `json:"ci,omitempty"`
	Title   string         `json:"title,omitempty"`
}

type ciInfo struct {
	Circle string `json:"circle"`
}

func getEnvRequired(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("Required environment variable %s is not set", key)
	}
	return val
}

func handleInfo(system string, s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const dbDetail = "Checks whether a connection to the SQLite credential store can be established"
		checks := map[string]any{}
		if err := s.Ping(); err != nil {
			checks["db"] = map[string]any{"ok": false, "techDetail": dbDetail, "debug": err.Error()}
			log.Printf("/_info db ping failed: %v", err)
		} else {
			checks["db"] = map[string]any{"ok": true, "techDetail": dbDetail}
		}

		info := infoResponse{
			System:  system,
			Checks:  checks,
			Metrics: map[string]any{},
			CI:      &ciInfo{Circle: "gh/lucas42/lucos_aithne"},
			Title:   "Aithne",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(info); err != nil {
			log.Printf("/_info encode error: %v", err)
		}
	}
}

// runHealthcheck performs a local HTTP check against /_info and exits 0/1.
// Called by the Docker HEALTHCHECK instruction.
func runHealthcheck(port string) {
	client := &http.Client{Timeout: healthcheckTimeout}
	url := fmt.Sprintf("http://127.0.0.1:%s/_info", port)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck failed: /_info returned HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}
	os.Exit(0)
}

// ensureDir creates the parent directory of path if it does not already exist.
// This is a no-op for in-memory paths (e.g. ":memory:").
func ensureDir(path string) error {
	if path == ":memory:" || path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0o700)
}

func getEnvWithDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// parseScopesYAML parses the minimal scopes.yaml format into a Vocabulary.
// It scans for "  - <scope>" lines and strips inline comments.
// No YAML library is used: the format is simple and a parsing dependency on
// the auth service's core path adds unnecessary attack surface.
func parseScopesYAML(data []byte) (*store.Vocabulary, error) {
	var scopes []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- ") {
			continue
		}
		scope := strings.TrimPrefix(trimmed, "- ")
		// Strip inline comments (e.g. "render-ui    # dev-only: ...").
		if idx := strings.Index(scope, " #"); idx >= 0 {
			scope = strings.TrimSpace(scope[:idx])
		}
		scope = strings.TrimSpace(scope)
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("scopes.yaml: no scopes found — vocabulary is empty")
	}
	return store.NewVocabulary(scopes), nil
}

// bootstrapAdmin ensures the principal identified by contactID has the
// aithne:admin grant for environment. Per ADR-0002, it self-disables once the
// principal holds ≥1 WebAuthn credential — at that point the admin has a usable
// passkey and the bootstrap grant is no longer needed to be re-seeded.
// Set BOOTSTRAP_ADMIN_CONTACT_ID on startup to activate.
func bootstrapAdmin(s *store.Store, contactID, environment string, vocab *store.Vocabulary) {
	// Ensure the principal exists.
	p, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID)
	if errors.Is(err, store.ErrNotFound) {
		p, err = s.CreatePrincipal(store.PrincipalClassHuman, contactID)
		if err != nil {
			log.Printf("bootstrap: create principal %q: %v", contactID, err)
			return
		}
		log.Printf("bootstrap: created human principal for contact %q", contactID)
	} else if err != nil {
		log.Printf("bootstrap: lookup principal %q: %v", contactID, err)
		return
	}

	// Credential gate (ADR-0002 decision 2): if the principal already holds a
	// WebAuthn credential the enrolment is complete — do NOT touch grants.
	// Gating on credential (not principal) ensures that catastrophic-recovery
	// re-enrolment still gets a grant even though the principal already exists.
	creds, err := s.ListCredentialsByPrincipal(p.ID)
	if err != nil {
		log.Printf("bootstrap: list credentials for %q: %v", contactID, err)
		return
	}
	for _, c := range creds {
		if c.Type == store.CredentialTypeWebAuthn {
			log.Printf("WARNING: BOOTSTRAP_ADMIN_CONTACT_ID is set for contact %q — "+
				"passkey already enrolled. The env var can now be removed.", contactID)
			return
		}
	}

	// Not-yet-enrolled: warn the operator that the bootstrap is still active.
	log.Printf("WARNING: BOOTSTRAP_ADMIN_CONTACT_ID is set for contact %q — "+
		"bootstrap active. Run `--bootstrap-invite` to get an enrolment URL and "+
		"remove the env var after enrolment is complete.", contactID)

	// Ensure the aithne:admin grant exists.
	_, err = s.CreateGrant(p.ID, "aithne:admin", environment, "bootstrap", vocab)
	if errors.Is(err, store.ErrDuplicate) {
		log.Printf("bootstrap: principal %q already has aithne:admin in %s", contactID, environment)
		return
	}
	if err != nil {
		log.Printf("bootstrap: create grant for %q: %v", contactID, err)
		return
	}
	log.Printf("bootstrap: granted aithne:admin to contact %q in %s", contactID, environment)
}

// bootstrapInvite creates a single-use enrolment invite for the bootstrap
// admin contact and returns its URL. It is the testable core of the
// --bootstrap-invite subcommand.
// contactID must equal BOOTSTRAP_ADMIN_CONTACT_ID — validated by the caller.
// appOrigin is APP_ORIGIN (e.g. "https://aithne.l42.eu").
func bootstrapInvite(s *store.Store, contactID, appOrigin string) (string, error) {
	// Ensure the principal exists (get-or-create, same as bootstrapAdmin).
	_, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID)
	if errors.Is(err, store.ErrNotFound) {
		if _, err = s.CreatePrincipal(store.PrincipalClassHuman, contactID); err != nil {
			return "", fmt.Errorf("bootstrap-invite: create principal %q: %w", contactID, err)
		}
	} else if err != nil {
		return "", fmt.Errorf("bootstrap-invite: lookup principal %q: %w", contactID, err)
	}

	rawToken := uuid.New().String()
	if _, err := s.CreateInvite(rawToken, contactID, "bootstrap-cli"); err != nil {
		return "", fmt.Errorf("bootstrap-invite: create invite for %q: %w", contactID, err)
	}

	inviteURL := appOrigin + "/enrol?token=" + rawToken
	return inviteURL, nil
}

// runBootstrapInvite is the entrypoint for the --bootstrap-invite subcommand.
// It reads BOOTSTRAP_ADMIN_CONTACT_ID, opens the store, mints an invite URL,
// prints it to stdout, and exits 0. Exits non-zero on any error.
// The HTTP server is never started.
func runBootstrapInvite() {
	contactID := os.Getenv("BOOTSTRAP_ADMIN_CONTACT_ID")
	if contactID == "" {
		fmt.Fprintln(os.Stderr, "bootstrap-invite: BOOTSTRAP_ADMIN_CONTACT_ID is not set; cannot create invite")
		os.Exit(1)
	}

	appOrigin := getEnvRequired("APP_ORIGIN")

	signingKEKStr := getEnvRequired("SIGNING_KEK")
	if len(signingKEKStr) != 32 {
		fmt.Fprintf(os.Stderr, "bootstrap-invite: SIGNING_KEK must be exactly 32 bytes, got %d\n", len(signingKEKStr))
		os.Exit(1)
	}
	var signingKEK [32]byte
	copy(signingKEK[:], signingKEKStr)

	dbPath := getEnvWithDefault("DB_PATH", "/data/aithne.db")
	s, err := store.Open(dbPath, signingKEK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap-invite: open store at %q: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer s.Close()

	inviteURL, err := bootstrapInvite(s, contactID, appOrigin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Println(inviteURL)
	os.Exit(0)
}

// --- Admin HTTP handlers ---

// grantJSON is the JSON representation of a grant returned by admin endpoints.
type grantJSON struct {
	ID          string  `json:"id"`
	PrincipalID string  `json:"principal_id"`
	Scope       string  `json:"scope"`
	Environment string  `json:"environment"`
	GrantedBy   string  `json:"granted_by"`
	GrantedAt   string  `json:"granted_at"`
	RevokedBy   *string `json:"revoked_by,omitempty"`
	RevokedAt   *string `json:"revoked_at,omitempty"`
}

func grantToJSON(g *store.Grant) grantJSON {
	j := grantJSON{
		ID:          g.ID,
		PrincipalID: g.PrincipalID,
		Scope:       g.Scope,
		Environment: g.Environment,
		GrantedBy:   g.GrantedBy,
		GrantedAt:   g.GrantedAt.Format(time.RFC3339),
	}
	if g.RevokedBy != nil {
		s := *g.RevokedBy
		j.RevokedBy = &s
	}
	if g.RevokedAt != nil {
		s := g.RevokedAt.Format(time.RFC3339)
		j.RevokedAt = &s
	}
	return j
}

// requireAdminScope wraps an HTTP handler, requiring a valid session JWT with
// the aithne:admin scope. The token must be passed as:
//
//	Authorization: Bearer <token>
//
// Returns 401 if no valid token is present and 403 if the scope is missing.
func requireAdminScope(s *store.Store, issuer string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Bearer token from Authorization header.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "401 Unauthorized — missing Bearer token", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		// Build verification key set from current signing keys.
		keys, err := s.ListVerificationKeys(token.VerificationWindow)
		if err != nil {
			log.Printf("requireAdminScope: list verification keys: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		keySet, err := token.BuildVerificationKeySet(keys)
		if err != nil {
			log.Printf("requireAdminScope: build key set: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		claims, err := token.ParseSession(tokenStr, keySet, issuer, "l42.eu")
		if err != nil {
			http.Error(w, "401 Unauthorized — invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Verify aithne:admin scope.
		hasAdmin := false
		for _, sc := range claims.Scopes {
			if sc == "aithne:admin" {
				hasAdmin = true
				break
			}
		}
		if !hasAdmin {
			http.Error(w, "403 Forbidden — aithne:admin scope required", http.StatusForbidden)
			return
		}

		// Inject the verified claims into the request context so downstream
		// handlers can read the authenticated subject for audit attribution
		// without trusting any client-supplied field.
		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next(w, r.WithContext(ctx))
	}
}

// requireAdminScopeFromCookie is like requireAdminScope but reads the session
// token from the aithne_session cookie instead of the Authorization header.
// It is used for browser-rendered admin pages (GET requests) where no
// Authorization header is present. On success it injects both the parsed claims
// (claimsContextKey) and the raw JWT string (rawTokenContextKey) into the
// request context so handlers can embed the token in HTML templates for AJAX.
// Unauthenticated requests are redirected to /auth/login?next=<current path>.
func requireAdminScopeFromCookie(s *store.Store, issuer string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("aithne_session")
		if err != nil {
			// No cookie — redirect to login and come back.
			http.Redirect(w, r, "/auth/login?next="+r.URL.RequestURI(), http.StatusFound)
			return
		}
		tokenStr := cookie.Value

		keys, err := s.ListVerificationKeys(token.VerificationWindow)
		if err != nil {
			log.Printf("requireAdminScopeFromCookie: list verification keys: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		keySet, err := token.BuildVerificationKeySet(keys)
		if err != nil {
			log.Printf("requireAdminScopeFromCookie: build key set: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		claims, err := token.ParseSession(tokenStr, keySet, issuer, "l42.eu")
		if err != nil {
			// Invalid or expired cookie — redirect to login to refresh.
			http.Redirect(w, r, "/auth/login?next="+r.URL.RequestURI(), http.StatusFound)
			return
		}

		hasAdmin := false
		for _, sc := range claims.Scopes {
			if sc == "aithne:admin" {
				hasAdmin = true
				break
			}
		}
		if !hasAdmin {
			http.Error(w, "403 Forbidden — aithne:admin scope required", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		ctx = context.WithValue(ctx, rawTokenContextKey, tokenStr)
		next(w, r.WithContext(ctx))
	}
}

// handleRotateSigningKey serves POST /admin/rotate-signing-key.
// It immediately rotates the active signing key regardless of its age, for use
// during incident response (key compromise) or operator-driven rotation.
// Requires aithne:admin scope (enforced by the requireAdminScope wrapper in main()).
func handleRotateSigningKey(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		newKey, err := s.RotateSigningKey()
		if err != nil {
			log.Printf("handleRotateSigningKey: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if claims, ok := r.Context().Value(claimsContextKey).(*token.SessionClaims); ok {
			log.Printf("Signing key rotated via admin endpoint — initiated by %s, new key ID: %s", claims.Subject, newKey.ID)
		} else {
			log.Printf("Signing key rotated via admin endpoint — new key ID: %s (actor unknown)", newKey.ID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"rotated":    true,
			"new_key_id": newKey.ID,
		})
	}
}

// handleGrants dispatches GET (list) and POST (create) for /admin/grants.
func handleGrants(s *store.Store, vocab *store.Vocabulary) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listGrants(s)(w, r)
		case http.MethodPost:
			createGrant(s, vocab)(w, r)
		default:
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// listGrants handles GET /admin/grants?principal_id=X&environment=Y.
func listGrants(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principalID := r.URL.Query().Get("principal_id")
		environment := r.URL.Query().Get("environment")
		if principalID == "" {
			http.Error(w, "400 Bad Request — principal_id is required", http.StatusBadRequest)
			return
		}

		grants, err := s.ListGrants(principalID, environment, true)
		if err != nil {
			log.Printf("listGrants: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		result := make([]grantJSON, 0, len(grants))
		for _, g := range grants {
			result = append(result, grantToJSON(g))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// createGrantRequest is the POST body for creating a grant.
type createGrantRequest struct {
	PrincipalID string `json:"principal_id"`
	Scope       string `json:"scope"`
	Environment string `json:"environment"`
}

// createGrant handles POST /admin/grants.
func createGrant(s *store.Store, vocab *store.Vocabulary) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createGrantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "400 Bad Request — invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.PrincipalID == "" || req.Scope == "" || req.Environment == "" {
			http.Error(w, "400 Bad Request — principal_id, scope, and environment are required", http.StatusBadRequest)
			return
		}

		// Attribution is read from the verified JWT claims injected by
		// requireAdminScope — never from a client-supplied field.
		claims := r.Context().Value(claimsContextKey).(*token.SessionClaims)
		grantedBy := claims.Subject

		g, err := s.CreateGrant(req.PrincipalID, req.Scope, req.Environment, grantedBy, vocab)
		if errors.Is(err, store.ErrUnknownScope) {
			http.Error(w, "400 Bad Request — unknown scope (not in vocabulary)", http.StatusBadRequest)
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "404 Not Found — principal_id not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, store.ErrDuplicate) {
			http.Error(w, "409 Conflict — active grant already exists for this principal/scope/environment", http.StatusConflict)
			return
		}
		if err != nil {
			log.Printf("createGrant: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(grantToJSON(g))
	}
}

// handleGrantByID dispatches DELETE for /admin/grants/{id}.
func handleGrantByID(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract the grant ID from the path: /admin/grants/{id}
		id := strings.TrimPrefix(r.URL.Path, "/admin/grants/")
		if id == "" {
			http.Error(w, "400 Bad Request — grant ID required", http.StatusBadRequest)
			return
		}

		// Attribution is read from the verified JWT claims injected by
		// requireAdminScope — never from a client-supplied header.
		claims := r.Context().Value(claimsContextKey).(*token.SessionClaims)
		revokedBy := claims.Subject

		err := s.RevokeGrant(id, revokedBy)
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
		if errors.Is(err, store.ErrGrantRevoked) {
			http.Error(w, "409 Conflict — grant is already revoked", http.StatusConflict)
			return
		}
		if err != nil {
			log.Printf("revokeGrant: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// serveStaticFile returns an http.HandlerFunc that serves a single embedded
// file from staticFS at the given path (e.g. "static/login.html").
func serveStaticFile(fsys fs.FS, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		http.ServeFileFS(w, r, fsys, path)
	}
}

// secureHeaders wraps an HTTP handler and adds standard defence-in-depth
// security headers to every response. See issue #66 for the rationale.
// Handlers that need a Content-Security-Policy (e.g. handleLoginPage) set it
// themselves after the global headers have been applied by this wrapper.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// generateNonce returns a 16-byte cryptographically random value encoded as
// base64url (no padding). Uses RawURLEncoding to avoid characters (+, /, =)
// that html/template would HTML-escape in attribute values, which would
// break the CSP nonce check in the browser.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// loginPageData holds the per-request data injected into templates/login.html.
type loginPageData struct {
	Nonce string
}

// handleLoginPage serves the login page as a Go template, injecting a fresh
// per-request nonce into the <script> and <style> tags so the Content-Security-
// Policy can be locked to 'nonce-{nonce}' without requiring hashes or 'unsafe-inline'.
func handleLoginPage(tmplFS fs.FS) http.HandlerFunc {
	tmpl := template.Must(template.ParseFS(tmplFS, "templates/login.html"))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		nonce, err := applyPageCSP(w)
		if err != nil {
			log.Printf("handleLoginPage: generate nonce: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err := tmpl.Execute(w, loginPageData{Nonce: nonce}); err != nil {
			log.Printf("handleLoginPage: render: %v", err)
		}
	}
}

// deriveRPID determines the WebAuthn RP ID from the APP_ORIGIN URL.
//
// In production (APP_ORIGIN = "https://aithne.l42.eu") the RP ID is set to
// the registrable parent "l42.eu" per ADR-0001 §2, so passkeys are valid on
// any *.l42.eu origin without re-enrolment.
//
// In development (APP_ORIGIN = "http://localhost:PORT") the RP ID must be
// "localhost" — the WebAuthn spec requires the RP ID to equal the effective
// domain of the origin or a registrable suffix of it. "l42.eu" is not a
// suffix of "localhost", which is why Chrome blocks passkey creation with
// "blocked by a security policy" when the RP ID is hardcoded.
func deriveRPID(appOrigin string) string {
	u, err := url.Parse(appOrigin)
	if err != nil || u.Hostname() == "" {
		return "l42.eu" // safe production default
	}
	host := u.Hostname()
	// Use the registrable parent domain for any *.l42.eu origin (or l42.eu
	// itself) so passkeys registered on aithne.l42.eu remain valid if the
	// login origin moves to another subdomain.
	if host == "l42.eu" || strings.HasSuffix(host, ".l42.eu") {
		return "l42.eu"
	}
	// For any other origin (e.g. localhost), use the hostname directly.
	return host
}

func main() {
	port := getEnvRequired("PORT")

	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		runHealthcheck(port)
	}
	if len(os.Args) > 1 && os.Args[1] == "--bootstrap-invite" {
		runBootstrapInvite()
	}

	system := getEnvRequired("SYSTEM")
	environment := getEnvWithDefault("ENVIRONMENT", "development")
	issuer := getEnvRequired("APP_ORIGIN")

	// Parse the scope vocabulary embedded at build time from scopes.yaml.
	vocab, err := parseScopesYAML(scopesYAML)
	if err != nil {
		log.Fatalf("Failed to parse scope vocabulary: %v", err)
	}
	log.Printf("Scope vocabulary loaded: %v", vocab.All())

	// Read the signing key KEK from the environment. Must be exactly 32 bytes
	// for AES-256-GCM. Stored in lucos_creds as SIGNING_KEK.
	//
	// The value MUST be randomly generated — not a human-typed passphrase.
	// Generate a suitable value with:
	//   openssl rand -base64 32 | head -c 32
	// Store the result in lucos_creds; never commit it to source control.
	signingKEKStr := getEnvRequired("SIGNING_KEK")
	if len(signingKEKStr) != 32 {
		log.Fatalf("SIGNING_KEK must be exactly 32 bytes, got %d", len(signingKEKStr))
	}
	var signingKEK [32]byte
	copy(signingKEK[:], signingKEKStr)

	dbPath := getEnvWithDefault("DB_PATH", "/data/aithne.db")
	if err := ensureDir(dbPath); err != nil {
		log.Fatalf("Cannot create data directory for %q: %v", dbPath, err)
	}
	s, err := store.Open(dbPath, signingKEK)
	if err != nil {
		log.Fatalf("Failed to open principal/credential store at %q: %v", dbPath, err)
	}
	defer s.Close()
	log.Printf("Principal/credential store ready at %s", dbPath)

	// Migrate any signing keys stored in the legacy unencrypted PKCS8 DER format
	// to AES-256-GCM ciphertext. No-op on a fresh DB or after the first post-upgrade
	// startup. Must run before GetOrCreateActiveSigningKey, which would otherwise
	// fail to decrypt legacy rows.
	migrated, err := s.MigrateSigningKeyEncryption()
	if err != nil {
		log.Fatalf("Failed to migrate signing key encryption: %v", err)
	}
	if migrated > 0 {
		log.Printf("Migrated %d signing key(s) from legacy plaintext to AES-256-GCM encryption", migrated)
	}

	// Ensure an active signing key exists before we start serving.
	// On first boot this generates a fresh ES256 key; on subsequent boots it
	// reuses the persisted key from the SQLite store.
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		log.Fatalf("Failed to initialise signing key: %v", err)
	}
	log.Printf("Signing key initialised")

	// Startup age-check: rotate the signing key if it is older than the
	// rotation interval. This runs on every deploy, bounding the maximum
	// key lifetime to rotationInterval + mean-time-between-deploys.
	// ListVerificationKeys covers in-flight tokens signed by the old key.
	rotated, _, err := s.RotateSigningKeyIfOlderThan(signingKeyRotationInterval)
	if err != nil {
		log.Fatalf("Failed to check/rotate signing key: %v", err)
	}
	if rotated {
		log.Printf("Signing key rotated at startup (exceeded %v)", signingKeyRotationInterval)
	}

	// Bootstrap admin if BOOTSTRAP_ADMIN_CONTACT_ID is set.
	// This is a development convenience for bootstrapping the first admin before
	// the enrolment flow can be used (the enrolment flow itself requires admin access).
	if adminContactID := os.Getenv("BOOTSTRAP_ADMIN_CONTACT_ID"); adminContactID != "" {
		bootstrapAdmin(s, adminContactID, environment, vocab)
	}

	// Initialise the lucos_contacts client for contact verification and name lookup.
	contactsOrigin := getEnvRequired("LUCOS_CONTACTS_ORIGIN")
	contactsKey := getEnvRequired("KEY_LUCOS_CONTACTS")
	contacts := newContactsClient(contactsOrigin, contactsKey)

	// Initialise the WebAuthn relying party.
	// RP ID is derived from APP_ORIGIN (see deriveRPID): "l42.eu" for any
	// *.l42.eu production origin (ADR-0001 §2 — passkeys valid estate-wide),
	// or the raw hostname (e.g. "localhost") for development environments.
	wa, err := gwebauthn.New(&gwebauthn.Config{
		RPID:          deriveRPID(issuer),
		RPDisplayName: "lucOS",
		RPOrigins:     []string{issuer},
	})
	if err != nil {
		log.Fatalf("Failed to initialise WebAuthn relying party: %v", err)
	}
	cs := newCeremonyStore()

	mux := http.NewServeMux()
	mux.HandleFunc("/_info", handleInfo(system, s))
	mux.HandleFunc("/.well-known/jwks.json", token.JWKSHandler(func() ([]*store.SigningKey, error) {
		return s.ListVerificationKeys(token.VerificationWindow)
	}))

	// OIDC discovery document (ADR §1).
	mux.HandleFunc("/.well-known/openid-configuration", handleOpenIDConfiguration(issuer))

	// Index page — serves the root path only (/{$} prevents catch-all matching).
	mux.HandleFunc("/{$}", serveStaticFile(staticFS, "static/index.html"))

	// Favicon — served from both paths; /favicon.ico handles the legacy automatic browser request.
	mux.HandleFunc("/favicon.svg", serveStaticFile(staticFS, "static/favicon.svg"))
	mux.HandleFunc("/favicon.ico", serveStaticFile(staticFS, "static/favicon.svg"))

	// lucOS navbar web-component bundle (compiled JS, embedded at build time).
	mux.HandleFunc("/lucos_navbar.js", serveStaticFile(staticFS, "static/lucos_navbar.js"))

	// Passkey login page (HTML).
	mux.HandleFunc("/auth/login", handleLoginPage(templateFS))

	// WebAuthn login ceremony endpoints.
	mux.HandleFunc("/auth/login/begin", handleLoginBegin(s, wa, cs))
	mux.HandleFunc("/auth/login/finish", handleLoginFinish(s, wa, cs, issuer, environment))

	// OAuth2/OIDC endpoints (ADR §1, §5).
	mux.HandleFunc("/oauth2/authorize", handleAuthorize(s, issuer, environment))
	mux.HandleFunc("/oauth2/token", handleOAuth2Token(s, issuer, environment))
	mux.HandleFunc("/oauth2/userinfo", handleUserinfo(s, issuer, contacts))

	// Admin enrolment surface (all gated on aithne:admin scope).
	mux.HandleFunc("/admin/grants", requireAdminScope(s, issuer, handleGrants(s, vocab)))
	mux.HandleFunc("/admin/grants/", requireAdminScope(s, issuer, handleGrantByID(s)))
	mux.HandleFunc("/admin/enrol", requireAdminScopeFromCookie(s, issuer, handleAdminEnrolPage()))
	mux.HandleFunc("/admin/invites", requireAdminScope(s, issuer, handleAdminInvites(s, contacts, issuer)))
	mux.HandleFunc("/admin/machine-keys", requireAdminScope(s, issuer, handleAdminMachineKeys(s)))
	mux.HandleFunc("/admin/oidc-clients", requireAdminScope(s, issuer, handleAdminOIDCClients(s)))
	mux.HandleFunc("/admin/oidc-clients/", requireAdminScope(s, issuer, handleAdminOIDCClients(s)))
	mux.HandleFunc("/admin/rotate-signing-key", requireAdminScope(s, issuer, handleRotateSigningKey(s)))

	// Invitee enrolment flow — invite-gated, no auth required.
	mux.HandleFunc("/enrol", handleEnrolPage(s, contacts))
	mux.HandleFunc("/enrol/begin", handleEnrolBegin(s, wa, cs, contacts))
	mux.HandleFunc("/enrol/finish", handleEnrolFinish(s, wa, cs))

	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting lucos_aithne — system=%s, environment=%s, listening on %s", system, environment, addr)
	if err := http.ListenAndServe(addr, secureHeaders(mux)); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
