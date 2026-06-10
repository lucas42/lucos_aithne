// lucos_aithne — Passkey-based OpenID Provider for the lucOS estate.
//
// See ADR-0001 for the full design:
// https://github.com/lucas42/lucos_aithne/blob/main/docs/adr/0001-foundational-design.md
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	gwebauthn "github.com/go-webauthn/webauthn/webauthn"
	"lucos_aithne/store"
	"lucos_aithne/token"
)

// contextKey is a private type for context keys in this package, preventing
// collisions with other packages that also store values in request contexts.
type contextKey int

const claimsContextKey contextKey = iota

// scopes.yaml is embedded at build time.
// In Docker CI builds the Dockerfile replaces this with the canonical
// vocabulary from lucas42/lucos_auth_scopes:v1.0.3. The local copy (in
// the repository) mirrors that vocabulary and is used for development and
// tests.
//
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
// aithne:admin grant for environment. It is idempotent: if the principal or
// grant already exist, this is a no-op.
// This is a development convenience until the proper admin enrolment flow lands
// (lucos_aithne#10). Set BOOTSTRAP_ADMIN_CONTACT_ID on startup to activate.
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

func main() {
	port := getEnvRequired("PORT")

	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		runHealthcheck(port)
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

	dbPath := getEnvWithDefault("DB_PATH", "/data/aithne.db")
	if err := ensureDir(dbPath); err != nil {
		log.Fatalf("Cannot create data directory for %q: %v", dbPath, err)
	}
	s, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to open principal/credential store at %q: %v", dbPath, err)
	}
	defer s.Close()
	log.Printf("Principal/credential store ready at %s", dbPath)

	// Ensure an active signing key exists before we start serving.
	// On first boot this generates a fresh ES256 key; on subsequent boots it
	// reuses the persisted key from the SQLite store.
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		log.Fatalf("Failed to initialise signing key: %v", err)
	}
	log.Printf("Signing key initialised")

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
	// RP ID = l42.eu (registrable parent domain per ADR-0001 §2): passkeys
	// registered here are valid on any service under *.l42.eu, so moving the
	// login origin to a different subdomain does not invalidate existing keys.
	wa, err := gwebauthn.New(&gwebauthn.Config{
		RPID:          "l42.eu",
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

	// Passkey login page (HTML).
	mux.HandleFunc("/auth/login", serveStaticFile(staticFS, "static/login.html"))

	// WebAuthn login ceremony endpoints.
	mux.HandleFunc("/auth/login/begin", handleLoginBegin(s, wa, cs))
	mux.HandleFunc("/auth/login/finish", handleLoginFinish(s, wa, cs, issuer, environment))

	// Admin enrolment surface (all gated on aithne:admin scope).
	mux.HandleFunc("/admin/grants", requireAdminScope(s, issuer, handleGrants(s, vocab)))
	mux.HandleFunc("/admin/grants/", requireAdminScope(s, issuer, handleGrantByID(s)))
	mux.HandleFunc("/admin/enrol", requireAdminScope(s, issuer, handleAdminEnrolPage()))
	mux.HandleFunc("/admin/invites", requireAdminScope(s, issuer, handleAdminInvites(s, contacts, issuer)))

	// Invitee enrolment flow — invite-gated, no auth required.
	mux.HandleFunc("/enrol", handleEnrolPage(s, contacts))
	mux.HandleFunc("/enrol/begin", handleEnrolBegin(s, wa, cs))
	mux.HandleFunc("/enrol/finish", handleEnrolFinish(s, wa, cs))

	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting lucos_aithne — system=%s, environment=%s, listening on %s", system, environment, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
