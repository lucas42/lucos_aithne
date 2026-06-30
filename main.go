// lucos_aithne — Passkey-based OpenID Provider for the lucOS estate.
//
// See ADR-0001 for the full design:
// https://github.com/lucas42/lucos_aithne/blob/main/docs/adr/0001-foundational-design.md
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

// maxSigningKeyAge is the /_info freshness threshold for the active signing key.
// aithne rotates only at startup (RotateSigningKeyIfOlderThan), so a key older
// than the rotation interval plus a grace margin means the process has been
// running long enough without a deploy that rotation is overdue. Surfacing that
// as an unhealthy check is the safety net that keeps startup-only rotation safe:
// it prompts a restart/rotation rather than letting the key age unbounded
// (lucos_aithne#149 cadence decision, #163 health check).
const maxSigningKeyAge = signingKeyRotationInterval + 5*24*time.Hour

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
		const signingKeyDetail = "Checks an active signing key exists and can be served via JWKS — estate-wide local token verification depends on it"
		const signingKeyAgeDetail = "Checks the active signing key has been rotated within the expected interval; aithne rotates only at startup, so an older key means the process has run too long without a deploy and should be restarted/rotated"
		checks := map[string]any{}
		metrics := map[string]any{}

		if err := s.Ping(); err != nil {
			checks["db"] = map[string]any{"ok": false, "techDetail": dbDetail, "debug": err.Error()}
			reqLogger(r).Printf("/_info db ping failed: %v", err)
		} else {
			checks["db"] = map[string]any{"ok": true, "techDetail": dbDetail}
		}

		// Signing-key / JWKS health. Use ListVerificationKeys (read-only) rather
		// than GetOrCreateActiveSigningKey, which would mint a key as a side
		// effect of a health poll. The active key is always within the
		// verification window, so a healthy aithne returns it here.
		keys, keysErr := s.ListVerificationKeys(token.VerificationWindow)
		var activeKey *store.SigningKey
		for _, k := range keys {
			if k.Status == "active" {
				activeKey = k
				break
			}
		}
		switch {
		case keysErr != nil:
			checks["signing_key"] = map[string]any{"ok": false, "techDetail": signingKeyDetail, "debug": keysErr.Error()}
			reqLogger(r).Printf("/_info signing_key check failed: %v", keysErr)
		case activeKey == nil:
			checks["signing_key"] = map[string]any{"ok": false, "techDetail": signingKeyDetail, "debug": "no active signing key in verification set — JWKS would serve no usable key"}
			reqLogger(r).Printf("/_info signing_key check failed: no active signing key")
		default:
			checks["signing_key"] = map[string]any{"ok": true, "techDetail": signingKeyDetail}
			metrics["signing_key_count"] = map[string]any{"value": len(keys), "techDetail": "Signing keys currently published in JWKS (active plus recently-retired within the verification window)"}
			age := time.Since(activeKey.CreatedAt)
			metrics["active_signing_key_age_seconds"] = map[string]any{"value": int(age.Seconds()), "techDetail": "Age of the active signing key (last rotation = now − this); aithne rotates it at startup once older than the rotation interval"}
			if age > maxSigningKeyAge {
				checks["signing_key_age"] = map[string]any{"ok": false, "techDetail": signingKeyAgeDetail, "debug": fmt.Sprintf("active signing key is %s old (> %s) — rotation is overdue; restart aithne or rotate via the admin endpoint", age.Round(time.Hour), maxSigningKeyAge)}
				reqLogger(r).Printf("/_info signing_key_age check failed: active key age %s exceeds %s", age.Round(time.Hour), maxSigningKeyAge)
			} else {
				checks["signing_key_age"] = map[string]any{"ok": true, "techDetail": signingKeyAgeDetail}
			}
		}

		info := infoResponse{
			System:  system,
			Checks:  checks,
			Metrics: metrics,
			CI:      &ciInfo{Circle: "gh/lucas42/lucos_aithne"},
			Title:   "Aithne",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(info); err != nil {
			reqLogger(r).Printf("/_info encode error: %v", err)
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
	signingKEK := sha256.Sum256([]byte(signingKEKStr))

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

// runRekey is the entrypoint for the --rekey subcommand.
// It reads SIGNING_KEK (old) and NEW_SIGNING_KEK (new), opens the credential store,
// re-encrypts all signing key BLOBs under the new KEK, prints a confirmation, and
// exits 0. Exits non-zero on any error. The HTTP server is never started.
//
// The service MUST be stopped before running --rekey. A running service holds the
// old KEK in memory; a concurrent RotateSigningKey() during re-keying would race
// on the SQLite write. Stop the container first, then run:
//
//	docker run --rm \
//	  -v lucos_aithne_credential_store:/data \
//	  -e SIGNING_KEK=<old-value> \
//	  -e NEW_SIGNING_KEK=<new-value> \
//	  lucas42/lucos_aithne_web:latest --rekey
//
// After successful exit: update SIGNING_KEK in lucos_creds, then restart the service.
func runRekey() {
	oldKEKStr := os.Getenv("SIGNING_KEK")
	newKEKStr := os.Getenv("NEW_SIGNING_KEK") // lucos_repos: noenv NEW_SIGNING_KEK

	if oldKEKStr == "" {
		fmt.Fprintln(os.Stderr, "rekey: SIGNING_KEK is not set")
		os.Exit(1)
	}
	if newKEKStr == "" {
		fmt.Fprintln(os.Stderr, "rekey: NEW_SIGNING_KEK is not set")
		os.Exit(1)
	}

	oldKEK := sha256.Sum256([]byte(oldKEKStr))
	newKEK := sha256.Sum256([]byte(newKEKStr))

	if oldKEK == newKEK {
		fmt.Fprintln(os.Stderr, "rekey: SIGNING_KEK and NEW_SIGNING_KEK are identical — nothing to do")
		os.Exit(0)
	}

	dbPath := getEnvWithDefault("DB_PATH", "/data/aithne.db")
	s, err := store.Open(dbPath, oldKEK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rekey: open store at %q: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer s.Close()

	n, err := s.RekeySigningKeys(newKEK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rekey: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("rekey: re-encrypted %d signing key(s) under new KEK. Update SIGNING_KEK in lucos_creds now, then restart the service.\n", n)
	os.Exit(0)
}

// --- Admin HTTP handlers ---

// credentialJSON is the JSON representation of a credential returned by admin endpoints.
type credentialJSON struct {
	ID        string  `json:"id"`
	Label     string  `json:"label"`
	CreatedAt string  `json:"created_at"`
	RevokedBy *string `json:"revoked_by,omitempty"`
	RevokedAt *string `json:"revoked_at,omitempty"`
}

func credentialToJSON(c *store.Credential) credentialJSON {
	j := credentialJSON{
		ID:        c.ID,
		Label:     c.Label,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
	}
	if c.RevokedBy != nil {
		s := *c.RevokedBy
		j.RevokedBy = &s
	}
	if c.RevokedAt != nil {
		s := c.RevokedAt.Format(time.RFC3339)
		j.RevokedAt = &s
	}
	return j
}

// scopeStatusData represents a single scope in the per-scope grant list rendered
// by the admin pages.  It tells the template whether the scope is actively
// granted and, if so, supplies the grant ID required to revoke it.
type scopeStatusData struct {
	Scope   string
	Granted bool   // true when an active (non-revoked) grant exists
	GrantID string // the grant's ID; empty when Granted is false
}

// buildScopeStatuses returns one entry per scope in the vocabulary, annotated
// with whether an active (non-revoked) grant exists in the supplied grants list.
func buildScopeStatuses(scopes []string, grants []grantJSON) []scopeStatusData {
	active := make(map[string]string, len(grants))
	for _, g := range grants {
		if g.RevokedAt == nil {
			active[g.Scope] = g.ID
		}
	}
	statuses := make([]scopeStatusData, len(scopes))
	for i, sc := range scopes {
		id, granted := active[sc]
		statuses[i] = scopeStatusData{Scope: sc, Granted: granted, GrantID: id}
	}
	return statuses
}

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
			reqLogger(r).Printf("requireAdminScope: list verification keys: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		keySet, err := token.BuildVerificationKeySet(keys)
		if err != nil {
			reqLogger(r).Printf("requireAdminScope: build key set: %v", err)
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
// Authenticated users who lack aithne:admin are shown a styled HTML 403 page.
func requireAdminScopeFromCookie(s *store.Store, issuer string, next http.HandlerFunc) http.HandlerFunc {
	accessDeniedTmpl := template.Must(template.ParseFS(templateFS, "templates/access_denied.html"))
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
			reqLogger(r).Printf("requireAdminScopeFromCookie: list verification keys: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		keySet, err := token.BuildVerificationKeySet(keys)
		if err != nil {
			reqLogger(r).Printf("requireAdminScopeFromCookie: build key set: %v", err)
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
			nonce, err := applyPageCSP(w)
			if err != nil {
				reqLogger(r).Printf("requireAdminScopeFromCookie: generate nonce: %v", err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			if err := accessDeniedTmpl.Execute(w, accessDeniedPageData{Nonce: nonce}); err != nil {
				reqLogger(r).Printf("requireAdminScopeFromCookie: render access denied: %v", err)
			}
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
			reqLogger(r).Printf("handleRotateSigningKey: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if claims, ok := r.Context().Value(claimsContextKey).(*token.SessionClaims); ok {
			reqLogger(r).Printf("Signing key rotated via admin endpoint — initiated by %s, new key ID: %s", claims.Subject, newKey.ID)
		} else {
			reqLogger(r).Printf("Signing key rotated via admin endpoint — new key ID: %s (actor unknown)", newKey.ID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"rotated":    true,
			"new_key_id": newKey.ID,
		})
	}
}

// handleAdminPrincipalActions serves admin actions on a specific principal.
// Currently supports:
//
//	DELETE /admin/principals/{id}/idp-sessions — revoke all active IdP sessions
//
// Requires aithne:admin scope (enforced by requireAdminScope in main).
// This endpoint is the operator tool for the credential-compromise runbook:
// after revoking a passkey credential, also call DELETE …/idp-sessions to
// prevent further silent re-mints until the principal re-authenticates.
func handleAdminPrincipalActions(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Path format: /admin/principals/{id}/idp-sessions
		// Strip the prefix to get "{id}/idp-sessions".
		rest := strings.TrimPrefix(r.URL.Path, "/admin/principals/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 || parts[0] == "" {
			http.Error(w, "400 Bad Request — path must be /admin/principals/{id}/idp-sessions", http.StatusBadRequest)
			return
		}
		principalID := parts[0]
		action := parts[1]

		switch {
		case action == "idp-sessions" && r.Method == http.MethodDelete:
			n, err := s.RevokeIDPSessionsForPrincipal(principalID)
			if err != nil {
				reqLogger(r).Printf("handleAdminPrincipalActions: revoke idp sessions for %s: %v", principalID, err)
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			reqLogger(r).Printf("handleAdminPrincipalActions: revoked %d idp session(s) for principal %s", n, principalID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"revoked": n})

		default:
			http.Error(w, "404 Not Found", http.StatusNotFound)
		}
	}
}

// adminGrantsPage serves the browser-facing grants management UI (GET /admin/grants
// without an Authorization header). It must be wrapped by requireAdminScopeFromCookie.
// Contact ID lookup and grant listing are server-rendered; grant creation and revocation
// are performed by the embedded JavaScript using the session token for AJAX auth.
func adminGrantsPage(s *store.Store, vocab *store.Vocabulary, environment string, contacts *contactsClient) http.HandlerFunc {
	tmpl := template.Must(template.ParseFS(templateFS, "templates/admin_grants.html"))
	scopes := vocab.All()
	return func(w http.ResponseWriter, r *http.Request) {
		// handleGrants only routes GET (no-Bearer) requests here, so a non-GET
		// cannot arrive in practice. The guard is removed to avoid dead code.
		nonce, err := applyPageCSP(w)
		if err != nil {
			reqLogger(r).Printf("adminGrantsPage: generate nonce: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		sessionToken, _ := r.Context().Value(rawTokenContextKey).(string)
		data := adminGrantsPageData{
			Nonce:        nonce,
			SessionToken: sessionToken,
		}
		contactID := r.URL.Query().Get("contact_id")
		if contactID != "" {
			data.ContactID = contactID
			p, perr := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID)
			if errors.Is(perr, store.ErrNotFound) {
				data.LookupError = fmt.Sprintf("No principal found for contact ID %q.", contactID)
			} else if perr != nil {
				reqLogger(r).Printf("adminGrantsPage: lookup principal %q: %v", contactID, perr)
				data.LookupError = "Could not look up principal. Try again."
			} else {
				data.PrincipalID = p.ID
				// Fetch display name from lucos_contacts so the admin sees who they've looked up.
				// Non-fatal: fall back to the contact ID if the lookup fails.
				if info, cerr := contacts.Get(contactID); cerr == nil {
					data.ContactDisplayName = info.DisplayName
					data.ContactNameAvailable = true
				} else {
					reqLogger(r).Printf("adminGrantsPage: contacts lookup %q: %v — using contact ID as display name fallback", contactID, cerr)
					data.ContactDisplayName = contactID
					// ContactNameAvailable stays false — template shows degradation hint
				}
				// Fetch only active grants for the instance environment; revoked
				// or foreign-environment rows have no bearing on the scope status list.
				grants, gerr := s.ListGrants(p.ID, environment, true)
				if gerr != nil {
					reqLogger(r).Printf("adminGrantsPage: list grants for principal %q: %v", p.ID, gerr)
					data.LookupError = "Could not load grants. Try again."
				} else {
					grantJSONs := make([]grantJSON, 0, len(grants))
					for _, g := range grants {
						grantJSONs = append(grantJSONs, grantToJSON(g))
					}
					data.ScopeStatuses = buildScopeStatuses(scopes, grantJSONs)
				}
			}
		}
		if err := tmpl.Execute(w, data); err != nil {
			reqLogger(r).Printf("adminGrantsPage: render: %v", err)
		}
	}
}

// handleGrants serves /admin/grants.
//
// GET without an Authorization: Bearer header → HTML management page (browser
// session via requireAdminScopeFromCookie).
// GET with Authorization: Bearer → JSON list of active grants (API).
// POST with Authorization: Bearer → JSON grant creation (API).
//
// This content-negotiation approach keeps the grants UI at the natural URL
// without adding a separate route, and is safe because browser-initiated GETs
// never carry an Authorization header.
func handleGrants(s *store.Store, vocab *store.Vocabulary, issuer, environment string, contacts *contactsClient) http.HandlerFunc {
	htmlPage := requireAdminScopeFromCookie(s, issuer, adminGrantsPage(s, vocab, environment, contacts))
	jsonList := requireAdminScope(s, issuer, listGrants(s))
	jsonCreate := requireAdminScope(s, issuer, createGrant(s, vocab, environment))
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				jsonList(w, r)
			} else {
				htmlPage(w, r)
			}
		case http.MethodPost:
			jsonCreate(w, r)
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
			reqLogger(r).Printf("listGrants: %v", err)
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
// The Environment field is accepted but ignored — environment is stamped
// server-side from the instance ENVIRONMENT variable (see createGrant).
type createGrantRequest struct {
	PrincipalID string `json:"principal_id"`
	Scope       string `json:"scope"`
	Environment string `json:"environment"` // ignored; retained for backward-compatible form POSTs
}

// createGrant handles POST /admin/grants. The environment is derived from the
// instance ENVIRONMENT at startup, not from the request body, so a caller
// cannot stamp a foreign environment onto a grant.
func createGrant(s *store.Store, vocab *store.Vocabulary, environment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createGrantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "400 Bad Request — invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.PrincipalID == "" || req.Scope == "" {
			http.Error(w, "400 Bad Request — principal_id and scope are required", http.StatusBadRequest)
			return
		}

		// Attribution is read from the verified JWT claims injected by
		// requireAdminScope — never from a client-supplied field.
		claims, ok := r.Context().Value(claimsContextKey).(*token.SessionClaims)
		if !ok {
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		grantedBy := claims.Subject

		// environment is the instance-level value passed at handler construction
		// time; any environment field in the request body is silently ignored.
		g, err := s.CreateGrant(req.PrincipalID, req.Scope, environment, grantedBy, vocab)
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
			reqLogger(r).Printf("createGrant: %v", err)
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
		claims, ok := r.Context().Value(claimsContextKey).(*token.SessionClaims)
		if !ok {
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
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
			reqLogger(r).Printf("revokeGrant: %v", err)
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

// privacyPageData holds the per-request data injected into templates/privacy.html.
type privacyPageData struct {
	Nonce string
}

// accessDeniedPageData holds the per-request data for templates/access_denied.html.
type accessDeniedPageData struct {
	Nonce string
}

// homePageData holds the per-request data injected into templates/index.html.
type homePageData struct {
	LoggedIn             bool
	IsAdmin              bool   // true when the session carries aithne:admin scope
	DisplayName          string
	DisplayNameAvailable bool   // false when contacts lookup failed and DisplayName is the raw contact ID
	Nonce                string
}

// adminGrantsPageData holds the per-request data for templates/admin_grants.html.
type adminGrantsPageData struct {
	Nonce                string
	SessionToken         string          // raw JWT — embedded for AJAX calls (HttpOnly cookie inaccessible to JS)
	ScopeStatuses        []scopeStatusData // per-scope granted/not-granted list for the redesigned UI
	ContactID            string          // what the admin searched for
	ContactDisplayName   string          // display name from lucos_contacts; falls back to ContactID on error
	ContactNameAvailable bool            // false when contacts lookup failed and ContactDisplayName is the raw contact ID
	PrincipalID          string          // resolved UUID, empty when not yet looked up or not found
	LookupError          string          // e.g. "contact not found"
}

// adminAgentsPageData holds the per-request data for templates/admin_agents.html.
type adminAgentsPageData struct {
	Nonce         string
	SessionToken  string           // raw JWT — embedded for AJAX calls
	ScopeStatuses []scopeStatusData // per-scope granted/not-granted list for the redesigned UI
	Slug          string           // agent slug searched for (URL ?slug=X)
	PrincipalID   string           // resolved UUID; empty when not yet searched or not found
	Credentials   []credentialJSON // machine keys for this agent (all, including revoked)
	LookupError   string           // e.g. "agent not found"
}

// adminAgentsPage serves the browser-facing agent management UI (GET /admin/agents
// without an Authorization header). It must be wrapped by requireAdminScopeFromCookie.
// ?slug=X resolves the agent principal server-side and populates the page.
func adminAgentsPage(s *store.Store, vocab *store.Vocabulary, environment string) http.HandlerFunc {
	tmpl := template.Must(template.ParseFS(templateFS, "templates/admin_agents.html"))
	scopes := vocab.All()
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := applyPageCSP(w)
		if err != nil {
			reqLogger(r).Printf("adminAgentsPage: generate nonce: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		sessionToken, _ := r.Context().Value(rawTokenContextKey).(string)
		data := adminAgentsPageData{
			Nonce:        nonce,
			SessionToken: sessionToken,
		}
		slug := r.URL.Query().Get("slug")
		if slug != "" {
			data.Slug = slug
			p, perr := s.GetPrincipalByExternalID(store.PrincipalClassAgent, slug)
			if errors.Is(perr, store.ErrNotFound) {
				data.LookupError = fmt.Sprintf("No agent principal found for slug %q.", slug)
			} else if perr != nil {
				reqLogger(r).Printf("adminAgentsPage: lookup agent %q: %v", slug, perr)
				data.LookupError = "Could not look up agent. Try again."
			} else {
				data.PrincipalID = p.ID
				creds, cerr := s.ListCredentialsByPrincipal(p.ID)
				if cerr != nil {
					reqLogger(r).Printf("adminAgentsPage: list credentials for %q: %v", slug, cerr)
					data.LookupError = "Could not load credentials. Try again."
				} else {
					data.Credentials = make([]credentialJSON, 0, len(creds))
					for _, c := range creds {
						if c.Type == store.CredentialTypeMachineKey {
							data.Credentials = append(data.Credentials, credentialToJSON(c))
						}
					}
				}
				// Fetch only active grants for the instance environment; revoked
				// or foreign-environment rows have no bearing on the scope status list.
				grants, gerr := s.ListGrants(p.ID, environment, true)
				if gerr != nil {
					reqLogger(r).Printf("adminAgentsPage: list grants for %q: %v", slug, gerr)
					data.LookupError = "Could not load grants. Try again."
				} else {
					grantJSONs := make([]grantJSON, 0, len(grants))
					for _, g := range grants {
						grantJSONs = append(grantJSONs, grantToJSON(g))
					}
					data.ScopeStatuses = buildScopeStatuses(scopes, grantJSONs)
				}
			}
		}
		if err := tmpl.Execute(w, data); err != nil {
			reqLogger(r).Printf("adminAgentsPage: render: %v", err)
		}
	}
}

// agentJSON is the JSON shape returned by the agent list endpoint.
type agentJSON struct {
	Slug        string `json:"slug"`
	PrincipalID string `json:"principal_id"`
}

// listAgents handles GET /admin/agents (with Authorization: Bearer).
// Returns a JSON list of all agent principals for the admin datalist picker.
func listAgents(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		principals, err := s.ListPrincipals(store.PrincipalClassAgent)
		if err != nil {
			reqLogger(r).Printf("listAgents: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		result := make([]agentJSON, 0, len(principals))
		for _, p := range principals {
			result = append(result, agentJSON{Slug: p.ExternalID, PrincipalID: p.ID})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// humanPrincipalJSON is the JSON shape returned by the human principals list endpoint.
type humanPrincipalJSON struct {
	ContactID   string `json:"contact_id"`
	PrincipalID string `json:"principal_id"`
}

// listHumanPrincipals handles GET /admin/human-principals (with Authorization: Bearer).
// Returns a JSON list of all human principals (each carrying their lucos_contacts
// contact ID) so the grants picker can restrict itself to contacts that already
// have an aithne principal record — avoiding dead-end "No principal found" errors.
func listHumanPrincipals(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		principals, err := s.ListPrincipals(store.PrincipalClassHuman)
		if err != nil {
			reqLogger(r).Printf("listHumanPrincipals: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		result := make([]humanPrincipalJSON, 0, len(principals))
		for _, p := range principals {
			result = append(result, humanPrincipalJSON{ContactID: p.ExternalID, PrincipalID: p.ID})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// handleAgents serves /admin/agents.
//
// GET without an Authorization: Bearer header → HTML agent management page
// (browser session via requireAdminScopeFromCookie).
// GET with Authorization: Bearer → JSON list of agent principals (API).
func handleAgents(s *store.Store, vocab *store.Vocabulary, issuer, environment string) http.HandlerFunc {
	htmlPage := requireAdminScopeFromCookie(s, issuer, adminAgentsPage(s, vocab, environment))
	jsonList := requireAdminScope(s, issuer, listAgents(s))
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				jsonList(w, r)
			} else {
				htmlPage(w, r)
			}
		default:
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleHomePage serves GET / — the homepage.
// It performs a soft session check: reads the aithne_session cookie and validates
// the JWT, but does not redirect on failure (unlike requireAdminScopeFromCookie).
// Logged-in users see their display name and a sign-out button; logged-out users
// see the existing sign-in prompt.
func handleHomePage(s *store.Store, issuer string, contacts *contactsClient, tmplFS fs.FS) http.HandlerFunc {
	tmpl := template.Must(template.ParseFS(tmplFS, "templates/index.html"))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		nonce, err := applyPageCSP(w)
		if err != nil {
			reqLogger(r).Printf("handleHomePage: generate nonce: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		data := homePageData{Nonce: nonce}

		// Soft session check — no redirect on failure.
		if cookie, err := r.Cookie("aithne_session"); err == nil {
			keys, kerr := s.ListVerificationKeys(token.VerificationWindow)
			if kerr == nil {
				keySet, kserr := token.BuildVerificationKeySet(keys)
				if kserr == nil {
					claims, perr := token.ParseSession(cookie.Value, keySet, issuer, "l42.eu")
					if perr == nil {
						data.LoggedIn = true
						contactID := claims.Subject
						for _, sc := range claims.Scopes {
							if sc == "aithne:admin" {
								data.IsAdmin = true
								break
							}
						}
						// Resolve display name from lucos_contacts; fall back to contact ID.
						if info, err := contacts.Get(contactID); err == nil {
							data.DisplayName = info.DisplayName
							data.DisplayNameAvailable = true
						} else {
							reqLogger(r).Printf("handleHomePage: contacts lookup %q: %v — using contact ID as display name fallback", contactID, err)
							data.DisplayName = contactID
							// DisplayNameAvailable stays false — template shows degradation hint
						}
					}
				}
			}
		}

		if err := tmpl.Execute(w, data); err != nil {
			reqLogger(r).Printf("handleHomePage: render: %v", err)
		}
	}
}

// handleLogout serves POST /auth/logout.
// It validates the Origin header as a CSRF guard, revokes the server-side IdP
// session record (so a captured cookie cannot be exploited after logout), clears
// both the aithne_session and aithne_idp_session cookies, and redirects to /.
// See lucos-security analysis on lucos_aithne#87 for the threat-model rationale.
// The Origin check is always required regardless of SameSite mode, since in
// development SameSite=Lax applies and in production SameSite=None applies.
func handleLogout(s *store.Store, appOrigin, environment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		// Origin-header CSRF check. Reject any request whose Origin does not
		// exactly match APP_ORIGIN — this covers cross-site form submissions.
		// A missing Origin header is also rejected (conservative, but browsers
		// always send Origin on same-origin form POSTs).
		if r.Header.Get("Origin") != appOrigin {
			http.Error(w, "403 Forbidden — invalid origin", http.StatusForbidden)
			return
		}
		// Revoke the server-side IdP session record so the token is unusable
		// even if the attacker captured it before the browser dropped the cookie.
		// Non-fatal: if the cookie is absent or revocation fails, continue —
		// the primary security action is clearing the cookies client-side.
		if cookie, err := r.Cookie(token.IdPSessionCookieName); err == nil {
			if revokeErr := s.RevokeIDPSessionByToken(cookie.Value); revokeErr != nil {
				reqLogger(r).Printf("handleLogout: revoke idp session: %v (non-fatal)", revokeErr)
			}
		}
		// Clear both session cookies. Attributes must match those used in the
		// corresponding Set* functions so the browser treats them as the same cookies.
		token.ClearSessionCookie(w, environment)
		token.ClearIDPSessionCookie(w, environment)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// handleLoginPage serves the login page as a Go template, injecting a fresh
// per-request nonce into the <script> tags so the Content-Security-Policy can be
// locked to 'nonce-{nonce}' without requiring hashes or 'unsafe-inline'.
func handleLoginPage(tmplFS fs.FS) http.HandlerFunc {
	tmpl := template.Must(template.ParseFS(tmplFS, "templates/login.html"))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		nonce, err := applyPageCSP(w)
		if err != nil {
			reqLogger(r).Printf("handleLoginPage: generate nonce: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err := tmpl.Execute(w, loginPageData{Nonce: nonce}); err != nil {
			reqLogger(r).Printf("handleLoginPage: render: %v", err)
		}
	}
}

// handlePrivacyPage serves GET /privacy — the privacy information page.
// No authentication required; the page is public.
func handlePrivacyPage(tmplFS fs.FS) http.HandlerFunc {
	tmpl := template.Must(template.ParseFS(tmplFS, "templates/privacy.html"))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		nonce, err := applyPageCSP(w)
		if err != nil {
			reqLogger(r).Printf("handlePrivacyPage: generate nonce: %v", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err := tmpl.Execute(w, privacyPageData{Nonce: nonce}); err != nil {
			reqLogger(r).Printf("handlePrivacyPage: render: %v", err)
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
	if len(os.Args) > 1 && os.Args[1] == "--rekey" {
		runRekey()
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

	// Read the signing key KEK from the environment. The raw value is run through
	// SHA-256 to produce the 32-byte AES-256-GCM key, so any high-entropy string
	// of any length is accepted. Stored in lucos_creds as SIGNING_KEK.
	//
	// The value MUST be randomly generated — not a human-typed passphrase.
	// Generate a suitable value with:
	//   openssl rand -base64 32
	// Store the result in lucos_creds; never commit it to source control.
	signingKEKStr := getEnvRequired("SIGNING_KEK")
	signingKEK := sha256.Sum256([]byte(signingKEKStr))

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

	// Rate limiters for authentication endpoints.
	tokenLimiter := newKeyedLimiter(tokenEndpointLimit, tokenEndpointWindow)
	ceremonyLimiter := newKeyedLimiter(ceremonyBeginLimit, ceremonyBeginWindow)

	// Background goroutine: sweep expired ceremony sessions on a timer.
	// This bounds memory independently of request volume — previously only the
	// opportunistic cleanup in put/putEnrol ran, which required a new request.
	go func() {
		ticker := time.NewTicker(challengeTTL)
		defer ticker.Stop()
		for range ticker.C {
			cs.sweepExpired()
		}
	}()

	// Background goroutine: sweep stale rate-limiter entries on a timer.
	go func() {
		ticker := time.NewTicker(rateLimiterCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			tokenLimiter.sweepExpired()
			ceremonyLimiter.sweepExpired()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/_info", handleInfo(system, s))
	mux.HandleFunc("/.well-known/jwks.json", token.JWKSHandler(func() ([]*store.SigningKey, error) {
		return s.ListVerificationKeys(token.VerificationWindow)
	}))

	// OIDC discovery document (ADR §1).
	mux.HandleFunc("/.well-known/openid-configuration", handleOpenIDConfiguration(issuer))

	// Index page — dynamic template handler so it can reflect the user's login state.
	mux.HandleFunc("/{$}", handleHomePage(s, issuer, contacts, templateFS))

	// Favicon — served from both paths; /favicon.ico handles the legacy automatic browser request.
	mux.HandleFunc("/favicon.svg", serveStaticFile(staticFS, "static/favicon.svg"))
	mux.HandleFunc("/favicon.ico", serveStaticFile(staticFS, "static/favicon.svg"))

	// lucOS navbar web-component bundle (compiled JS, embedded at build time).
	mux.HandleFunc("/lucos_navbar.js", serveStaticFile(staticFS, "static/lucos_navbar.js"))

	// Shared stylesheet and JS helpers used by all aithne pages.
	mux.HandleFunc("/aithne.css", serveStaticFile(staticFS, "static/aithne.css"))
	mux.HandleFunc("/aithne.js", serveStaticFile(staticFS, "static/aithne.js"))

	// Privacy information page — public, no auth required.
	mux.HandleFunc("/privacy", handlePrivacyPage(templateFS))

	// Passkey login page (HTML).
	mux.HandleFunc("/auth/login", handleLoginPage(templateFS))

	// WebAuthn login ceremony endpoints.
	mux.HandleFunc("/auth/login/begin", handleLoginBegin(s, wa, cs, ceremonyLimiter))
	mux.HandleFunc("/auth/login/finish", handleLoginFinish(s, wa, cs, issuer, environment))

	// Logout endpoint — clears the session cookie and redirects to /.
	mux.HandleFunc("/auth/logout", handleLogout(s, issuer, environment))

	// Silent re-mint endpoint (ADR-0003 §2) — given a valid IdP-session cookie,
	// re-issues a fresh 15-minute aithne_session without a WebAuthn ceremony.
	// Also handles CORS OPTIONS preflight for cross-origin calls from *.l42.eu consumers.
	mux.HandleFunc("/auth/remint", handleReMint(s, issuer, environment, issuer))

	// OAuth2/OIDC endpoints (ADR §1, §5).
	mux.HandleFunc("/oauth2/authorize", handleAuthorize(s, issuer, environment))
	mux.HandleFunc("/oauth2/token", handleOAuth2Token(s, issuer, environment, tokenLimiter))
	mux.HandleFunc("/oauth2/userinfo", handleUserinfo(s, issuer, contacts))

	// Admin enrolment surface (all gated on aithne:admin scope).
	mux.HandleFunc("/admin/grants", handleGrants(s, vocab, issuer, environment, contacts))
	mux.HandleFunc("/admin/grants/", requireAdminScope(s, issuer, handleGrantByID(s)))
	mux.HandleFunc("/admin/enrol", requireAdminScopeFromCookie(s, issuer, handleAdminEnrolPage()))
	mux.HandleFunc("/admin/contacts", requireAdminScope(s, issuer, handleAdminContacts(contacts)))
	mux.HandleFunc("/admin/human-principals", requireAdminScope(s, issuer, listHumanPrincipals(s)))
	mux.HandleFunc("/admin/invites", requireAdminScope(s, issuer, handleAdminInvites(s, contacts, issuer)))
	mux.HandleFunc("/admin/invites/", requireAdminScope(s, issuer, handleAdminInviteByHash(s)))
	mux.HandleFunc("/admin/agents", handleAgents(s, vocab, issuer, environment))
	mux.HandleFunc("/admin/machine-keys", requireAdminScope(s, issuer, handleAdminMachineKeys(s)))
	mux.HandleFunc("/admin/machine-keys/", requireAdminScope(s, issuer, handleAdminMachineKeyByID(s)))
	mux.HandleFunc("/admin/oidc-clients", requireAdminScope(s, issuer, handleAdminOIDCClients(s)))
	mux.HandleFunc("/admin/oidc-clients/", requireAdminScope(s, issuer, handleAdminOIDCClients(s)))
	mux.HandleFunc("/admin/rotate-signing-key", requireAdminScope(s, issuer, handleRotateSigningKey(s)))
	// Revoke all active IdP sessions for a principal (credential-compromise runbook).
	// DELETE /admin/principals/{id}/idp-sessions
	mux.HandleFunc("/admin/principals/", requireAdminScope(s, issuer, handleAdminPrincipalActions(s)))

	// Invitee enrolment flow — invite-gated, no auth required.
	mux.HandleFunc("/enrol", handleEnrolPage(s, contacts))
	mux.HandleFunc("/enrol/begin", handleEnrolBegin(s, wa, cs, contacts, ceremonyLimiter))
	mux.HandleFunc("/enrol/finish", handleEnrolFinish(s, wa, cs))

	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting lucos_aithne — system=%s, environment=%s, listening on %s", system, environment, addr)
	if err := http.ListenAndServe(addr, withRequestLogger(secureHeaders(mux))); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
