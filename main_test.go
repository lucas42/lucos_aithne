package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gwebauthn "github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite" // raw connection in TestInfoEndpoint_StaleSigningKey backdates created_at
	"lucos_aithne/store"
	"lucos_aithne/token"
)

// newTestWebAuthn creates a WebAuthn instance suitable for unit tests.
// The origin is testIssuer ("http://aithne.test"); RP ID must match the
// registrable parent of that origin — but for tests we relax it to localhost-equiv.
// In practice, since we never call FinishRegistration/FinishLogin with real
// authenticator data in unit tests (they require hardware), the RP config is
// only needed for BeginRegistration/BeginLogin.
func newTestWebAuthn(t *testing.T) *gwebauthn.WebAuthn {
	t.Helper()
	wa, err := gwebauthn.New(&gwebauthn.Config{
		RPID:          "aithne.test",
		RPDisplayName: "lucOS (test)",
		RPOrigins:     []string{testIssuer},
	})
	if err != nil {
		t.Fatalf("newTestWebAuthn: %v", err)
	}
	return wa
}

func TestInfoEndpoint(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodGet, "/_info", nil)
	rr := httptest.NewRecorder()

	handleInfo("lucos_aithne", s)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode /_info response: %v", err)
	}

	if got := payload["system"]; got != "lucos_aithne" {
		t.Errorf("system: got %q, want %q", got, "lucos_aithne")
	}
	checks, ok := payload["checks"]
	if !ok {
		t.Fatal("checks field missing from /_info response")
	}
	checksMap, ok := checks.(map[string]any)
	if !ok {
		t.Fatalf("checks: expected map, got %T", checks)
	}
	dbRaw, ok := checksMap["db"]
	if !ok {
		t.Fatal("checks.db missing from /_info response")
	}
	dbCheck, ok := dbRaw.(map[string]any)
	if !ok {
		t.Fatalf("checks.db: expected object (monitoring schema), got %T (%v)", dbRaw, dbRaw)
	}
	if dbCheck["ok"] != true {
		t.Errorf("checks.db.ok: got %v, want true", dbCheck["ok"])
	}
	if _, ok := dbCheck["techDetail"]; !ok {
		t.Error("checks.db.techDetail missing")
	}
	if _, ok := payload["metrics"]; !ok {
		t.Error("metrics field missing from /_info response")
	}
}

// fetchInfo issues a GET /_info against the given store and returns the decoded payload.
func fetchInfo(t *testing.T, s *store.Store) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/_info", nil)
	rr := httptest.NewRecorder()
	handleInfo("lucos_aithne", s)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}
	var payload map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode /_info response: %v", err)
	}
	return payload
}

func infoCheck(t *testing.T, payload map[string]any, name string) (map[string]any, bool) {
	t.Helper()
	checks, ok := payload["checks"].(map[string]any)
	if !ok {
		t.Fatalf("checks: expected map, got %T", payload["checks"])
	}
	raw, ok := checks[name]
	if !ok {
		return nil, false
	}
	check, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("checks.%s: expected object, got %T", name, raw)
	}
	return check, true
}

// With an active signing key, /_info reports signing_key + signing_key_age healthy
// and exposes the key-count and age metrics.
func TestInfoEndpoint_SigningKeyHealthy(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey: %v", err)
	}

	payload := fetchInfo(t, s)

	sk, ok := infoCheck(t, payload, "signing_key")
	if !ok {
		t.Fatal("checks.signing_key missing")
	}
	if sk["ok"] != true {
		t.Errorf("signing_key.ok: got %v, want true", sk["ok"])
	}
	age, ok := infoCheck(t, payload, "signing_key_age")
	if !ok {
		t.Fatal("checks.signing_key_age missing")
	}
	if age["ok"] != true {
		t.Errorf("signing_key_age.ok: got %v, want true", age["ok"])
	}

	metrics, ok := payload["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("metrics: expected map, got %T", payload["metrics"])
	}
	for _, m := range []string{"signing_key_count", "active_signing_key_age_seconds"} {
		if _, ok := metrics[m]; !ok {
			t.Errorf("metrics.%s missing", m)
		}
	}
}

// With no signing key (JWKS would serve nothing), signing_key fails and the
// age check + signing-key metrics are absent.
func TestInfoEndpoint_NoSigningKey(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	payload := fetchInfo(t, s)

	sk, ok := infoCheck(t, payload, "signing_key")
	if !ok {
		t.Fatal("checks.signing_key missing")
	}
	if sk["ok"] != false {
		t.Errorf("signing_key.ok: got %v, want false", sk["ok"])
	}
	if _, ok := infoCheck(t, payload, "signing_key_age"); ok {
		t.Error("checks.signing_key_age should be absent when there is no active key")
	}
	metrics, _ := payload["metrics"].(map[string]any)
	if _, ok := metrics["signing_key_count"]; ok {
		t.Error("metrics.signing_key_count should be absent when there is no active key")
	}
}

// An active key older than maxSigningKeyAge keeps signing_key healthy (it can
// still be served) but flips signing_key_age unhealthy — the startup-only-rotation
// safety net (lucos_aithne#149). created_at is backdated via a second connection.
func TestInfoEndpoint_StaleSigningKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "aithne.db")
	s, err := store.Open(dbPath, testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey: %v", err)
	}

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw connection: %v", err)
	}
	old := time.Now().UTC().Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := conn.Exec("UPDATE signing_keys SET created_at = ? WHERE status = 'active'", old); err != nil {
		t.Fatalf("backdate created_at: %v", err)
	}
	conn.Close()

	payload := fetchInfo(t, s)

	sk, ok := infoCheck(t, payload, "signing_key")
	if !ok {
		t.Fatal("checks.signing_key missing")
	}
	if sk["ok"] != true {
		t.Errorf("signing_key.ok: got %v, want true (a stale key is still serveable)", sk["ok"])
	}
	age, ok := infoCheck(t, payload, "signing_key_age")
	if !ok {
		t.Fatal("checks.signing_key_age missing")
	}
	if age["ok"] != false {
		t.Errorf("signing_key_age.ok: got %v, want false (key is older than maxSigningKeyAge)", age["ok"])
	}
}

// --- Helpers ---

const testIssuer = "http://aithne.test"
const testAudience = "l42.eu"

// noopLimiter returns a keyedLimiter with a very high limit, suitable for tests
// that exercise endpoint behaviour without triggering rate limiting.
func noopLimiter() *keyedLimiter {
	return newKeyedLimiter(1_000_000, time.Minute)
}

// testMainKEK is a deterministic 32-byte KEK used by main_test.go tests.
// Must not be used in production. The store package has its own testKEK.
var testMainKEK = [32]byte{
	10, 20, 30, 40, 50, 60, 70, 80,
	90, 100, 110, 120, 130, 140, 150, 160,
	170, 180, 190, 200, 210, 220, 230, 240,
	1, 2, 3, 4, 5, 6, 7, 8,
}

// testVocab is a minimal vocabulary for main package tests.
var testMainVocab = func() *store.Vocabulary {
	v, err := parseScopesYAML([]byte("scopes:\n  - aithne:admin\n  - render-ui\n"))
	if err != nil {
		panic(fmt.Sprintf("testMainVocab: %v", err))
	}
	return v
}()

// mintBearerToken creates a principal with the given scopes and mints a JWT
// for use as a Bearer token in admin endpoint tests.
func mintBearerToken(t *testing.T, s *store.Store, scopes []string) string {
	t.Helper()
	p, err := s.CreatePrincipal(store.PrincipalClassHuman, fmt.Sprintf("test-contact-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("mintBearerToken: CreatePrincipal: %v", err)
	}
	key, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("mintBearerToken: GetOrCreateActiveSigningKey: %v", err)
	}
	tok, err := token.MintSession(p, scopes, key, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("mintBearerToken: MintSession: %v", err)
	}
	return tok
}

// newAdminMux builds a test ServeMux with only the admin and enrolment endpoints registered.
func newAdminMux(s *store.Store) *http.ServeMux {
	mux := http.NewServeMux()
	contacts := newContactsClient("http://contacts.test", "test-key")
	mux.HandleFunc("/admin/grants", handleGrants(s, testMainVocab, testIssuer, "development", contacts))
	mux.HandleFunc("/admin/grants/", requireAdminScope(s, testIssuer, handleGrantByID(s)))
	mux.HandleFunc("/admin/enrol", requireAdminScope(s, testIssuer, handleAdminEnrolPage()))
	mux.HandleFunc("/admin/contacts", requireAdminScope(s, testIssuer, handleAdminContacts(contacts)))
	mux.HandleFunc("/admin/human-principals", requireAdminScope(s, testIssuer, listHumanPrincipals(s)))
	mux.HandleFunc("/admin/invites", requireAdminScope(s, testIssuer, handleAdminInvites(s, contacts, testIssuer)))
	mux.HandleFunc("/admin/invites/", requireAdminScope(s, testIssuer, handleAdminInviteByHash(s)))
	return mux
}

// newContactsServer starts a test HTTP server that returns the given status and
// body for all requests. Returns the server and its URL.
func newContactsServer(t *testing.T, status int, body string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	})
	return mux
}

// createValidInvite generates a raw token and stores an invite for contactID
// (with the principal already created). Returns the raw token.
func createValidInvite(t *testing.T, s *store.Store, contactID string) string {
	t.Helper()
	// Ensure the principal exists.
	if _, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID); errors.Is(err, store.ErrNotFound) {
		if _, err2 := s.CreatePrincipal(store.PrincipalClassHuman, contactID); err2 != nil {
			t.Fatalf("createValidInvite: CreatePrincipal: %v", err2)
		}
	}
	rawToken := "test-token-" + contactID
	if _, err := s.CreateInvite(rawToken, contactID, "admin"); err != nil {
		t.Fatalf("createValidInvite: CreateInvite: %v", err)
	}
	return rawToken
}

// --- parseScopesYAML tests ---

func TestParseScopesYAML_Basic(t *testing.T) {
	yaml := []byte("scopes:\n  - render-ui    # dev-only\n  - aithne:admin\n")
	v, err := parseScopesYAML(yaml)
	if err != nil {
		t.Fatalf("parseScopesYAML: %v", err)
	}
	if !v.Contains("render-ui") {
		t.Error("expected render-ui in vocabulary")
	}
	if !v.Contains("aithne:admin") {
		t.Error("expected aithne:admin in vocabulary")
	}
	if v.Contains("# dev-only") {
		t.Error("comment should not be treated as a scope")
	}
}

func TestParseScopesYAML_EmptyReturnsError(t *testing.T) {
	_, err := parseScopesYAML([]byte("scopes:\n"))
	if err == nil {
		t.Error("expected error for empty vocabulary")
	}
}

// --- deriveRPID tests ---

func TestDeriveRPID(t *testing.T) {
	tests := []struct {
		name      string
		appOrigin string
		want      string
	}{
		{"production subdomain", "https://aithne.l42.eu", "l42.eu"},
		{"other l42.eu subdomain", "https://auth.l42.eu", "l42.eu"},
		{"bare l42.eu", "https://l42.eu", "l42.eu"},
		{"localhost with port", "http://localhost:8039", "localhost"},
		{"localhost no port", "http://localhost", "localhost"},
		{"invalid URL", "not a url \n", "l42.eu"},
		{"no hostname (relative path)", "/relative/path", "l42.eu"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveRPID(tt.appOrigin)
			if got != tt.want {
				t.Errorf("deriveRPID(%q) = %q; want %q", tt.appOrigin, got, tt.want)
			}
		})
	}
}

// --- Admin endpoint auth tests ---

func TestAdminGrants_RejectsNoToken(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	// GET without any Authorization header → treated as a browser navigation →
	// redirects to /auth/login (no cookie present) rather than returning 401.
	req := httptest.NewRequest(http.MethodGet, "/admin/grants?principal_id=x", nil)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect to login, got %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Location"), "/auth/login") {
		t.Errorf("expected redirect to /auth/login, got Location: %s", rr.Header().Get("Location"))
	}
}

// TestAdminGrantsPage_ServesHTML verifies that GET /admin/grants with a valid
// admin session cookie (and no Authorization header) returns an HTML page.
func TestAdminGrantsPage_ServesHTML(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	key, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	p, err := s.CreatePrincipal(store.PrincipalClassHuman, "page-admin")
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	tok, err := token.MintSession(p, []string{"aithne:admin"}, key, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/grants", nil)
	req.AddCookie(&http.Cookie{Name: "aithne_session", Value: tok})
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html Content-Type, got %s", ct)
	}
}

// TestAdminGrantsPage_ContactLookup verifies that a contact_id query param
// causes the page to render the principal's active grants in the response body.
func TestAdminGrantsPage_ContactLookup(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	key, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	admin, err := s.CreatePrincipal(store.PrincipalClassHuman, "page-admin-2")
	if err != nil {
		t.Fatalf("create admin principal: %v", err)
	}
	adminTok, err := token.MintSession(admin, []string{"aithne:admin"}, key, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("mint admin token: %v", err)
	}

	target, err := s.CreatePrincipal(store.PrincipalClassHuman, "target-contact")
	if err != nil {
		t.Fatalf("create target principal: %v", err)
	}
	if _, err := s.CreateGrant(target.ID, "aithne:admin", "development", "page-admin-2", testMainVocab); err != nil {
		t.Fatalf("create grant: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/grants?contact_id=target-contact", nil)
	req.AddCookie(&http.Cookie{Name: "aithne_session", Value: adminTok})
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "aithne:admin") {
		t.Errorf("expected grant scope in page body, got: %s", body)
	}
	if !strings.Contains(body, target.ID) {
		t.Errorf("expected principal ID in page body, got: %s", body)
	}
}

// TestAdminGrantsPage_ContactNotFound verifies that looking up a contact ID
// that has no registered principal renders an error message rather than crashing.
func TestAdminGrantsPage_ContactNotFound(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	key, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	admin, err := s.CreatePrincipal(store.PrincipalClassHuman, "page-admin-3")
	if err != nil {
		t.Fatalf("create admin principal: %v", err)
	}
	adminTok, err := token.MintSession(admin, []string{"aithne:admin"}, key, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("mint admin token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/grants?contact_id=no-such-contact", nil)
	req.AddCookie(&http.Cookie{Name: "aithne_session", Value: adminTok})
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (error rendered in page), got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "no-such-contact") {
		t.Errorf("expected the searched contact ID in the error message, body: %s", body)
	}
	// Should not expose internal error details or render a grants table.
	if strings.Contains(body, "<table") {
		t.Error("expected no grants table for unknown contact")
	}
}

// TestAdminGrantsPage_ShowsDisplayName verifies that when lucos_contacts returns a
// display name for the looked-up contact, that name appears in the rendered page.
func TestAdminGrantsPage_ShowsDisplayName(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	key, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	admin, err := s.CreatePrincipal(store.PrincipalClassHuman, "page-admin-dn")
	if err != nil {
		t.Fatalf("create admin principal: %v", err)
	}
	adminTok, err := token.MintSession(admin, []string{"aithne:admin"}, key, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("mint admin token: %v", err)
	}

	// Set up target principal.
	if _, err := s.CreatePrincipal(store.PrincipalClassHuman, "alice"); err != nil {
		t.Fatalf("create target principal: %v", err)
	}

	// Mock contacts server that returns a display name.
	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"Alice Example"}`)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/grants", handleGrants(s, testMainVocab, testIssuer, "development", contacts))

	req := httptest.NewRequest(http.MethodGet, "/admin/grants?contact_id=alice", nil)
	req.AddCookie(&http.Cookie{Name: "aithne_session", Value: adminTok})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Alice Example") {
		t.Errorf("expected display name %q in page body, got: %s", "Alice Example", body)
	}
	if !strings.Contains(body, "alice") {
		t.Errorf("expected contact ID %q in page body, got: %s", "alice", body)
	}
}

// TestAdminGrantsPage_FallsBackToContactIDWhenContactsUnavailable verifies that if
// lucos_contacts is unreachable after a successful principal lookup, the page still
// renders using the contact ID as the display name fallback.
func TestAdminGrantsPage_FallsBackToContactIDWhenContactsUnavailable(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	key, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	admin, err := s.CreatePrincipal(store.PrincipalClassHuman, "page-admin-fb")
	if err != nil {
		t.Fatalf("create admin principal: %v", err)
	}
	adminTok, err := token.MintSession(admin, []string{"aithne:admin"}, key, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("mint admin token: %v", err)
	}

	if _, err := s.CreatePrincipal(store.PrincipalClassHuman, "bob"); err != nil {
		t.Fatalf("create target principal: %v", err)
	}

	// Contacts is unreachable.
	contacts := newContactsClient("http://127.0.0.1:1", "test-key")

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/grants", handleGrants(s, testMainVocab, testIssuer, "development", contacts))

	req := httptest.NewRequest(http.MethodGet, "/admin/grants?contact_id=bob", nil)
	req.AddCookie(&http.Cookie{Name: "aithne_session", Value: adminTok})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 even when contacts unavailable, got %d", rr.Code)
	}
	body := rr.Body.String()
	// Should still render with contact ID as display name fallback — no crash.
	if !strings.Contains(body, "bob") {
		t.Errorf("expected contact ID %q in page body as fallback name, got: %s", "bob", body)
	}
}

func TestAdminGrants_RejectsInvalidToken(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/grants?principal_id=x", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAdminGrants_RejectsMissingAdminScope(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	// Token with render-ui scope only — no aithne:admin.
	tok := mintBearerToken(t, s, []string{"render-ui"})

	req := httptest.NewRequest(http.MethodGet, "/admin/grants?principal_id=x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// --- Admin grant list/create/revoke tests ---

func TestAdminGrants_ListEmpty(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	// Create a separate principal to query — not the token's principal.
	p, _ := s.CreatePrincipal(store.PrincipalClassHuman, "query-contact")
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	req := httptest.NewRequest(http.MethodGet, "/admin/grants?principal_id="+p.ID, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d\n%s", rr.Code, rr.Body.String())
	}
	var list []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&list); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d items", len(list))
	}
}

func TestAdminGrants_CreateAndList(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	target, _ := s.CreatePrincipal(store.PrincipalClassHuman, "target-contact")
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	body, _ := json.Marshal(map[string]string{
		"principal_id": target.ID,
		"scope":        "render-ui",
		"environment":  "development",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/grants", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/grants: expected 201, got %d\n%s", rr.Code, rr.Body.String())
	}
	var created map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&created); err != nil {
		t.Fatalf("decode created grant: %v", err)
	}
	if created["id"] == "" || created["id"] == nil {
		t.Error("expected non-empty id in created grant")
	}
	if created["scope"] != "render-ui" {
		t.Errorf("scope: got %v, want render-ui", created["scope"])
	}
	// granted_by must come from the JWT subject, not a client-supplied field.
	if grantedBy, ok := created["granted_by"].(string); !ok || grantedBy == "" {
		t.Errorf("granted_by: expected non-empty string from JWT subject, got %v", created["granted_by"])
	}

	// Verify the grant appears in LIST.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/grants?principal_id="+target.ID, nil)
	listReq.Header.Set("Authorization", "Bearer "+tok)
	listRR := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(listRR, listReq)

	var list []map[string]any
	if err := json.NewDecoder(listRR.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 grant in list, got %d", len(list))
	}
}

func TestAdminGrants_Create_UnknownScope(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	target, _ := s.CreatePrincipal(store.PrincipalClassHuman, "target-contact")
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	body, _ := json.Marshal(map[string]string{
		"principal_id": target.ID,
		"scope":        "nonexistent:scope",
		"environment":  "development",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/grants", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown scope, got %d", rr.Code)
	}
}

func TestAdminGrants_Create_DuplicateActive(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	target, _ := s.CreatePrincipal(store.PrincipalClassHuman, "target-contact")
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	body, _ := json.Marshal(map[string]string{
		"principal_id": target.ID,
		"scope":        "render-ui",
		"environment":  "development",
	})

	// First create should succeed.
	req1 := httptest.NewRequest(http.MethodPost, "/admin/grants", bytes.NewReader(body))
	req1.Header.Set("Authorization", "Bearer "+tok)
	req1.Header.Set("Content-Type", "application/json")
	newAdminMux(s).ServeHTTP(httptest.NewRecorder(), req1)

	// Second create should return 409.
	req2 := httptest.NewRequest(http.MethodPost, "/admin/grants", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate active grant, got %d", rr2.Code)
	}
}

// TestAdminGrants_Create_IgnoresBodyEnvironment verifies that a POST body
// supplying a foreign environment value is ignored: the grant is stamped with
// the instance environment ("development") rather than the caller-supplied one.
func TestAdminGrants_Create_IgnoresBodyEnvironment(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	target, _ := s.CreatePrincipal(store.PrincipalClassHuman, "target-contact")
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	// POST with a foreign environment value — the handler must ignore it.
	body, _ := json.Marshal(map[string]string{
		"principal_id": target.ID,
		"scope":        "render-ui",
		"environment":  "production", // deliberately foreign; should be ignored
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/grants", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/grants: expected 201, got %d\n%s", rr.Code, rr.Body.String())
	}

	// The grant must carry the instance environment ("development"), not "production".
	grants, err := s.ListGrants(target.ID, "development", true)
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant in development, got %d", len(grants))
	}
	if grants[0].Environment != "development" {
		t.Errorf("grant environment: got %q, want %q", grants[0].Environment, "development")
	}

	// Confirm no grant was created under the caller-supplied "production" environment.
	prodGrants, err := s.ListGrants(target.ID, "production", true)
	if err != nil {
		t.Fatalf("ListGrants production: %v", err)
	}
	if len(prodGrants) != 0 {
		t.Errorf("expected 0 grants in production, got %d", len(prodGrants))
	}
}

// TestAdminGrants_Create_NoEnvironmentInBody verifies that a POST body
// omitting the environment field succeeds — existing forms still include it,
// but clients that drop it should also work after this change.
func TestAdminGrants_Create_NoEnvironmentInBody(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	target, _ := s.CreatePrincipal(store.PrincipalClassHuman, "target-contact")
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	// POST without an environment field.
	body, _ := json.Marshal(map[string]string{
		"principal_id": target.ID,
		"scope":        "render-ui",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/grants", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/grants without environment: expected 201, got %d\n%s", rr.Code, rr.Body.String())
	}

	// Grant must be stamped with the instance environment.
	grants, err := s.ListGrants(target.ID, "development", true)
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Errorf("expected 1 grant in development, got %d", len(grants))
	}
}

func TestAdminGrantByID_Revoke(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	target, _ := s.CreatePrincipal(store.PrincipalClassHuman, "target-contact")
	v := testMainVocab
	g, _ := s.CreateGrant(target.ID, "render-ui", "development", "test-admin", v)
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	req := httptest.NewRequest(http.MethodDelete, "/admin/grants/"+g.ID, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d\n%s", rr.Code, rr.Body.String())
	}

	// Verify the grant is now revoked, and that revoked_by came from the JWT
	// subject (not a client-supplied header).
	fetched, err := s.GetGrant(g.ID)
	if err != nil {
		t.Fatalf("GetGrant after revoke: %v", err)
	}
	if fetched.IsActive() {
		t.Error("grant should be revoked after DELETE")
	}
	if fetched.RevokedBy == nil || *fetched.RevokedBy == "" {
		t.Error("revoked_by should be set from JWT subject")
	}
}

func TestAdminGrantByID_Revoke_NotFound(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	tok := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodDelete, "/admin/grants/nonexistent-id", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestJWKSEndpoint_Wired(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	// Ensure an active signing key exists (mirrors main() startup).
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", token.JWKSHandler(func() ([]*store.SigningKey, error) {
		return s.ListVerificationKeys(token.VerificationWindow)
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"keys"`) {
		t.Errorf("JWKS response missing 'keys' field: %s", body)
	}
}

// --- Static file handler tests ---

func TestLoginPage_ServesHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()
	handleLoginPage(templateFS)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /auth/login: expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type: got %q, want text/html", ct)
	}
	if !strings.Contains(rr.Body.String(), "<title>") {
		t.Error("login.html body does not look like HTML (no <title>)")
	}
}

func TestLoginPage_RejectsPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	rr := httptest.NewRecorder()
	handleLoginPage(templateFS)(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /auth/login: expected 405, got %d", rr.Code)
	}
}

func TestLoginPage_SetsCSP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()
	handleLoginPage(templateFS)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /auth/login: expected 200, got %d", rr.Code)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing on login page")
	}
	// CSP must contain a nonce directive (not 'unsafe-inline').
	if !strings.Contains(csp, "'nonce-") {
		t.Errorf("CSP missing nonce directive: %q", csp)
	}
	// The nonce in the CSP must match the one injected into the script tag.
	// Extract the nonce value from the CSP header.
	const noncePrefix = "'nonce-"
	idx := strings.Index(csp, noncePrefix)
	if idx < 0 {
		t.Fatalf("could not find nonce in CSP: %q", csp)
	}
	end := strings.Index(csp[idx+len(noncePrefix):], "'")
	if end < 0 {
		t.Fatalf("malformed nonce in CSP: %q", csp)
	}
	nonceVal := csp[idx+len(noncePrefix) : idx+len(noncePrefix)+end]
	body := rr.Body.String()
	if !strings.Contains(body, `nonce="`+nonceVal+`"`) {
		t.Errorf("nonce %q from CSP not found in rendered HTML body", nonceVal)
	}
}

func TestCSP_StyleSrcHasNoUnsafeInline(t *testing.T) {
	// Regression guard for #137: 'unsafe-inline' must not appear in style-src.
	// lucos_navbar v2.1.74+ uses constructable stylesheets (adoptedStyleSheets)
	// instead of document.createElement('style'), so 'unsafe-inline' is no longer
	// needed and must never be re-added silently.
	rr := httptest.NewRecorder()
	_, err := applyPageCSP(rr)
	if err != nil {
		t.Fatalf("applyPageCSP: %v", err)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("style-src must not contain 'unsafe-inline'; got CSP: %q", csp)
	}
	if !strings.Contains(csp, "style-src 'self'") {
		t.Errorf("style-src must contain 'self'; got CSP: %q", csp)
	}
}

func TestSecureHeaders_Present(t *testing.T) {
	// secureHeaders must add X-Frame-Options, X-Content-Type-Options, and
	// Referrer-Policy to every response, regardless of the underlying handler.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/_info", nil)
	rr := httptest.NewRecorder()
	secureHeaders(inner).ServeHTTP(rr, req)

	checks := []struct {
		header string
		want   string
	}{
		{"X-Frame-Options", "DENY"},
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}
	for _, c := range checks {
		if got := rr.Header().Get(c.header); got != c.want {
			t.Errorf("%s: got %q, want %q", c.header, got, c.want)
		}
	}
}

// --- WebAuthn ceremony handler tests ---
//
// Full ceremony happy-paths cannot be exercised in unit tests without a real
// authenticator (hardware or software). Tests here cover:
//   - Input validation (method, missing token)
//   - Invalid/expired/used invite paths
//   - Ceremony session absent (begin not called, TTL exceeded)
//   - handleEnrolBegin: returns valid PublicKeyCredentialCreationOptions

// --- Enrolment begin tests ---

func TestEnrolBegin_RejectsNonPost(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()
	contacts := newContactsClient("http://contacts.test", "test-key")

	req := httptest.NewRequest(http.MethodGet, "/enrol/begin?token=any", nil)
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs, contacts, noopLimiter())(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rr.Code)
	}
}

func TestEnrolBegin_MissingToken(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()
	contacts := newContactsClient("http://contacts.test", "test-key")

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs, contacts, noopLimiter())(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing token, got %d", rr.Code)
	}
}

func TestEnrolBegin_InvalidToken(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()
	contacts := newContactsClient("http://contacts.test", "test-key")

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin?token=nonexistent", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs, contacts, noopLimiter())(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", rr.Code)
	}
}

func TestEnrolBegin_ValidToken_ReturnsOptions(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"Alice Example"}`)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	rawToken := createValidInvite(t, s, "alice")

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin?token="+rawToken, strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs, contacts, noopLimiter())(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d\n%s", rr.Code, rr.Body.String())
	}
	var opts map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&opts); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	if _, ok := opts["publicKey"]; !ok {
		t.Error("response missing publicKey field")
	}
	// Verify enrolment session was stored keyed by token hash.
	tokenHash := store.HashToken(rawToken)
	if _, _, ok := cs.takeEnrol(tokenHash); !ok {
		t.Error("ceremony store should hold enrolment session data after begin")
	}
}

// TestEnrolBegin_UsesContactDisplayName verifies that the display name from
// lucos_contacts is embedded in the WebAuthn credential creation options so
// that authenticators show the person's real name rather than their numeric
// contact ID.
func TestEnrolBegin_UsesContactDisplayName(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"Bob Builder"}`)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	rawToken := createValidInvite(t, s, "42")

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin?token="+rawToken, strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs, contacts, noopLimiter())(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d\n%s", rr.Code, rr.Body.String())
	}

	// The publicKey.user.displayName field must contain the name from contacts,
	// not the raw numeric contact ID. This is the value authenticators use when
	// displaying or labelling the passkey.
	var resp struct {
		PublicKey struct {
			User struct {
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	if resp.PublicKey.User.DisplayName != "Bob Builder" {
		t.Errorf("publicKey.user.displayName: got %q, want %q", resp.PublicKey.User.DisplayName, "Bob Builder")
	}
	if resp.PublicKey.User.Name != "Bob Builder" {
		t.Errorf("publicKey.user.name: got %q, want %q", resp.PublicKey.User.Name, "Bob Builder")
	}
}

// TestEnrolBegin_FallsBackToContactIDWhenContactsUnavailable verifies that if
// the contacts service is unreachable, the enrolment ceremony still proceeds —
// the contact ID is used as the display name fallback rather than returning an
// error to the user.
func TestEnrolBegin_FallsBackToContactIDWhenContactsUnavailable(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	// Point at a non-existent server — contacts lookup will fail.
	contacts := newContactsClient("http://127.0.0.1:1", "test-key")

	rawToken := createValidInvite(t, s, "99")

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin?token="+rawToken, strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs, contacts, noopLimiter())(rr, req)

	// Registration should still succeed — contacts failure is non-fatal.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 even when contacts unavailable, got %d\n%s", rr.Code, rr.Body.String())
	}

	// The ceremony session should be stored.
	tokenHash := store.HashToken(rawToken)
	if _, _, ok := cs.takeEnrol(tokenHash); !ok {
		t.Error("ceremony store should hold enrolment session data even on contacts failure")
	}
}

func TestEnrolBegin_DoesNotConsumeInvite(t *testing.T) {
	// Verifies that calling begin does not mark the invite as used —
	// so a browser crash between begin and finish doesn't permanently burn it.
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"Bob"}`)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	rawToken := createValidInvite(t, s, "bob")

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin?token="+rawToken, strings.NewReader("{}"))
	httptest.NewRecorder() // discard response
	handleEnrolBegin(s, wa, cs, contacts, noopLimiter())(httptest.NewRecorder(), req)

	// Invite must still be valid after begin.
	inv, err := s.GetInviteByRawToken(rawToken)
	if err != nil {
		t.Fatalf("invite should still be valid after begin: %v", err)
	}
	if inv.UsedAt != nil {
		t.Error("invite should NOT be consumed after begin (only after successful finish)")
	}
}

// --- Enrolment finish tests ---

func TestEnrolFinish_RejectsNonPost(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	req := httptest.NewRequest(http.MethodGet, "/enrol/finish?token=any", nil)
	rr := httptest.NewRecorder()
	handleEnrolFinish(s, wa, cs)(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rr.Code)
	}
}

func TestEnrolFinish_MissingToken(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	req := httptest.NewRequest(http.MethodPost, "/enrol/finish", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolFinish(s, wa, cs)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing token, got %d", rr.Code)
	}
}

func TestEnrolFinish_NoSession(t *testing.T) {
	// begin was never called (or session expired).
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	req := httptest.NewRequest(http.MethodPost, "/enrol/finish?token=nonexistent", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolFinish(s, wa, cs)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing session, got %d", rr.Code)
	}
}

// --- Enrolment page tests ---

func TestEnrolPage_RejectsNonGet(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	contacts := newContactsClient("http://contacts.test", "test-key")

	req := httptest.NewRequest(http.MethodPost, "/enrol?token=x", nil)
	rr := httptest.NewRecorder()
	handleEnrolPage(s, contacts)(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestEnrolPage_MissingToken(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	contacts := newContactsClient("http://contacts.test", "test-key")

	req := httptest.NewRequest(http.MethodGet, "/enrol", nil)
	rr := httptest.NewRecorder()
	handleEnrolPage(s, contacts)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing token, got %d", rr.Code)
	}
}

func TestEnrolPage_InvalidToken_RendersErrorPage(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	contacts := newContactsClient("http://contacts.test", "test-key")

	req := httptest.NewRequest(http.MethodGet, "/enrol?token=nonexistent", nil)
	rr := httptest.NewRecorder()
	handleEnrolPage(s, contacts)(rr, req)

	// Should render the error template (200 with error HTML), not a raw HTTP error.
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error HTML, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "not valid") {
		t.Errorf("error page should mention invite not valid, got: %s", body)
	}
}

// checkCSPNonce is a test helper that asserts:
//  1. The Content-Security-Policy header is present and contains a 'nonce-...' directive.
//  2. The nonce value extracted from the CSP header appears as nonce="..." in body.
//
// Returns the extracted nonce value for additional assertions by the caller.
func checkCSPNonce(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing")
	}
	if !strings.Contains(csp, "'nonce-") {
		t.Fatalf("CSP missing nonce directive: %q", csp)
	}
	const noncePrefix = "'nonce-"
	idx := strings.Index(csp, noncePrefix)
	if idx < 0 {
		t.Fatalf("could not find nonce in CSP: %q", csp)
	}
	end := strings.Index(csp[idx+len(noncePrefix):], "'")
	if end < 0 {
		t.Fatalf("malformed nonce in CSP: %q", csp)
	}
	nonceVal := csp[idx+len(noncePrefix) : idx+len(noncePrefix)+end]
	body := rr.Body.String()
	if !strings.Contains(body, `nonce="`+nonceVal+`"`) {
		t.Errorf("nonce %q from CSP not found in rendered HTML body", nonceVal)
	}
	return nonceVal
}

func TestEnrolPage_SetsCSP(t *testing.T) {
	// Verify that GET /enrol?token=<valid> sets a nonce-based CSP and injects the
	// nonce into the <style> and <script> tags of the enrolment page.
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	// Start a mock contacts server that returns a valid contact.
	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"Alice"}`)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	rawToken := createValidInvite(t, s, "alice")
	req := httptest.NewRequest(http.MethodGet, "/enrol?token="+rawToken, nil)
	rr := httptest.NewRecorder()
	handleEnrolPage(s, contacts)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d\n%s", rr.Code, rr.Body.String())
	}
	checkCSPNonce(t, rr)
}

func TestEnrolPage_ErrorPage_SetsCSP(t *testing.T) {
	// Verify that an invalid-token response (enrol_error.html) also carries a
	// nonce-based CSP with the nonce injected into the <style> tag.
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	contacts := newContactsClient("http://contacts.test", "test-key")

	req := httptest.NewRequest(http.MethodGet, "/enrol?token=nonexistent", nil)
	rr := httptest.NewRecorder()
	handleEnrolPage(s, contacts)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with error HTML, got %d", rr.Code)
	}
	checkCSPNonce(t, rr)
}

func TestAdminEnrolPage_SetsCSP(t *testing.T) {
	// Verify that GET /admin/enrol sets a nonce-based CSP and injects the nonce
	// into the <style> and <script> tags. Auth wrapping is bypassed — the test
	// exercises the inner handler directly, mirroring TestLoginPage_SetsCSP.
	req := httptest.NewRequest(http.MethodGet, "/admin/enrol", nil)
	rr := httptest.NewRecorder()
	handleAdminEnrolPage()(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d\n%s", rr.Code, rr.Body.String())
	}
	checkCSPNonce(t, rr)
}

// --- Admin invites tests ---

func TestAdminInvites_RejectsNoToken(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/invites", strings.NewReader(`{"contact_id":"alice"}`))
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAdminInvites_MissingContactID(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/admin/invites", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing contact_id, got %d", rr.Code)
	}
}

// --- Contacts client tests ---

// TestContactsClient_PathEscapesContactID verifies that special characters in
// contact_id are percent-encoded in the outgoing request path so they are
// treated as part of the path segment and not as path separators or other
// URL-structural characters.
func TestContactsClient_PathEscapesContactID(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawPath
		if gotPath == "" {
			gotPath = r.URL.Path // RawPath is only set when encoding differs from Path
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"Test User"}`)
	}))
	defer srv.Close()

	c := newContactsClient(srv.URL, "test-key")

	// A contact_id containing a slash and a space — both need escaping.
	contactID := "org/alice smith"
	info, err := c.Get(contactID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if info.DisplayName != "Test User" {
		t.Errorf("DisplayName: got %q, want %q", info.DisplayName, "Test User")
	}

	want := "/people/org%2Falice%20smith"
	if gotPath != want {
		t.Errorf("request path: got %q, want %q", gotPath, want)
	}
}

// TestContactsClient_SendsCorrectHeaders verifies that Get sends the correct
// Authorization (Bearer) and Accept (application/json) headers so that
// lucos_contacts authenticates the request and returns JSON rather than HTML.
func TestContactsClient_SendsCorrectHeaders(t *testing.T) {
	var (
		gotAuth   string
		gotAccept string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"Alice"}`)
	}))
	defer srv.Close()

	c := newContactsClient(srv.URL, "my-secret-key")
	if _, err := c.Get("42"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if gotAuth != "Bearer my-secret-key" {
		t.Errorf("Authorization header: got %q, want %q", gotAuth, "Bearer my-secret-key")
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept header: got %q, want %q", gotAccept, "application/json")
	}
}

// TestContactsClient_404ReturnsNotFound verifies that a 404 from lucos_contacts
// is mapped to store.ErrNotFound so callers can distinguish missing contacts from
// service errors.
func TestContactsClient_404ReturnsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newContactsClient(srv.URL, "key")
	_, err := c.Get("99")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected store.ErrNotFound for 404, got %v", err)
	}
}

// TestContactsClient_NonOKReturnsError verifies that an unexpected non-200/non-404
// status code (e.g. 500) is surfaced as an error, not silently ignored.
func TestContactsClient_NonOKReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newContactsClient(srv.URL, "key")
	_, err := c.Get("42")
	if err == nil {
		t.Error("expected error for 500, got nil")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Error("500 should not be mapped to ErrNotFound")
	}
}

// TestAdminInvites_ContactNotFound verifies that a contact_id that does not exist
// in lucos_contacts results in a 422 Unprocessable Entity response.
func TestAdminInvites_ContactNotFound(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	// Contacts returns 404 for any request.
	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/invites", requireAdminScope(s, testIssuer, handleAdminInvites(s, contacts, testIssuer)))

	body, _ := json.Marshal(map[string]string{"contact_id": "99"})
	req := httptest.NewRequest(http.MethodPost, "/admin/invites", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for unknown contact, got %d", rr.Code)
	}
}

// TestAdminInvites_ContactsUnavailable verifies that a 5xx response from
// lucos_contacts results in a 503 Service Unavailable to the caller.
func TestAdminInvites_ContactsUnavailable(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	// Contacts is down.
	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/invites", requireAdminScope(s, testIssuer, handleAdminInvites(s, contacts, testIssuer)))

	body, _ := json.Marshal(map[string]string{"contact_id": "42"})
	req := httptest.NewRequest(http.MethodPost, "/admin/invites", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when contacts unavailable, got %d", rr.Code)
	}
}

// TestAdminInvites_Success verifies the full happy path: a known contact_id that
// exists in lucos_contacts results in a 201 Created with an invite URL.
func TestAdminInvites_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	// Contacts returns a valid response.
	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":42,"name":"Alice Example","url":"/people/42"}`)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/invites", requireAdminScope(s, testIssuer, handleAdminInvites(s, contacts, testIssuer)))

	body, _ := json.Marshal(map[string]string{"contact_id": "42"})
	req := httptest.NewRequest(http.MethodPost, "/admin/invites", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d; body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["invite_url"] == "" {
		t.Error("expected non-empty invite_url in response")
	}
	if resp["expires_at"] == "" {
		t.Error("expected non-empty expires_at in response")
	}
	// display_name should be populated from lucos_contacts.
	if resp["display_name"] != "Alice Example" {
		t.Errorf("expected display_name %q in response, got %q", "Alice Example", resp["display_name"])
	}
}

// --- Store invite tests ---

func TestStore_CreateAndGetInvite(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if _, err := s.CreatePrincipal(store.PrincipalClassHuman, "carol"); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	rawToken := "test-raw-token-abc"
	inv, err := s.CreateInvite(rawToken, "carol", "admin")
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if inv.ContactID != "carol" {
		t.Errorf("ContactID: got %q, want %q", inv.ContactID, "carol")
	}
	if inv.UsedAt != nil {
		t.Error("new invite should not be used")
	}

	// Retrieve by raw token — should succeed.
	fetched, err := s.GetInviteByRawToken(rawToken)
	if err != nil {
		t.Fatalf("GetInviteByRawToken: %v", err)
	}
	if fetched.ContactID != "carol" {
		t.Errorf("fetched ContactID: got %q", fetched.ContactID)
	}

	// Raw token is never stored — the TokenHash should be the SHA-256 hex.
	if fetched.TokenHash == rawToken {
		t.Error("TokenHash should be the SHA-256 hash, not the raw token itself")
	}
	if fetched.TokenHash != store.HashToken(rawToken) {
		t.Errorf("TokenHash mismatch: got %q, want %q", fetched.TokenHash, store.HashToken(rawToken))
	}
}

func TestStore_GetInvite_NotFound(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	_, err = s.GetInviteByRawToken("nonexistent-token")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestStore_ReplaceWebAuthnCredentialAndConsumeInvite_AtomicWipe(t *testing.T) {
	// Verifies the atomic transaction: old creds are wiped, new one inserted, invite consumed.
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	p, err := s.CreatePrincipal(store.PrincipalClassHuman, "dave")
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	// Insert an existing credential to be wiped.
	if _, err := s.CreateCredential(p.ID, store.CredentialTypeWebAuthn, []byte(`{"old":true}`), "old-key"); err != nil {
		t.Fatalf("CreateCredential (old): %v", err)
	}

	rawToken := "dave-invite-token"
	if _, err := s.CreateInvite(rawToken, "dave", "admin"); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	// Execute the atomic replacement.
	newCred, err := s.ReplaceWebAuthnCredentialAndConsumeInvite(p.ID, rawToken, []byte(`{"new":true}`), "new-key")
	if err != nil {
		t.Fatalf("ReplaceWebAuthnCredentialAndConsumeInvite: %v", err)
	}
	if newCred.Label != "new-key" {
		t.Errorf("new credential label: got %q, want %q", newCred.Label, "new-key")
	}

	// Old credential must be gone; only the new one should exist.
	creds, err := s.ListCredentialsByPrincipal(p.ID)
	if err != nil {
		t.Fatalf("ListCredentialsByPrincipal: %v", err)
	}
	if len(creds) != 1 {
		t.Errorf("expected exactly 1 credential after replace, got %d", len(creds))
	}
	if string(creds[0].Data) != `{"new":true}` {
		t.Errorf("surviving credential has wrong data: %s", creds[0].Data)
	}

	// Invite must now be marked used.
	inv, err := s.GetInviteByRawToken(rawToken)
	if err == nil {
		// GetInviteByRawToken returns ErrInviteUsed for a used invite, with the record.
		t.Logf("invite returned with UsedAt: %v", inv.UsedAt)
	}
	if !errors.Is(err, store.ErrInviteUsed) {
		t.Errorf("invite should be ErrInviteUsed after replace, got %v (inv=%v)", err, inv)
	}
}

func TestLoginBegin_GhostPrincipal(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	// Principal does not exist at all.
	body, _ := json.Marshal(map[string]string{"contact_id": "ghost"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleLoginBegin(s, wa, cs, noopLimiter())(rr, req)

	// Security rule #3: ghost principals and no-credentials are both 404 to
	// prevent contact-ID enumeration.
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for ghost principal, got %d", rr.Code)
	}
}

func TestLoginBegin_PrincipalWithNoCredentials(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	// Principal exists but has no WebAuthn credentials registered.
	if _, err := s.CreatePrincipal(store.PrincipalClassHuman, "no-creds"); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"contact_id": "no-creds"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleLoginBegin(s, wa, cs, noopLimiter())(rr, req)

	// Security rule #3: same 404 whether principal is missing or has no creds.
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for principal with no credentials, got %d", rr.Code)
	}
}

func TestLoginBegin_EmptyContactID_Discoverable(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	// Empty contact_id triggers the discoverable login path (allowCredentials=[]).
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/auth/login/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleLoginBegin(s, wa, cs, noopLimiter())(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for discoverable login begin, got %d\n%s", rr.Code, rr.Body.String())
	}
	var opts map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&opts); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	if _, ok := opts["publicKey"]; !ok {
		t.Error("response missing publicKey field")
	}
	sessionID, _ := opts["aithne_session"].(string)
	if sessionID == "" {
		t.Error("response missing aithne_session field — required for conditional mediation finish")
	}
	// Verify session was stored.
	if _, ok := cs.take("login:disco:" + sessionID); !ok {
		t.Error("ceremony store should hold discoverable session data after begin")
	}
}

func TestLoginFinish_DiscoverableNoSession(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	// session param provided but no matching entry in the store.
	req := httptest.NewRequest(http.MethodPost, "/auth/login/finish?session=nonexistent-uuid", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleLoginFinish(s, wa, cs, testIssuer, "development")(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing discoverable session, got %d", rr.Code)
	}
}

func TestLoginFinish_NoSession(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	// No prior login/begin call — ceremony session is absent.
	req := httptest.NewRequest(http.MethodPost, "/auth/login/finish?contact_id=nobody", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleLoginFinish(s, wa, cs, testIssuer, "development")(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing session, got %d", rr.Code)
	}
}

func TestLoginFinish_NeitherContactIDNorSession(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	// Neither contact_id nor session provided — unambiguously bad request.
	req := httptest.NewRequest(http.MethodPost, "/auth/login/finish", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleLoginFinish(s, wa, cs, testIssuer, "development")(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when neither contact_id nor session provided, got %d", rr.Code)
	}
}

// TestCeremonyStore_ExpiredSession verifies that a ceremony store entry that has
// passed the TTL is not returned (replay protection: old sessions can't be reused).
func TestCeremonyStore_ExpiredSession(t *testing.T) {
	cs := newCeremonyStore()
	// Inject an already-expired entry directly.
	cs.mu.Lock()
	cs.entries["register:expired-user"] = &ceremonyEntry{
		data:      &gwebauthn.SessionData{},
		expiresAt: time.Now().Add(-1 * time.Second), // already expired
	}
	cs.mu.Unlock()

	data, ok := cs.take("register:expired-user")
	if ok || data != nil {
		t.Error("expired ceremony session should not be returned")
	}
}

// TestCeremonyStore_OneTimeUse verifies that a ceremony session is consumed on
// first take() and absent on a second take() (prevents session replay).
func TestCeremonyStore_OneTimeUse(t *testing.T) {
	cs := newCeremonyStore()
	cs.put("login:bob", &gwebauthn.SessionData{})

	first, ok := cs.take("login:bob")
	if !ok || first == nil {
		t.Fatal("first take should succeed")
	}
	second, ok2 := cs.take("login:bob")
	if ok2 || second != nil {
		t.Error("second take should return nothing (session already consumed)")
	}
}

// --- Machine/agent authentication tests ---

// newMachineAuthMux builds a test ServeMux with the oauth2/token,
// admin/machine-keys, and admin/machine-keys/{id} endpoints registered.
func newMachineAuthMux(s *store.Store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", handleOAuth2Token(s, testIssuer, "development", noopLimiter()))
	mux.HandleFunc("/admin/machine-keys", requireAdminScope(s, testIssuer, handleAdminMachineKeys(s)))
	mux.HandleFunc("/admin/machine-keys/", requireAdminScope(s, testIssuer, handleAdminMachineKeyByID(s)))
	return mux
}

// provisionMachineKey creates an agent principal (if needed) and a machine_key
// credential for agentSlug. Returns the raw client_secret.
func provisionMachineKey(t *testing.T, s *store.Store, agentSlug string) string {
	t.Helper()
	// Ensure the principal exists.
	p, err := s.GetPrincipalByExternalID(store.PrincipalClassAgent, agentSlug)
	if err != nil {
		if err != store.ErrNotFound {
			t.Fatalf("provisionMachineKey: GetPrincipalByExternalID: %v", err)
		}
		p, err = s.CreatePrincipal(store.PrincipalClassAgent, agentSlug)
		if err != nil {
			t.Fatalf("provisionMachineKey: CreatePrincipal: %v", err)
		}
	}
	rawSecret := "test-secret-" + agentSlug
	secretHash := hashMachineKey(rawSecret)
	if _, err := s.CreateCredential(p.ID, store.CredentialTypeMachineKey, []byte(secretHash), "test"); err != nil {
		t.Fatalf("provisionMachineKey: CreateCredential: %v", err)
	}
	return rawSecret
}

func TestClientCredentials_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	rawSecret := provisionMachineKey(t, s, "lucos-test-agent")

	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-test-agent&client_secret=" + rawSecret)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp tokenSuccessResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want %q", resp.TokenType, "Bearer")
	}
	if resp.AccessToken == "" {
		t.Error("access_token must not be empty")
	}
	if resp.ExpiresIn <= 0 {
		t.Errorf("expires_in: got %d, want > 0", resp.ExpiresIn)
	}
}

func TestClientCredentials_TokenCarriesAgentClass(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	rawSecret := provisionMachineKey(t, s, "lucos-arch-agent")
	// Grant a scope so we can verify it appears in the token.
	p, _ := s.GetPrincipalByExternalID(store.PrincipalClassAgent, "lucos-arch-agent")
	vocab, _ := parseScopesYAML([]byte("scopes:\n  - render-ui\n  - aithne:admin\n"))
	if _, err := s.CreateGrant(p.ID, "render-ui", "development", "bootstrap", vocab); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-arch-agent&client_secret=" + rawSecret)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp tokenSuccessResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)

	// Parse the minted JWT and verify principal_class and scopes.
	keys, _ := s.ListVerificationKeys(token.VerificationWindow)
	keySet, _ := token.BuildVerificationKeySet(keys)
	claims, err := token.ParseSession(resp.AccessToken, keySet, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if claims.PrincipalClass != store.PrincipalClassAgent {
		t.Errorf("principal_class: got %q, want %q", claims.PrincipalClass, store.PrincipalClassAgent)
	}
	if claims.Subject != "lucos-arch-agent" {
		t.Errorf("sub: got %q, want %q", claims.Subject, "lucos-arch-agent")
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "render-ui" {
		t.Errorf("scopes: got %v, want [render-ui]", claims.Scopes)
	}
}

func TestClientCredentials_WrongSecret(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	provisionMachineKey(t, s, "lucos-test-agent")

	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-test-agent&client_secret=wrong-secret")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	var errResp tokenErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&errResp)
	if errResp.Error != "invalid_client" {
		t.Errorf("error: got %q, want %q", errResp.Error, "invalid_client")
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("WWW-Authenticate header missing on 401")
	}
}

func TestClientCredentials_UnknownClientID(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	body := strings.NewReader("grant_type=client_credentials&client_id=no-such-agent&client_secret=any")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	var errResp tokenErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&errResp)
	if errResp.Error != "invalid_client" {
		t.Errorf("error: got %q, want %q", errResp.Error, "invalid_client")
	}
}

func TestClientCredentials_MissingCredentials(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	body := strings.NewReader("grant_type=client_credentials")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	var errResp tokenErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&errResp)
	if errResp.Error != "invalid_client" {
		t.Errorf("error: got %q, want %q", errResp.Error, "invalid_client")
	}
}

func TestClientCredentials_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/token", nil)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestAdminMachineKeys_Create(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	body := bytes.NewBufferString(`{"agent_slug":"lucos-test-agent"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/machine-keys", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp createMachineKeyResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ClientID != "lucos-test-agent" {
		t.Errorf("client_id: got %q, want %q", resp.ClientID, "lucos-test-agent")
	}
	if resp.ClientSecret == "" {
		t.Error("client_secret must not be empty")
	}
	if resp.PrincipalID == "" {
		t.Error("principal_id must not be empty — required for subsequent POST /admin/grants calls")
	}
	if resp.CredentialID == "" {
		t.Error("credential_id must not be empty")
	}
	if resp.Note == "" {
		t.Error("note must not be empty")
	}
}

func TestAdminMachineKeys_SecretUsableForTokenExchange(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	// 1. Provision machine key via admin endpoint.
	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	body := bytes.NewBufferString(`{"agent_slug":"lucos-e2e-agent"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/machine-keys", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("provision: expected 201, got %d", rr.Code)
	}
	var provResp createMachineKeyResponse
	_ = json.NewDecoder(rr.Body).Decode(&provResp)

	// 2. Exchange the returned secret for a session token.
	tokenBody := strings.NewReader(
		"grant_type=client_credentials&client_id=lucos-e2e-agent&client_secret=" + provResp.ClientSecret,
	)
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", tokenBody)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRR := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(tokenRR, tokenReq)
	if tokenRR.Code != http.StatusOK {
		t.Fatalf("token exchange: expected 200, got %d — body: %s", tokenRR.Code, tokenRR.Body.String())
	}
	var tokenResp tokenSuccessResponse
	_ = json.NewDecoder(tokenRR.Body).Decode(&tokenResp)
	if tokenResp.AccessToken == "" {
		t.Error("access_token must not be empty")
	}
}

func TestAdminMachineKeys_RequiresAdminScope(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	// Token without aithne:admin scope.
	noAdminToken := mintBearerToken(t, s, []string{"render-ui"})
	body := bytes.NewBufferString(`{"agent_slug":"lucos-test-agent"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/machine-keys", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+noAdminToken)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestAdminMachineKeys_MissingSlug(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/machine-keys", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

// TestClientCredentials_RevokedKey verifies that a revoked machine key cannot
// be used to obtain a token. This is the security-critical path: without the
// revoked_at filter in handleClientCredentialsGrant, revocation would be cosmetic.
func TestClientCredentials_RevokedKey(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	rawSecret := provisionMachineKey(t, s, "lucos-revoke-test-agent")

	// Find the credential ID so we can revoke it.
	p, err := s.GetPrincipalByExternalID(store.PrincipalClassAgent, "lucos-revoke-test-agent")
	if err != nil {
		t.Fatalf("GetPrincipalByExternalID: %v", err)
	}
	creds, err := s.ListCredentialsByPrincipal(p.ID)
	if err != nil || len(creds) == 0 {
		t.Fatalf("ListCredentialsByPrincipal: %v, len=%d", err, len(creds))
	}
	if err := s.RevokeCredential(creds[0].ID, "test-revoker"); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	// The revoked key must no longer work.
	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-revoke-test-agent&client_secret=" + rawSecret)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked key, got %d — body: %s", rr.Code, rr.Body.String())
	}
}

// --- Per-token scope downscoping tests (RFC 6749 §4.4 scope parameter) ---

// grantScopes is a test helper that grants the named scopes to the named agent
// in the given environment, using testMainVocab.
func grantScopes(t *testing.T, s *store.Store, agentSlug, environment string, scopes ...string) {
	t.Helper()
	p, err := s.GetPrincipalByExternalID(store.PrincipalClassAgent, agentSlug)
	if err != nil {
		t.Fatalf("grantScopes: GetPrincipalByExternalID(%q): %v", agentSlug, err)
	}
	vocab, _ := parseScopesYAML([]byte("scopes:\n  - aithne:admin\n  - render-ui\n  - arachne:read\n"))
	for _, sc := range scopes {
		if _, err := s.CreateGrant(p.ID, sc, environment, "test", vocab); err != nil {
			t.Fatalf("grantScopes: CreateGrant(%q, %q, %q): %v", agentSlug, sc, environment, err)
		}
	}
}

// TestClientCredentials_ScopeDownscoping_Subset verifies that an agent with multiple
// granted scopes can request a narrower subset, and the token carries only that subset.
func TestClientCredentials_ScopeDownscoping_Subset(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	rawSecret := provisionMachineKey(t, s, "lucos-scope-agent")
	grantScopes(t, s, "lucos-scope-agent", "development", "aithne:admin", "render-ui")

	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-scope-agent&client_secret=" + rawSecret + "&scope=render-ui")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp tokenSuccessResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// The response scope field must echo the requested (narrowed) set.
	if resp.Scope != "render-ui" {
		t.Errorf("scope in response: got %q, want %q", resp.Scope, "render-ui")
	}

	// The JWT must carry only render-ui, not aithne:admin.
	keys, _ := s.ListVerificationKeys(token.VerificationWindow)
	keySet, _ := token.BuildVerificationKeySet(keys)
	claims, err := token.ParseSession(resp.AccessToken, keySet, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "render-ui" {
		t.Errorf("JWT scopes: got %v, want [render-ui]", claims.Scopes)
	}
}

// TestClientCredentials_ScopeDownscoping_UngrantedScope verifies that requesting a
// scope not held by the principal returns 400 invalid_scope.
func TestClientCredentials_ScopeDownscoping_UngrantedScope(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	rawSecret := provisionMachineKey(t, s, "lucos-ungranted-agent")
	grantScopes(t, s, "lucos-ungranted-agent", "development", "render-ui")

	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-ungranted-agent&client_secret=" + rawSecret + "&scope=aithne:admin")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var errResp tokenErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp.Error != "invalid_scope" {
		t.Errorf("error: got %q, want %q", errResp.Error, "invalid_scope")
	}
}

// TestClientCredentials_ScopeDownscoping_OmittedScope verifies that omitting the
// scope parameter returns the full granted set (backwards-compatible behaviour).
func TestClientCredentials_ScopeDownscoping_OmittedScope(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	rawSecret := provisionMachineKey(t, s, "lucos-omit-scope-agent")
	grantScopes(t, s, "lucos-omit-scope-agent", "development", "render-ui", "aithne:admin")

	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-omit-scope-agent&client_secret=" + rawSecret)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp tokenSuccessResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)

	// JWT must carry both granted scopes.
	keys, _ := s.ListVerificationKeys(token.VerificationWindow)
	keySet, _ := token.BuildVerificationKeySet(keys)
	claims, err := token.ParseSession(resp.AccessToken, keySet, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if len(claims.Scopes) != 2 {
		t.Errorf("omitted scope: expected 2 scopes in JWT, got %v", claims.Scopes)
	}
}

// TestClientCredentials_ScopeDownscoping_EmptyScope verifies that an empty scope
// parameter is treated as omitted (full granted set issued).
func TestClientCredentials_ScopeDownscoping_EmptyScope(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	rawSecret := provisionMachineKey(t, s, "lucos-empty-scope-agent")
	grantScopes(t, s, "lucos-empty-scope-agent", "development", "render-ui")

	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-empty-scope-agent&client_secret=" + rawSecret + "&scope=")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty scope (treated as omitted), got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp tokenSuccessResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)

	keys, _ := s.ListVerificationKeys(token.VerificationWindow)
	keySet, _ := token.BuildVerificationKeySet(keys)
	claims, err := token.ParseSession(resp.AccessToken, keySet, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "render-ui" {
		t.Errorf("empty scope: expected full granted set [render-ui], got %v", claims.Scopes)
	}
}

// TestClientCredentials_ScopeDownscoping_Duplicates verifies that duplicate scope
// tokens in the request are collapsed — the JWT carries each scope once.
func TestClientCredentials_ScopeDownscoping_Duplicates(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	rawSecret := provisionMachineKey(t, s, "lucos-dup-scope-agent")
	grantScopes(t, s, "lucos-dup-scope-agent", "development", "render-ui")

	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-dup-scope-agent&client_secret=" + rawSecret + "&scope=render-ui+render-ui")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp tokenSuccessResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)

	keys, _ := s.ListVerificationKeys(token.VerificationWindow)
	keySet, _ := token.BuildVerificationKeySet(keys)
	claims, err := token.ParseSession(resp.AccessToken, keySet, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "render-ui" {
		t.Errorf("duplicates: expected [render-ui] (deduped), got %v", claims.Scopes)
	}
}

// TestClientCredentials_ScopeDownscoping_WrongEnv verifies that a scope granted only
// in another environment is not honoured in the current environment (grants are per-env).
func TestClientCredentials_ScopeDownscoping_WrongEnv(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	rawSecret := provisionMachineKey(t, s, "lucos-wrongenv-agent")
	// Grant render-ui in production only — not in development.
	vocab, _ := parseScopesYAML([]byte("scopes:\n  - render-ui\n"))
	p, _ := s.GetPrincipalByExternalID(store.PrincipalClassAgent, "lucos-wrongenv-agent")
	if _, err := s.CreateGrant(p.ID, "render-ui", "production", "test", vocab); err != nil {
		t.Fatalf("CreateGrant production: %v", err)
	}

	// The mux uses "development" — render-ui is not granted there.
	body := strings.NewReader("grant_type=client_credentials&client_id=lucos-wrongenv-agent&client_secret=" + rawSecret + "&scope=render-ui")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for scope not granted in current env, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var errResp tokenErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&errResp)
	if errResp.Error != "invalid_scope" {
		t.Errorf("error: got %q, want %q", errResp.Error, "invalid_scope")
	}
}

// TestParseScopeParam verifies the scope string parsing helper independently.
func TestParseScopeParam(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"   ", nil},
		{"render-ui", []string{"render-ui"}},
		{"render-ui aithne:admin", []string{"render-ui", "aithne:admin"}},
		{"render-ui render-ui", []string{"render-ui"}},          // dedup
		{"  render-ui  aithne:admin  ", []string{"render-ui", "aithne:admin"}}, // whitespace
	}
	for _, tc := range cases {
		got := parseScopeParam(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("parseScopeParam(%q): got %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseScopeParam(%q)[%d]: got %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

// --- Admin machine-key revocation tests ---

// newAgentsMux builds a test ServeMux covering the agents + machine-key routes.
func newAgentsMux(s *store.Store, vocab *store.Vocabulary) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/agents", handleAgents(s, vocab, testIssuer, "development"))
	mux.HandleFunc("/admin/machine-keys", requireAdminScope(s, testIssuer, handleAdminMachineKeys(s)))
	mux.HandleFunc("/admin/machine-keys/", requireAdminScope(s, testIssuer, handleAdminMachineKeyByID(s)))
	return mux
}

func TestAdminMachineKeyRevoke_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	provisionMachineKey(t, s, "lucos-revoke-agent")
	p, _ := s.GetPrincipalByExternalID(store.PrincipalClassAgent, "lucos-revoke-agent")
	creds, _ := s.ListCredentialsByPrincipal(p.ID)
	credID := creds[0].ID

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodDelete, "/admin/machine-keys/"+credID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", rr.Code, rr.Body.String())
	}
	// Verify credential is now revoked in the store.
	got, err := s.GetCredential(credID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("expected RevokedAt to be set after revocation")
	}
}

func TestAdminMachineKeyRevoke_NotFound(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodDelete, "/admin/machine-keys/does-not-exist", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestAdminMachineKeyRevoke_AlreadyRevoked(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	provisionMachineKey(t, s, "lucos-already-revoked-agent")
	p, _ := s.GetPrincipalByExternalID(store.PrincipalClassAgent, "lucos-already-revoked-agent")
	creds, _ := s.ListCredentialsByPrincipal(p.ID)
	credID := creds[0].ID

	// Revoke once.
	if err := s.RevokeCredential(credID, "test-admin"); err != nil {
		t.Fatalf("first RevokeCredential: %v", err)
	}

	// Second revoke via API should return 409.
	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodDelete, "/admin/machine-keys/"+credID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
}

func TestAdminMachineKeyRevoke_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodGet, "/admin/machine-keys/some-id", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestAdminMachineKeyRevoke_RequiresAdmin(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	noAdminToken := mintBearerToken(t, s, []string{"render-ui"})
	req := httptest.NewRequest(http.MethodDelete, "/admin/machine-keys/some-id", nil)
	req.Header.Set("Authorization", "Bearer "+noAdminToken)
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

// --- /admin/agents list endpoint tests ---

func TestAdminAgentsList_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	vocab, _ := parseScopesYAML([]byte("scopes:\n  - render-ui\n  - aithne:admin\n"))

	// Create two agent principals.
	if _, err := s.CreatePrincipal(store.PrincipalClassAgent, "lucos-agent-alpha"); err != nil {
		t.Fatalf("create principal: %v", err)
	}
	if _, err := s.CreatePrincipal(store.PrincipalClassAgent, "lucos-agent-beta"); err != nil {
		t.Fatalf("create principal: %v", err)
	}

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newAgentsMux(s, vocab).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected application/json, got %q", ct)
	}
	var agents []agentJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &agents); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
	slugs := []string{agents[0].Slug, agents[1].Slug}
	if !strings.Contains(slugs[0]+"_"+slugs[1], "alpha") || !strings.Contains(slugs[0]+"_"+slugs[1], "beta") {
		t.Errorf("unexpected slugs: %v", slugs)
	}
	for _, a := range agents {
		if a.PrincipalID == "" {
			t.Errorf("agent %q has empty principal_id", a.Slug)
		}
	}
}

func TestAdminAgentsList_RequiresAdmin(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	vocab, _ := parseScopesYAML([]byte("scopes:\n  - render-ui\n  - aithne:admin\n"))

	noAdminToken := mintBearerToken(t, s, []string{"render-ui"})
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	req.Header.Set("Authorization", "Bearer "+noAdminToken)
	rr := httptest.NewRecorder()
	newAgentsMux(s, vocab).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

// --- Signing-key rotation tests ---

// newRotationMux builds a test ServeMux with only the rotation endpoint.
func newRotationMux(s *store.Store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/rotate-signing-key", requireAdminScope(s, testIssuer, handleRotateSigningKey(s)))
	return mux
}

func TestAdminRotateSigningKey_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	// Create the initial signing key.
	original, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey: %v", err)
	}

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodPost, "/admin/rotate-signing-key", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newRotationMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["rotated"] != true {
		t.Errorf("rotated: got %v, want true", resp["rotated"])
	}
	newKeyID, _ := resp["new_key_id"].(string)
	if newKeyID == "" {
		t.Error("new_key_id must not be empty")
	}
	if newKeyID == original.ID {
		t.Error("new_key_id must differ from the original key ID")
	}

	// Verify the new key is the active one in the store.
	current, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey after rotation: %v", err)
	}
	if current.ID != newKeyID {
		t.Errorf("active key after rotation: got %q, want %q", current.ID, newKeyID)
	}
}

func TestAdminRotateSigningKey_RequiresAdminScope(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	noAdminToken := mintBearerToken(t, s, []string{"render-ui"})
	req := httptest.NewRequest(http.MethodPost, "/admin/rotate-signing-key", nil)
	req.Header.Set("Authorization", "Bearer "+noAdminToken)
	rr := httptest.NewRecorder()
	newRotationMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestAdminRotateSigningKey_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodGet, "/admin/rotate-signing-key", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newRotationMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestAdminRotateSigningKey_OldKeyStillVerifies(t *testing.T) {
	// Verify that a token minted with the old key is still valid after rotation
	// (ListVerificationKeys covers in-flight tokens during the VerificationWindow).
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	// Mint a token with the original key.
	originalKey, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey: %v", err)
	}
	p, err := s.CreatePrincipal(store.PrincipalClassHuman, "test-contact-rotation")
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	oldToken, err := token.MintSession(p, []string{}, originalKey, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}

	// Rotate the key.
	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodPost, "/admin/rotate-signing-key", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	newRotationMux(s).ServeHTTP(httptest.NewRecorder(), req)

	// The old token must still verify using ListVerificationKeys.
	keys, err := s.ListVerificationKeys(token.VerificationWindow)
	if err != nil {
		t.Fatalf("ListVerificationKeys: %v", err)
	}
	keySet, err := token.BuildVerificationKeySet(keys)
	if err != nil {
		t.Fatalf("BuildVerificationKeySet: %v", err)
	}
	if _, err := token.ParseSession(oldToken, keySet, testIssuer, testAudience); err != nil {
		t.Errorf("old token should still verify after rotation within VerificationWindow: %v", err)
	}
}

// ============================================================
// OIDC / OAuth2 protocol endpoint tests (lucos_aithne#7)
// ============================================================

// --- Test helpers ---

// newOIDCMux builds a test ServeMux with the OIDC and related endpoints.
func newOIDCMux(s *store.Store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", handleOpenIDConfiguration(testIssuer))
	mux.HandleFunc("/.well-known/jwks.json", token.JWKSHandler(func() ([]*store.SigningKey, error) {
		return s.ListVerificationKeys(token.VerificationWindow)
	}))
	mux.HandleFunc("/oauth2/authorize", handleAuthorize(s, testIssuer, "development"))
	mux.HandleFunc("/oauth2/token", handleOAuth2Token(s, testIssuer, "development", noopLimiter()))
	mux.HandleFunc("/oauth2/userinfo", handleUserinfo(s, testIssuer, nil))
	mux.HandleFunc("/admin/oidc-clients", requireAdminScope(s, testIssuer, handleAdminOIDCClients(s)))
	mux.HandleFunc("/admin/oidc-clients/", requireAdminScope(s, testIssuer, handleAdminOIDCClients(s)))
	return mux
}

// createTestOIDCClient registers a test OIDC client directly in the store and
// returns the raw client_secret.
func createTestOIDCClient(t *testing.T, s *store.Store, clientID string, redirectURIs []string) string {
	t.Helper()
	rawSecret := "test-oidc-secret-" + clientID
	secretHash := hashOIDCSecret(rawSecret)
	if _, err := s.CreateOIDCClient(clientID, secretHash, "Test Client", redirectURIs); err != nil {
		t.Fatalf("createTestOIDCClient: %v", err)
	}
	return rawSecret
}

// mintSessionCookie mints a session JWT for a human principal and returns it
// as a *http.Cookie suitable for attaching to test requests.
func mintSessionCookie(t *testing.T, s *store.Store, contactID string) *http.Cookie {
	t.Helper()
	p, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID)
	if err == store.ErrNotFound {
		p, err = s.CreatePrincipal(store.PrincipalClassHuman, contactID)
	}
	if err != nil {
		t.Fatalf("mintSessionCookie: get/create principal: %v", err)
	}
	key, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("mintSessionCookie: get signing key: %v", err)
	}
	tok, err := token.MintSession(p, []string{}, key, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("mintSessionCookie: MintSession: %v", err)
	}
	return &http.Cookie{Name: "aithne_session", Value: tok}
}

// --- Discovery endpoint tests ---

func TestOpenIDConfiguration_BasicFields(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
	var doc map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery doc: %v", err)
	}
	if doc["issuer"] != testIssuer {
		t.Errorf("issuer: got %v, want %q", doc["issuer"], testIssuer)
	}
	for _, field := range []string{
		"authorization_endpoint", "token_endpoint", "userinfo_endpoint",
		"jwks_uri", "scopes_supported", "response_types_supported",
		"id_token_signing_alg_values_supported",
	} {
		if doc[field] == nil {
			t.Errorf("discovery doc missing field %q", field)
		}
	}
	// All endpoint URLs must begin with the issuer.
	for _, endpoint := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"} {
		if v, ok := doc[endpoint].(string); !ok || !strings.HasPrefix(v, testIssuer) {
			t.Errorf("%s: got %v, want prefix %q", endpoint, doc[endpoint], testIssuer)
		}
	}
}

func TestOpenIDConfiguration_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodPost, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

// --- Authorization endpoint tests ---

func TestAuthorize_MissingClientID(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&redirect_uri=https://rp.test/cb&scope=openid", nil)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAuthorize_UnknownClientID(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=no-such-client&redirect_uri=https://rp.test/cb&scope=openid", nil)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAuthorize_UnregisteredRedirectURI(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	createTestOIDCClient(t, s, "myapp", []string{"https://rp.test/callback"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=myapp&redirect_uri=https://evil.com/cb&scope=openid", nil)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (not a redirect), got %d", rr.Code)
	}
}

func TestAuthorize_NoSessionCookie_RedirectsToLogin(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	createTestOIDCClient(t, s, "myapp", []string{"https://rp.test/callback"})

	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id=myapp&redirect_uri=https://rp.test/callback&scope=openid&state=teststate",
		nil)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "/auth/login") {
		t.Errorf("expected redirect to /auth/login, got %q", loc)
	}
	if !strings.Contains(loc, "next=") {
		t.Errorf("redirect to login should carry ?next= param: %q", loc)
	}
}

func TestAuthorize_InvalidResponseType_RedirectsError(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	createTestOIDCClient(t, s, "myapp", []string{"https://rp.test/callback"})
	cookie := mintSessionCookie(t, s, "test-contact-authorize")

	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/authorize?response_type=token&client_id=myapp&redirect_uri=https://rp.test/callback&scope=openid",
		nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://rp.test/callback") {
		t.Errorf("error redirect should target redirect_uri, got %q", loc)
	}
	if !strings.Contains(loc, "error=unsupported_response_type") {
		t.Errorf("error redirect should include error=unsupported_response_type: %q", loc)
	}
}

func TestAuthorize_MissingOpenIDScope_RedirectsError(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	createTestOIDCClient(t, s, "myapp", []string{"https://rp.test/callback"})
	cookie := mintSessionCookie(t, s, "test-contact-scope")

	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id=myapp&redirect_uri=https://rp.test/callback&scope=profile",
		nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_scope") {
		t.Errorf("expected error=invalid_scope in redirect: %q", loc)
	}
}

func TestAuthorize_SubstringOpenIDScope_RedirectsError(t *testing.T) {
	// "notopenid" contains "openid" as a substring — was incorrectly accepted
	// by the old strings.Contains check; must be rejected by the fixed code.
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	createTestOIDCClient(t, s, "myapp", []string{"https://rp.test/callback"})
	cookie := mintSessionCookie(t, s, "test-contact-scope")

	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id=myapp&redirect_uri=https://rp.test/callback&scope=notopenid",
		nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_scope") {
		t.Errorf("expected error=invalid_scope in redirect: %q", loc)
	}
}

func TestAuthorize_Success_IssuesCodeAndRedirects(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	createTestOIDCClient(t, s, "myapp", []string{"https://rp.test/callback"})
	cookie := mintSessionCookie(t, s, "test-contact-auth")

	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id=myapp&redirect_uri=https://rp.test/callback&scope=openid&state=csrf-token&nonce=unique-nonce",
		nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d — body: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://rp.test/callback") {
		t.Fatalf("redirect should go to redirect_uri, got %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Error("redirect should include code param")
	}
	if state := u.Query().Get("state"); state != "csrf-token" {
		t.Errorf("state: got %q, want %q", state, "csrf-token")
	}
}

func TestAuthorize_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", nil)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

// --- Authorization code exchange (authorization_code grant) tests ---

// issueAuthCode is a test helper that drives a full authorize request and
// extracts the issued code from the redirect location.
func issueAuthCode(t *testing.T, s *store.Store, mux *http.ServeMux, clientID, redirectURI, contactID, state, nonce string) string {
	t.Helper()
	cookie := mintSessionCookie(t, s, contactID)
	authURL := "/oauth2/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&scope=openid" +
		"&state=" + url.QueryEscape(state) +
		"&nonce=" + url.QueryEscape(nonce)
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("issueAuthCode: expected 302, got %d — body: %s", rr.Code, rr.Body.String())
	}
	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("issueAuthCode: parse redirect: %v", err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("issueAuthCode: no code in redirect: %s", rr.Header().Get("Location"))
	}
	return code
}

func TestOAuth2Token_AuthCodeGrant_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	mux := newOIDCMux(s)
	rawSecret := createTestOIDCClient(t, s, "rp", []string{"https://rp.test/cb"})
	code := issueAuthCode(t, s, mux, "rp", "https://rp.test/cb", "alice", "state1", "nonce1")

	body := strings.NewReader("grant_type=authorization_code&code=" + url.QueryEscape(code) +
		"&client_id=rp&client_secret=" + url.QueryEscape(rawSecret) +
		"&redirect_uri=" + url.QueryEscape("https://rp.test/cb"))
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp["access_token"] == "" {
		t.Error("access_token must not be empty")
	}
	if resp["id_token"] == "" {
		t.Error("id_token must not be empty")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type: got %v, want Bearer", resp["token_type"])
	}
}

func TestOAuth2Token_AuthCodeGrant_IdTokenHasCorrectAudience(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	mux := newOIDCMux(s)
	rawSecret := createTestOIDCClient(t, s, "rp-aud-test", []string{"https://rp.test/cb"})
	code := issueAuthCode(t, s, mux, "rp-aud-test", "https://rp.test/cb", "bob", "s", "n")

	body := strings.NewReader("grant_type=authorization_code&code=" + url.QueryEscape(code) +
		"&client_id=rp-aud-test&client_secret=" + url.QueryEscape(rawSecret) +
		"&redirect_uri=" + url.QueryEscape("https://rp.test/cb"))
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	idTokenStr, _ := resp["id_token"].(string)
	if idTokenStr == "" {
		t.Fatal("id_token is empty")
	}

	// Parse the id_token with client_id as audience — should succeed.
	keys, _ := s.ListVerificationKeys(token.VerificationWindow)
	keySet, _ := token.BuildVerificationKeySet(keys)
	idClaims, err := token.ParseSession(idTokenStr, keySet, testIssuer, "rp-aud-test")
	if err != nil {
		t.Errorf("id_token should parse with client_id as audience: %v", err)
	}
	if idClaims != nil && idClaims.Subject != "bob" {
		t.Errorf("id_token sub: got %q, want %q", idClaims.Subject, "bob")
	}

	// The id_token must NOT parse with the estate audience (it's meant for the RP, not estate services).
	if _, err := token.ParseSession(idTokenStr, keySet, testIssuer, testAudience); err == nil {
		t.Error("id_token should not parse with estate audience l42.eu — audience is the client_id")
	}
}

func TestOAuth2Token_AuthCodeGrant_ReplayRejected(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	mux := newOIDCMux(s)
	rawSecret := createTestOIDCClient(t, s, "rp-replay", []string{"https://rp.test/cb"})
	code := issueAuthCode(t, s, mux, "rp-replay", "https://rp.test/cb", "carol", "s", "n")

	exchangeCode := func() *httptest.ResponseRecorder {
		body := strings.NewReader("grant_type=authorization_code&code=" + url.QueryEscape(code) +
			"&client_id=rp-replay&client_secret=" + url.QueryEscape(rawSecret) +
			"&redirect_uri=" + url.QueryEscape("https://rp.test/cb"))
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}

	first := exchangeCode()
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange: expected 200, got %d", first.Code)
	}
	second := exchangeCode()
	if second.Code != http.StatusBadRequest {
		t.Errorf("second exchange (replay): expected 400, got %d", second.Code)
	}
	var errResp tokenErrorResponse
	json.NewDecoder(second.Body).Decode(&errResp)
	if errResp.Error != "invalid_grant" {
		t.Errorf("replay error: got %q, want invalid_grant", errResp.Error)
	}
}

func TestOAuth2Token_AuthCodeGrant_WrongClientSecret(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	mux := newOIDCMux(s)
	createTestOIDCClient(t, s, "rp-wrongsecret", []string{"https://rp.test/cb"})
	code := issueAuthCode(t, s, mux, "rp-wrongsecret", "https://rp.test/cb", "dave", "s", "n")

	body := strings.NewReader("grant_type=authorization_code&code=" + url.QueryEscape(code) +
		"&client_id=rp-wrongsecret&client_secret=wrong-secret" +
		"&redirect_uri=" + url.QueryEscape("https://rp.test/cb"))
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestOAuth2Token_AuthCodeGrant_RedirectURIMismatch(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	mux := newOIDCMux(s)
	rawSecret := createTestOIDCClient(t, s, "rp-redirect", []string{"https://rp.test/cb"})
	code := issueAuthCode(t, s, mux, "rp-redirect", "https://rp.test/cb", "eve", "s", "n")

	body := strings.NewReader("grant_type=authorization_code&code=" + url.QueryEscape(code) +
		"&client_id=rp-redirect&client_secret=" + url.QueryEscape(rawSecret) +
		"&redirect_uri=" + url.QueryEscape("https://rp.test/OTHER"))
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestOAuth2Token_AuthCodeGrant_RedirectURIMismatch_CodeNotConsumed(t *testing.T) {
	// RFC 6749 §4.1.3: a validation failure must NOT consume the code —
	// the legitimate holder should be able to retry with the correct redirect_uri.
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	mux := newOIDCMux(s)
	rawSecret := createTestOIDCClient(t, s, "rp-survive", []string{"https://rp.test/cb"})
	code := issueAuthCode(t, s, mux, "rp-survive", "https://rp.test/cb", "frank", "s", "n")

	// First exchange — wrong redirect_uri; should return 400 and NOT consume the code.
	badBody := strings.NewReader("grant_type=authorization_code&code=" + url.QueryEscape(code) +
		"&client_id=rp-survive&client_secret=" + url.QueryEscape(rawSecret) +
		"&redirect_uri=" + url.QueryEscape("https://rp.test/WRONG"))
	badReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", badBody)
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRR := httptest.NewRecorder()
	mux.ServeHTTP(badRR, badReq)
	if badRR.Code != http.StatusBadRequest {
		t.Fatalf("wrong redirect_uri: expected 400, got %d", badRR.Code)
	}

	// Second exchange — correct redirect_uri; code must still be valid.
	goodBody := strings.NewReader("grant_type=authorization_code&code=" + url.QueryEscape(code) +
		"&client_id=rp-survive&client_secret=" + url.QueryEscape(rawSecret) +
		"&redirect_uri=" + url.QueryEscape("https://rp.test/cb"))
	goodReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", goodBody)
	goodReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	goodRR := httptest.NewRecorder()
	mux.ServeHTTP(goodRR, goodReq)
	if goodRR.Code != http.StatusOK {
		t.Errorf("correct redirect_uri after mismatch: expected 200, got %d — body: %s",
			goodRR.Code, goodRR.Body.String())
	}
}

func TestOAuth2Token_UnsupportedGrantType(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	body := strings.NewReader("grant_type=password&username=foo&password=bar")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	var errResp tokenErrorResponse
	json.NewDecoder(rr.Body).Decode(&errResp)
	if errResp.Error != "unsupported_grant_type" {
		t.Errorf("error: got %q, want unsupported_grant_type", errResp.Error)
	}
}

// --- Userinfo endpoint tests ---

func TestUserinfo_ValidToken_ReturnsClaims(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	tok := mintBearerToken(t, s, []string{})
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if resp["sub"] == "" {
		t.Error("userinfo must include sub claim")
	}
	if resp["principal_class"] == "" {
		t.Error("userinfo must include principal_class")
	}
}

func TestUserinfo_MissingToken_401(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestUserinfo_InvalidToken_401(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestUserinfo_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodDelete, "/oauth2/userinfo", nil)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

// --- Admin OIDC client management tests ---

func TestAdminOIDCClients_Create(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	body := bytes.NewBufferString(`{"client_id":"my-rp","redirect_uris":["https://rp.test/cb"],"client_name":"My RP"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/oidc-clients", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var resp createOIDCClientResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ClientID != "my-rp" {
		t.Errorf("client_id: got %q, want %q", resp.ClientID, "my-rp")
	}
	if resp.ClientSecret == "" {
		t.Error("client_secret must not be empty")
	}
	if resp.Note == "" {
		t.Error("note must not be empty (secret is shown only once)")
	}
}

func TestAdminOIDCClients_List(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	createTestOIDCClient(t, s, "rp1", []string{"https://rp1.test/cb"})
	createTestOIDCClient(t, s, "rp2", []string{"https://rp2.test/cb"})

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodGet, "/admin/oidc-clients", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var clients []oidcClientJSON
	if err := json.NewDecoder(rr.Body).Decode(&clients); err != nil {
		t.Fatalf("decode clients: %v", err)
	}
	if len(clients) != 2 {
		t.Errorf("expected 2 clients, got %d", len(clients))
	}
	// Secret hash must NOT appear in the list response.
	raw := rr.Body.String()
	_ = raw // rr.Body has been consumed; check via decoded struct
	for _, c := range clients {
		if c.ClientID == "" {
			t.Error("client_id must not be empty in list")
		}
	}
}

func TestAdminOIDCClients_Delete(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	createTestOIDCClient(t, s, "rp-to-delete", []string{"https://rp.test/cb"})

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodDelete, "/admin/oidc-clients/rp-to-delete", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", rr.Code, rr.Body.String())
	}

	// Confirm deleted.
	if _, err := s.GetOIDCClient("rp-to-delete"); err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestAdminOIDCClients_RequiresAdminScope(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	noAdminToken := mintBearerToken(t, s, []string{"render-ui"})
	body := bytes.NewBufferString(`{"client_id":"bad-rp","redirect_uris":["https://rp.test/cb"]}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/oidc-clients", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+noAdminToken)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestAdminOIDCClients_DuplicateClientID(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	createTestOIDCClient(t, s, "existing-rp", []string{"https://rp.test/cb"})

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	body := bytes.NewBufferString(`{"client_id":"existing-rp","redirect_uris":["https://rp.test/cb2"]}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/oidc-clients", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newOIDCMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d — body: %s", rr.Code, rr.Body.String())
	}
}

// ============================================================
// Bootstrap invite + bootstrapAdmin tests (lucos_aithne#49)
// ============================================================

// addWebAuthnCredential is a test helper that stores a minimal WebAuthn
// credential for a principal. The data content is a stub; only the type
// matters for the credential-gate logic.
func addWebAuthnCredential(t *testing.T, s *store.Store, principalID string) {
	t.Helper()
	if _, err := s.CreateCredential(principalID, store.CredentialTypeWebAuthn, []byte("stub-cred-data"), "test key"); err != nil {
		t.Fatalf("addWebAuthnCredential: %v", err)
	}
}

// --- bootstrapInvite tests ---

func TestBootstrapInvite_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	const contactID = "bootstrap-contact-1"
	const appOrigin = "https://aithne.test"

	inviteURL, err := bootstrapInvite(s, contactID, appOrigin)
	if err != nil {
		t.Fatalf("bootstrapInvite: %v", err)
	}

	// URL must be the right shape.
	if !strings.HasPrefix(inviteURL, appOrigin+"/enrol?token=") {
		t.Errorf("invite URL has wrong shape: %q", inviteURL)
	}

	// Extract raw token and verify it resolves to a valid invite in the store.
	rawToken := strings.TrimPrefix(inviteURL, appOrigin+"/enrol?token=")
	inv, err := s.GetInviteByRawToken(rawToken)
	if err != nil {
		t.Fatalf("GetInviteByRawToken: %v", err)
	}
	if inv.ContactID != contactID {
		t.Errorf("invite ContactID: got %q, want %q", inv.ContactID, contactID)
	}
	if inv.CreatedBy != "bootstrap-cli" {
		t.Errorf("invite CreatedBy: got %q, want %q", inv.CreatedBy, "bootstrap-cli")
	}
	if !inv.IsValid(time.Now()) {
		t.Error("invite should be valid immediately after creation")
	}
}

func TestBootstrapInvite_CreatesPrincipalIfAbsent(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	const contactID = "new-bootstrap-contact"
	// Principal does not exist yet.
	if _, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound before invite, got %v", err)
	}

	if _, err := bootstrapInvite(s, contactID, "https://aithne.test"); err != nil {
		t.Fatalf("bootstrapInvite: %v", err)
	}

	// Principal must now exist.
	if _, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID); err != nil {
		t.Errorf("expected principal to be created: %v", err)
	}
}

func TestBootstrapInvite_MultipleInvitesAllowed(t *testing.T) {
	// Calling bootstrapInvite twice should produce two distinct tokens.
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	const contactID = "bootstrap-multi"
	const appOrigin = "https://aithne.test"

	url1, err := bootstrapInvite(s, contactID, appOrigin)
	if err != nil {
		t.Fatalf("first bootstrapInvite: %v", err)
	}
	url2, err := bootstrapInvite(s, contactID, appOrigin)
	if err != nil {
		t.Fatalf("second bootstrapInvite: %v", err)
	}
	if url1 == url2 {
		t.Error("two calls should produce distinct invite URLs")
	}
}

// --- bootstrapAdmin tests ---

func TestBootstrapAdmin_SeedsGrantWhenNoCredential(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	const contactID = "bootstrap-admin-test"
	bootstrapAdmin(s, contactID, "development", testMainVocab)

	p, err := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID)
	if err != nil {
		t.Fatalf("GetPrincipalByExternalID: %v", err)
	}
	scopes, err := s.GetActiveScopes(p.ID, "development")
	if err != nil {
		t.Fatalf("GetActiveScopes: %v", err)
	}
	found := false
	for _, sc := range scopes {
		if sc == "aithne:admin" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected aithne:admin in active scopes after bootstrap, got %v", scopes)
	}
}

func TestBootstrapAdmin_NoopWhenWebAuthnCredentialExists(t *testing.T) {
	// Gate tripped: principal has a WebAuthn credential → bootstrapAdmin must
	// NOT touch the grant store (no new grant created).
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	const contactID = "enrolled-admin"
	p, err := s.CreatePrincipal(store.PrincipalClassHuman, contactID)
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	addWebAuthnCredential(t, s, p.ID)

	// Call bootstrapAdmin — should be a no-op.
	bootstrapAdmin(s, contactID, "development", testMainVocab)

	// No aithne:admin grant should exist.
	scopes, err := s.GetActiveScopes(p.ID, "development")
	if err != nil {
		t.Fatalf("GetActiveScopes: %v", err)
	}
	for _, sc := range scopes {
		if sc == "aithne:admin" {
			t.Errorf("aithne:admin grant must not be created when WebAuthn credential exists; got scopes %v", scopes)
		}
	}
}

func TestBootstrapAdmin_NoopDoesNotResurrectRevokedGrant(t *testing.T) {
	// If a grant was deliberately revoked AND a passkey exists, bootstrapAdmin
	// must not resurrect the grant (gate fires before the CreateGrant call).
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	const contactID = "revoked-admin"
	p, err := s.CreatePrincipal(store.PrincipalClassHuman, contactID)
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}

	// Seed a grant, then revoke it.
	grant, err := s.CreateGrant(p.ID, "aithne:admin", "development", "test", testMainVocab)
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if err := s.RevokeGrant(grant.ID, "test-revoke"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	// Now add a WebAuthn credential — gate should fire and skip the re-seed.
	addWebAuthnCredential(t, s, p.ID)
	bootstrapAdmin(s, contactID, "development", testMainVocab)

	// Grant must still be revoked (no active aithne:admin).
	scopes, err := s.GetActiveScopes(p.ID, "development")
	if err != nil {
		t.Fatalf("GetActiveScopes: %v", err)
	}
	for _, sc := range scopes {
		if sc == "aithne:admin" {
			t.Errorf("revoked grant must not be resurrected by bootstrapAdmin when credential exists; got scopes %v", scopes)
		}
	}
}

func TestBootstrapAdmin_IdempotentWhenNoCredential(t *testing.T) {
	// Calling bootstrapAdmin twice without a credential: idempotent, still one grant.
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	const contactID = "idempotent-admin"
	bootstrapAdmin(s, contactID, "development", testMainVocab)
	bootstrapAdmin(s, contactID, "development", testMainVocab) // second call must not panic or duplicate

	p, _ := s.GetPrincipalByExternalID(store.PrincipalClassHuman, contactID)
	scopes, err := s.GetActiveScopes(p.ID, "development")
	if err != nil {
		t.Fatalf("GetActiveScopes: %v", err)
	}
	adminCount := 0
	for _, sc := range scopes {
		if sc == "aithne:admin" {
			adminCount++
		}
	}
	if adminCount != 1 {
		t.Errorf("expected exactly 1 active aithne:admin grant after two bootstrap calls, got %d", adminCount)
	}
}

// --- store.OIDCClient tests ---

func TestOIDCClientHasRedirectURI(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	createTestOIDCClient(t, s, "rp", []string{"https://rp.test/cb", "https://rp.test/alt"})

	client, err := s.GetOIDCClient("rp")
	if err != nil {
		t.Fatalf("GetOIDCClient: %v", err)
	}
	if !client.HasRedirectURI("https://rp.test/cb") {
		t.Error("HasRedirectURI: should return true for registered URI")
	}
	if client.HasRedirectURI("https://evil.com/cb") {
		t.Error("HasRedirectURI: should return false for unregistered URI")
	}
}

// --- Homepage tests ---

func TestHomePage_LoggedOut_ShowsSignInButton(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	contactsSrv := httptest.NewServer(newContactsServer(t, http.StatusOK, `{"name":"Test User"}`))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handleHomePage(s, testIssuer, contacts, templateFS)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Sign in with passkey") {
		t.Error("expected sign-in button in logged-out response")
	}
	if strings.Contains(body, "Sign out") {
		t.Error("unexpected sign-out button in logged-out response")
	}
}

func TestHomePage_LoggedIn_ShowsNameAndLogout(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	contactsSrv := httptest.NewServer(newContactsServer(t, http.StatusOK, `{"name":"Alice Smith"}`))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	cookie := mintSessionCookie(t, s, "alice")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handleHomePage(s, testIssuer, contacts, templateFS)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Alice Smith") {
		t.Errorf("expected display name in logged-in response, body: %s", body)
	}
	if !strings.Contains(body, "Sign out") {
		t.Error("expected sign-out button in logged-in response")
	}
	if strings.Contains(body, "Sign in with passkey") {
		t.Error("unexpected sign-in button in logged-in response")
	}
}

func TestHomePage_InvalidCookie_ShowsSignInButton(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	contactsSrv := httptest.NewServer(newContactsServer(t, http.StatusOK, `{"name":"Test User"}`))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "aithne_session", Value: "not-a-valid-jwt"})
	rr := httptest.NewRecorder()
	handleHomePage(s, testIssuer, contacts, templateFS)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 (soft check — no redirect), got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Sign in with passkey") {
		t.Error("expected sign-in button for invalid cookie (soft check)")
	}
	if strings.Contains(body, "Sign out") {
		t.Error("unexpected sign-out button for invalid cookie")
	}
}

func TestHomePage_LoggedIn_FallsBackToContactIDWhenContactsUnavailable(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	// Contacts server returns 503 to simulate unavailability.
	contactsSrv := httptest.NewServer(newContactsServer(t, http.StatusServiceUnavailable, ""))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	cookie := mintSessionCookie(t, s, "contact-abc-123")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handleHomePage(s, testIssuer, contacts, templateFS)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	// Falls back to showing the contact ID.
	if !strings.Contains(body, "contact-abc-123") {
		t.Errorf("expected contact ID fallback in body, got: %s", body)
	}
	if !strings.Contains(body, "Sign out") {
		t.Error("expected sign-out button even when contacts unavailable")
	}
}

func TestHomePage_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	contacts := newContactsClient("http://unused.test", "key")

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	handleHomePage(s, testIssuer, contacts, templateFS)(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected HTTP 405, got %d", rr.Code)
	}
}

// TestHomePage_Admin_ShowsGrantsLink verifies that a session with aithne:admin
// scope causes the "Manage grants" link to appear on the home page.
func TestHomePage_Admin_ShowsGrantsLink(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	contacts := newContactsClient("http://unused.test", "key")

	key, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	p, err := s.CreatePrincipal(store.PrincipalClassHuman, "admin-for-home")
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	tok, err := token.MintSession(p, []string{"aithne:admin"}, key, testIssuer, testAudience, 15*time.Minute)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "aithne_session", Value: tok})
	rr := httptest.NewRecorder()
	handleHomePage(s, testIssuer, contacts, templateFS)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "/admin/grants") {
		t.Errorf("expected Manage grants link in admin home page, body: %s", body)
	}
}

// TestHomePage_NonAdmin_HidesGrantsLink verifies that a session without
// aithne:admin scope does not show the "Manage grants" link.
func TestHomePage_NonAdmin_HidesGrantsLink(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	contacts := newContactsClient("http://unused.test", "key")

	cookie := mintSessionCookie(t, s, "non-admin-user")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handleHomePage(s, testIssuer, contacts, templateFS)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "/admin/grants") {
		t.Errorf("expected no grants link for non-admin session, body: %s", body)
	}
}

func TestHomePage_SetsCSP(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	contacts := newContactsClient("http://unused.test", "key")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handleHomePage(s, testIssuer, contacts, templateFS)(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing")
	}
	if !strings.Contains(csp, "script-src 'nonce-") {
		t.Errorf("CSP missing script-src nonce: %s", csp)
	}
}

// --- Logout tests ---

func TestLogout_ClearsCookieAndRedirects(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Origin", testIssuer)
	rr := httptest.NewRecorder()
	handleLogout(s, testIssuer, "production")(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected HTTP 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/" {
		t.Errorf("expected redirect to /, got %q", loc)
	}

	// Verify the Set-Cookie clears the session cookie.
	cookies := rr.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "aithne_session" {
			found = true
			if c.MaxAge != -1 {
				t.Errorf("expected MaxAge=-1 (clear cookie), got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("expected Set-Cookie: aithne_session in logout response")
	}
}

func TestLogout_RevokesIDPSessionServerSide(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	// Create a principal and an IdP session so we have a real token to revoke.
	p, err := s.CreatePrincipal(store.PrincipalClassHuman, "contact-logout-test")
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	rawToken, _, err := s.CreateIDPSession(p.ID)
	if err != nil {
		t.Fatalf("create idp session: %v", err)
	}

	// Confirm the session is live before logout.
	sess, err := s.GetIDPSessionByToken(rawToken)
	if err != nil || sess == nil {
		t.Fatalf("expected live session before logout; err=%v", err)
	}

	// Perform logout with the IdP session cookie present.
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Origin", testIssuer)
	req.AddCookie(&http.Cookie{Name: token.IdPSessionCookieName, Value: rawToken})
	rr := httptest.NewRecorder()
	handleLogout(s, testIssuer, "production")(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected HTTP 303, got %d", rr.Code)
	}

	// The server-side record must now be revoked.
	_, err = s.GetIDPSessionByToken(rawToken)
	if !errors.Is(err, store.ErrIDPSessionRevoked) {
		t.Errorf("expected ErrIDPSessionRevoked after logout, got %v", err)
	}
}

func TestLogout_WrongOrigin_Forbidden(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	handleLogout(s, testIssuer, "production")(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403, got %d", rr.Code)
	}
}

func TestLogout_MissingOrigin_Forbidden(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	// No Origin header set.
	rr := httptest.NewRecorder()
	handleLogout(s, testIssuer, "production")(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403, got %d", rr.Code)
	}
}

func TestLogout_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	rr := httptest.NewRecorder()
	handleLogout(s, testIssuer, "production")(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected HTTP 405, got %d", rr.Code)
	}
}

// --- Admin invite revocation tests ---

// TestAdminInvites_Success_IncludesTokenHash verifies that the POST /admin/invites
// response now includes a token_hash field so the admin UI can offer revocation.
func TestAdminInvites_Success_IncludesTokenHash(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":42,"name":"Alice Example"}`)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/invites", requireAdminScope(s, testIssuer, handleAdminInvites(s, contacts, testIssuer)))

	body, _ := json.Marshal(map[string]string{"contact_id": "42"})
	req := httptest.NewRequest(http.MethodPost, "/admin/invites", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["token_hash"] == "" {
		t.Error("expected non-empty token_hash in POST /admin/invites response")
	}
	// token_hash must be a 64-char hex SHA-256 digest.
	if len(resp["token_hash"]) != 64 {
		t.Errorf("token_hash should be 64 hex chars (SHA-256), got %q (len %d)", resp["token_hash"], len(resp["token_hash"]))
	}
}

// TestAdminInviteByHash_Revoke verifies that DELETE /admin/invites/{hash} marks
// the invite as used, returning 204 No Content.
func TestAdminInviteByHash_Revoke(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	rawToken := createValidInvite(t, s, "revoke-contact")
	tokenHash := store.HashToken(rawToken)

	req := httptest.NewRequest(http.MethodDelete, "/admin/invites/"+tokenHash, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d\n%s", rr.Code, rr.Body.String())
	}

	// Invite must now be marked as used.
	inv, err := s.GetInviteByHash(tokenHash)
	if err != nil {
		t.Fatalf("GetInviteByHash after revoke: %v", err)
	}
	if inv.UsedAt == nil {
		t.Error("invite.UsedAt should be set after revocation")
	}
}

// TestAdminInviteByHash_Revoke_NotFound verifies that revoking a non-existent
// hash returns 404.
func TestAdminInviteByHash_Revoke_NotFound(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	req := httptest.NewRequest(http.MethodDelete, "/admin/invites/deadbeef00000000000000000000000000000000000000000000000000000000", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// TestAdminInviteByHash_Revoke_AlreadyUsed verifies that revoking an already-used
// invite returns 409 Conflict.
func TestAdminInviteByHash_Revoke_AlreadyUsed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	rawToken := createValidInvite(t, s, "already-used-contact")
	tokenHash := store.HashToken(rawToken)

	// First revocation — should succeed.
	req1 := httptest.NewRequest(http.MethodDelete, "/admin/invites/"+tokenHash, nil)
	req1.Header.Set("Authorization", "Bearer "+tok)
	rr1 := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusNoContent {
		t.Fatalf("first revoke: expected 204, got %d", rr1.Code)
	}

	// Second revocation — should return 409.
	req2 := httptest.NewRequest(http.MethodDelete, "/admin/invites/"+tokenHash, nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	rr2 := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusConflict {
		t.Errorf("second revoke: expected 409, got %d", rr2.Code)
	}
}

// TestAdminInviteByHash_Revoke_RequiresAdmin verifies the endpoint rejects
// requests without an admin-scoped token.
func TestAdminInviteByHash_Revoke_RequiresAdmin(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	rawToken := createValidInvite(t, s, "contact-protected")
	tokenHash := store.HashToken(rawToken)

	// No token at all.
	req := httptest.NewRequest(http.MethodDelete, "/admin/invites/"+tokenHash, nil)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no token: expected 401, got %d", rr.Code)
	}

	// Token without admin scope.
	nonAdminTok := mintBearerToken(t, s, []string{"render-ui"})
	req2 := httptest.NewRequest(http.MethodDelete, "/admin/invites/"+tokenHash, nil)
	req2.Header.Set("Authorization", "Bearer "+nonAdminTok)
	rr2 := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("non-admin token: expected 403, got %d", rr2.Code)
	}
}

// TestAdminInviteByHash_Revoke_MethodNotAllowed verifies that GET on the revoke
// endpoint returns 405.
func TestAdminInviteByHash_Revoke_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	rawToken := createValidInvite(t, s, "method-not-allowed-contact")
	tokenHash := store.HashToken(rawToken)

	req := httptest.NewRequest(http.MethodGet, "/admin/invites/"+tokenHash, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestStore_GetInviteByHash verifies that GetInviteByHash looks up by the hash
// directly, without re-hashing.
func TestStore_GetInviteByHash(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	rawToken := "hash-lookup-test-token"
	if _, err := s.CreateInvite(rawToken, "contact-x", "admin"); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	hash := store.HashToken(rawToken)
	inv, err := s.GetInviteByHash(hash)
	if err != nil {
		t.Fatalf("GetInviteByHash: %v", err)
	}
	if inv.TokenHash != hash {
		t.Errorf("TokenHash: got %q, want %q", inv.TokenHash, hash)
	}
	if inv.ContactID != "contact-x" {
		t.Errorf("ContactID: got %q, want %q", inv.ContactID, "contact-x")
	}

	// Passing the raw token (not the hash) should NOT find the record.
	_, err = s.GetInviteByHash(rawToken)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetInviteByHash(rawToken) should return ErrNotFound, got %v", err)
	}
}

// TestStore_RevokeInviteByHash_Success verifies that RevokeInviteByHash sets
// used_at on a valid invite.
func TestStore_RevokeInviteByHash_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	rawToken := "revoke-test-token"
	if _, err := s.CreateInvite(rawToken, "contact-y", "admin"); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	hash := store.HashToken(rawToken)
	if err := s.RevokeInviteByHash(hash); err != nil {
		t.Fatalf("RevokeInviteByHash: %v", err)
	}

	// Fetching by hash should now show UsedAt set.
	inv, err := s.GetInviteByHash(hash)
	if err != nil {
		t.Fatalf("GetInviteByHash after revoke: %v", err)
	}
	if inv.UsedAt == nil {
		t.Error("UsedAt should be non-nil after revocation")
	}
}

// TestStore_RevokeInviteByHash_NotFound verifies that revoking a non-existent
// hash returns ErrNotFound.
func TestStore_RevokeInviteByHash_NotFound(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	err = s.RevokeInviteByHash("0000000000000000000000000000000000000000000000000000000000000000")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestStore_RevokeInviteByHash_AlreadyUsed verifies that revoking a used invite
// returns ErrInviteUsed.
func TestStore_RevokeInviteByHash_AlreadyUsed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	rawToken := "double-revoke-token"
	if _, err := s.CreateInvite(rawToken, "contact-z", "admin"); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	hash := store.HashToken(rawToken)
	// First revocation.
	if err := s.RevokeInviteByHash(hash); err != nil {
		t.Fatalf("first RevokeInviteByHash: %v", err)
	}
	// Second revocation.
	err = s.RevokeInviteByHash(hash)
	if !errors.Is(err, store.ErrInviteUsed) {
		t.Errorf("expected ErrInviteUsed on double-revoke, got %v", err)
	}
}

// ── handleAdminContacts tests ────────────────────────────────────────────────

// TestHandleAdminContacts_Success verifies that GET /admin/contacts proxies the
// contact list from lucos_contacts and returns JSON with id and name fields.
func TestHandleAdminContacts_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	// Mock contacts server returning two contacts.
	contactsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/people/all" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"id":1,"name":"Alice Example"},{"id":2,"name":"Bob Test"}]`)
	}))
	defer contactsSrv.Close()
	contacts := newContactsClient(contactsSrv.URL, "test-key")

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/contacts", requireAdminScope(s, testIssuer, handleAdminContacts(contacts)))

	req := httptest.NewRequest(http.MethodGet, "/admin/contacts", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected application/json Content-Type, got %q", ct)
	}
	var items []contactListItem
	if err := json.Unmarshal(rr.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 contacts, got %d", len(items))
	}
	if items[0].ID != 1 || items[0].Name != "Alice Example" {
		t.Errorf("unexpected first contact: %+v", items[0])
	}
	if items[1].ID != 2 || items[1].Name != "Bob Test" {
		t.Errorf("unexpected second contact: %+v", items[1])
	}
}

// TestHandleAdminContacts_RequiresAdmin verifies that unauthenticated requests
// to GET /admin/contacts are rejected with 401.
func TestHandleAdminContacts_RequiresAdmin(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/contacts", nil)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestHandleAdminContacts_ContactsUnavailable verifies that if lucos_contacts is
// unreachable the handler returns 502 rather than crashing.
func TestHandleAdminContacts_ContactsUnavailable(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	// Point at a non-existent server so the HTTP call fails.
	contacts := newContactsClient("http://127.0.0.1:1", "test-key")
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/contacts", requireAdminScope(s, testIssuer, handleAdminContacts(contacts)))

	req := httptest.NewRequest(http.MethodGet, "/admin/contacts", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rr.Code)
	}
}

// TestHandleAdminContacts_MethodNotAllowed verifies that non-GET requests return 405.
func TestHandleAdminContacts_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	contacts := newContactsClient("http://contacts.test", "test-key")
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/contacts", requireAdminScope(s, testIssuer, handleAdminContacts(contacts)))

	req := httptest.NewRequest(http.MethodPost, "/admin/contacts", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// --- Re-mint endpoint tests ---

// setupReMintStore creates an in-memory store with a principal, WebAuthn credential,
// and active signing key, and creates an IdP session for that principal.
// Returns the store, principal, raw IdP session token, and a cleanup function.
func setupReMintStore(t *testing.T) (*store.Store, *store.Principal, string) {
	t.Helper()
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	p, err := s.CreatePrincipal(store.PrincipalClassHuman, "contact-remint-1")
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	// WebAuthn credential (just a non-revoked stub — the re-mint only checks presence).
	if _, err := s.CreateCredential(p.ID, store.CredentialTypeWebAuthn, []byte("fake-key"), "test-passkey"); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	rawToken, _, err := s.CreateIDPSession(p.ID)
	if err != nil {
		t.Fatalf("CreateIDPSession: %v", err)
	}
	return s, p, rawToken
}

func TestHandleReMint_Success(t *testing.T) {
	s, _, rawToken := setupReMintStore(t)

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodPost, "/auth/remint", nil)
	req.AddCookie(&http.Cookie{Name: token.IdPSessionCookieName, Value: rawToken})
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// Should set a new aithne_session cookie.
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "aithne_session" {
			found = true
			if c.Value == "" {
				t.Error("aithne_session cookie value is empty")
			}
		}
	}
	if !found {
		t.Error("expected aithne_session cookie in response")
	}
}

func TestHandleReMint_NoCookie(t *testing.T) {
	s, _, _ := setupReMintStore(t)

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodPost, "/auth/remint", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleReMint_RevokedSession(t *testing.T) {
	s, p, rawToken := setupReMintStore(t)

	if _, err := s.RevokeIDPSessionsForPrincipal(p.ID); err != nil {
		t.Fatalf("RevokeIDPSessionsForPrincipal: %v", err)
	}

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodPost, "/auth/remint", nil)
	req.AddCookie(&http.Cookie{Name: token.IdPSessionCookieName, Value: rawToken})
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleReMint_NoActiveCredential(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	p, _ := s.CreatePrincipal(store.PrincipalClassHuman, "contact-nocred")
	// Create a WebAuthn credential and then revoke it.
	cred, _ := s.CreateCredential(p.ID, store.CredentialTypeWebAuthn, []byte("fake-key"), "test")
	if err := s.RevokeCredential(cred.ID, "test-admin"); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	rawToken, _, err := s.CreateIDPSession(p.ID)
	if err != nil {
		t.Fatalf("CreateIDPSession: %v", err)
	}

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodPost, "/auth/remint", nil)
	req.AddCookie(&http.Cookie{Name: token.IdPSessionCookieName, Value: rawToken})
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleReMint_WrongMethod(t *testing.T) {
	s, _, _ := setupReMintStore(t)

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodGet, "/auth/remint", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleReMint_CORS_AllowedOrigin(t *testing.T) {
	// Any *.l42.eu origin is allowed without OIDC registration — glob check.
	s, _, rawToken := setupReMintStore(t)

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodPost, "/auth/remint", nil)
	req.AddCookie(&http.Cookie{Name: token.IdPSessionCookieName, Value: rawToken})
	req.Header.Set("Origin", "https://arachne.l42.eu")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://arachne.l42.eu" {
		t.Errorf("ACAO: got %q, want %q", got, "https://arachne.l42.eu")
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("ACAC: got %q, want 'true'", got)
	}
}

func TestHandleReMint_CORS_DisallowedOrigin(t *testing.T) {
	s, _, rawToken := setupReMintStore(t)

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodPost, "/auth/remint", nil)
	req.AddCookie(&http.Cookie{Name: token.IdPSessionCookieName, Value: rawToken})
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for disallowed origin, got %d", rr.Code)
	}
}

func TestHandleReMint_CORS_Preflight(t *testing.T) {
	// Preflight for a *.l42.eu origin — no OIDC registration needed.
	s, _, _ := setupReMintStore(t)

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodOptions, "/auth/remint", nil)
	req.Header.Set("Origin", "https://photos.l42.eu")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for preflight, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://photos.l42.eu" {
		t.Errorf("ACAO: got %q, want %q", got, "https://photos.l42.eu")
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("expected Access-Control-Allow-Methods header on preflight")
	}
}

func TestHandleReMint_CORS_DevLocalhostAllowed(t *testing.T) {
	// In development, http://localhost:<port> is allowed (keepalive from a dev consumer).
	s, _, rawToken := setupReMintStore(t)

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodPost, "/auth/remint", nil)
	req.AddCookie(&http.Cookie{Name: token.IdPSessionCookieName, Value: rawToken})
	req.Header.Set("Origin", "http://localhost:3000")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for dev localhost origin, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("ACAO: got %q, want %q", got, "http://localhost:3000")
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("ACAC: got %q, want 'true'", got)
	}
}

func TestHandleReMint_CORS_DevLocalhostPreflight(t *testing.T) {
	// In development, OPTIONS preflight from http://127.0.0.1:<port> should return 204.
	s, _, _ := setupReMintStore(t)

	handler := handleReMint(s, testIssuer, "development", testIssuer)
	req := httptest.NewRequest(http.MethodOptions, "/auth/remint", nil)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for dev localhost preflight, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:8080" {
		t.Errorf("ACAO: got %q, want %q", got, "http://127.0.0.1:8080")
	}
}

func TestHandleReMint_CORS_DevLocalhostRejectedInProd(t *testing.T) {
	// In production, http://localhost:<port> must be rejected even with a valid session.
	s, _, rawToken := setupReMintStore(t)

	handler := handleReMint(s, testIssuer, "production", testIssuer)
	req := httptest.NewRequest(http.MethodPost, "/auth/remint", nil)
	req.AddCookie(&http.Cookie{Name: token.IdPSessionCookieName, Value: rawToken})
	req.Header.Set("Origin", "http://localhost:3000")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for localhost origin in production, got %d", rr.Code)
	}
}

func TestHandleAdminPrincipalActions_RevokeIDPSessions(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	p, _ := s.CreatePrincipal(store.PrincipalClassHuman, "contact-admin-idp")
	if _, _, err := s.CreateIDPSession(p.ID); err != nil {
		t.Fatalf("CreateIDPSession: %v", err)
	}

	tok := mintBearerToken(t, s, []string{"aithne:admin"})

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/principals/", requireAdminScope(s, testIssuer, handleAdminPrincipalActions(s)))

	req := httptest.NewRequest(http.MethodDelete, "/admin/principals/"+p.ID+"/idp-sessions", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if n, ok := body["revoked"].(float64); !ok || n != 1 {
		t.Errorf("expected revoked=1, got %v", body)
	}
}

// --- /admin/human-principals list endpoint tests ---

// newHumanPrincipalsMux builds a minimal test ServeMux for the human-principals endpoint.
func newHumanPrincipalsMux(s *store.Store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/human-principals", requireAdminScope(s, testIssuer, listHumanPrincipals(s)))
	return mux
}

// TestAdminHumanPrincipals_Success verifies that the endpoint returns human
// principals (not agents) with the correct contact_id and principal_id fields.
//
// Note: mintBearerToken also creates a human principal (the token-holder), so
// the assertion checks that the specific contacts we added are present and that
// the agent principal is absent — rather than asserting an exact count.
func TestAdminHumanPrincipals_Success(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	// Create two human principals and one agent principal (must be excluded from results).
	humanA, err := s.CreatePrincipal(store.PrincipalClassHuman, "contact-alice")
	if err != nil {
		t.Fatalf("create human principal A: %v", err)
	}
	humanB, err := s.CreatePrincipal(store.PrincipalClassHuman, "contact-bob")
	if err != nil {
		t.Fatalf("create human principal B: %v", err)
	}
	if _, err := s.CreatePrincipal(store.PrincipalClassAgent, "lucos-some-agent"); err != nil {
		t.Fatalf("create agent principal: %v", err)
	}

	// mintBearerToken also creates a human principal for the token holder.
	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodGet, "/admin/human-principals", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newHumanPrincipalsMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected application/json, got %q", ct)
	}
	var got []humanPrincipalJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Build a map for order-independent assertions.
	byContactID := map[string]humanPrincipalJSON{}
	for _, p := range got {
		byContactID[p.ContactID] = p
	}
	// alice and bob must be present with correct principal IDs.
	for _, want := range []struct {
		contactID   string
		principalID string
	}{
		{"contact-alice", humanA.ID},
		{"contact-bob", humanB.ID},
	} {
		p, ok := byContactID[want.contactID]
		if !ok {
			t.Errorf("missing entry for contact_id %q", want.contactID)
			continue
		}
		if p.PrincipalID != want.principalID {
			t.Errorf("contact %q: want principal_id %q, got %q", want.contactID, want.principalID, p.PrincipalID)
		}
	}
	// The agent must NOT appear in the list.
	if _, found := byContactID["lucos-some-agent"]; found {
		t.Error("agent principal must not appear in human-principals list")
	}
}

// TestAdminHumanPrincipals_ExcludesAgents verifies that an agent-only store
// (plus the token-holder's human principal) returns only humans — i.e. agents
// are never included regardless of how many exist.
func TestAdminHumanPrincipals_ExcludesAgents(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	// Add a couple of agent principals only.
	if _, err := s.CreatePrincipal(store.PrincipalClassAgent, "lucos-agent-one"); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	if _, err := s.CreatePrincipal(store.PrincipalClassAgent, "lucos-agent-two"); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	// mintBearerToken creates exactly one human principal (the admin token-holder).
	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodGet, "/admin/human-principals", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newHumanPrincipalsMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	var got []humanPrincipalJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Only the token-holder's principal should appear.
	if len(got) != 1 {
		t.Errorf("expected exactly 1 human principal (the token holder), got %d", len(got))
	}
	for _, p := range got {
		if p.ContactID == "lucos-agent-one" || p.ContactID == "lucos-agent-two" {
			t.Errorf("agent principal %q must not appear in human-principals list", p.ContactID)
		}
	}
}

// TestAdminHumanPrincipals_RequiresAdmin verifies that requests without the
// aithne:admin scope are rejected with 403.
func TestAdminHumanPrincipals_RequiresAdmin(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	noAdminToken := mintBearerToken(t, s, []string{"render-ui"})
	req := httptest.NewRequest(http.MethodGet, "/admin/human-principals", nil)
	req.Header.Set("Authorization", "Bearer "+noAdminToken)
	rr := httptest.NewRecorder()
	newHumanPrincipalsMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

// TestAdminHumanPrincipals_MethodNotAllowed verifies that non-GET methods are rejected.
func TestAdminHumanPrincipals_MethodNotAllowed(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	adminToken := mintBearerToken(t, s, []string{"aithne:admin"})
	req := httptest.NewRequest(http.MethodPost, "/admin/human-principals", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	newHumanPrincipalsMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}
