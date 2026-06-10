package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gwebauthn "github.com/go-webauthn/webauthn/webauthn"
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
	s, err := store.Open(":memory:")
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

// --- Helpers ---

const testIssuer = "http://aithne.test"
const testAudience = "l42.eu"

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

// newAdminMux builds a test ServeMux with only the admin endpoints registered.
func newAdminMux(s *store.Store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/grants", requireAdminScope(s, testIssuer, handleGrants(s, testMainVocab)))
	mux.HandleFunc("/admin/grants/", requireAdminScope(s, testIssuer, handleGrantByID(s)))
	return mux
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

// --- Admin endpoint auth tests ---

func TestAdminGrants_RejectsNoToken(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/grants?principal_id=x", nil)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAdminGrants_RejectsInvalidToken(t *testing.T) {
	s, err := store.Open(":memory:")
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
	s, err := store.Open(":memory:")
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
	s, err := store.Open(":memory:")
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
	s, err := store.Open(":memory:")
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
	s, err := store.Open(":memory:")
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
	s, err := store.Open(":memory:")
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

func TestAdminGrantByID_Revoke(t *testing.T) {
	s, err := store.Open(":memory:")
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
	s, err := store.Open(":memory:")
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
	s, err := store.Open(":memory:")
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

func TestServeStaticFile_LoginPage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()
	serveStaticFile(staticFS, "static/login.html")(rr, req)
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

func TestServeStaticFile_RegisterPage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/register", nil)
	rr := httptest.NewRecorder()
	serveStaticFile(staticFS, "static/register.html")(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /auth/register: expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<title>") {
		t.Error("register.html body does not look like HTML (no <title>)")
	}
}

func TestServeStaticFile_RejectsPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	rr := httptest.NewRecorder()
	serveStaticFile(staticFS, "static/login.html")(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /auth/login: expected 405, got %d", rr.Code)
	}
}

// --- WebAuthn ceremony handler tests ---
//
// Full ceremony happy-paths cannot be exercised in unit tests without a real
// authenticator (hardware or software). Tests here cover:
//   - Input validation (method, missing fields)
//   - Ghost-principal and no-credentials paths (security rule #3)
//   - Expired/missing ceremony session (begin not called, TTL exceeded)
//   - handleRegisterBegin: returns valid PublicKeyCredentialCreationOptions

func TestRegisterBegin_MissingContactID(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/auth/register/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleRegisterBegin(s, wa, cs)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing contact_id, got %d", rr.Code)
	}
}

func TestRegisterBegin_RejectsNonPost(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	req := httptest.NewRequest(http.MethodGet, "/auth/register/begin", nil)
	rr := httptest.NewRecorder()
	handleRegisterBegin(s, wa, cs)(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rr.Code)
	}
}

func TestRegisterBegin_ReturnsOptions(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	body, _ := json.Marshal(map[string]string{"contact_id": "alice", "label": "Test Key"})
	req := httptest.NewRequest(http.MethodPost, "/auth/register/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleRegisterBegin(s, wa, cs)(rr, req)

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
	// Verify session was stored in the ceremony store.
	if _, ok := cs.take("register:alice"); !ok {
		t.Error("ceremony store should hold session data after begin")
	}
}

func TestRegisterFinish_NoSession(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	// No prior begin call — ceremony session is absent.
	req := httptest.NewRequest(http.MethodPost, "/auth/register/finish?contact_id=nobody", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleRegisterFinish(s, wa, cs)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing session, got %d", rr.Code)
	}
}

func TestRegisterFinish_MissingContactIDParam(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()
	wa := newTestWebAuthn(t)
	cs := newCeremonyStore()

	req := httptest.NewRequest(http.MethodPost, "/auth/register/finish", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleRegisterFinish(s, wa, cs)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing contact_id param, got %d", rr.Code)
	}
}

func TestLoginBegin_GhostPrincipal(t *testing.T) {
	s, err := store.Open(":memory:")
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
	handleLoginBegin(s, wa, cs)(rr, req)

	// Security rule #3: ghost principals and no-credentials are both 404 to
	// prevent contact-ID enumeration.
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for ghost principal, got %d", rr.Code)
	}
}

func TestLoginBegin_PrincipalWithNoCredentials(t *testing.T) {
	s, err := store.Open(":memory:")
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
	handleLoginBegin(s, wa, cs)(rr, req)

	// Security rule #3: same 404 whether principal is missing or has no creds.
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for principal with no credentials, got %d", rr.Code)
	}
}

func TestLoginBegin_EmptyContactID_Discoverable(t *testing.T) {
	s, err := store.Open(":memory:")
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
	handleLoginBegin(s, wa, cs)(rr, req)

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
	s, err := store.Open(":memory:")
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
	s, err := store.Open(":memory:")
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
	s, err := store.Open(":memory:")
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
