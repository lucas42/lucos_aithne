package main

import (
	"bytes"
	"encoding/json"
	"errors"
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

// --- Helpers ---

const testIssuer = "http://aithne.test"
const testAudience = "l42.eu"

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
	mux.HandleFunc("/admin/grants", requireAdminScope(s, testIssuer, handleGrants(s, testMainVocab)))
	mux.HandleFunc("/admin/grants/", requireAdminScope(s, testIssuer, handleGrantByID(s)))
	contacts := newContactsClient("http://contacts.test", "test-key")
	mux.HandleFunc("/admin/enrol", requireAdminScope(s, testIssuer, handleAdminEnrolPage()))
	mux.HandleFunc("/admin/invites", requireAdminScope(s, testIssuer, handleAdminInvites(s, contacts, testIssuer)))
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

	req := httptest.NewRequest(http.MethodGet, "/admin/grants?principal_id=x", nil)
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
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

	req := httptest.NewRequest(http.MethodGet, "/enrol/begin?token=any", nil)
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs)(rr, req)

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

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs)(rr, req)

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

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin?token=nonexistent", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs)(rr, req)

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

	rawToken := createValidInvite(t, s, "alice")

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin?token="+rawToken, strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handleEnrolBegin(s, wa, cs)(rr, req)

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

	rawToken := createValidInvite(t, s, "bob")

	req := httptest.NewRequest(http.MethodPost, "/enrol/begin?token="+rawToken, strings.NewReader("{}"))
	httptest.NewRecorder() // discard response
	handleEnrolBegin(s, wa, cs)(httptest.NewRecorder(), req)

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

	want := "/agents/org%2Falice%20smith"
	if gotPath != want {
		t.Errorf("request path: got %q, want %q", gotPath, want)
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
	handleLoginBegin(s, wa, cs)(rr, req)

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
	handleLoginBegin(s, wa, cs)(rr, req)

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

// newMachineAuthMux builds a test ServeMux with the oauth2/token and
// admin/machine-keys endpoints registered.
func newMachineAuthMux(s *store.Store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", handleClientCredentials(s, testIssuer, "development"))
	mux.HandleFunc("/admin/machine-keys", requireAdminScope(s, testIssuer, handleAdminMachineKeys(s)))
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

func TestClientCredentials_WrongGrantType(t *testing.T) {
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	defer s.Close()

	body := strings.NewReader("grant_type=authorization_code&client_id=foo&client_secret=bar")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	newMachineAuthMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	var errResp tokenErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&errResp)
	if errResp.Error != "unsupported_grant_type" {
		t.Errorf("error: got %q, want %q", errResp.Error, "unsupported_grant_type")
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
