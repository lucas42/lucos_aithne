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

	"lucos_aithne/store"
	"lucos_aithne/token"
)

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
		"granted_by":   "test-admin",
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
	req.Header.Set("X-Revoked-By", "test-revoker")
	rr := httptest.NewRecorder()
	newAdminMux(s).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d\n%s", rr.Code, rr.Body.String())
	}

	// Verify the grant is now revoked.
	fetched, err := s.GetGrant(g.ID)
	if err != nil {
		t.Fatalf("GetGrant after revoke: %v", err)
	}
	if fetched.IsActive() {
		t.Error("grant should be revoked after DELETE")
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
