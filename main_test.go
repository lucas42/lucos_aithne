package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
