package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lucos_aithne/store"
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
		t.Error("checks field missing from /_info response")
	}
	if checksMap, ok := checks.(map[string]any); ok {
		if checksMap["db"] != "ok" {
			t.Errorf("checks.db: got %v, want %q", checksMap["db"], "ok")
		}
	}
	if _, ok := payload["metrics"]; !ok {
		t.Error("metrics field missing from /_info response")
	}
}
