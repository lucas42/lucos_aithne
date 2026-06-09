package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInfoEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/_info", nil)
	rr := httptest.NewRecorder()

	handleInfo("lucos_aithne")(rr, req)

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
	if _, ok := payload["checks"]; !ok {
		t.Error("checks field missing from /_info response")
	}
	if _, ok := payload["metrics"]; !ok {
		t.Error("metrics field missing from /_info response")
	}
}
