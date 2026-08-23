package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRobotsTxt verifies /robots.txt is served and disallows all bots.
// See issue #317: nothing on aithne.l42.eu is worth 3rd-party scraping, and
// this is hygiene for well-behaved bots -- auth is what actually protects
// the site.
func TestRobotsTxt(t *testing.T) {
	handler := serveStaticFile(staticFS, "static/robots.txt")

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	got := string(body)
	if !strings.Contains(got, "User-agent: *") {
		t.Errorf("robots.txt missing \"User-agent: *\", got: %q", got)
	}
	if !strings.Contains(got, "Disallow: /") {
		t.Errorf("robots.txt missing \"Disallow: /\", got: %q", got)
	}
}

// TestRobotsTxt_RejectsNonGet verifies serveStaticFile's existing
// method-guard applies to /robots.txt like every other static route.
func TestRobotsTxt_RejectsNonGet(t *testing.T) {
	handler := serveStaticFile(staticFS, "static/robots.txt")

	req := httptest.NewRequest(http.MethodPost, "/robots.txt", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}
