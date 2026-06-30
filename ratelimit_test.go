package main

// ratelimit_test.go — unit tests for keyedLimiter and clientIP, plus
// integration tests verifying 429 responses on the rate-limited endpoints.

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
)

// --- keyedLimiter unit tests ---

func TestKeyedLimiter_AllowUnderLimit(t *testing.T) {
	rl := newKeyedLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		ok, count := rl.Allow("key1")
		if !ok {
			t.Fatalf("request %d: expected Allow=true, got false (count=%d)", i+1, count)
		}
		if count != i+1 {
			t.Errorf("request %d: expected count=%d, got %d", i+1, i+1, count)
		}
	}
}

func TestKeyedLimiter_DenyOnBreach(t *testing.T) {
	rl := newKeyedLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		ok, _ := rl.Allow("key1")
		if !ok {
			t.Fatalf("request %d: should be allowed", i+1)
		}
	}
	// 4th request exceeds limit.
	ok, count := rl.Allow("key1")
	if ok {
		t.Fatal("4th request: expected Allow=false, got true")
	}
	if count != 4 {
		t.Errorf("4th request: expected count=4, got %d", count)
	}
}

func TestKeyedLimiter_IndependentKeys(t *testing.T) {
	rl := newKeyedLimiter(2, time.Minute)
	// key1 hits its limit.
	rl.Allow("key1")
	rl.Allow("key1")
	ok, _ := rl.Allow("key1")
	if ok {
		t.Error("key1: expected 3rd allow to fail")
	}
	// key2 should still be allowed — independent counter.
	ok, count := rl.Allow("key2")
	if !ok {
		t.Errorf("key2: expected allow=true (count=%d)", count)
	}
}

func TestKeyedLimiter_WindowReset(t *testing.T) {
	// Use a very short window to avoid test sleeps while still testing reset.
	window := 20 * time.Millisecond
	rl := newKeyedLimiter(2, window)

	rl.Allow("key1")
	rl.Allow("key1")
	ok, _ := rl.Allow("key1")
	if ok {
		t.Fatal("3rd request before window reset: expected false")
	}

	// Wait for the window to pass.
	time.Sleep(window + 5*time.Millisecond)

	// After the window, the first request of a new window should be allowed.
	ok, count := rl.Allow("key1")
	if !ok {
		t.Fatalf("1st request after window reset: expected true, got false (count=%d)", count)
	}
	if count != 1 {
		t.Errorf("1st request after reset: expected count=1, got %d", count)
	}
}

func TestKeyedLimiter_SweepExpired(t *testing.T) {
	window := 20 * time.Millisecond
	rl := newKeyedLimiter(10, window)

	// Add an entry.
	rl.Allow("key1")

	// Wait for its window to expire.
	time.Sleep(window + 5*time.Millisecond)

	// Sweep should remove it.
	rl.sweepExpired()

	rl.mu.Lock()
	_, present := rl.entries["key1"]
	rl.mu.Unlock()
	if present {
		t.Error("sweepExpired: stale entry still present after sweep")
	}
}

// --- clientIP unit tests ---

func TestClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Real-IP", "203.0.113.42")
	if got := clientIP(req); got != "203.0.113.42" {
		t.Errorf("clientIP: expected 203.0.113.42, got %q", got)
	}
}

func TestClientIP_FallbackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	if got := clientIP(req); got != "192.0.2.1" {
		t.Errorf("clientIP: expected 192.0.2.1, got %q", got)
	}
}

// --- integration tests: 429 on rate-limited endpoints ---

// newTestStore is a helper that opens an in-memory store for rate-limit tests.
func newTestStoreForRL(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:", testMainKEK)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// newTestWA creates a WebAuthn instance for rate-limit endpoint tests.
func newTestWAForRL(t *testing.T) *gwebauthn.WebAuthn {
	t.Helper()
	wa, err := gwebauthn.New(&gwebauthn.Config{
		RPID:          "aithne.test",
		RPDisplayName: "lucOS (test)",
		RPOrigins:     []string{testIssuer},
	})
	if err != nil {
		t.Fatalf("newTestWA: %v", err)
	}
	return wa
}

func TestRateLimit_TokenEndpoint_429OnBreach(t *testing.T) {
	s := newTestStoreForRL(t)
	// Limit of 2 so the 3rd request triggers 429.
	limiter := newKeyedLimiter(2, time.Minute)
	handler := handleOAuth2Token(s, testIssuer, "development", limiter)

	makeRequest := func() *httptest.ResponseRecorder {
		body := "grant_type=client_credentials&client_id=testclient&client_secret=testpass"
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "10.0.0.1")
		rr := httptest.NewRecorder()
		handler(rr, req)
		return rr
	}

	// First two requests reach the auth logic (fail with 401 — wrong secret, but not 429).
	for i := 0; i < 2; i++ {
		rr := makeRequest()
		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpected 429 before limit exceeded", i+1)
		}
	}

	// Third request should be rate-limited.
	rr := makeRequest()
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request: expected 429, got %d\nbody: %s", rr.Code, rr.Body.String())
	}
	wantRetryAfter := fmt.Sprintf("%d", int(tokenEndpointWindow.Seconds()))
	if ra := rr.Header().Get("Retry-After"); ra != wantRetryAfter {
		t.Errorf("3rd request: Retry-After header: got %q, want %q", ra, wantRetryAfter)
	}
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err == nil {
		if errResp.Error != "rate_limited" {
			t.Errorf("3rd request: error field: got %q, want %q", errResp.Error, "rate_limited")
		}
	}
}

func TestRateLimit_TokenEndpoint_KeyIsClientID(t *testing.T) {
	s := newTestStoreForRL(t)
	// Limit of 1 per key.
	limiter := newKeyedLimiter(1, time.Minute)
	handler := handleOAuth2Token(s, testIssuer, "development", limiter)

	makeRequest := func(clientID, ip string) *httptest.ResponseRecorder {
		body := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=pass", clientID)
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", ip)
		rr := httptest.NewRecorder()
		handler(rr, req)
		return rr
	}

	// Exhaust client-A's window.
	makeRequest("client-A", "10.0.0.1")
	rr := makeRequest("client-A", "10.0.0.1")
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("client-A 2nd request: expected 429, got %d", rr.Code)
	}

	// client-B (different client_id, same IP) should still be allowed.
	rr = makeRequest("client-B", "10.0.0.1")
	if rr.Code == http.StatusTooManyRequests {
		t.Errorf("client-B: expected not-429 (different client_id), got 429")
	}
}

func TestRateLimit_AuthCodeGrant_429OnBreach(t *testing.T) {
	s := newTestStoreForRL(t)
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	// Limit of 2 so the 3rd request triggers 429.
	limiter := newKeyedLimiter(2, time.Minute)
	handler := handleOAuth2Token(s, testIssuer, "development", limiter)

	makeRequest := func() *httptest.ResponseRecorder {
		body := "grant_type=authorization_code&client_id=testclient&client_secret=badsecret&code=fakecode&redirect_uri=https://rp.test/callback"
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "10.0.0.1")
		rr := httptest.NewRecorder()
		handler(rr, req)
		return rr
	}

	// First two requests reach the auth logic (fail with 4xx — unknown client, but not 429).
	for i := 0; i < 2; i++ {
		rr := makeRequest()
		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpected 429 before limit exceeded", i+1)
		}
	}

	// Third request should be rate-limited.
	rr := makeRequest()
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request: expected 429, got %d\nbody: %s", rr.Code, rr.Body.String())
	}
	wantRetryAfter := fmt.Sprintf("%d", int(tokenEndpointWindow.Seconds()))
	if ra := rr.Header().Get("Retry-After"); ra != wantRetryAfter {
		t.Errorf("3rd request: Retry-After header: got %q, want %q", ra, wantRetryAfter)
	}
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err == nil {
		if errResp.Error != "rate_limited" {
			t.Errorf("3rd request: error field: got %q, want %q", errResp.Error, "rate_limited")
		}
	}
}

func TestRateLimit_LoginBegin_429OnBreach(t *testing.T) {
	s := newTestStoreForRL(t)
	wa := newTestWAForRL(t)
	cs := newCeremonyStore()
	// Limit of 2 so the 3rd request triggers 429.
	limiter := newKeyedLimiter(2, time.Minute)
	handler := handleLoginBegin(s, wa, cs, limiter)

	makeRequest := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"contact_id": "12345"})
		req := httptest.NewRequest(http.MethodPost, "/auth/login/begin", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Real-IP", "10.0.0.2")
		rr := httptest.NewRecorder()
		handler(rr, req)
		return rr
	}

	// First two requests pass rate limiting (may fail for other reasons — principal not found etc.)
	for i := 0; i < 2; i++ {
		rr := makeRequest()
		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpected 429 before limit exceeded", i+1)
		}
	}

	// Third request should be rate-limited.
	rr := makeRequest()
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request: expected 429, got %d\nbody: %s", rr.Code, rr.Body.String())
	}
	wantRetryAfter := fmt.Sprintf("%d", int(ceremonyBeginWindow.Seconds()))
	if ra := rr.Header().Get("Retry-After"); ra != wantRetryAfter {
		t.Errorf("Retry-After header: got %q, want %q", ra, wantRetryAfter)
	}
}

func TestRateLimit_EnrolBegin_429OnBreach(t *testing.T) {
	s := newTestStoreForRL(t)
	wa := newTestWAForRL(t)
	cs := newCeremonyStore()
	contacts := newContactsClient("http://contacts.test", "test-key")
	// Limit of 2 so the 3rd request triggers 429.
	limiter := newKeyedLimiter(2, time.Minute)
	handler := handleEnrolBegin(s, wa, cs, contacts, limiter)

	makeRequest := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/enrol/begin?token=test-token", nil)
		req.Header.Set("X-Real-IP", "10.0.0.3")
		rr := httptest.NewRecorder()
		handler(rr, req)
		return rr
	}

	// First two requests pass rate limiting (will fail — token not valid, but not 429).
	for i := 0; i < 2; i++ {
		rr := makeRequest()
		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpected 429 before limit exceeded", i+1)
		}
	}

	// Third request should be rate-limited.
	rr := makeRequest()
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request: expected 429, got %d\nbody: %s", rr.Code, rr.Body.String())
	}
	wantRetryAfterEnrol := fmt.Sprintf("%d", int(ceremonyBeginWindow.Seconds()))
	if ra := rr.Header().Get("Retry-After"); ra != wantRetryAfterEnrol {
		t.Errorf("Retry-After header: got %q, want %q", ra, wantRetryAfterEnrol)
	}
}

func TestRateLimit_CeremonyLimiter_SharedAcrossEndpoints(t *testing.T) {
	// login/begin and enrol/begin share the same ceremonyLimiter, so exhausting
	// the limit via login/begin also blocks enrol/begin (and vice-versa) for the
	// same IP. This mirrors how main() wires both handlers to one instance.
	s := newTestStoreForRL(t)
	wa := newTestWAForRL(t)
	cs := newCeremonyStore()
	contacts := newContactsClient("http://contacts.test", "test-key")
	// Limit of 1 — one login/begin should block one enrol/begin.
	limiter := newKeyedLimiter(1, time.Minute)

	loginHandler := handleLoginBegin(s, wa, cs, limiter)
	enrolHandler := handleEnrolBegin(s, wa, cs, contacts, limiter)

	ip := "10.0.0.4"

	// Use up the single allowed request via login/begin.
	loginReq, _ := http.NewRequest(http.MethodPost, "/auth/login/begin", bytes.NewReader([]byte(`{"contact_id":"1"}`)))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("X-Real-IP", ip)
	rr := httptest.NewRecorder()
	loginHandler(rr, loginReq)
	if rr.Code == http.StatusTooManyRequests {
		t.Fatalf("login/begin first request: unexpected 429")
	}

	// Now enrol/begin for the same IP should be blocked.
	enrolReq := httptest.NewRequest(http.MethodPost, "/enrol/begin?token=tok", nil)
	enrolReq.Header.Set("X-Real-IP", ip)
	rr2 := httptest.NewRecorder()
	enrolHandler(rr2, enrolReq)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("enrol/begin after login/begin exhausted limit: expected 429, got %d", rr2.Code)
	}
}

// TestCeremonyStoreSweepExpired verifies that sweepExpired removes stale entries
// from both the login and enrol maps independently of any request.
func TestCeremonyStoreSweepExpired(t *testing.T) {
	cs := newCeremonyStore()

	// Manually insert an expired login entry.
	expired := &ceremonyEntry{data: nil, expiresAt: time.Now().Add(-time.Second)}
	cs.mu.Lock()
	cs.entries["login:test"] = expired
	cs.enrol["enrol:test"] = &enrolCeremonyEntry{data: nil, contactID: "x", expiresAt: time.Now().Add(-time.Second)}
	cs.mu.Unlock()

	cs.sweepExpired()

	cs.mu.Lock()
	defer cs.mu.Unlock()
	if _, ok := cs.entries["login:test"]; ok {
		t.Error("sweepExpired: expired login entry still present")
	}
	if _, ok := cs.enrol["enrol:test"]; ok {
		t.Error("sweepExpired: expired enrol entry still present")
	}
}

// TestCeremonyStoreSweepExpired_KeepsValid verifies that non-expired entries are
// left intact by sweepExpired.
func TestCeremonyStoreSweepExpired_KeepsValid(t *testing.T) {
	cs := newCeremonyStore()

	// Insert a valid (non-expired) entry.
	cs.mu.Lock()
	cs.entries["login:valid"] = &ceremonyEntry{data: nil, expiresAt: time.Now().Add(time.Minute)}
	cs.mu.Unlock()

	cs.sweepExpired()

	cs.mu.Lock()
	defer cs.mu.Unlock()
	if _, ok := cs.entries["login:valid"]; !ok {
		t.Error("sweepExpired: valid entry was incorrectly removed")
	}
}
