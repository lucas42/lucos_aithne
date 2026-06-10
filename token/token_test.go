package token_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lucos_aithne/store"
	"lucos_aithne/token"
)

// tokenTestKEK is a deterministic 32-byte KEK for token package tests.
var tokenTestKEK = [32]byte{
	99, 98, 97, 96, 95, 94, 93, 92,
	91, 90, 89, 88, 87, 86, 85, 84,
	83, 82, 81, 80, 79, 78, 77, 76,
	75, 74, 73, 72, 71, 70, 69, 68,
}

// newTestSigningKey generates a fresh signing key via an in-memory store.
func newTestSigningKey(t *testing.T) (*store.SigningKey, *store.Store) {
	t.Helper()
	s, err := store.Open(":memory:", tokenTestKEK)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	k, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey: %v", err)
	}
	return k, s
}

func newTestPrincipal(t *testing.T, s *store.Store, class store.PrincipalClass, externalID string) *store.Principal {
	t.Helper()
	p, err := s.CreatePrincipal(class, externalID)
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	return p
}

const testIssuer = "https://aithne.l42.eu"
const testAudience = "l42.eu"

// --- MintSession ---

func TestMintSession_HumanPrincipal(t *testing.T) {
	k, s := newTestSigningKey(t)
	p := newTestPrincipal(t, s, store.PrincipalClassHuman, "contact-xyz")

	tok, err := token.MintSession(p, []string{"photos:read"}, k, testIssuer, testAudience, 0)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
	// JWT format: three dot-separated base64url segments.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 JWT segments, got %d", len(parts))
	}
}

func TestMintSession_AgentPrincipal(t *testing.T) {
	k, s := newTestSigningKey(t)
	p := newTestPrincipal(t, s, store.PrincipalClassAgent, "lucos-architect")

	tok, err := token.MintSession(p, []string{"render-ui"}, k, testIssuer, testAudience, 0)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestMintSession_EmptyScopes(t *testing.T) {
	k, s := newTestSigningKey(t)
	p := newTestPrincipal(t, s, store.PrincipalClassHuman, "contact-abc")

	tok, err := token.MintSession(p, nil, k, testIssuer, testAudience, 0)
	if err != nil {
		t.Fatalf("MintSession with nil scopes: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
}

// --- ParseSession (round-trip) ---

func TestParseSession_RoundTrip_Human(t *testing.T) {
	k, s := newTestSigningKey(t)
	p := newTestPrincipal(t, s, store.PrincipalClassHuman, "contact-roundtrip")

	scopes := []string{"photos:read", "photos:write"}
	tokStr, err := token.MintSession(p, scopes, k, testIssuer, testAudience, 0)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}

	keys, err := s.ListVerificationKeys(token.VerificationWindow)
	if err != nil {
		t.Fatalf("ListVerificationKeys: %v", err)
	}
	keySet, err := token.BuildVerificationKeySet(keys)
	if err != nil {
		t.Fatalf("BuildVerificationKeySet: %v", err)
	}

	claims, err := token.ParseSession(tokStr, keySet, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}

	if claims.JWTID == "" {
		t.Error("JWTID should be non-empty")
	}
	if claims.Subject != "contact-roundtrip" {
		t.Errorf("Subject: got %q, want %q", claims.Subject, "contact-roundtrip")
	}
	if claims.PrincipalClass != store.PrincipalClassHuman {
		t.Errorf("PrincipalClass: got %q, want %q", claims.PrincipalClass, store.PrincipalClassHuman)
	}
	if len(claims.Scopes) != 2 {
		t.Fatalf("Scopes: got %v, want 2 entries", claims.Scopes)
	}
	if claims.Scopes[0] != "photos:read" || claims.Scopes[1] != "photos:write" {
		t.Errorf("Scopes: got %v", claims.Scopes)
	}
	if claims.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}
	if claims.IssuedAt.IsZero() {
		t.Error("IssuedAt should be set")
	}
	// Expiry should be approximately DefaultSessionTTL from now.
	remaining := time.Until(claims.ExpiresAt)
	if remaining < 14*time.Minute || remaining > 16*time.Minute {
		t.Errorf("ExpiresAt: expected ~15min from now, got %v remaining", remaining)
	}
}

func TestParseSession_RoundTrip_Agent(t *testing.T) {
	k, s := newTestSigningKey(t)
	p := newTestPrincipal(t, s, store.PrincipalClassAgent, "lucos-developer")

	tokStr, err := token.MintSession(p, []string{"render-ui"}, k, testIssuer, testAudience, 0)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}

	keys, err := s.ListVerificationKeys(token.VerificationWindow)
	if err != nil {
		t.Fatalf("ListVerificationKeys: %v", err)
	}
	keySet, err := token.BuildVerificationKeySet(keys)
	if err != nil {
		t.Fatalf("BuildVerificationKeySet: %v", err)
	}

	claims, err := token.ParseSession(tokStr, keySet, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if claims.JWTID == "" {
		t.Error("JWTID should be non-empty")
	}
	if claims.Subject != "lucos-developer" {
		t.Errorf("Subject: got %q, want %q", claims.Subject, "lucos-developer")
	}
	if claims.PrincipalClass != store.PrincipalClassAgent {
		t.Errorf("PrincipalClass: got %q, want agent", claims.PrincipalClass)
	}
}

func TestParseSession_RejectsWrongIssuer(t *testing.T) {
	k, s := newTestSigningKey(t)
	p := newTestPrincipal(t, s, store.PrincipalClassHuman, "contact-x")

	tokStr, err := token.MintSession(p, nil, k, testIssuer, testAudience, 0)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}

	keys, _ := s.ListVerificationKeys(token.VerificationWindow)
	keySet, _ := token.BuildVerificationKeySet(keys)

	_, err = token.ParseSession(tokStr, keySet, "https://evil.example.com", testAudience)
	if err == nil {
		t.Error("expected error for wrong issuer, got nil")
	}
}

func TestParseSession_RejectsWrongAudience(t *testing.T) {
	k, s := newTestSigningKey(t)
	p := newTestPrincipal(t, s, store.PrincipalClassHuman, "contact-aud")

	tokStr, err := token.MintSession(p, nil, k, testIssuer, testAudience, 0)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}

	keys, _ := s.ListVerificationKeys(token.VerificationWindow)
	keySet, _ := token.BuildVerificationKeySet(keys)

	_, err = token.ParseSession(tokStr, keySet, testIssuer, "evil.example.com")
	if err == nil {
		t.Error("expected error for wrong audience, got nil")
	}
}

func TestParseSession_RejectsExpiredToken(t *testing.T) {
	k, s := newTestSigningKey(t)
	p := newTestPrincipal(t, s, store.PrincipalClassHuman, "contact-exp")

	// Mint a token that is already expired (negative TTL → resolved to DefaultSessionTTL by MintSession,
	// so we need to use a tiny positive TTL and sleep is not acceptable in tests).
	// Use a 1ns TTL — lestrrat-go/jwx/v2 has a configurable clock-skew; default is 1 minute.
	// A 1ns TTL will still be within the default skew window, so let's use a large negative duration
	// via a custom TTL by subtracting a day from the expiration by minting normally then trying
	// to parse with a zero-skew requirement.
	//
	// The simpler route: mint a token with ttl=-1*time.Hour (invalid — MintSession treats
	// <= 0 as DefaultSessionTTL), so instead we confirm the default TTL is set correctly
	// and verify that a token with a past expiration is rejected.
	//
	// We achieve a truly expired token by minting with 1ns TTL and then parsing with
	// AcceptableSkew(0). lestrrat-go/jwt.ParseString validates exp and the default AcceptableSkew
	// is 0 — a 1ns TTL token will be expired immediately after mint.
	tokStr, err := token.MintSession(p, nil, k, testIssuer, testAudience, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}

	keys, _ := s.ListVerificationKeys(token.VerificationWindow)
	keySet, _ := token.BuildVerificationKeySet(keys)

	// Give the nanosecond token time to actually expire.
	time.Sleep(2 * time.Millisecond)

	_, err = token.ParseSession(tokStr, keySet, testIssuer, testAudience)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestParseSession_RejectsWrongKey(t *testing.T) {
	// Mint with key1, try to verify with key2.
	k1, s1 := newTestSigningKey(t)
	p := newTestPrincipal(t, s1, store.PrincipalClassHuman, "contact-wrongkey")

	tokStr, err := token.MintSession(p, nil, k1, testIssuer, testAudience, 0)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}

	// Different store → different key.
	_, s2 := newTestSigningKey(t)
	keys2, _ := s2.ListVerificationKeys(token.VerificationWindow)
	keySet2, _ := token.BuildVerificationKeySet(keys2)

	_, err = token.ParseSession(tokStr, keySet2, testIssuer, testAudience)
	if err == nil {
		t.Error("expected error when verifying with wrong key, got nil")
	}
}

// --- JWKSHandler ---

func TestJWKSHandler_ReturnsJSON(t *testing.T) {
	_, s := newTestSigningKey(t)

	handler := token.JWKSHandler(func() ([]*store.SigningKey, error) {
		return s.ListVerificationKeys(token.VerificationWindow)
	})

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	// Body must be valid JSON with a "keys" array.
	body := rr.Body.String()
	if !strings.Contains(body, `"keys"`) {
		t.Errorf("JWKS body missing 'keys' field: %s", body)
	}
	if !strings.Contains(body, `"EC"`) {
		t.Errorf("JWKS body missing EC key type: %s", body)
	}
}

func TestJWKSHandler_PublicKeyOnly(t *testing.T) {
	_, s := newTestSigningKey(t)

	handler := token.JWKSHandler(func() ([]*store.SigningKey, error) {
		return s.ListVerificationKeys(token.VerificationWindow)
	})

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	body := rr.Body.String()
	// Private key material must not appear in JWKS output.
	if strings.Contains(body, `"d"`) {
		t.Error("JWKS body contains private key parameter 'd' — must not expose private key")
	}
}

func TestJWKSHandler_CacheControlHeader(t *testing.T) {
	_, s := newTestSigningKey(t)

	handler := token.JWKSHandler(func() ([]*store.SigningKey, error) {
		return s.ListVerificationKeys(token.VerificationWindow)
	})

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}
	cc := rr.Header().Get("Cache-Control")
	if cc != "public, max-age=300" {
		t.Errorf("Cache-Control: got %q, want %q", cc, "public, max-age=300")
	}
}

// --- SetSessionCookie ---

func TestSetSessionCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	token.SetSessionCookie(rr, "test-token-value")

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected at least one cookie")
	}
	var sessionCookie *http.Cookie
	for i := range cookies {
		if cookies[i].Name == "aithne_session" {
			sessionCookie = cookies[i]
		}
	}
	if sessionCookie == nil {
		t.Fatal("aithne_session cookie not set")
	}
	if sessionCookie.Value != "test-token-value" {
		t.Errorf("cookie value: got %q, want %q", sessionCookie.Value, "test-token-value")
	}
	if sessionCookie.Domain != "l42.eu" {
		t.Errorf("cookie domain: got %q, want l42.eu", sessionCookie.Domain)
	}
	if !sessionCookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Error("cookie should be Secure")
	}
}
