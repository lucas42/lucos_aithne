// Package token implements JWT minting, verification, and JWKS serving for
// lucos_aithne session tokens.
//
// Per ADR-0001 §3, both human and machine principals yield the same artefact:
// a short-lived signed JWT that is verified locally by consumers via JWKS —
// eliminating the /data?token= introspection round-trip.
//
// See docs/local-verification-contract.md for the contract consumers must implement.
package token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"lucos_aithne/store"
)

// DefaultSessionTTL is the lifetime of a freshly minted session token.
// Short-lived by design: revocation is eventually-consistent (a revoked grant
// persists until expiry), so the TTL bounds the revocation window.
const DefaultSessionTTL = 15 * time.Minute

// VerificationWindow is the minimum window for ListVerificationKeys: it governs
// how long a retired signing key stays published in the JWKS after rotation.
//
// Must satisfy: VerificationWindow >= DefaultSessionTTL + max-consumer-JWKS-cache-TTL + clock-drift.
//
//   - DefaultSessionTTL = 15 min  (token lifetime)
//   - Consumer JWKS cache TTL = 5 min  (recommended in local-verification-contract.md)
//   - Clock drift + headroom ≈ 10 min
//   ──────────────────────────────────────────
//   Minimum ≈ 30 min
//
// 30 min flat. If DefaultSessionTTL or the recommended consumer cache TTL changes,
// update this constant to keep the relationship satisfied.
const VerificationWindow = 30 * time.Minute

// ClaimPrincipalClass is the custom JWT claim name for the principal class.
// Values: "human" | "agent".
const ClaimPrincipalClass = "principal_class"

// ClaimScopes is the custom JWT claim name for the granted scope list.
const ClaimScopes = "scopes"

// SessionClaims holds the decoded fields from a validated session JWT.
type SessionClaims struct {
	// Subject is the external identity: lucos_contacts contact-id (human) or
	// personas slug (agent). Set from the JWT "sub" claim.
	Subject string

	// PrincipalClass distinguishes human from agent principals.
	PrincipalClass store.PrincipalClass

	// Scopes are the granted capabilities stamped into this session at mint time.
	Scopes []string

	// IssuedAt and ExpiresAt are the standard JWT validity window.
	IssuedAt  time.Time
	ExpiresAt time.Time

	// JWTID is the unique token identifier (JWT "jti" claim).
	JWTID string
}

// MintSession creates a signed session JWT for the given principal.
// The token is signed with the provided signing key using ES256.
// scopes is the list of granted capabilities to embed (may be empty).
// issuer should be the full HTTPS URL of the aithne service (APP_ORIGIN).
// audience identifies the intended token consumers; use "l42.eu" for estate-wide tokens.
// ttl overrides the default TTL; pass 0 to use DefaultSessionTTL.
func MintSession(
	p *store.Principal,
	scopes []string,
	signingKey *store.SigningKey,
	issuer string,
	audience string,
	ttl time.Duration,
) (string, error) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if scopes == nil {
		scopes = []string{}
	}

	// Load the private key from PKCS8 DER.
	privKeyRaw, err := x509.ParsePKCS8PrivateKey(signingKey.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("token: parse signing key: %w", err)
	}
	privKey, ok := privKeyRaw.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("token: expected *ecdsa.PrivateKey, got %T", privKeyRaw)
	}

	// Build the JWK with kid so verifiers can look up the correct public key.
	jwkKey, err := jwk.FromRaw(privKey)
	if err != nil {
		return "", fmt.Errorf("token: build JWK: %w", err)
	}
	if err := jwkKey.Set(jwk.KeyIDKey, signingKey.ID); err != nil {
		return "", fmt.Errorf("token: set kid: %w", err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return "", fmt.Errorf("token: set alg: %w", err)
	}

	now := time.Now().UTC()
	jti := uuid.New().String()

	// Build the token with standard + custom claims per ADR §3.
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(string(p.ExternalID)).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(ttl)).
		JwtID(jti).
		Claim(ClaimPrincipalClass, string(p.Class)).
		Claim(ClaimScopes, scopes).
		Build()
	if err != nil {
		return "", fmt.Errorf("token: build JWT: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, jwkKey))
	if err != nil {
		return "", fmt.Errorf("token: sign JWT: %w", err)
	}
	return string(signed), nil
}

// ParseSession parses and validates a session JWT string.
// keySet must contain the public keys corresponding to the signing keys in use.
// issuer must match the "iss" claim in the token.
// audience must appear in the token's "aud" claim.
func ParseSession(tokenStr string, keySet jwk.Set, issuer, audience string) (*SessionClaims, error) {
	tok, err := jwt.ParseString(tokenStr,
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
	)
	if err != nil {
		return nil, fmt.Errorf("token: parse session: %w", err)
	}

	claims := &SessionClaims{
		Subject:   tok.Subject(),
		IssuedAt:  tok.IssuedAt(),
		ExpiresAt: tok.Expiration(),
		JWTID:     tok.JwtID(),
	}

	if pc, ok := tok.Get(ClaimPrincipalClass); ok {
		claims.PrincipalClass = store.PrincipalClass(fmt.Sprintf("%v", pc))
	}

	if scopesRaw, ok := tok.Get(ClaimScopes); ok {
		switch v := scopesRaw.(type) {
		case []string:
			claims.Scopes = v
		case []interface{}:
			for _, s := range v {
				claims.Scopes = append(claims.Scopes, fmt.Sprintf("%v", s))
			}
		}
	}
	if claims.Scopes == nil {
		claims.Scopes = []string{}
	}

	return claims, nil
}

// BuildVerificationKeySet constructs a jwk.Set from a list of signing keys for use
// in ParseSession. Only the public key portion of each key is included.
func BuildVerificationKeySet(keys []*store.SigningKey) (jwk.Set, error) {
	set := jwk.NewSet()
	for _, k := range keys {
		privKeyRaw, err := x509.ParsePKCS8PrivateKey(k.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("token: parse key %s: %w", k.ID, err)
		}
		jwkKey, err := jwk.FromRaw(privKeyRaw)
		if err != nil {
			return nil, fmt.Errorf("token: build JWK for %s: %w", k.ID, err)
		}
		if err := jwkKey.Set(jwk.KeyIDKey, k.ID); err != nil {
			return nil, fmt.Errorf("token: set kid %s: %w", k.ID, err)
		}
		if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
			return nil, fmt.Errorf("token: set alg %s: %w", k.ID, err)
		}
		if err := jwkKey.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
			return nil, fmt.Errorf("token: set use %s: %w", k.ID, err)
		}
		pubKey, err := jwkKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("token: extract public key %s: %w", k.ID, err)
		}
		if err := set.AddKey(pubKey); err != nil {
			return nil, fmt.Errorf("token: add key %s to set: %w", k.ID, err)
		}
	}
	return set, nil
}

// JWKSHandler returns an http.HandlerFunc that serves the JWKS JSON.
// getKeys is called on every request so key rotation is reflected immediately.
func JWKSHandler(getKeys func() ([]*store.SigningKey, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys, err := getKeys()
		if err != nil {
			http.Error(w, "failed to load signing keys", http.StatusInternalServerError)
			return
		}
		set, err := BuildVerificationKeySet(keys)
		if err != nil {
			http.Error(w, "failed to build JWKS", http.StatusInternalServerError)
			return
		}
		b, err := json.Marshal(set)
		if err != nil {
			http.Error(w, "failed to serialise JWKS", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(b)
	}
}

// MintIDToken creates an OIDC ID token for the authorization-code flow.
// The ID token is a signed JWT with OIDC Core 1.0 required claims:
//   - iss: issuer (APP_ORIGIN)
//   - sub: subject (principal's external identity)
//   - aud: clientID (the relying party — NOT the estate-wide "l42.eu")
//   - exp, iat
//   - nonce: forwarded from the authorization request (empty string if not provided)
//
// It is signed with the same key as session tokens (ES256) and carries the
// principal class so the RP can distinguish human from agent subjects.
// The ID token is separate from the access token — the access token uses
// audience "l42.eu" for estate-wide verification; the ID token uses the client_id.
func MintIDToken(
	p *store.Principal,
	clientID string,
	nonce string,
	signingKey *store.SigningKey,
	issuer string,
	ttl time.Duration,
) (string, error) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}

	privKeyRaw, err := x509.ParsePKCS8PrivateKey(signingKey.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("token: parse signing key for id_token: %w", err)
	}
	privKey, ok := privKeyRaw.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("token: expected *ecdsa.PrivateKey for id_token, got %T", privKeyRaw)
	}

	jwkKey, err := jwk.FromRaw(privKey)
	if err != nil {
		return "", fmt.Errorf("token: build JWK for id_token: %w", err)
	}
	if err := jwkKey.Set(jwk.KeyIDKey, signingKey.ID); err != nil {
		return "", fmt.Errorf("token: set kid for id_token: %w", err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return "", fmt.Errorf("token: set alg for id_token: %w", err)
	}

	now := time.Now().UTC()
	jti := uuid.New().String()

	builder := jwt.NewBuilder().
		Issuer(issuer).
		Subject(string(p.ExternalID)).
		Audience([]string{clientID}).
		IssuedAt(now).
		Expiration(now.Add(ttl)).
		JwtID(jti).
		Claim(ClaimPrincipalClass, string(p.Class))

	// Embed nonce if provided — required for replay protection when the RP
	// supplied it in the authorization request (OIDC Core §3.1.3.7).
	if nonce != "" {
		builder = builder.Claim("nonce", nonce)
	}

	tok, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("token: build id_token: %w", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, jwkKey))
	if err != nil {
		return "", fmt.Errorf("token: sign id_token: %w", err)
	}
	return string(signed), nil
}

// cookieDomain returns the Domain attribute for the session cookie.
// In development the domain is left empty so the browser scopes the cookie to
// the current host (e.g. localhost) rather than rejecting it as a mismatch
// against "l42.eu". In production it is set to "l42.eu" for estate-wide SSO.
func cookieDomain(environment string) string {
	if environment == "development" {
		return ""
	}
	return "l42.eu"
}

// cookieSameSite returns the SameSite attribute for the session cookie.
// Production uses SameSite=None (requires Secure) to allow cross-origin
// sub-frame access within *.l42.eu. Development uses SameSite=Lax, which
// is compatible with plain-HTTP localhost origins and is the safe browser default.
func cookieSameSite(environment string) http.SameSite {
	if environment == "development" {
		return http.SameSiteLaxMode
	}
	return http.SameSiteNoneMode
}

// SetSessionCookie sets a session cookie containing tokenStr on the response.
// Cookie attributes are environment-aware:
//   - production: Domain="l42.eu" (estate-wide SSO across *.l42.eu), Secure,
//     SameSite=None (permits cross-origin sub-frame cookie sending).
//   - development: no Domain (browser scopes to current host, e.g. localhost),
//     no Secure (plain-HTTP dev server), SameSite=Lax.
//
// The dev relaxation is intentional and necessary: Domain="l42.eu" + Secure=true
// both cause browsers to silently discard the cookie on plain-HTTP localhost,
// making the logged-in flow impossible to test locally.
func SetSessionCookie(w http.ResponseWriter, tokenStr, environment string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "aithne_session",
		Value:    tokenStr,
		Domain:   cookieDomain(environment),
		Path:     "/",
		HttpOnly: true,
		Secure:   environment != "development",
		SameSite: cookieSameSite(environment),
		// MaxAge matches the JWT TTL so the cookie and token expire together.
		MaxAge: int(DefaultSessionTTL.Seconds()),
	})
}

// ClearSessionCookie removes the aithne_session cookie from the client.
// Domain, Secure, and SameSite must match the attributes used in SetSessionCookie;
// a mismatch would cause the browser to treat the clear as targeting a different
// cookie, leaving the original session cookie intact.
func ClearSessionCookie(w http.ResponseWriter, environment string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "aithne_session",
		Value:    "",
		Domain:   cookieDomain(environment),
		Path:     "/",
		HttpOnly: true,
		Secure:   environment != "development",
		SameSite: cookieSameSite(environment),
		// MaxAge: -1 sends Max-Age=0, instructing the browser to delete the cookie.
		MaxAge: -1,
	})
}

// IdPSessionCookieName is the name of the long-lived IdP session cookie (ADR-0003 §1).
const IdPSessionCookieName = "aithne_idp_session"

// SetIDPSessionCookie sets the long-lived IdP session cookie (ADR-0003 §1).
// Cookie attributes mirror SetSessionCookie (same Domain/Secure/SameSite rules)
// but MaxAge is set to the IdP session lifetime rather than the JWT TTL.
// The raw token value is the random token generated by store.CreateIDPSession.
func SetIDPSessionCookie(w http.ResponseWriter, rawToken, environment string) {
	http.SetCookie(w, &http.Cookie{
		Name:     IdPSessionCookieName,
		Value:    rawToken,
		Domain:   cookieDomain(environment),
		Path:     "/auth/remint", // restrict to the re-mint path — no reason to send it elsewhere
		HttpOnly: true,
		Secure:   environment != "development",
		SameSite: cookieSameSite(environment),
		MaxAge:   int(store.IdPSessionTTL.Seconds()),
	})
}

// ClearIDPSessionCookie removes the aithne_idp_session cookie from the client.
// Attributes must match SetIDPSessionCookie to target the same cookie.
func ClearIDPSessionCookie(w http.ResponseWriter, environment string) {
	http.SetCookie(w, &http.Cookie{
		Name:     IdPSessionCookieName,
		Value:    "",
		Domain:   cookieDomain(environment),
		Path:     "/auth/remint",
		HttpOnly: true,
		Secure:   environment != "development",
		SameSite: cookieSameSite(environment),
		MaxAge:   -1,
	})
}
