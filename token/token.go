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

// VerificationWindow is the minimum window for ListVerificationKeys:
// it must be >= DefaultSessionTTL so all tokens in circulation can be verified.
const VerificationWindow = DefaultSessionTTL

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

// SetSessionCookie sets a session cookie containing tokenStr on the response.
// The cookie is scoped to l42.eu (without the leading dot — RFC 6265 makes the
// leading dot optional and Go's http.Cookie drops it on serialisation) so it is
// sent to all *.l42.eu subdomains, enabling estate-wide SSO.
// SameSite=None allows the cookie to be sent in cross-origin iframes
// (e.g. a lucos service embedded on another l42.eu subdomain). SameSite=None
// requires Secure; this function always sets Secure.
func SetSessionCookie(w http.ResponseWriter, tokenStr string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "aithne_session",
		Value:    tokenStr,
		Domain:   "l42.eu", // covers all *.l42.eu subdomains per RFC 6265
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		// MaxAge matches the JWT TTL so the cookie and token expire together.
		MaxAge: int(DefaultSessionTTL.Seconds()),
	})
}
