# Local Verification Contract for aithne Session Tokens

Consumers of `lucos_aithne` session tokens verify them **locally** — no per-request
callback to aithne. This document defines the contract that every consumer must
implement. Implementing it with an off-the-shelf JWKS + JWT library is the recommended
approach.

## Token format

A `lucos_aithne` session token is a compact-serialised **JWS** (a signed JWT):
three base64url-encoded segments separated by `.`.

```
<header>.<payload>.<signature>
```

Signing algorithm: **ES256** (ECDSA P-256, SHA-256).

## Claims

All standard JWT claims below are required unless marked optional.

| Claim | Type | Description |
|---|---|---|
| `iss` | string | Issuer — the HTTPS origin of the aithne service (`https://aithne.l42.eu`). |
| `sub` | string | Subject — the principal's external identity. `lucos_contacts` contact-id for humans; `lucos_agent` personas slug (e.g. `lucos-architect`) for agents. |
| `aud` | string[] | Audience — always `["l42.eu"]`. |
| `iat` | NumericDate | Issued-at timestamp (Unix seconds). |
| `exp` | NumericDate | Expiry timestamp (Unix seconds). |
| `jti` | string | Unique token ID — UUID v4. Consumers MAY use this for deduplication or audit logging. |
| `principal_class` | string | `"human"` or `"agent"`. Use this to distinguish identity types before interpreting `sub`. |
| `scopes` | string[] | Granted capabilities. May be empty (`[]`). A near-empty scope set is the default-deny baseline. |

## Validation rules

Consumers MUST verify ALL of the following in order. A token failing any check must be
rejected with HTTP 401.

### 1. Fetch the public key set (JWKS)

`GET https://aithne.l42.eu/.well-known/jwks.json`

The response is a JWKS JSON object. Cache the key set (recommended TTL: 5 minutes).
Refresh if a token's `kid` header is not found in the cache (the active key may have
been rotated).

### 2. Locate the signing key

Read the `kid` field from the JWT header. Look up the matching key in the cached key
set. If no matching key is found even after a cache refresh, reject the token.

### 3. Verify the signature

Use the matching EC public key (P-256) to verify the JWS signature. Reject if invalid.

### 4. Validate standard claims

| Check | Rule |
|---|---|
| `iss` | Must equal `https://aithne.l42.eu`. |
| `aud` | Must contain `l42.eu`. |
| `exp` | Must be in the future (with clock-skew tolerance — see §"Clock skew"). |
| `iat` | Must be in the past (with clock-skew tolerance). |

### 5. Check `principal_class`

Verify that the `principal_class` claim contains a value you recognise (`"human"` or
`"agent"`). Reject unknown classes.

### 6. Apply authorisation

Authentication (the checks above) proves the token is valid. Authorisation — whether
the principal may perform the requested action — is the consumer's responsibility.

**A sensitive action must never be gated on bare "is there a valid session?"** A machine
principal (agent) would pass that check. Gate on one of:

- **Scope check**: the `scopes` array must contain the required capability string (e.g.
  `photos:read`). Scope strings follow `domain:capability` format; estate-wide
  capabilities are bare (e.g. `render-ui`).
- **Identity check**: the `sub` claim must match the expected contact-id (for per-resource
  ownership checks the consumer knows about and aithne does not).

Both levers may be combined.

## Token TTL and clock skew

Session tokens are short-lived: **15 minutes** from issue. Consumers SHOULD accept a
clock skew of up to **30 seconds** in either direction to tolerate minor host-clock
drift across the estate.

Because tokens are short-lived and stateless, revocation is eventually-consistent: a
revoked grant persists in already-issued tokens until those tokens expire (≤15 min).

## Obtaining the token

### Human sessions

Delivered as a cookie named `aithne_session`, scoped to `l42.eu` (covering all
`*.l42.eu` subdomains), `Secure`, `HttpOnly`, `SameSite=None`. Consumers using
browser-originated requests receive it automatically.

### CSRF protection required for cookie-based state mutation

Because the session cookie uses `SameSite=None`, it is sent on **all** cross-origin
requests — including CSRF-triggered ones. `HttpOnly` protects against XSS reading the
cookie value; it provides no CSRF protection.

Consumers that expose write endpoints (POST / PUT / PATCH / DELETE) and authenticate
via the cookie MUST add CSRF mitigation. Two common approaches:

- **Custom request header**: require a header such as `X-Requested-With: XMLHttpRequest`
  on state-mutating requests. Browsers do not automatically send custom headers on
  cross-origin requests, so this distinguishes legitimate AJAX calls from CSRF-triggered
  form submissions.
- **`Origin` / `Referer` verification**: reject requests where the `Origin` or `Referer`
  header does not match an expected `*.l42.eu` origin.

Consumers that use the JWT as a `Bearer` token in the `Authorization` header (rather
than relying on the cookie) are **not affected** — browsers do not automatically set
`Authorization` headers on CSRF-triggered requests.

### Machine / agent sessions

Obtained programmatically via the OAuth2 client-credentials endpoint (see the
machine-auth ticket for that path). The response includes the JWT string directly.

## Key rotation

aithne rotates signing keys periodically. The JWKS endpoint serves **all keys whose
signatures may be in circulation**: the active key plus recently-retired keys within the
session-token TTL window. This means a token minted with a retired key remains
verifiable for its full lifetime without any consumer action.

Consumers SHOULD NOT hard-code the signing key. Cache the JWKS with a short TTL and
refresh on unknown `kid` as described above.

## Example (Go, using lestrrat-go/jwx/v2)

```go
import (
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwt"
)

// On startup — or cache-miss — fetch the key set:
keySet, err := jwk.Fetch(ctx, "https://aithne.l42.eu/.well-known/jwks.json")

// Per-request verification:
tok, err := jwt.ParseString(tokenStr,
    jwt.WithKeySet(keySet),
    jwt.WithValidate(true),
    jwt.WithIssuer("https://aithne.l42.eu"),
    jwt.WithAudience("l42.eu"),
    jwt.WithAcceptableSkew(30*time.Second),
)
if err != nil {
    // reject — 401
}

// Read claims:
sub := tok.Subject()                       // contact-id or agent slug
pc, _ := tok.Get("principal_class")        // "human" | "agent"
scopesRaw, _ := tok.Get("scopes")          // []interface{} — cast to []string
```

For other languages, use the corresponding JOSE/JWT library (e.g. `node-jose` or
`jose` for Node.js; `PyJWT` + `cryptography` for Python; `nimbus-jose-jwt` for Java).
The validation steps are the same — the library handles the JWS signature; you check
`iss`, `aud`, `exp`, `principal_class`, and `scopes` yourself.
