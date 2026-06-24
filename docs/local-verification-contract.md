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

### Exempt paths — `/_info` MUST NOT require auth

The `/_info` endpoint MUST be reachable without a session token. It is the
unauthenticated monitoring endpoint defined by the estate-wide info-endpoint spec;
`lucos_monitoring` polls it without any credential on a ~60-second heartbeat. If a
consumer applies its auth to `/_info`, the unauthenticated poll fails the auth check
(whatever the exact response) and the monitor records a failing check — a false
"service down" alert — on every cycle.

This failure is invisible to unit tests — auth-middleware tests rarely exercise
`/_info` — so it MUST be caught by convention, not testing.

**Preferred pattern — register unauthenticated routes before the auth middleware.**
Where the framework lets you order route registration (e.g. Express), declare `/_info`
(and any other deliberately-public route, such as static resources) **before** the auth
middleware is added to the chain. The middleware then never sees those requests and
needs no knowledge of which paths are public.

```js
// Node (Express) — lucos_notes src/server/index.js
app.get('/_info', (req, res) => { /* … serve the info payload … */ });
app.use(express.static('./resources'));           // other public routes, also pre-auth
app.use((req, res, next) => app.auth(req, res, next));  // auth applies to everything below
```

This is preferred over an in-middleware path check (`if (req.path === '/_info') …`)
because the latter makes the middleware duplicate the app's routing knowledge: every
time the set of public paths changes, the middleware allow-list must change in lock-step,
and forgetting to is a security hazard (a route silently left unauthenticated, or a
public route that starts demanding auth). Registration order keeps the "is this public?"
decision in one place — the route table.

Where the framework wraps the whole app in a single middleware with no per-route
exemption (e.g. ASGI middleware in Python), the fallback is an explicit `request.path`
check at the very top of the middleware, **before** any token extraction. Keep that
allow-list minimal and in sync with the routes, given the hazard above.

See the
[info-endpoint spec](https://github.com/lucas42/lucos/blob/main/docs/info-endpoint-spec.md)
for what `/_info` must serve.

### 1. Fetch the public key set (JWKS)

`GET https://aithne.l42.eu/.well-known/jwks.json`

The response is a JWKS JSON object. Cache the key set (recommended TTL: 5 minutes).
Refresh if a token's `kid` header is not found in the cache (the active key may have
been rotated).

### 2. Locate the signing key

Read the `kid` field from the JWT header. Look up the matching key in the cached key
set. If no matching key is found even after a cache refresh, reject the token.

**Sanitise `kid` before logging it.** `kid` is an attacker-controlled JWT header field,
and it appears **verbatim** in the error messages of common libraries (`PyJWKClientError`,
`jose`). Logging such a message unmodified lets an attacker inject arbitrary content —
including newlines and terminal control sequences — into the log stream (log injection /
log forging). Before logging any `kid`-bearing value or error message, strip the C0
control characters (`\x00`–`\x1f`) and DEL (`\x7f`). This applies wherever the `kid`
(or a library error carrying it) reaches a log call, not only at this step.
(Requirement from lucas42/lucos_arachne#646.)

### 3. Verify the signature

Use the matching EC public key (P-256) to verify the JWS signature. Reject if invalid.

**Pin the verification algorithm to ES256.** The verify call MUST constrain the accepted
algorithm explicitly — pass `algorithms: ['ES256']` (jose / PyJWT) or the
library-equivalent parameter — and MUST NOT trust the `alg` named in the token header.
A verifier that accepts whatever the header declares is open to an **algorithm-confusion
attack**: e.g. an unsigned `alg: none` token, or coercing the asymmetric verify into a
symmetric one by presenting an `HS256` token whose "signature" is computed by treating the
EC public key bytes as the HMAC secret. The signing algorithm is fixed by this contract
(ES256, §"Token format"); the verifier enforces it, the token never selects it.
(Requirement from lucas42/lucos_arachne#637.)

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

#### Development-only `render-ui` bypass

Consumers SHOULD accept the estate-wide `render-ui` scope as a pass **in development
only**. This lets `lucos-ux` take page snapshots and run local rendering checks without
provisioning a full aithne session per service. It is a deliberate escape hatch, gated
strictly on `ENVIRONMENT == "development"` so it can never weaken production auth.

Add it where the consumer evaluates scopes, after the normal scope check:

```js
// Node
if ((process.env.ENVIRONMENT ?? 'production') === 'development' && scopes.includes('render-ui')) {
    return true;
}
```

```python
# Python
if os.environ.get("ENVIRONMENT", "production") == "development" and "render-ui" in scopes:
    return True
```

Because the guard is environment-scoped, a production deployment (`ENVIRONMENT` unset or
`production`) ignores the `render-ui` scope entirely and falls through to the normal
authorisation check.

## Token TTL and clock skew

Session tokens are short-lived: **15 minutes** from issue. Consumers SHOULD accept a
clock skew of up to **30 seconds** in either direction to tolerate minor host-clock
drift across the estate.

Because tokens are short-lived and stateless, revocation is eventually-consistent: a
revoked grant persists in already-issued tokens until those tokens expire (≤15 min).
For the operator response when a credential is suspected compromised, see the
[incident response runbook](runbooks/incident-response-credential-compromise.md).

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

An agent that needs to **call** a protected service mints its own token via the OAuth2
**client-credentials** grant. This is the client (consumer) side of the contract — the
resource-server verification rules above are unchanged; the token an agent mints is
format-identical to a human login token (`principal_class: "agent"`).

#### Token request

```
POST {AITHNE_ORIGIN}/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<agent-slug>&client_secret=<secret>&scope=<optional>
```

| Field | Value |
|---|---|
| `grant_type` | `client_credentials` (required). |
| `client_id` | The consumer's agent slug — the `lucos_agent` persona slug (e.g. `lucos-architect`). Becomes the `sub` of the minted token. |
| `client_secret` | The machine key provisioned for that agent (see "Provisioning" below). |
| `scope` | **Optional**, space-delimited (RFC 6749 §4.4). Omit to receive the principal's full granted set. If present, each scope MUST be a subset of what's granted — requesting an ungranted scope is rejected with `invalid_scope`. Use it to down-scope a token to least privilege for a specific call. |

#### Success response — `200 OK`, `application/json`

```json
{
  "access_token": "<compact JWS — use as the Bearer token>",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "photos:read media:write"
}
```

`access_token` is the session JWT — present it to downstream services as
`Authorization: Bearer <access_token>`. `expires_in` is the TTL in seconds (900 = 15 min).
`scope` echoes the effective (space-joined) granted set.

#### Error response — RFC 6749 §5.2, `application/json`

```json
{ "error": "invalid_client", "error_description": "invalid client_id or client_secret" }
```

| `error` | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 | The form body could not be parsed. |
| `unsupported_grant_type` | 400 | `grant_type` was missing or not a supported grant (`client_credentials`). |
| `invalid_client` | 401 | Unknown `client_id`, or wrong/revoked `client_secret`. (The two are deliberately indistinguishable — no information leak.) |
| `invalid_scope` | 400 | A requested scope is not granted to this principal in the current environment. |
| `rate_limited` | 429 | Rate limit exceeded for this `client_id` (the limiter is applied per-`client_id`, before any credential lookup). Back off for the number of seconds in the `Retry-After` response header before retrying. |
| `server_error` | 500 | aithne-side failure. |

#### Provisioning the `client_secret`

A machine key is provisioned by an aithne admin via `POST /admin/machine-keys`
(`aithne:admin`-gated) for the agent principal. The raw secret is returned **once** and
only its hash is stored, so it must be saved to `lucos_creds` immediately.

- **Env vars** (namespaced to the called service, matching the `AITHNE_ORIGIN` convention):
  `AITHNE_CLIENT_ID` (the agent slug) and `AITHNE_CLIENT_SECRET` (the machine key).
- **Storage**: in `lucos_creds`. The development secret lives at `lucos_agent/development`
  and is agent-writable; the **production** machine key is minted and stored by `lucas42`
  (agents cannot write production creds).
- Granting the scopes a token carries is a **separate** admin step (`POST /admin/grants`) —
  a freshly provisioned principal with no grants still receives a valid but scopeless
  token, which every default-deny resource rejects. See ADR-0001 §6.

#### Token lifecycle (client side)

Tokens are short-lived (15 min) and stateless — there is no refresh token; you re-run the
grant. Recommended pattern:

1. **Mint on startup** and cache the token in memory with its expiry.
2. **Proactively refresh** shortly before expiry (e.g. at ~12 min) so no request races the
   boundary; **and/or** treat a `401` from a downstream service as a signal to re-mint once
   and retry the call.
3. **Respect `429 rate_limited`.** The token endpoint is rate-limited per `client_id`. If a
   mint returns `429`, do not hot-loop — back off for the `Retry-After` interval before
   retrying. Proactive refresh (step 2) keeps you clear of the limit in normal operation;
   a `429` usually means a retry storm or a misconfigured credential.
4. Never persist the token to disk — re-minting is cheap and bounds the blast radius of a
   leak to the TTL.

## Key rotation

aithne rotates signing keys periodically. The JWKS endpoint serves **all keys whose
signatures may be in circulation**: the active key plus recently-retired keys still
inside the verification window (below). A token minted with a since-retired key remains
verifiable for its full lifetime without any consumer action.

Consumers SHOULD NOT hard-code the signing key. Cache the JWKS with a short TTL and
refresh on unknown `kid` as described in §1.

### Overlap invariant — a retired key stays published long enough

A rotated-out key MUST remain in the JWKS for at least:

```
token TTL  +  consumer JWKS cache TTL  +  clock-drift / propagation margin
```

The "within the session-token TTL window" framing alone is **insufficient** — it omits
the cache-TTL term. A consumer holding a cached key set up to its full TTL after a
rotation must still find the retired key when it finally refreshes, otherwise an
in-circulation token becomes unverifiable. With the recommended values
(token TTL 15 min, cache TTL 5 min, ~10 min drift/headroom) the minimum overlap is
**≈ 30 min**, which is what aithne publishes (`VerificationWindow` in `token/token.go`).
If either TTL changes, this window must change with it.

### Serve last-known-good on a failed refresh (resilience)

Local verification is supposed to keep a brief aithne outage off the request hot path —
but two windows still need a live JWKS fetch: **consumer cold start** (empty cache) and a
**refresh forced by an unknown `kid`** (post-rotation). If aithne's JWKS is unreachable
during either window, a naive client rejects **every** token — re-introducing the single
point of failure local verification was meant to remove, with a blast radius spanning
every consumer that shares the one JWKS origin.

Consumers MUST therefore:

- **Retain the last-known-good key set when a refresh fails.** Do not drop or empty the
  cache on a fetch error. Keep verifying against the keys you already hold.
- **Reject a token only when its `kid` is genuinely absent** from the held key set **and**
  a refresh was attempted (and either failed or returned no matching key) — not merely
  because a refresh failed.
- **Log a failed JWKS fetch distinctly, at `WARNING` level, before any fallback or retry.**
  A JWKS outage during a cold start or a forced refresh otherwise surfaces only as a silent
  401 storm, indistinguishable from "every token is genuinely invalid". Per-token JWT
  decode/validation failures, by contrast, MAY be logged silently or at low severity — they
  are expected noise (expired tokens, stale bookmarks, the occasional forged token). Logging
  the two at different severities is what lets an operator tell a JWKS outage apart from a
  wave of invalid tokens during an incident. (Requirement from lucas42/lucos_arachne#641.)

> **Library caveat.** The common off-the-shelf clients do **not** do this by default:
> `jose`'s `createRemoteJWKSet` (Node) and `PyJWKClient` (Python) **raise** on a failed
> fetch, which surfaces as a 401 for every token in that window. Achieving serve-stale
> requires explicit configuration or a thin wrapper that caches the last successful key
> set and falls back to it on fetch error. Verify your library's failure behaviour rather
> than assuming it degrades gracefully.

## Example (Go, using lestrrat-go/jwx/v2)

```go
import (
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwt"
)

// On startup — or cache-miss — fetch the key set:
keySet, err := jwk.Fetch(ctx, "https://aithne.l42.eu/.well-known/jwks.json")

// Per-request verification:
// NB: pin the signature algorithm to ES256 — see §3 "Verify the signature". Configure
// the key set / verify options so only ES256 is accepted; never let the token's header
// `alg` select the algorithm.
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
