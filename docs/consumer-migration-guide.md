# Consumer migration guide: moving the estate to aithne auth

How the lucOS estate migrates its services from `lucos_authentication` to **aithne**. This is a **bulk migration** — the consumers are moved together as one coordinated rollout, not one service at a time on independent schedules — so it's organised as estate-wide prerequisite passes plus a repeated per-consumer unit applied across all of them at once.

It complements — and does not duplicate — the two reference documents:

- **[local-verification-contract.md](local-verification-contract.md)** — the precise token verification rules (JWKS, claims, validation, authorisation levers).
- **[ADR-0001](adr/0001-foundational-design.md)** — the model (passkeys, scopes, default-deny, no shared library).

**Canonical worked example:** `lucas42/lucos_arachne` (`explore/src/server/auth.js` middleware). Every consumer mirrors this.

> **Scope of this guide.** It covers migrating **human session auth** — the thing `lucos_authentication` actually did. It deliberately does **not** cover machine/agent credentials: `lucos_authentication` had no equivalent, so nothing migrates across on that axis. A service that needs to *call* other services as an agent provisions a machine key separately (not part of this migration).

> **Sequencing — the migration runs after the keepalive ships.** Once a consumer requires an aithne session, a human would hit a fresh WebAuthn ceremony every 15 minutes unless the background keepalive exists. So the bulk flip is gated on the session-continuity work landing first: the aithne IdP session + re-mint endpoint (lucas42/lucos_aithne#181) and the navbar keepalive (lucas42/lucos_navbar#174). See [ADR-0003](adr/0003-human-session-continuity.md).

---

## Prerequisite passes (estate-wide, once)

### P1. Add every required scope to the vocabulary — first (build-time gate)

Each consumer gates access on a scope string (e.g. `photos:read`). Enumerate the scope every consumer needs, add them **all** to the scope vocabulary (`lucas42/lucos_auth_scopes`) in one pass, and rebuild/redeploy aithne so the scopes exist before any token can carry them. Nothing downstream works until this lands.

### P2. Session continuity is in place

Confirm the keepalive is shipped and deployed: aithne#181 (IdP session + re-mint endpoint) and the `lucos_navbar` release that closed lucas42/lucos_navbar#174. Consumers pin **`lucos_navbar >= 2.2.0`**. With it, human sessions stay alive while a tab is open — no per-form code, no 15-minute re-auth.

### P3. `AITHNE_ORIGIN` convention (plus the optional `AITHNE_JWKS_URL` override)

Consumers take the aithne origin from an injected **`AITHNE_ORIGIN`** env var — never a hardcoded `https://aithne.l42.eu`. It is aithne's **single browser-facing identity** and the sole source of three things: the `iss` value checked during JWT validation, the login-redirect base (`{AITHNE_ORIGIN}/auth/login?next=…`), and — *by default* — the JWKS fetch URL (`{AITHNE_ORIGIN}/.well-known/jwks.json`). Set it **per environment**: development → the **dev** aithne instance (prod's `l42.eu`-domain `Secure` cookie never reaches `http://localhost`), production → prod aithne (lucas42/lucos_aithne#148).

**Why an override is needed.** `AITHNE_ORIGIN` does double duty: *browser-facing* (issuer + login redirect) and *server-facing* (the consumer container fetches JWKS from it). In production the two coincide — `https://aithne.l42.eu` is reachable from browsers and from containers alike — so a single var suffices. In development they diverge: the browser reaches dev aithne at `localhost`, but from inside a bridge-network container `localhost` is the container's *own* loopback, so the JWKS fetch fails (`ECONNREFUSED`) and every token is rejected — a redirect loop back to login. (This affects the arachne canary too, by design; production is unaffected.)

**The optional `AITHNE_JWKS_URL`.** Consumers support an **optional** `AITHNE_JWKS_URL` env var that overrides the JWKS fetch URL — *and nothing else*:

- **Set** → feeds *only* the JWKS-fetch call; point it at an internally-reachable address (the concrete value is a per-environment detail settled at rollout, not part of this contract).
- **Unset** → JWKS URL defaults to `{AITHNE_ORIGIN}/.well-known/jwks.json`. **Unset in production** under normal circumstances — origin and fetch coincide.

**Guard-rail (normative — see local-verification-contract.md §1).** `AITHNE_JWKS_URL` MUST NOT influence the `iss` check or the `?next=` redirect; both continue to derive from `AITHNE_ORIGIN` only. `iss` is an exact-match against the value aithne *minted* (the browser-facing origin), and the redirect must land the user's *browser* somewhere it can reach — neither is a server-side fetch address. Wiring the override into the issuer check silently breaks validation of every legitimately-minted token.

## Per-consumer unit (applied across all consumers in the rollout)

For each consumer, in the same coordinated sweep:

### C1. Add a JWKS / JWT verification library

Local verification only (no per-request call to aithne). Library varies by language — see local-verification-contract.md §"Example" for the Go reference.

### C2. Write the auth middleware — the three-branch pattern

Follow local-verification-contract.md §1–6 for the verification itself, then structure request handling as a **three-branch** decision (the agreed estate-wide pattern, lucas42/lucos_arachne#657 Option 1):

1. **Valid token *and* required scope** → proceed.
2. **Valid token, missing/wrong scope** → render **the consumer's own styled 403** (its existing error view). **Do not** redirect to login — the user is already signed in; re-login yields the same scopeless token and an infinite loop. There is **no** shared aithne "request access" endpoint. The 403 **must name the missing scope**, and surfaces are gated on the **capability the action requires** (not the HTTP method or route group) — see local-verification-contract.md §6 ("Gate on the capability…" and "Name the missing scope…") for the normative rules and constraints.

   **Name ONLY the required scope — never enumerate the scopes the principal currently holds.** This applies to **both** the 403 response body **and** any associated log line. The required scope is a server-side constant from public vocabulary (`lucos_auth_scopes`); echoing the principal's *granted* set instead turns your service's 403 into a cross-service inventory of that principal's access across the whole estate — more disclosure than the grant flow needs, and a self-contradiction hazard (the page says "you lack `X`" while listing `X` among the held scopes). It also risks response/log injection if any user-supplied value is reflected. So: 403 body says *"This action requires the `<domain>:<cap>` scope"* and nothing more; the log line records only that the required scope was absent — **not** `scopes present: [...]`. (Normative: local-verification-contract.md §6, "Name **only** the required scope … never enumerate the principal's *currently granted* scopes". The `lucos_eolas` reference impl shipped a `Scopes granted: [...]` 403 line and a full-scope WARNING log and had to remove both — lucas42/lucos_eolas#324.)
3. **No token, or expired/invalid** → redirect to `{AITHNE_ORIGIN}/auth/login?next=<full URL>`.

   **`next` MUST be a full, absolute, same-origin URL — not a bare path.** Build it server-side from *your own* origin plus the current request path, then URL-encode it. The canonical example (`lucos_arachne` `explore/src/server/auth.js`) does exactly this: `` `${req.protocol}://${req.headers.host}${req.originalUrl}` `` (Django: `request.build_absolute_uri()`).

   **Why a bare path gets stuck:** login happens on *aithne's* origin, and after authenticating aithne redirects the browser to whatever `next` holds. A bare path such as `/admin/` resolves *relative to aithne's origin* (`{AITHNE_ORIGIN}/admin/`), so the user lands back on **aithne**, never returns to your service, and the login round-trip never completes. Only an absolute URL on your own origin sends them back to the right place. (aithne accepts `next` when its host is `l42.eu` / `*.l42.eu`, or a `localhost` origin in development — see `redirect.go`'s `isAllowedRedirect`.)

   **Open-redirect guard (still required):** derive `next` from the **server-side request**, never reflect a caller-supplied `?next=` query parameter — that would let an attacker craft a login URL that bounces the user to an arbitrary external site after authentication. Validate that the URL you assemble is your **own** origin before sending (Django: `url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()}, require_https=request.is_secure())`, falling back to a safe default). aithne re-validates host-side, but the consumer must not emit an off-origin `next` in the first place.

**Authorise on the scope alone — never on `principal_class`.** The access decision in all three branches above is the granted *scope*, applied **identically to every principal** (human or agent). `principal_class` (`human` / `agent`) is for **identity attribution only** — e.g. attaching a contact name for the navbar — and MUST NOT gate access. Gating on it both breaks the uniform model and wrongly closes the door to legitimately granting an agent a scope in production; default-deny by scope is the protection (ADR-0001 §6; `lucos_eolas` ADR-0002 §4).

Wire the two standard exemptions (ADR-0001 / contract doc): `/_info` is exempt from auth, and the `render-ui` dev bypass.

### C3. Set `AITHNE_ORIGIN`

Per P3: add `AITHNE_ORIGIN` to `docker-compose.yml` (`environment:`, array syntax) and store the per-environment value in lucos_creds. Inject it into the navbar too, so its keepalive calls the right aithne. In environments where the container can't reach aithne at the `AITHNE_ORIGIN` address (chiefly local dev), also set the optional `AITHNE_JWKS_URL` (per P3) to an internally-reachable address; leave it unset in production.

**Use these exact lucos_creds values — not just "the dev aithne" in the abstract.** "dev → dev aithne" is satisfied by *any* address that resolves to an aithne, including the prod URL, so spell out the literal values to remove that ambiguity (a prod-URL slip on an earlier consumer is why this is concrete):

| Env | `AITHNE_ORIGIN` | `AITHNE_JWKS_URL` |
|---|---|---|
| **development** | `http://localhost:8039` | `http://172.17.0.1:8039/.well-known/jwks.json` |
| **production** | `https://aithne.l42.eu` | *(unset)* |

- **`AITHNE_ORIGIN` is browser-facing** (issuer + login redirect), so in dev it must be the address the *browser* uses — `http://localhost:8039` (the prod `l42.eu`-domain `Secure` cookie never reaches `http://localhost`). It must **not** be `https://aithne.l42.eu` in dev.
- **`AITHNE_JWKS_URL` is the server-side, in-container fetch address.** In dev the container cannot reach the browser-facing `localhost` (that's the container's own loopback), so it points at **`172.17.0.1`** — the default Docker bridge gateway to the host — on the same dev-aithne port `8039`. (Confirm the gateway if the daemon's default bridge is customised; `172.17.0.1` is the standard default.)
- **In production both addresses coincide** (`https://aithne.l42.eu` is reachable from browsers and containers alike), so `AITHNE_JWKS_URL` is left **unset** and the JWKS URL defaults to `{AITHNE_ORIGIN}/.well-known/jwks.json`.

### C4. Test the middleware

The auth path needs a **real token or a deliberate test double**, not a mock that asserts nothing about the real JWKS/verification interface. Exercise all three branches.

### C5. Audit write endpoints for CSRF protection

`aithne_session` is `SameSite=None`, so the browser sends it on **all** cross-origin requests — including state-mutating `POST`/`PUT`/`PATCH`/`DELETE`. This is a CSRF-posture **regression** from the `lucos_authentication` `auth_token` cookie it replaces: that cookie set no `SameSite` attribute, so modern browsers defaulted it to `SameSite=Lax` and withheld it from cross-origin POSTs. **Do not assume an existing write endpoint is already protected** — under the old cookie it was protected implicitly, and that protection disappears on migration.

Every consumer with **cookie-authenticated** write endpoints MUST add explicit CSRF mitigation — see local-verification-contract.md §"CSRF protection required for cookie-based state mutation" for the full contract. The two accepted approaches:

- require a custom request header (e.g. `X-Requested-With: XMLHttpRequest`) on state-mutating requests, or
- validate the `Origin` / `Referer` header against an expected `*.l42.eu` origin.

A consumer that authenticates its write endpoints with an `Authorization: Bearer` token (rather than the cookie) is **not** affected — browsers don't attach `Authorization` to CSRF-triggered cross-origin requests.

## Verify the rollout

Per consumer, against the running service (not just unit tests): a human with the grant reaches the resource; a signed-in human **without** the grant sees the styled 403 (not a redirect loop); an unauthenticated request is redirected to login; `/_info` stays reachable without auth; a session left open past 15 minutes stays alive (keepalive); and — for any consumer with cookie-authenticated write endpoints — a cross-origin state-mutating request sent **without** the required CSRF header (or with a non-`l42.eu` `Origin`) is **rejected** (C5).

## Rollout safety — halt criterion and rollback

This is a **bulk** flip of the estate's consumers in waves, so decide *before the first wave* what "a wave has gone wrong" looks like and how to back it out. It needs no new monitoring component — the signals already exist.

The failure mode to catch is **quiet**: a mis-ordered grant (scope not yet granted before enforce) or a consumer-side verification bug renders branch 2 — the consumer's own **styled 403**. A signed-in human sees a polite access-denied page and may never report it, so the rollout looks healthy while it silently locks people out. The watch below is what turns that silent failure into an observable one.

### The signal (already exists)

The **lucos_router access log** records per-domain HTTP status codes for every request it proxies — no new instrumentation required. Auth failures show up as **401** (no/invalid token → redirected, but a stuck loop re-hits) and **403** (valid token, missing scope → styled 403). Watch the sum of 401 + 403 for the flipped consumer's domain.

- **Exclude 499** — that's an Nginx client-closed-connection code, not an auth result; counting it produces false alarms (per prior cutover experience).
- The board's `fetch-info` check on the consumer won't catch this: `/_info` is auth-exempt (C2), so it stays 200 green while real user paths 403.

### Halt criterion (per flipped consumer)

1. **Before flipping**, capture a ~10-minute pre-flip **baseline** of 401 + 403 for the target domain from the router access log. Most consumers sit near zero; some have a steady trickle (bots, stale bookmarks) — the baseline is what makes the comparison meaningful rather than absolute.
2. **After flipping**, watch the same domain's 401 + 403 rate. **If it rises materially above the baseline and stays there past one JWKS-cache TTL (~5 min), halt the wave** and roll back the affected consumer(s).

The one-cache-TTL settle window matters: during convergence, consumers holding a token signed just before a key event can momentarily 401/403 on stale-cache timing. Those clear themselves within a cache TTL — a spike that *persists* past it is a real grant/verification fault, not convergence noise.

### Per-consumer rollback

Rollback is a **standard orb redeploy of the consumer's last-green pipeline** — redeploy the previous image, nothing aithne-side to undo.

This is valid because the migration leaves the old `lucos_authentication` `auth_token` cookie path **in place** until the final per-consumer cleanup (lucas42/lucos_aithne#12 step 8). During the flip window both auth paths coexist, so the prior image still authenticates real users while you diagnose. Roll the consumer back, fix the cause (usually a missing or mis-ordered grant — re-check the grant-before-enforce ordering in lucas42/lucos_aithne#12 step 7), and re-flip when the next wave runs.

> Sequencing and wave order are lucas42's call. This section just makes the abort path a written step rather than one improvised mid-incident.
