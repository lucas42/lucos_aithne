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

Confirm the keepalive is shipped and deployed: aithne#181 (IdP session + re-mint endpoint) and the `lucos_navbar` release that closes lucas42/lucos_navbar#174. Consumers pin **at least that navbar version** (record the exact version here once #174 ships). With it, human sessions stay alive while a tab is open — no per-form code, no 15-minute re-auth.

### P3. `AITHNE_ORIGIN` convention

Consumers take the aithne origin from an injected **`AITHNE_ORIGIN`** env var (deriving JWKS URL, issuer, audience and login-redirect from it) — never a hardcoded `https://aithne.l42.eu`. Set it **per environment**: development → the **dev** aithne instance (prod's `l42.eu`-domain `Secure` cookie never reaches `http://localhost`), production → prod aithne (lucas42/lucos_aithne#148).

## Per-consumer unit (applied across all consumers in the rollout)

For each consumer, in the same coordinated sweep:

### C1. Add a JWKS / JWT verification library

Local verification only (no per-request call to aithne). Library varies by language — see local-verification-contract.md §"Example" for the Go reference.

### C2. Write the auth middleware — the three-branch pattern

Follow local-verification-contract.md §1–6 for the verification itself, then structure request handling as a **three-branch** decision (the agreed estate-wide pattern, lucas42/lucos_arachne#657 Option 1):

1. **Valid token *and* required scope** → proceed.
2. **Valid token, missing/wrong scope** → render **the consumer's own styled 403** (its existing error view). **Do not** redirect to login — the user is already signed in; re-login yields the same scopeless token and an infinite loop. There is **no** shared aithne "request access" endpoint.
3. **No token, or expired/invalid** → redirect to `{AITHNE_ORIGIN}/auth/login?next=…`.

Wire the two standard exemptions (ADR-0001 / contract doc): `/_info` is exempt from auth, and the `render-ui` dev bypass.

### C3. Set `AITHNE_ORIGIN`

Per P3: add it to `docker-compose.yml` (`environment:`, array syntax) and store the per-environment value in lucos_creds. Inject it into the navbar too, so its keepalive calls the right aithne.

### C4. Test the middleware

The auth path needs a **real token or a deliberate test double**, not a mock that asserts nothing about the real JWKS/verification interface. Exercise all three branches.

## Verify the rollout

Per consumer, against the running service (not just unit tests): a human with the grant reaches the resource; a signed-in human **without** the grant sees the styled 403 (not a redirect loop); an unauthenticated request is redirected to login; `/_info` stays reachable without auth; a session left open past 15 minutes stays alive (keepalive).
