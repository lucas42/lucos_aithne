# Consumer migration guide: moving a service to aithne auth

How to migrate a lucOS service from `lucos_authentication` to **aithne**. This is the end-to-end checklist; it complements — and does not duplicate — the two reference documents:

- **[local-verification-contract.md](local-verification-contract.md)** — the precise token verification rules (JWKS, claims, validation, authorisation levers). The middleware step below points at it rather than restating it.
- **[ADR-0001](adr/0001-foundational-design.md)** — the model (passkeys, scopes, default-deny, no shared library).

**Canonical worked example:** `lucas42/lucos_arachne` (`explore/src/server/auth.js` middleware; `mcp/server.py` agent path).

> The single biggest trap is ordering: the **scope must exist in the vocabulary before** aithne can mint a token carrying it, and **machine-key provisioning needs a running aithne with an `aithne:admin` token**. Do steps 1 and 6 in order or you'll discover them mid-migration.

---

## 1. Add the required scope to the vocabulary — **first** (build-time gate)

A consumer gates access on a scope string (e.g. `photos:read`). That scope must exist in the scope vocabulary (`lucas42/lucos_auth_scopes`) and be built into aithne **before** any token can carry it. Raise the vocab PR, and if the scope is new, ensure aithne is rebuilt/redeployed to pick it up. This is a prerequisite for everything downstream.

## 2. Add a JWKS / JWT verification library

Local verification only (no per-request call to aithne). Library varies by language — see local-verification-contract.md §"Example" for the Go reference (`lestrrat-go/jwx/v2`).

## 3. Write the auth middleware

Follow local-verification-contract.md §1–6 for the verification itself (fetch JWKS → locate key → verify signature → standard claims → `principal_class` → **apply authorisation**). Then structure the request handling as a **three-branch** decision — this is the agreed estate-wide pattern (lucas42/lucos_arachne#657, Option 1):

1. **Valid token *and* required scope present** → proceed.
2. **Valid token, but missing/wrong scope** → render **the consumer's own styled access-denied page (HTTP 403)** using its existing error view. **Do not** redirect to the aithne login — the user is already signed in; signing in again yields the same scopeless token and an infinite loop. There is **no** shared aithne "request access" endpoint; each consumer renders its own 403.
3. **No token, or expired/invalid token** → redirect to the aithne login (`{AITHNE_ORIGIN}/auth/login?next=…`).

Also wire the two standard exemptions (see ADR-0001 / the contract doc): the **`/_info` endpoint is exempt** from auth, and the **`render-ui` dev bypass** for local development.

## 4. Configuration — inject `AITHNE_ORIGIN`, never hardcode (lucas42/lucos_aithne#148)

Do **not** hardcode `https://aithne.l42.eu`. Inject an **`AITHNE_ORIGIN`** env var and derive the JWKS URL, issuer, audience and login-redirect from it. Set it **per environment**:

- **development → the dev aithne instance** (`AITHNE_ORIGIN` points at dev aithne, not prod — prod's `l42.eu`-domain `Secure` cookie will never reach `http://localhost`, so dev must verify against dev aithne);
- **production → prod aithne**.

Wire `AITHNE_ORIGIN` into `docker-compose.yml`'s `environment:` (array syntax) and store the per-environment value in lucos_creds.

## 5. Human session continuity — you get it for free (lucas42/lucos_aithne#147, ADR-0003)

Access tokens are short (15 min). You do **not** need any per-form logic to keep long-form POSTs from losing data on expiry: load the **current shared navbar** (`lucos_navbar`), whose background keepalive silently re-mints the `aithne_session` cookie while a tab is open. Two requirements on the consumer:

- load/refresh to the current `lucos_navbar` version, and
- inject `AITHNE_ORIGIN` into the navbar (per step 4) so its keepalive calls the right aithne.

No form or route changes. See [ADR-0003](adr/0003-human-session-continuity.md) for the mechanism.

## 6. Provision a machine key — only if the consumer makes its *own* server-side calls

For a consumer that itself calls other aithne-protected services (an agent/server principal), not just verifies human sessions:

1. `POST /admin/machine-keys` on aithne (requires an **`aithne:admin`** JWT — i.e. a running aithne and an admin token).
2. Store the returned `client_secret` in lucos_creds at the consumer's **development** scope (shown once).
3. `POST /admin/grants` to grant the required scope to the principal (default-deny: no grant → scopeless token).
4. Wire `LUCOS_<PERSONA>_AITHNE_CLIENT_SECRET` into `docker-compose.yml`.

## 7. Production provisioning → hand to lucas42

Agents cannot write production creds or mint production machine keys. Steps 1 (prod creds value) and 6 (prod machine key + grant) for **production** must be done by lucas42. Prepare everything in development first; hand off the prod steps.

## 8. Test the middleware locally

The auth path differs from mocked unit tests — it needs a **real token or a deliberate test double**, not a mock that asserts nothing about the real JWKS/verification interface. Verify all three middleware branches (proceed / 403 / login-redirect).

## 9. Verify end-to-end before declaring done

Confirm against the running service (not just unit tests): a human with the grant reaches the resource; a signed-in human **without** the grant sees the styled 403 (not a redirect loop); an unauthenticated request is redirected to login; `/_info` stays reachable without auth.
