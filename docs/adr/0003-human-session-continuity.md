# ADR-0003: Human session continuity — long-lived IdP session with navbar-driven silent re-mint

**Date:** 2026-06-18
**Status:** Proposed (awaiting lucas42 sign-off on this PR)
**Supplements:** [ADR-0001 §3 (the single 15-minute session JWT)](0001-foundational-design.md) — adds the human session-continuity layer it left open.
**Issue:** [lucas42/lucos_aithne#147](https://github.com/lucas42/lucos_aithne/issues/147)

## Context

ADR-0001 §3 defines one session artefact: a short-lived (15-minute) signed JWT, delivered to humans as the `aithne_session` cookie. There is no separate, longer-lived IdP login session. ADR-0001's mitigation for eventually-consistent revocation — *"short TTL + cheap re-mint"* — is genuinely cheap for **agents** (non-interactive client-credentials with a stored secret), but for **humans** "re-mint" means a full WebAuthn biometric/PIN ceremony **every 15 minutes, on every service**. With 11 consumers about to adopt aithne, that asymmetry would set the human UX baseline for the whole estate.

A specific journey makes it concrete (lucas42, #147): a human opens a form, spends ~20 minutes filling it, then POSTs — by which point the 15-minute session has expired. The middleware sees an expired token, returns a top-level redirect to login, the browser follows it as a GET, and the **POST body is lost**.

### Constraint: central only

lucas42 ruled out any approach requiring **per-form** logic (a silent-refresh or stash-and-replay hook in each form) — it doesn't scale across 11 consumers × many forms each. The accepted solution must live entirely in shared/central layers; no individual form or route may change. Lengthening the access-token TTL was rejected too: because consumers verify the JWT locally via JWKS with scopes baked in at mint, a longer *stateless* token widens the revocation window to hours/days on the estate's crown-jewel auth surface.

## Decision

Keep the short (15-minute) access token, and add a **long-lived IdP session** plus a **silent re-mint path driven from the shared navbar**, so the human's session stays alive while they work without any per-form code.

### 1. Long-lived IdP session (new, server-side at aithne)

The standard OIDC split between "you are logged in to the provider" (long-lived) and the short access token. Its finite lifetime cap (hours–days) is the new ceiling on silent continuity: a fresh WebAuthn ceremony is required only when the **IdP session** itself expires, not when the access token does.

### 2. Silent re-mint endpoint (new, at aithne)

Presented with a valid IdP-session cookie, it re-issues a fresh 15-minute `aithne_session` via `Set-Cookie` and returns 200 to a `fetch()` — no top-level navigation, no WebAuthn prompt. It must:

- act **only** on the IdP-session cookie, and **re-validate the principal is still active** (a revoked principal gets no new token);
- allow the credentialed **cross-site** `fetch()` from `*.l42.eu` consumer origins (CORS `Access-Control-Allow-Origin: <origin>` + `Allow-Credentials: true`); the `aithne_session` cookie is already `SameSite=None; Secure` (local-verification-contract §"Human sessions"), so it is sent and can be re-set cross-site;
- be **CSRF-safe** — it mints a session cookie, so it must gate on the IdP session, not on a forgeable cross-site trigger.

### 3. Shared-navbar background keepalive (the central mechanism)

`lucos_navbar` is already loaded on every consumer page (`import 'lucos_navbar'` / `<script src="/resources/lucos_navbar.js">`). It runs a **background keepalive**: a timer firing every N minutes (N < 15) **and** a `visibilitychange`/focus handler, each doing the credentialed `fetch()` to the re-mint endpoint. While any consumer tab is open, the `aithne_session` cookie is continuously refreshed, so it is **never expired at POST time** — the middleware's existing "valid token → proceed" branch fires, and no form changes.

The aithne origin the navbar calls varies by environment (dev→dev, prod→prod via `AITHNE_ORIGIN` — ADR/issue #148), so it is **injected into the navbar by the consumer**, never hardcoded.

### 4. Multi-tab coordination (implementation requirement — lucas42)

Many tabs each run the navbar; they must **not** all refresh independently. Coordinate via a shared signal — a `BroadcastChannel`, or a `localStorage` last-refresh timestamp with leader election — so that when one tab re-mints, the others observe the fresh expiry and skip their own refresh until it is genuinely due. **One refresh per session per interval, regardless of tab count.**

### 5. Optional: global submit-intercept (closes the wake-from-sleep race)

Timers don't fire while a laptop sleeps; a tab woken with an expired cookie has a narrow window before the focus-handler refresh completes. A **single, generic** `document.addEventListener('submit', …)` in the navbar that guarantees a fresh token before any submit proceeds closes this race — still central (one listener in the shared component, no per-form code). Recommended but separable.

## Consequences

### Positive

- **Human SSO that lasts a working session**, not 15 minutes; no biometric prompt mid-work.
- **The access token stays short (15 min)** — the eventual-consistency revocation window for scopes/grants is unchanged (≤15 min, per the local-verification contract). We get continuity *without* widening it, which a longer stateless token would not.
- **Fully central**: forms, routes and consumer middleware are untouched; a consumer gets continuity by loading the current shared navbar. No per-consumer churn beyond a navbar version bump.
- The POST-data-loss journey is resolved structurally (the token is never expired at submit), not patched per form.

### Negative / trade-offs (stated honestly)

- **Two new aithne capabilities** (IdP session + re-mint endpoint) and **non-trivial navbar logic** (keepalive timer, focus handler, multi-tab coordination, optional submit-intercept). Materially more than "bump a TTL".
- **A new session layer to revoke.** The IdP session is a longer-lived artefact; revoking a *principal* must invalidate it (the re-mint endpoint re-checks principal validity, so the next re-mint fails — but a still-valid access token persists ≤15 min). Operators now reason about two layers (access token ≤15 min; IdP session up to its cap); reflect this in the credential-compromise runbook.
- **Cross-site credentialed fetch + `Set-Cookie` reliance.** Depends on the cookie/CORS model (`SameSite=None; Secure`; per-origin CORS allow-list). #148's dev→dev + `AITHNE_ORIGIN` settles this; if that model changed, the keepalive breaks.
- **The wake-from-sleep race** persists unless the submit-intercept (§5) is implemented; without it, a tab woken past expiry can still drop one POST in a narrow window.
- **Idle-with-tab-open extends the session** to the IdP-session cap (the keepalive refreshes even an idle tab). Conventional, but it means "tab open" ≈ "session alive"; the IdP-session cap is the backstop.

## Follow-up (implementation — tracked separately)

The work this ADR defers, each to its own issue:

- **aithne** — long-lived IdP session + silent re-mint endpoint (CORS allow-list + principal re-check + CSRF-safe): lucas42/lucos_aithne#181.
- **lucos_navbar** — background keepalive + multi-tab coordination (+ optional global submit-intercept): lucas42/lucos_navbar#174.
