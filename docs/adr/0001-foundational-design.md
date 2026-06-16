# ADR-0001: lucos_aithne foundational design — passkey authentication and scoped authorisation

**Date:** 2026-06-09
**Status:** Accepted
**Accepted:** 2026-06-09 — approved by lucas42 (PR #2)
**Discussion:** https://github.com/lucas42/lucos_aithne/issues/1

## Context

`lucos_authentication` has done its job but is showing its age. Two structural problems drove the decision to replace rather than evolve it:

1. **It depends on third-party identity providers.** Login is delegated to external OAuth2 providers (Google etc.); the service maps a provider identity to a `lucos_contacts` agentid via `contacts /identify`. There is no first-party credential.
2. **It bundles two unrelated jobs.** Besides authenticating users, it also brokers third-party API tokens (`/apptoken`, trusted `/data` with `appkeys.conf`) so applications can call external APIs. Authenticating a user and storing someone's Google token are different concerns; bundling them is part of why the service is hard to reason about.

Consumers validate sessions by calling `GET /data?token=<token>` **per request** — a credential-introspection-per-request pattern that amplifies load on the auth service and is what forces every integrating service to grow its own brute-force / rate-limiting defences (which CodeQL and `lucos-security` then flag, across a deliberately heterogeneous set of tech stacks).

The wish-list for the replacement (lucos_aithne#1): passkeys; no third-party reliance; a standard protocol usable by off-the-shelf tools; a mechanism for trusted LLM agents to authenticate; expose a `lucos_contacts` ID for the logged-in person; single-sign-on across services within a session (including across `iframe`-embedded services); and migration of all existing consumers.

The machine-principal and authorisation model below was worked through on the ticket over several rounds and signed off by lucas42 on 2026-06-09, along with the eight decisions this ADR records.

## Decision

### 0. Implementation stack — Go

aithne is written in **Go**. Rationale, in priority order for an auth service:

- **Minimal attack surface.** A single static binary in a distroless/minimal image is the right profile for the estate's most security-sensitive service — no interpreter or broad package runtime to harden, no large dependency tree to keep audited.
- **Mature, production-proven building blocks for its core jobs**, so "full OIDC from day one" does not mean hand-rolling protocol-critical code: an OIDC-Provider foundation (e.g. Ory Fosite — which powers the OpenID-certified Ory Hydra — or Zitadel's `oidc`), WebAuthn (e.g. `go-webauthn`), and JWT/JWKS (e.g. `golang-jwt` + `lestrrat-go/jwx`).
- **Alignment with the adjacent security service.** `lucos_creds` — which aithne integrates with for machine-principal keys — is Go; shared idioms reduce risk on that integration boundary.
- **Team muscle memory.** The recent estate (`lucos_firewall`, `lucos_repos`, `lucos_creds`, `lucos_docker_health`) is Go.

**Alternative considered — Node.js** (`node-oidc-provider` is the most complete, OpenID-certified OP library, with `SimpleWebAuthn` and `jose`). Rejected as the default on attack-surface / supply-chain grounds for a security service and on estate alignment — but it is the fallback if assembling a correct OP on the Go foundations proves materially harder than expected. (Decided by the architect, inviting override; the choice gates the scaffold ticket lucas42/lucos_aithne#3.)

### 1. Self-hosted OpenID Provider — full OIDC from day one

`lucos_aithne` is its own OpenID Provider (OIDC/OAuth2): standard discovery, authorization, token, userinfo and JWKS endpoints. Identity is proved by a passkey we verify ourselves — satisfying *"standard protocol usable by off-the-shelf tools"* and *"no third-party reliance"* simultaneously.

**Full OIDC (authorization-code flow) is a day-one requirement, not a later phase.** It is how off-the-shelf tools integrate, and how any system we choose to run on a *separate domain* (outside `l42.eu`) authenticates. Internal lucos services *may also* consume the lightweight shared session token (§3); both paths coexist.

### 2. Human authentication — WebAuthn passkeys

The login ceremony lives only in aithne. Passkeys are phishing-resistant, first-party, and need no shared secret or third party. **The WebAuthn RP ID is `l42.eu`** (the registrable parent), not the service subdomain — so the login origin can move within `l42.eu` (e.g. `aithne.l42.eu` → `auth.l42.eu`) without invalidating every registered passkey.

### 3. The session token — short-lived signed JWT, verified locally

Both the human and machine paths yield the *same artefact*: a short-lived **signed JWT**. It carries:

- **principal class** — `human` / `service` / `agent`;
- **identity** — a `lucos_contacts` ID for humans, the agent-registry slug for agents, or (for services, if/when migrated — §4) the `lucos_configy` system code; typed by principal class. aithne never mints identities of its own;
- **granted scopes** (§6).

It is set as a cookie on `.l42.eu` for same-site SSO. Services verify it **locally via JWKS** — no per-request callback to aithne. This replaces the `/data?token=` introspection pattern and removes the amplification/brute-force surface (see §"Rate-limiting").

### 4. Principal and credential model — aithne-owned

aithne owns the credential store (WebAuthn public keys, machine keys) and a principal registry. **aithne mints no identities of its own — this is an architectural stance, not an omission.** Every principal's identity is issued by an external authority, and aithne owns only the *credential* bound to it. There are exactly three identity authorities: `lucos_contacts` (humans), the agent registry (AI agents), and `lucos_configy` system codes (services).

- **Humans MUST have a `lucos_contacts` entry**, and the human principal carries that contact-id. Invariant: no human is granted access without being a contact ("if they're not a contact of mine, why would I be giving them access to my stuff?").
- **AI agents are not `lucos_contacts`.** An agent principal's identity is the **canonical agent-registry identifier — today the `lucos_agent` `personas.json` slug** (e.g. `lucos-architect`) — *referenced*, not freshly minted. This mirrors the human model: identity authority is always external to aithne (`lucos_contacts` for humans, the agent registry for agents), and aithne owns only the credential. aithne captures the slug when an agent's credential is provisioned and does **not** take a runtime/build dependency on `personas.json`, so that file's format can evolve freely. The id is carried in the session under the `agent` principal class, kept distinct from human contact-ids by class + type.
- **Non-AI service principals (e.g. `lucos_root`) are deliberately *not* given an aithne-native identity.** Short term they remain on `lucos_creds` linkedCredentials (the existing M2M mechanism) and are not aithne principals at all. If they are ever migrated to aithne (see the parked M2M-convergence under Consequences), they will be identified by their **`lucos_configy` system code** — never a minted id. This closes the one place the model could otherwise have grown a bespoke aithne identity registry.

### 5. Machine and agent authentication — OAuth2 client-credentials

A non-human principal acquires a session **non-interactively** via the OAuth2 client-credentials grant. The long-lived key lives in `lucos_creds` (per-env, rotatable), injected into the principal's environment at deploy; it is exchanged at runtime for a short-lived session. **The session is never stored in creds** — so there is no runtime creds dependency on the hot path, and a dropped session is cheap to re-mint. A machine session validates *identically* to a human session (backends need no second auth path) but is scoped least-privilege (§6).

Day-one, the non-human principal on this path is the **AI agent** (agent-registry identity, §4). **Service principals (e.g. `lucos_root`) deliberately stay on `lucos_creds` linkedCredentials short-term** rather than acquiring aithne sessions — consistent with the parked M2M-convergence; a future migration would use this same grant with the service's `lucos_configy` system code as identity.

> **Amendment (2026-06-16, [lucas42/lucos_arachne#636](https://github.com/lucas42/lucos_arachne/issues/636)): agent principals are per-agent.** Each AI agent is its **own** aithne principal, identified by its `personas.json` slug (e.g. `lucos-architect`) per §4 — there is **no shared fleet principal**. A single `lucos_agent` identity would collapse the per-principal scope, audit, and revocation §6 requires: a leaked shared secret would compromise the whole fleet, and grants and audit could not distinguish one agent from another. Each agent's OAuth2 `client_secret` lives in `lucos_agent/development` (`lucos_creds`) as **`LUCOS_<PERSONA>_AITHNE_CLIENT_SECRET`**, mirroring the existing per-agent `LUCOS_<PERSONA>_PEM` convention; the `client_id` is the slug itself, derived from the agent's own identity at runtime (no separate variable, and — consistent with §4 — no aithne runtime dependency on `personas.json`).

### 6. Authorisation — easy authentication, hard authorisation

Authentication is made easy and uniform; **authorisation is the real gate.** Scopes decompose into three concerns that live in different places:

- **Vocabulary** — the set of valid `domain:capability` scope strings. Central, neutral registry (§7).
- **Grant** — "principal P is granted scope S in environment E". Central, in aithne: **default-deny, human-gated, auditable, per-env, revocable**. The grant is stamped into the signed session. This is the crown jewel of the system.
- **Enforcement** — does the presented scope permit *this* action? **Per-backend** — only the service knows what its actions mean. aithne makes an authenticated, scoped *assertion*; the backend makes the authorisation *decision*.

A fresh session resolves to a **near-empty default-deny scope** — it authenticates fine but can do almost nothing until capability is granted one named scope at a time. Backends have two complementary levers: **scope-based** (capabilities; the only safe lever for non-human principals) and **identity-based** (gate on contact-id for per-resource ownership aithne need not know about). **A sensitive action must never be gated on bare "is there a valid session?"** — a machine principal would pass; gate on scope or contact-id.

This supports lucas42's agent use-cases directly: agents may hold **narrow production scopes** (there is no "dev-only" global rule), and a dev-environment session may carry a coarse `render-ui` scope (GET, not POST/mutation) so an agent such as `lucos-ux` can snapshot rendered pages — including forms, and confirmation pages reached only via a form submission — that it would not be permitted to act on in production.

### 7. Scope vocabulary — a dedicated repo, published as a docker image, consumed at build-time

The scope vocabulary is **issuer-agnostic** (both aithne and `lucos_creds` issue scoped credentials), so it lives outside both. It is a **new repository** holding a YAML file of valid `domain:capability` strings (a flat allowlist — the file *is* the set of valid scopes), namespaced by **resource/capability domain** rather than by owning service: a capability often spans services (e.g. `photos:add` is satisfied by `lucos_photos`, the Android app, and a future uploader) and some are genuinely estate-wide and sit **bare** (e.g. `render-ui`, `webhook`). It is **published as a docker image** through the existing docker publish flow (semantic versioning for free). Both `lucos_aithne` and `lucos_creds` pull it in at **build-time** (e.g. `COPY --from` the published image) — **no runtime polling, caching, or retries**.

`lucos_creds` linked-credential scopes (currently character-class-validated freetext) are aligned to this vocabulary. Putting the registry in its own repo also lets it carry its own PR-approval policy (lucas42's approval required on every vocabulary change).

> **Amendment (2026-06-10, [#52](https://github.com/lucas42/lucos_aithne/issues/52)):** aithne keeps `//go:embed scopes.yaml` — the vocabulary is compiled **into the binary** — but **no stub is committed to this repo**. `scopes.yaml` is git-ignored and fetched from canonical before *every* compile: the image build `COPY --from`s it before `go build` (as before), and the CircleCI test job and local dev extract the same digest-pinned file from the `scratch` `lucos_auth_scopes` image via `docker create` + `docker cp` (a pre-compile step / `go generate`), reading the image reference from the Dockerfile. The vocab image is pinned as a **named build stage** — `FROM lucas42/lucos_auth_scopes:<tag>@sha256:… AS scopes`, with `COPY --from=scopes /scopes.yaml ./` — so the pin lives in exactly one place **and stays Dependabot-tracked**: Dependabot parses `FROM` but not `COPY --from` (dependabot-core#5103), and only bumps a pin that carries a **tag *and* digest**, so the `FROM …:tag@digest AS scopes` form is what receives automated update PRs — a bare `COPY --from=image@digest` (today's form) gets none. (An `ARG`-based pin is *not* an option: ARG indirection in `FROM` is unsupported and silently drops the dependency.) lucas42 directed removing the committed stub so there is **one canonical source and no in-repo copy to diverge**; embed-in-binary is retained deliberately — the vocab travels inside the self-contained static binary, so there is **no runtime file dependency and no startup failure mode**. §7's "build-time, no runtime polling" decision is unchanged. The alternative — dropping the embed and reading the file at startup — was considered and rejected: it avoids a pre-compile fetch but weakens the build-time coupling and adds a startup-read failure path, not a trade worth making for the estate's most security-sensitive binary. The cost accepted instead: `go build`/`go test` need the file fetched first (trivial in CI; a `go generate` step locally). A drift-enforcing CI check (the original instinct, recorded in #52) is unnecessary once there is no committed copy; the only thing that must stay consistent is the digest pin, which lives in one place.

### 8. Migration and the third-party-token split

- **Third-party token brokering is split out of authentication entirely.** aithne is identity-only; the `/apptoken` role leaves the auth service. The impact (what consumes it today) is audited separately and handled case-by-case.
- **Migration is incremental.** Stand aithne up alongside `lucos_authentication`; migrate the ~12 consumer repos one at a time (both services live during the window); then decommission. No backwards compatibility is required. Because the new contract is standard JWT + JWKS, each consumer uses an off-the-shelf library for its own language — no bespoke shared library across the polyglot estate.

### Rate-limiting — answering the brute-force concern

The structural fix for *"can we centralise rate-limiting?"* is **not** to redirect everyone to a central checker, but to **remove the per-backend credential check**. Local JWKS verification means a backend validates a session by checking a signature it already holds the public key for — there is nothing to brute-force and nothing to amplify against. Login and token-minting rate-limiting then live on exactly one system (aithne) by construction. Volumetric DoS is a router concern (`limit_req`) and is out of scope here.

The estate-wide default-deny firewall is now enforcing (lucas42/lucos#182), so backend ports are reachable only via the router. Identity is asserted by the **signed session**, not a plaintext `X-Lucos-Contact-Id` header — so an actor with SSH access to a host (including an over-eager agent) cannot forge identity against another system by connecting directly to an internal port: forging identity requires the signing key, not a network position.

## Consequences

### Positive

- One protocol family (OAuth2/OIDC), standard and off-the-shelf-compatible; no third-party dependency for authentication.
- Local verification kills the introspection-amplification and per-service brute-force surface, and centralises rate-limiting onto aithne by construction.
- Default-deny central grant gives a single auditable answer to "what can principal P do?", and makes narrow agent access (dev *and* prod) safe to hand out.
- Signed, scoped sessions mean on-host network position cannot forge identity or widen scope.
- **A brief aithne outage does not break already-authenticated requests** — backends verify locally, so only new logins and token mints fail while aithne is down. This materially softens the single-point-of-failure that a central auth service would otherwise be.
- **aithne is a credential/session authority, never an identity registry.** Every principal identity is externally owned (`lucos_contacts` / agent registry / `lucos_configy` system codes), so there is no bespoke identity store inside aithne to maintain, secure, or keep in sync — a clean boundary that also makes "who is this principal, really?" answerable from a system that already owns that fact.

### Negative / costs

- ~12 consumers to migrate across 6+ languages; a transition window with two auth services live.
- The scope vocabulary is **build-time coupled** — changing it requires a rebuild + redeploy of aithne and creds to take effect. Accepted deliberately: vocabulary changes are rare and should be deliberate, and it removes any runtime dependency on the registry.
- Stateless JWTs make **revocation eventually-consistent** — a revoked grant persists until the current short-lived token expires. Short TTL + cheap re-mint mitigates; instant revocation, if ever needed, is a later narrow addition (a targeted callback) rather than the default.
- **Two M2M scope-bearing mechanisms coexist** — creds' direct-key validation and aithne sessions. Convergence is deliberately parked (it would bloat the migration). The design keeps the door open: shared scope vocabulary, the long-lived key already creds-held, and one common token format — so a future where aithne signs creds-held grants reuses the same verification path.
- aithne is on the login/mint hot path and must be reliable; its availability budget matters even though per-request verification does not depend on it.
- Agent principal identity references the `lucos_agent` `personas.json` slug as a **stable external identifier**. `personas.json` is acknowledged ad-hoc and is slated for replacement by something more structured; the constraint this places on that future work is that **agent slugs must remain stable** (or aithne's agent principal records need migrating in step). Recorded here so the replacement honours it. The same stability expectation applies to `lucos_configy` system codes should service principals ever be migrated onto aithne.

### Follow-up actions

Tracked as separate issues (raised alongside this ADR):

- Scaffold the service + register in configy + apply repo settings.
- Principal & credential store (aithne-owned binding model).
- Session-token spine: signed JWT + JWKS + local-verification contract.
- WebAuthn passkey login ceremony.
- OIDC/OAuth2 protocol endpoints (full OIDC).
- Machine/agent client-credentials path.
- Scope-grant authority (default-deny grant store + admin surface).
- Admin-invite enrolment flow (= account recovery).
- Create the scope-vocabulary registry repo.
- Align `lucos_creds` scopes to the shared vocabulary.
- Audit the third-party-token-brokering split-out.
- Migrate `lucos_authentication` consumers (tracking).

### Alternatives considered

- **Every internal service a full OIDC relying party** — more textbook, but a far heavier migration for a same-domain estate. Rejected as the default; OIDC remains supported for off-domain and off-the-shelf consumers.
- **Scope vocabulary served by `lucos_configy` at runtime** — rejected in favour of a build-time docker image (lucas42's preference), which avoids runtime polling/caching/retries and gets semver + an independent approval gate for free.
- **Trusted `X-Lucos-Contact-Id` header behind the firewall** — rejected; forgeable by anyone with on-host/loopback access. The signed session replaces it.
- **≥2 registered passkeys, or recovery codes, for account recovery** — rejected. Recovery is **admin re-enrolment only**, and enrolment and recovery are the *same* admin-invite flow.
