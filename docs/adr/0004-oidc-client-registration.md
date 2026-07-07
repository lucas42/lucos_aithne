# ADR-0004: Source-controlled OIDC client registration with creds-distributed secrets

**Date:** 2026-07-07
**Status:** Proposed
**Supplements:** [ADR-0001 §6/§7 (scope vocabulary + default-deny)](0001-foundational-design.md), [ADR-0002 (`bootstrapAdmin` reconcile-from-config precedent)](0002-bootstrapping-the-first-admin.md)
**Issue:** [lucas42/lucos_aithne#281](https://github.com/lucas42/lucos_aithne/issues/281)
**Originating assessment:** lucas42/lucos_locations#94

## Context

Today an OIDC relying party (RP) exists **only** as a row in aithne's SQLite `oidc_clients` table, created at runtime via `POST /admin/oidc-clients` (`aithne:admin`-gated). aithne generates a random secret, persists only its hex SHA-256 hash (`store/oidc.go`, `CreateOIDCClient`), and returns the raw secret **once**; the RP operator must capture and stash it manually.

Three problems follow:

1. **Opaque, un-reviewed mutable state.** The registry — including the security-critical `redirect_uris` allowlist — lives only in a runtime table. Nobody reviews a change to it.
2. **Not reproducible.** Lose aithne's volume and every RP integration silently breaks until each client is manually re-`POST`ed.
3. **Manual secret handling** — copy-paste of a raw secret between two services.

lucas42 wants OIDC clients kept **under source control**, with client secrets landing in **lucos_creds automatically** (originating issue: lucas42/lucos_locations#94, where registering the owntracks client surfaced the pain). Both halves are achievable with **existing** in-house primitives:

- **Source-control half** — precedent is `scopes.yaml` (`//go:embed`-ed, parsed at startup) and `bootstrapAdmin` (reconciles a DB grant from startup config, idempotently).
- **Secret-in-creds half** — creds' linked-credential primitive already *generates* a shared secret and distributes it to both sides. `CLIENT_KEYS` (verified in `lucos_creds/server/src/storage.go`) serialises each entry as `clientsystem:clientenv=secret[|scope]`, so it carries the client's identity — aithne (as serversystem) can bind each secret to a client by its system slug.

lucas42 has chosen **option B** (see Decision §4 / Alternatives): lucos_creds generates and distributes the secret; aithne only ever *reads* creds — no new write-edge (comment on lucas42/lucos_aithne#281, 2026-07-07).

## Decision

### 1. A source-controlled, committed client manifest

- A committed `oidc_clients.json` in this repo: a list of `{client_id, client_name, redirect_uris}` objects — **no secrets** — embedded at build with `//go:embed`, exactly as `scopes.yaml` is.
- **Format is JSON, parsed by the standard library `encoding/json` — not YAML.** The scope vocabulary deliberately uses *no* YAML library ("No YAML library is used: … a parsing dependency on the auth service's core path adds unnecessary attack surface", `main.go`; `go.mod` carries no YAML dependency) and hand-parses a *flat* list. A client entry is *structured* (a nested `redirect_uris` array), where a no-library hand-parser is error-prone. JSON gives structured parsing with **zero new dependencies**, honouring the same "no new parser on the auth path" principle. (The originating assessment sketched `oidc_clients.yaml`; I'm recommending JSON for stdlib parsing — the format is overridable at review.)
- **Committed, unlike `scopes.yaml`.** `scopes.yaml` is *fetched* at build from the central scope registry and never committed; the client list is aithne's own data and belongs in aithne's repo. Committing it is the point — it puts the `redirect_uris` allowlist under PR review, and there is no build-time fetch step to arrange (simpler than the scopes flow).
- Convention: **`client_id` = the RP's lucos system slug** (e.g. `lucos_locations`, `lucos_worlds`). This is what lets a `CLIENT_KEYS` entry (`clientsystem:…`) be matched to a manifest client.

### 2. Startup reconcile (idempotent upsert)

- At startup — alongside `bootstrapAdmin`, after `store.Open` and before serving — aithne reconciles the `oidc_clients` table from the embedded manifest plus the secrets in `CLIENT_KEYS`.
- For each **declared** client: read its creds-delivered secret from `CLIENT_KEYS` (matched by `clientsystem` == `client_id`), compute hex SHA-256 (the same scheme used today), and **upsert** `(id, secret_hash, redirect_uris, client_name)`. Implementation adds an INSERT-or-UPDATE store method; today the store has only `CreateOIDCClient` / `DeleteOIDCClient`.
- aithne reads a **new environment variable, `CLIENT_KEYS`** — not currently consumed by aithne. It remains **read-only** against creds; no write capability is introduced.

> **Amendment (2026-07-07, [lucos_aithne#291](https://github.com/lucas42/lucos_aithne/issues/291)): loopback `redirect_uris` are filtered out of non-development reconciles.** See [Amendment — 2026-07-07](#amendment--2026-07-07-environment-scoped-redirect_uri-filtering) below.

### 3. Prune-safety — upsert-only, skip-never-wipe

- Reconcile **never deletes.** It upserts declared clients and leaves any undeclared table rows in place, logged loudly as orphans. Rationale is the creds#333 empty-source lesson: a delete-on-absence loop wipes everything if the manifest is empty/unreadable or `CLIENT_KEYS` is absent at startup — and deleting an OIDC client instantly breaks an RP's login.
- Per-client skips (log, never fail startup): a manifest entry with **no matching `CLIENT_KEYS` secret** is skipped (never half-registered without a secret); an **empty or unparseable manifest** skips the whole reconcile and leaves the table untouched.
- Full declarative pruning (deleting undeclared clients) is a possible future enhancement but is **deliberately not the default**, for the same empty-source safety reason. Removing a client stays an explicit, separate action.

### 4. Secret lifecycle (option B)

- lucas42 creates one linked credential in creds per client: `clientsystem/env => lucos_aithne/env`. creds **generates** the shared random secret and delivers it to both sides — the RP reads `KEY_lucos_aithne`, aithne reads `CLIENT_KEYS`. The only residual manual step is that one-line `=>` link — the familiar estate M2M-credential operation, not a bespoke OIDC `POST`.
- **Rotation:** changing the linked credential rotates the secret → both `CLIENT_KEYS` (aithne) and `KEY_lucos_aithne` (RP) change → a **coordinated aithne + RP redeploy** converges them (the standard creds rotation pattern). Honest note: there is a 401/403 **convergence window** between the two redeploys (one side presenting/holding the old secret while the other has rotated) — the same window as any linked-credential rotation, not specific to this design.

### 5. `POST /admin/oidc-clients` is removed

- The manual `POST /admin/oidc-clients` endpoint is **removed entirely.** The startup reconcile from the manifest becomes the **sole** OIDC-client registration path.
- Rationale (lucas42, PR review): the estate already has a break-glass admin workflow via `BOOTSTRAP_ADMIN_CONTACT_ID`; a second `aithne:admin`-gated admin write-surface adds no value over it and is unnecessary attack surface on the auth service.
- Scope note: only the HTTP admin **endpoint and its route** are removed. The underlying store capability to write a client row remains — the reconcile upsert is built on it.
- Note: `GET`/`POST`/`DELETE /admin/oidc-clients` share one handler/route, so this also removes the online `DELETE` (client revocation/deletion) path. See Consequences → Negative for how revocation is handled afterwards, and Alternatives considered for why a narrow revocation-only `DELETE` was declined.

## Consequences

### Positive
- The client registry — including the `redirect_uris` allowlist — becomes **declarative, PR-reviewed, and reproducible**, self-healing on volume loss. This is the strongest single argument for the change.
- **Zero manual secret handling.** The secret is *generated in* creds; nothing needs creds-write — strictly better than "pushed to creds".
- **No new trust edge.** aithne stays read-only against creds (option B); the estate's auth SPOF gains no automated prod-creds-write.
- Reuses two proven in-house patterns (`//go:embed` + parse; reconcile-from-config) — idiomatic and low-risk.
- **Removes a privileged admin write-surface.** With `POST /admin/oidc-clients` gone (§5), client registration has exactly one path, and the auth service carries one fewer `aithne:admin`-gated mutation endpoint.
- Unblocks lucas42/lucos_worlds#2 (register the lucos_worlds client with no manual secret handling) and reframes lucas42/lucos_locations#94.

### Negative / trade-offs
- aithne now consumes `CLIENT_KEYS` — a small conceptual overlap, repurposing creds' bearer-key plumbing as the distribution channel for an OIDC secret. Legitimate (creds is the estate secret store; a shared OIDC secret is a secret) but worth naming.
- Registering a new client is now **two steps** — add to the manifest (a PR) *and* create the `=>` linked credential (one ssh line) — versus a single `POST`. Both are familiar, reviewable, reproducible estate operations, but it is more steps.
- Upsert-only reconcile means **removing** a client is not automated — a deliberate safety trade (§3).
- **Removing the endpoint removes online *revocation/deletion*, not just registration.** `GET`/`POST`/`DELETE /admin/oidc-clients` are one handler on one route (`main.go`, `oidc.go`), so §5 drops `DELETE` with them. Combined with §3's never-delete reconcile, no HTTP path remains to revoke or delete a client post-merge. Routine secret **rotation** is still available without host access — rotate the linked credential (§4) and the old secret stops validating on the next reconcile/redeploy (deploy-gated, not instant). But **immediate revocation or full client removal** requires host-level DB access (`docker exec` + SQLite) — the ADR-0002 break-glass tier (not a new trust boundary), a step down in friction/auditability from today's scoped, audited API call. A narrow, scoped `DELETE /admin/oidc-clients/{id}` revocation-only path was **considered and declined** in favour of this break-glass tier (see Alternatives considered).
- Secret rotation carries the standard linked-credential **convergence window** (§4).
- Client secrets remain **hex SHA-256 (unsalted)** — unchanged from today; acceptable because the secrets are high-entropy random, but noted as inherited rather than improved.

## Alternatives considered

- **Option A — aithne generates the secret and writes it into creds** (matches the literal "pushed into creds" wording). **Rejected by lucas42:** it gives aithne — the estate auth SPOF — automated prod-creds-write, a new high-value trust edge, for no benefit over the read-only model. Recorded so the rejection is on file.
- **YAML manifest hand-parsed like `scopes.yaml`.** Rejected: the nested structure makes a no-library hand-parser error-prone; stdlib JSON is safer with the same zero-dependency property.
- **Full declarative reconcile (delete undeclared clients).** Rejected as the default on empty-source-safety grounds (§3).
- **A narrow revocation-only `DELETE /admin/oidc-clients/{id}`** (raised by lucos-security and lucos-code-reviewer during review, to preserve an online path to revoke a compromised secret). **Declined:** it would reintroduce exactly the `aithne:admin`-gated admin write-surface §5 removes, against lucas42's stated reasoning (break-glass via `BOOTSTRAP_ADMIN_CONTACT_ID` suffices; no value in a second admin surface). Routine secret revocation is met by cred-rotation (§4); immediate revocation / full removal is the accepted host-DB break-glass tier. Revisit only if an operational need for online revocation emerges.

## Out of scope (explicit)

Extending the same reconcile-from-source pattern to **grants** (`bootstrapAdmin` is the precedent). Human-principal access grants are a different risk profile and a **separable** decision; if adopted later it would supersede lucas42/lucos_locations#95. It is **not** folded in here — flagged as a candidate follow-up only.

## Deferred work (to be ticketed on acceptance)

1. **Implement** `oidc_clients.json` + the startup reconcile (embed, stdlib-JSON parse, `CLIENT_KEYS` match, hash, prune-safe skips, and a store upsert method), **and remove the `POST /admin/oidc-clients` endpoint + its route** (§5) — aithne repo.
2. **Reframe** lucas42/lucos_locations#94 (register the owntracks client) onto the new mechanism.
3. **(Only if lucas42 opts in)** a separate decision for grants-source-control, which would supersede lucas42/lucos_locations#95.

## Amendment — 2026-07-07: environment-scoped `redirect_uri` filtering

Raised by lucos-security ([lucos_aithne#291](https://github.com/lucas42/lucos_aithne/issues/291)) once the first real manifest entry landed ([lucos_aithne#290](https://github.com/lucas42/lucos_aithne/pull/290)): §1 deliberately keeps **one** committed manifest for every environment — there is no dev/prod manifest split — so a client entry legitimately lists both a production redirect_uri and a dev loopback callback (e.g. `http://localhost:8028/oauth2/callback`) side by side. §2's reconcile originally upserted `redirect_uris` verbatim, which meant production would register the loopback redirect_uri too, the moment lucas42 created the production linked credential for that client.

Severity was assessed as low — `HasRedirectURI` is an exact string match (no wildcard repointing), and `handleAuthCodeGrant` unconditionally requires the client secret, so a captured authorization code redirected to a rogue local listener isn't independently redeemable — but it's a real, avoidable widening of production's registered-client surface, and architectural rather than a one-off mistake (it recurs for every future client needing both a prod and dev redirect_uri in the manifest).

**Fix:** `reconcileOIDCClients` now takes `environment` (already available in `main()`, passed the same way as to `bootstrapAdmin`) and drops any `redirect_uri` whose host is loopback (`localhost`, or an IP where `net.IP.IsLoopback()` is true) before upserting, whenever `environment != "development"`. Dropped URIs are logged, never cause the reconcile to fail — consistent with §3's log-don't-fail posture. The single-manifest design (§1) is unchanged; this only narrows what actually reaches a non-development `oidc_clients` row.
