# ADR-0002: Bootstrapping the first admin passkey

- **Status:** Proposed
- **Date:** 2026-06-10
- **Supplements:** [ADR-0001 §6 (authorisation)](0001-foundational-design.md) and its rejected
  *"≥2 registered passkeys / recovery codes"* alternative.
- **Issue:** [lucas42/lucos_aithne#48](https://github.com/lucas42/lucos_aithne/issues/48)

## Context

ADR-0001 settled that account **recovery is admin re-enrolment only**, and that
enrolment and recovery are the *same* admin-invite flow. That flow is sound once
**at least one** admin can wield the `aithne:admin` scope. It says nothing about
how the **first** admin gets a passkey — and that is a genuine chicken-and-egg:

- Minting an enrolment invite requires `POST /admin/invites`, which requires an
  `aithne:admin` session JWT, which requires a registered passkey, which requires
  an invite.
- `BOOTSTRAP_ADMIN_CONTACT_ID` (set in dev + prod) makes `bootstrapAdmin` seed a
  human principal **and** an `aithne:admin` grant at startup — but a grant with
  **zero passkeys is inert**: nobody can log in to use it. lucos-security assessed
  the bootstrap as safe *precisely because* the admin is locked out.

So there is a grant but no key, and no defined, repeatable way to get the first
key in. This ADR defines that procedure and closes two related gaps lucos-security
flagged in the same assessment.

Two facts about the current code ground the decisions below:

1. **The `/enrol` flow needs no admin auth.** An enrolment invite is simply a row
   in `enrolment_invites` (primary key = `SHA-256(rawToken)`; the raw token is
   never stored). `store.CreateInvite(rawToken, contactID, createdBy)` is the
   entire dependency for a working invite — `createdBy` is an audit string only.
2. **The bootstrap grant re-applies on every startup, with teeth.** The unique
   index `idx_grants_active` is partial (`WHERE revoked_at IS NULL`), so a
   *revoked* `aithne:admin` grant does **not** block a re-insert. `bootstrapAdmin`
   therefore **silently resurrects a deliberately-revoked admin grant** on the next
   restart, for as long as `BOOTSTRAP_ADMIN_CONTACT_ID` remains set.

## Decision

### 1. First passkey is seeded by a one-shot `--bootstrap-invite` subcommand — not an HTTP endpoint

A new subcommand of the existing `lucos_aithne` binary:

```
docker exec lucos_aithne /lucos_aithne --bootstrap-invite
```

It opens the same SQLite store, **refuses any contact other than the configured
`BOOTSTRAP_ADMIN_CONTACT_ID`**, calls `store.CreateInvite` for that contact, prints
a single-use, 24h-TTL invite URL to **stdout**, and exits. The operator opens the
URL in a browser and completes the ordinary `/enrol` passkey ceremony. No new
network surface is added.

**Why a subcommand and not an HTTP endpoint** (lucos-security floated a
"one-time bootstrap-enrol code path, self-disabling"): an HTTP path is
network-reachable and would reopen exactly the lockout that makes the bootstrap
safe. The subcommand requires `docker exec` / host access — a trust level that
**already trivially compromises aithne** (read `SIGNING_KEK` from the environment
and forge any token; or write the SQLite store directly). It therefore grants
**zero marginal capability** over a hand DB insert, while being *correct by
construction*: it reuses `CreateInvite`, so there is no hand-hashing of a UUID into
SHA-256 and no hand-written RFC3339 timestamps to get subtly wrong during a
stressful break-glass recovery. lucos-security accepted this reasoning (no-new-
capability, no code change to the trust boundary).

**Why a subcommand and not a standalone script** (the literal "provisioning
script" option): a separate script would duplicate store-open and schema knowledge
and rot out of sync with the DB. A subcommand of the same binary always matches the
deployed schema.

The `contact != BOOTSTRAP_ADMIN_CONTACT_ID` refusal floors the blast radius: the
tool can only ever target the one designated bootstrap/recovery identity, even if
misinvoked.

### 2. `bootstrapAdmin` self-disables once the admin holds a passkey (credential gate)

`bootstrapAdmin` is gated on **"does the bootstrap admin already hold ≥1 WebAuthn
credential?"**. If yes, it is a complete no-op — it does **not** touch grants.

This turns the bootstrap into a true **first-run seed**: it seeds the principal and
grant before the first enrolment, and goes inert afterwards. Crucially, it stops the
revocation-resurrection of fact (2): once the admin has enrolled, a later, deliberate
revocation of `aithne:admin` **sticks across restarts**.

We chose the **credential gate** over the simpler "gate on principal-row exists"
(Option B) because Option B has a catastrophic-recovery failure mode: the principal
row outlives the credentials, so after a stacked failure (passkey *and* grant lost)
the gate stays permanently tripped, `bootstrapAdmin` never re-seeds the grant, and an
operator who runs `--bootstrap-invite` + `/enrol` ends up with a fresh passkey but
**no admin grant** — requiring direct DB intervention. The credential gate handles
this naturally: credentials wiped → count 0 → gate not tripped → grant re-seeded on
the next startup → break-glass recovery works end-to-end.

### 3. A startup warning while the bootstrap is still active

When `BOOTSTRAP_ADMIN_CONTACT_ID` is set, `main` logs a `WARNING` line so the live
state is visible in production logs:

- **set, admin not yet enrolled** (gate not tripped): warn that bootstrap is active
  and that `BOOTSTRAP_ADMIN_CONTACT_ID` should be removed after enrolment.
- **set, admin already enrolled** (gate tripped, self-disabled): warn that bootstrap
  is complete and the env var can now be removed.

(This extends lucos-security's requested single-state warning to both states — the
"already enrolled but env var still set" state is the more common hygiene lapse, and
it is cheap to nag about. The extension is additive, not a contradiction.)

### 4. Removing `BOOTSTRAP_ADMIN_CONTACT_ID` after enrolment is the documented hygiene step

The credential gate (decision 2) is the **primary, structural** protection against
resurrection. Removing the env var after first enrolment is defence-in-depth: it
also closes the one marginal window the credential gate does not — deliberately
revoking the grant *before* the admin has enrolled, where a restart would re-seed it.
The runbook makes this an explicit step.

### 5. The compose file must pass `BOOTSTRAP_ADMIN_CONTACT_ID` through

`docker-compose.yml` uses the bare-list `environment:` syntax, under which a value in
the creds-generated `.env` reaches the container **only if its name appears in the
array**. `BOOTSTRAP_ADMIN_CONTACT_ID` is present in dev creds but is **not** listed,
so it does not currently reach the container and `bootstrapAdmin` cannot fire
(verified against the committed compose; `PORT` is the working counter-example — it
is in `.env`, listed in the array, and reaches the app). The implementation must add
`- BOOTSTRAP_ADMIN_CONTACT_ID` to the array. The variable is optional (the existing
`if adminContactID != ""` guard covers absence), so a bare passthrough is safe and
does not affect the build step (which only sees a dummy `PORT`).

## Recovery taxonomy

| Scenario | Path |
|---|---|
| **Initial bootstrap** (first admin, no passkey yet) | `--bootstrap-invite` subcommand → `/enrol` |
| **Normal recovery** (≥1 working admin still exists) | An existing admin issues an invite via `POST /admin/invites` → `/enrol` (ADR-0001 flow, unchanged) |
| **Catastrophic recovery** (zero working admins) | Break-glass: ensure `BOOTSTRAP_ADMIN_CONTACT_ID` is set and restart (grant auto-re-seeds via the credential gate), then `--bootstrap-invite` → `/enrol`, then unset the env var |

## Consequences

### Positive

- The first admin can be seeded by a repeatable, documented, **correct-by-construction**
  procedure that adds no network attack surface.
- The same subcommand is the break-glass for total admin lockout — and because of the
  credential gate, it recovers the grant as well as the passkey, end-to-end.
- A deliberately-revoked admin grant now stays revoked across restarts.
- The live bootstrap state is visible in logs rather than silent.

### Negative / costs

- ~30 lines of code plus a test, for a path run perhaps once per environment. Justified
  because it is *also* the catastrophic-recovery path, run while already locked out.
- The break-glass depends on host/`docker exec` access, which on the prod host is a
  lucas42-only capability (and setting/unsetting the prod env var is a creds write +
  redeploy, also lucas42-only). This is appropriate for the most privileged credential
  in the estate, but it means recovery cannot be delegated.
- The credential gate re-seeds the grant whenever **all** WebAuthn credentials are
  absent. For the bootstrap admin during recovery that is the desired behaviour; it is
  not a general-principal mechanism (only the single configured bootstrap contact is
  ever seeded).

## Alternatives considered

- **A network-reachable bootstrap-enrol HTTP endpoint, self-disabling on first passkey.**
  Rejected: reopens the lockout that makes the bootstrap safe, and a self-disable gate on
  an HTTP path is a race / a permanently-open door if the admin never enrols or their
  passkey is ever wiped. See decision 1.
- **Hand-written direct DB invite insert (no code).** Rejected as the primary procedure:
  the table stores `SHA-256(token)`, so a hand insert means hand-hashing the token and
  hand-writing timestamps — silently fails on a typo, during the exact moment (locked-out
  recovery) you can least afford it. It remains available as a last-ditch fallback for an
  operator with DB access, but is not the documented path.
- **Gate `bootstrapAdmin` on principal-row existence (Option B).** Rejected: leaves a fresh
  passkey with no grant after catastrophic recovery. See decision 2.
