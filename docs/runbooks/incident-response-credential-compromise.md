# Runbook: responding to a compromised credential

**Audience:** the operator with admin access to `lucos_aithne` (currently lucas42 only in
production).

**Two different scenarios — pick the right one.** The response differs significantly:

| Scenario | What's compromised | Effect |
|---|---|---|
| **A** | An agent `client_secret` (machine key) | Attacker can mint tokens as that agent |
| **B** | The signing key material (`SIGNING_KEK` or the SQLite DB) | Attacker can forge tokens as *anyone* |

Scenario B is more severe. Do not conflate them — the remediation that helps in B
(rotating the signing key) is actively harmful in A.

---

## Scenario A — Compromised `client_secret`

### What's happening

An attacker holding the raw `client_secret` can call `POST /oauth2/token` with the
agent's slug as `client_id` to mint fresh short-lived JWTs. If they keep minting, they
have continuous access to whatever scopes the agent holds. A captured JWT (e.g. found in
a log) gives at most 15 minutes; a captured *secret* is indefinite until revoked.

### Step 1 — Revoke the credential and grant immediately

Both can be done via the admin UI or the API. Do step 1 before anything else.

**Via the admin UI** (if you have a browser session):

1. Go to `/admin/agents?slug=<agent-slug>`.
2. In the **Machine Keys** table, click **Revoke** next to the compromised key. Note the
   credential ID (e.g. `abc123…`) from the table — you may need it for audit.
3. In the **Grants** table, click **Revoke** next to each active grant for this agent.

**Via the API** (if you have a JWT with `aithne:admin` scope):

```sh
# Revoke the machine_key credential:
curl -s -X DELETE https://aithne.l42.eu/admin/machine-keys/<credential_id> \
     -H "Authorization: Bearer <your-admin-jwt>"

# Revoke each active grant for this agent:
curl -s -X DELETE https://aithne.l42.eu/admin/grants/<grant_id> \
     -H "Authorization: Bearer <your-admin-jwt>"
```

To list credential and grant IDs if you don't have them:

```sh
# Resolve the agent's principal_id:
curl -s https://aithne.l42.eu/admin/agents \
     -H "Authorization: Bearer <your-admin-jwt>" \
  | jq '.[] | select(.slug=="<agent-slug>")'

# List machine keys (all, including revoked):
curl -s https://aithne.l42.eu/admin/agents?slug=<agent-slug> \
     ...
# (Easier to use the UI page /admin/agents?slug=<agent-slug> to read the IDs.)
```

### Step 2 — Understand the effective lockout window

After step 1, **the attacker cannot mint any new tokens**. However, any JWT already
minted before the revocation remains cryptographically valid:

- Up to **15 minutes** from when it was minted (the `DefaultSessionTTL`).
- Consumers cache the JWKS for up to **5 minutes**, so verification continues even after
  the token has technically expired on some consumer clocks.

**Worst-case effective window: ≤20 minutes from the time you revoke.**

This is a fundamental property of the stateless JWT design (no per-request callback to
aithne) and cannot be shortened in scenario A. Downstream services cannot be notified;
they will naturally stop accepting the old tokens once the TTLs expire.

If 20 minutes is unacceptable for a specific incident, escalate — the only way to
shorten the window would be to temporarily bypass JWKS caching in every affected
consumer, which is an out-of-band intervention.

### ⚠ Do NOT rotate the signing key

It is tempting to reach for `POST /admin/rotate-signing-key` to "invalidate everything
immediately." **This does not help in scenario A and causes collateral damage:**

1. After rotation, `ListVerificationKeys()` still returns the *old* key for **30 minutes**
   (the `VerificationWindow`), so the attacker's existing tokens remain verifiable anyway.
2. Consumer JWKS caches add another 5 minutes on top.
3. Meanwhile, every human session and every other agent's token is immediately
   invalidated — all agents must re-mint, all users must log in again.

Signing-key rotation does not shorten the revocation window in scenario A. It only
expands the blast radius.

(Signing-key rotation IS appropriate in scenario B — see below.)

### Step 3 — Provision a replacement credential (when ready to restore access)

After the incident is contained and you're confident the compromise is understood:

1. In the admin UI (`/admin/agents?slug=<agent-slug>`), click **Provision new key**.
   Or via API: `POST /admin/machine-keys` with `{ "agent_slug": "<agent-slug>" }`.
2. Copy the `client_secret` from the response — **it is shown exactly once**.
3. Store it in `lucos_creds` under `lucos_agent / development` (or `production`) as
   `LUCOS_<PERSONA_UPPER>_AITHNE_CLIENT_SECRET`.
4. Re-grant the required scopes via `/admin/grants`.
5. Redeploy the agent so it picks up the new secret from creds.

---

## Scenario B — Compromised signing key material

### What's happening

If an attacker obtains the raw EC private key from the SQLite store (e.g. via DB
exfiltration) **or** the `SIGNING_KEK` (AES-256-GCM key-encryption key stored as an env
var), they can decrypt stored private keys and forge arbitrary JWTs as any principal with
any scope. This is the most severe compromise scenario.

### Step 1 — Rotate the signing key immediately

```sh
curl -s -X POST https://aithne.l42.eu/admin/rotate-signing-key \
     -H "Authorization: Bearer <your-admin-jwt>"
```

This generates a new EC key-pair and retires the compromised key. **New forgeries are
immediately impossible** — the old key can no longer sign tokens.

However, the old key remains in the JWKS verification endpoint for **30 minutes** (the
`VerificationWindow`), so any tokens already forged with the compromised key remain
verifiable for up to ≤35 minutes. Nothing can be done about those within that window.

### Step 2 — Re-key the SIGNING_KEK

The SIGNING_KEK is the AES-256-GCM key that wraps the EC signing private keys stored in
SQLite. Simply updating `SIGNING_KEK` in lucos_creds and redeploying is **not safe** — on
startup, aithne would attempt to decrypt the stored keys with the new KEK, fail (the keys
are still wrapped with the old KEK), and crash.

The `--rekey` subcommand handles this safely: it re-wraps all stored signing keys in place,
so the database is consistent with the new KEK before the service is restarted.

**Stop the service before running `--rekey`.** A running container holds the old KEK in
memory; a concurrent key rotation during re-keying would race on the SQLite write.

```sh
# 1. Generate a new high-entropy KEK value.
NEW_KEK=$(openssl rand -base64 32)

# 2. Stop the aithne container.
docker stop lucos_aithne_web

# 3. Run --rekey against the live database volume.
docker run --rm \
  -v lucos_aithne_credential_store:/data \
  -e SIGNING_KEK=<old-kek-value> \
  -e NEW_SIGNING_KEK="$NEW_KEK" \
  lucas42/lucos_aithne_web:latest --rekey

# 4. If --rekey exits 0: update SIGNING_KEK in lucos_creds to $NEW_KEK.
#    (Only lucas42 can write to the production environment.)

# 5. Restart the service — it picks up the new KEK and starts cleanly.
docker start lucos_aithne_web
```

`--rekey` is atomic: if any key cannot be decrypted with the old KEK, it aborts before
writing anything. If it exits 0, all signing key BLOBs have been re-wrapped and validated
under the new KEK.

### Step 3 — Audit for forged tokens

After the JWKS cache TTL has elapsed (~35 minutes), all old-key tokens are expired.
Review logs for any unusual activity from the ≤35-minute window — unexpected scopes,
access patterns inconsistent with the identified agent slugs, etc.

---

---

## Scenario C — Compromised human passkey (stolen device / compromised authenticator)

### What's happening

A human user's WebAuthn credential is on a device that has been stolen or otherwise
compromised. The attacker can use that device to authenticate at `/auth/login/finish`
and mint new access tokens, and — since ADR-0003 introduced long-lived IdP sessions —
can also silently re-mint access tokens via `/auth/remint` using any IdP session
established before the device was compromised.

### Step 1 — Revoke the WebAuthn credential and IdP sessions

Revoking the credential prevents new WebAuthn logins. Revoking the IdP sessions prevents
the attacker from using the existing IdP-session cookie to re-mint access tokens.
**Both steps are required.** A credential revocation alone does not stop re-mints while
an active IdP session exists.

You need the principal's **internal UUID** for the IdP-session revocation. Resolve it
first if you don't have it:

```sh
# Find the principal_id for a contact ID (human principal):
curl -s "https://aithne.l42.eu/admin/grants?principal_id=..." \
     -H "Authorization: Bearer <your-admin-jwt>"
# (Or look it up in the admin UI: /admin/grants?contact_id=<contact-id>)
```

**Step 1a — Revoke IdP sessions** (closes the re-mint path immediately):

```sh
curl -s -X DELETE \
     "https://aithne.l42.eu/admin/principals/<principal-uuid>/idp-sessions" \
     -H "Authorization: Bearer <your-admin-jwt>"
# Response: {"revoked": N}  where N is the number of sessions invalidated.
```

After this call, any attempt to use `/auth/remint` with an existing IdP-session cookie
returns 401. The re-mint path is closed.

**Step 1b — Revoke the WebAuthn credential** (closes the direct login path):

The human passkey revocation is not yet exposed in the admin UI. Use the API via the
`/admin/machine-keys/` endpoint to revoke the credential:
> _Note: a dedicated human-credential revocation endpoint is tracked separately._
> In the meantime, revoke via a direct DB update or contact lucas42.

### Step 2 — Understand the residual access-token window

After step 1, the attacker cannot mint any new tokens. However:

- Any access token (`aithne_session` JWT) already minted is valid for **up to 15 minutes**
  from when it was issued.
- Consumer JWKS caches add up to **5 minutes** on top.

**Worst-case residual window: ≤20 minutes from the time you complete step 1.**

This is the same window as Scenario A. It is a fundamental property of the stateless JWT
design and cannot be shortened without out-of-band consumer intervention.

### Step 3 — Issue a re-enrolment invite (when ready to restore access)

Once the incident is contained and the user has a new/secure device:

1. Issue a re-enrolment invite via the admin UI (`/admin/invites`).
2. The user completes `/enrol` on the new device, which atomically wipes the old passkey
   and registers the new one.
3. Verify the user can log in via `/auth/login`.

---

## Summary table

| Action | Scenario A: agent secret | Scenario B: signing key | Scenario C: human passkey |
|---|---|---|---|
| Revoke machine_key credential | ✅ Do first | No effect | — |
| Revoke WebAuthn credential | — | No effect | ✅ Do first |
| **Revoke IdP sessions** | — | — | **✅ Do first (step 1a)** |
| Revoke scope grants | ✅ Do first | Partial | Optional |
| `POST /admin/rotate-signing-key` | ❌ Do NOT | ✅ Do first | ❌ Do NOT |
| Effective window before full lockout | ≤20 min | ≤35 min | ≤20 min |
| New tokens minted after remediation | Immediately blocked | Immediately blocked | Immediately blocked |

The two-layer model after ADR-0003: for human principals, revoking the passkey credential
closes the direct login path, but the IdP session (up to 72 h) can still drive re-mints
until explicitly revoked. **Always revoke IdP sessions as part of a human credential
compromise response.**

---

## See also

- [local-verification-contract.md](../local-verification-contract.md) — the consumer
  verification contract, including the eventually-consistent revocation model.
- [bootstrap-first-admin.md](bootstrap-first-admin.md) — break-glass for total admin
  lockout (relevant if the compromise also locked out all admins).
- lucas42/lucos_aithne#162 — the issue that identified this runbook gap.
- lucas42/lucos_aithne#151 — the issue that introduced the `--rekey` subcommand.
- lucas42/lucos_aithne#181 — the issue that added the IdP session + re-mint endpoint.
