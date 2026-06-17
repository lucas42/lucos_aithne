# Runbook: bootstrapping (and recovering) the first aithne admin

**Audience:** the operator with host access to where `lucos_aithne` runs (currently
lucas42 only in production).

**What this solves:** aithne's admin surface (issuing enrolment invites, granting
scopes) is gated on an `aithne:admin` passkey session — but the *first* admin has no
passkey, and no passkey can be registered without an invite from the admin surface.
This runbook breaks that cycle. It is also the break-glass for total admin lockout.

The design rationale is in [ADR-0002](../adr/0002-bootstrapping-the-first-admin.md).
This file is the procedure.

> **Depends on** the `--bootstrap-invite` subcommand and the `bootstrapAdmin`
> credential gate (lucas42/lucos_aithne#49 implementation). If those are not yet
> deployed, only the *fallback direct DB insert* at the bottom applies.

---

## Pre-requisites

1. `BOOTSTRAP_ADMIN_CONTACT_ID` is set in lucos_creds for the target environment, to
   the lucos_contacts ID of the intended first admin. Production creds writes are
   lucas42-only.
2. That value is passed through to the container — it **must** appear in the
   `environment:` array of `docker-compose.yml` (bare `- BOOTSTRAP_ADMIN_CONTACT_ID`).
   If it is only in creds/`.env` but not in the array, it never reaches the container
   and nothing below will work.
3. The service is deployed and healthy (`/_info` returns 200). On a startup with the
   env var set, the logs show either `bootstrap: granted aithne:admin to contact …`
   (first run) or a `WARNING: bootstrap admin … has not yet enrolled a passkey …` line.

---

## A. Initial bootstrap (first admin)

1. **Mint the invite** on the host:

   ```
   docker exec lucos_aithne /lucos_aithne --bootstrap-invite
   ```

   It prints a single-use enrolment URL (valid 24h), e.g.
   `https://aithne.l42.eu/enrol?token=…`. The subcommand refuses to target any contact
   other than `BOOTSTRAP_ADMIN_CONTACT_ID`.

   > If your shell session is being audit-logged, keep the URL on the terminal —
   > don't redirect it to a file. The token is a live credential until consumed.

2. **Enrol the passkey.** Open the URL in a browser on the device that holds the
   passkey authenticator, and complete the WebAuthn registration. On success the
   invite is consumed atomically.

3. **Verify.** Log in at `https://aithne.l42.eu/auth/login` with the new passkey and
   confirm you can load `/admin/enrol`. You now hold a working `aithne:admin` session.

4. **Close the bootstrap.** Remove `BOOTSTRAP_ADMIN_CONTACT_ID` from the environment
   (creds + redeploy). This is a hygiene step: the credential gate already prevents the
   grant from being re-seeded now that a passkey exists, but unsetting the var also
   closes the marginal "revoke-before-enrolment" window and silences the startup
   warning. After redeploy, the `WARNING` line is gone.

---

## B. Normal recovery (you still have at least one working admin)

This is **not** a bootstrap case. Use the ordinary flow from ADR-0001: a working admin
issues an invite for the locked-out contact via `POST /admin/invites` (or the
`/admin/enrol` page), and that person completes `/enrol`. Re-enrolment atomically wipes
the old passkey and registers the new one. No host access required.

---

## C. Catastrophic recovery (no working admin at all)

Every admin has lost their passkey, or grants were revoked into a corner. Break-glass:

1. Ensure `BOOTSTRAP_ADMIN_CONTACT_ID` is set (re-add it if step A.4 removed it) and
   **restart / redeploy** the service. Because the bootstrap admin now holds no usable
   WebAuthn credential, the credential gate is *not* tripped, so `bootstrapAdmin`
   re-seeds the `aithne:admin` grant at startup. (This is why the gate keys on
   credential existence, not principal existence — see ADR-0002 decision 2.)
2. Run `docker exec lucos_aithne /lucos_aithne --bootstrap-invite` and complete `/enrol`
   as in section A, steps 1–3.
3. Remove `BOOTSTRAP_ADMIN_CONTACT_ID` again (section A, step 4).

---

## D. Credential store volume lost

The `lucos_aithne_credential_store` volume holds the SQLite database. If the volume is
destroyed (disk failure, accidental `docker volume rm`, etc.):

1. **Restore from backup first.** The volume is backed up by `lucos_backups` (classified
   `recreate_effort: considerable` in lucos_configy). Follow the standard volume restore
   procedure for `lucos_aithne_credential_store`. After a successful restore, the service
   restarts normally — all principals, passkeys, and grants are intact and no bootstrap
   procedure is needed. Proceed no further.

2. **If restore is not possible** (no usable backup, or backup pre-dates the passkey
   enrolment): the database must be rebuilt from scratch. Treat this as a full
   catastrophic recovery — proceed with section C. A fresh database has no principals, so
   `BOOTSTRAP_ADMIN_CONTACT_ID` re-seeds the admin principal and grant at startup, exactly
   as in the initial-setup case.

   Note that re-enrolment registers a new passkey but does not restore grants for other
   principals — those must be re-granted by the recovered admin after enrolment.

---

## Fallback: direct DB invite insert (last resort, no subcommand available)

Only if the `--bootstrap-invite` subcommand is not deployed and you cannot redeploy.
Requires write access to the SQLite store. The token is **not** stored raw — the table
holds `SHA-256(token)` — so you must insert the hash of a token you generate, then visit
the enrolment URL with the *raw* token:

```sh
RAW=$(uuidgen)                                   # the token you will put in the URL
HASH=$(printf '%s' "$RAW" | sha256sum | cut -d' ' -f1)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EXP=$(date -u -d '+24 hours' +%Y-%m-%dT%H:%M:%SZ)
docker exec -i lucos_aithne sqlite3 /data/aithne.db \
  "INSERT INTO enrolment_invites (token_hash, contact_id, created_by, created_at, expires_at)
   VALUES ('$HASH', '<BOOTSTRAP_ADMIN_CONTACT_ID>', 'manual-bootstrap', '$NOW', '$EXP');"
echo "Enrol at: https://aithne.l42.eu/enrol?token=$RAW"
```

This grants nothing the operator did not already have (DB write access is
aithne-admin-equivalent), but it is error-prone — prefer the subcommand. Note it does
**not** create the principal or the grant; on prod those are seeded by `bootstrapAdmin`
at startup (env var set), so ensure the service has started with
`BOOTSTRAP_ADMIN_CONTACT_ID` set before relying on this.
