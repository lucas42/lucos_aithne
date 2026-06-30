# Runbook: restoring the aithne credential store

**Audience:** the operator with host access to where `lucos_aithne` runs (currently
`avalon`, lucas42 only in production).

**What this solves:** the data-loss / host-loss case for the
`lucos_aithne_credential_store` volume — the SQLite database holding **all** estate
authentication state. Loss of new-token issuance and login is estate-wide while aithne
is down, so this is the runbook you want to have read *before* the day you need it.

This is distinct from the two existing aithne runbooks:

- [bootstrap-first-admin.md](bootstrap-first-admin.md) — section D ("credential store
  volume lost") is the *index* into this procedure. Bootstrapping is only needed when
  there is **no usable backup**; with a good backup you restore and skip bootstrap
  entirely.
- [incident-response-credential-compromise.md](incident-response-credential-compromise.md)
  — for a *compromise* (you want to invalidate state), not data loss (you want to
  recover it).

> **This runbook was tested end-to-end on 2026-06-30** (lucas42/lucos_aithne#240): the
> latest production backup was restored into a throwaway scratch instance on `avalon`
> and verified to boot healthy, decrypt its signing key, and serve JWKS. The
> environment-specific gotchas below are the ones that test actually surfaced — not
> hypotheticals.

---

## What's in the volume, and what each part needs to recover

The volume contains a single SQLite file, `aithne.db` (`DB_PATH=/data/aithne.db`). Its
recoverability is **not uniform** — this matters for deciding whether a restore is
sufficient:

| Data | Table | Regenerable? | Needs `SIGNING_KEK`? |
|---|---|---|---|
| WebAuthn passkeys | `credentials` (`type='webauthn'`) | **No** — every human must physically re-enrol | No |
| Machine keys | `credentials` (`type='machine_key'`) | Yes — re-provision per agent | No |
| Principals | `principals` | Partly — recreated on enrolment/bootstrap | No |
| Scope grants | `grants` | Yes — admin re-issues | No |
| Signing key(s) | `signing_keys` | Yes — auto-generated at startup | **Yes** (to *reuse* the existing key) |
| IdP sessions, invites, OIDC | `idp_sessions`, `enrolment_invites`, `oidc_*` | Yes — transient | No |

**Two consequences worth internalising:**

1. **The passkeys are the crown jewels.** They cannot be recreated by us — losing them
   means every human re-enrols an authenticator from scratch (and bootstrapping the
   first admin is itself a runbook step). They are recoverable from the volume backup
   **alone**, with or without the KEK. Protect the backup accordingly.
2. **`SIGNING_KEK` is a co-dependency, but only for the signing key.** The KEK
   (AES-256-GCM, stored as an env var in `lucos_creds`, *not* in the volume) wraps only
   the EC signing private keys. If you restore the volume but the KEK in creds no longer
   matches, aithne **cannot decrypt the restored signing key and will fail to start**.
   A *lost* KEK is survivable — see [§ Lost or mismatched SIGNING_KEK](#lost-or-mismatched-signing_kek)
   — but a *silently-changed* one will bite you mid-restore. Restore the volume and the
   matching KEK together.

---

## Pre-requisites

1. Host access to where aithne runs (`avalon`).
2. The environment variables aithne needs are populated in `lucos_creds` for the target
   environment — in particular `SIGNING_KEK`, `LUCOS_CONTACTS_ORIGIN`, and
   `KEY_LUCOS_CONTACTS`. **aithne fails fast at startup if any required env var is
   missing** (the test instance crashed with `Required environment variable
   LUCOS_CONTACTS_ORIGIN is not set` before it would serve anything). On a fresh host
   rebuild, make sure creds are deployed *before* expecting the restored service to come
   up. Production creds writes are lucas42-only.
3. A backup archive exists. They are produced nightly by `lucos_backups`.

---

## Step 1 — Locate the latest archive

The volume uses the default full-snapshot strategy, so backups are dated `.tar.gz`
archives. On the originating host (`avalon`):

```sh
ls -lt /srv/backups/local/volume/lucos_aithne_credential_store.*.tar.gz | head
```

On any backup host (e.g. `aurora`, reached via the `lucos_backups` container's
ProxyJump path):

```sh
/srv/backups/host/avalon/volume/lucos_aithne_credential_store.<date>.tar.gz
```

Pick the most recent archive from **before** the data loss. Prefer the originating-host
copy where present — it's freshest. (For full location/strategy detail see
[`lucos_backups/docs/restore-runbook.md`](https://github.com/lucas42/lucos_backups/blob/main/docs/restore-runbook.md).)

Each archive contains a single member, `./aithne.db` — no WAL/SHM, so it is a clean
point-in-time snapshot.

---

## Step 2 — (Recommended) dry-run the archive into a scratch volume first

A backup you have never restored is a backup you don't know you have. Before touching
the live volume, prove the archive is good and the DB is intact — **non-destructively**,
into a throwaway volume. This is exactly the 2026-06-30 test procedure:

```sh
ARCHIVE=/srv/backups/local/volume/lucos_aithne_credential_store.<date>.tar.gz

# Extract into a scratch volume (never the live name)
docker volume rm aithne_restore_test 2>/dev/null || true
docker volume create aithne_restore_test
docker run --rm --volume aithne_restore_test:/raw-data \
  --mount src=$(dirname "$ARCHIVE"),target=$(dirname "$ARCHIVE"),type=bind,readonly \
  alpine:latest tar -C /raw-data -xzf "$ARCHIVE"

# Integrity-check and sanity-count the restored DB
docker run --rm --volume aithne_restore_test:/data alpine:latest sh -c '
  apk add --no-cache sqlite >/dev/null 2>&1
  sqlite3 /data/aithne.db "PRAGMA integrity_check;"
  echo "--- principals by class ---";   sqlite3 /data/aithne.db "SELECT class, COUNT(*) FROM principals GROUP BY class;"
  echo "--- credentials by type ---";   sqlite3 /data/aithne.db "SELECT type, COUNT(*) FROM credentials GROUP BY type;"
  echo "--- active signing keys ---";   sqlite3 /data/aithne.db "SELECT status, COUNT(*) FROM signing_keys GROUP BY status;"
'
```

Expect `integrity_check` → `ok`, at least one `webauthn` credential, and exactly one
`active` signing key. If you want to confirm the **KEK can decrypt the restored signing
key** (the failure mode that a row-count check cannot catch), boot a throwaway instance —
see [§ Optional: full scratch-instance boot test](#optional-full-scratch-instance-boot-test).

Clean up when done:

```sh
docker volume rm aithne_restore_test
```

---

## Step 3 — Restore onto the live volume

Use the generic `restore-volume.sh` from `lucos_backups` — it recreates the volume via
Docker Compose so the Compose labels are applied (a bare `docker volume create` omits
them and makes `lucos_backups` tracking crash). Fetch it onto the host:

```sh
wget -O /tmp/restore-volume.sh \
  https://raw.githubusercontent.com/lucas42/lucos_backups/main/restore-volume.sh
chmod +x /tmp/restore-volume.sh

bash /tmp/restore-volume.sh lucos_aithne_credential_store \
  /srv/backups/local/volume/lucos_aithne_credential_store.<date>.tar.gz
```

The script stops the `lucos_aithne` container, removes and recreates the volume with
correct labels (fetching aithne's `docker-compose.yml` from GitHub since production hosts
don't keep it on disk), and extracts the archive. It asks for a typed `yes` first and
warns that existing volume data is permanently deleted — which on the live volume it is,
so be sure you picked the right archive.

> **Severe-incident caveat (from the generic runbook):** the script's volume-recreation
> step needs a pullable aithne image and network to GitHub. On a cold host rebuild with
> the registry unreachable, fall back to the manual procedure's step 3b
> (`docker volume create --label …`) to apply Compose labels without an image. See
> [`lucos_backups/docs/restore-runbook.md`](https://github.com/lucas42/lucos_backups/blob/main/docs/restore-runbook.md).

Then restart the service:

```sh
cd /srv/lucos_aithne 2>/dev/null || true   # compose dir is transient on prod; fetch from GitHub if absent
docker compose up -d
```

After a successful restore, aithne starts normally with all principals, passkeys, and
grants intact — **no bootstrap procedure is needed.** If instead you have no usable
backup, stop here and follow [bootstrap-first-admin.md](bootstrap-first-admin.md)
section C/D (catastrophic rebuild).

---

## Step 4 — Verify

Run these in order. The first three are operator-only and were all exercised by the
2026-06-30 test; the last requires a human with an enrolled authenticator.

1. **Container healthy.** The image is `FROM scratch` (no shell, no `wget`/`curl`
   inside — don't try to `docker exec` debugging tools into it). Use the embedded
   healthcheck status instead:

   ```sh
   docker inspect lucos_aithne --format '{{.State.Health.Status}}'   # want: healthy
   ```

2. **`/_info` checks green.** Curl from the host via the published port (not via
   `docker exec`):

   ```sh
   curl -s http://127.0.0.1:<PORT>/_info | jq '.checks'
   ```

   Want `db`, `signing_key`, and `signing_key_age` all `ok`. `signing_key` confirms an
   active key exists *and is decryptable/servable*; `signing_key_age` confirms it is
   within the rotation window (aithne flags it once older than 35 days — rotation
   interval 30d + 5d grace).

3. **JWKS serves a usable key.** This is the end-to-end proof that the restored signing
   key decrypted under the current `SIGNING_KEK`:

   ```sh
   curl -s http://127.0.0.1:<PORT>/.well-known/jwks.json | jq '.keys[] | {kid, alg, kty}'
   ```

   Want at least one `ES256` / `EC` key with a `kid`. An empty `keys` array means the
   signing key could not be loaded — see [§ Lost or mismatched SIGNING_KEK](#lost-or-mismatched-signing_kek).

4. **A known principal authenticates (human step).** Log in at
   `https://aithne.l42.eu/auth/login` with an enrolled passkey and confirm a session is
   issued. This is the only step an operator cannot perform headlessly — it needs a
   physical authenticator — so it is a manual sign-off, not an automated check.

5. **Backups tracking is happy.** Confirm the restored volume kept its Compose labels
   and `lucos_backups` is not erroring on it:

   ```sh
   docker volume inspect lucos_aithne_credential_store --format '{{ .Labels }}'   # non-empty
   ```

---

## Lost or mismatched SIGNING_KEK

If JWKS serves no key, or aithne logs a signing-key decryption failure at startup, the
`SIGNING_KEK` in `lucos_creds` does not match the keys in the restored DB.

- **If you still have the KEK that was in use when the backup was taken:** put it back in
  `lucos_creds` (production: lucas42 only) and redeploy. The restored keys decrypt and
  JWKS serves again.
- **If the KEK is genuinely lost:** the existing signing keys are unrecoverable, but this
  is survivable. Everything *except* signing-key continuity is intact (passkeys,
  principals, grants are not KEK-encrypted). Generate a fresh KEK and let aithne mint a
  new signing key. Tokens already signed with the old key stop being accepted within
  **≤5 minutes** — the consumer JWKS cache TTL. Note this is *shorter* than a normal
  rotation's window, not the same: a deliberate rotation keeps the old (still-decryptable)
  key in JWKS for the 30-minute `VerificationWindow`, but in KEK-loss the old key cannot
  be decrypted at all, so it is **never served** in the new JWKS. Consumers therefore stop
  trusting old-key tokens as soon as they flush their cached JWKS (≤5 min), regardless of
  the token's own ≤15-minute TTL. Do **not** attempt `--rekey`: it re-wraps existing keys
  and needs the *old* KEK, which by assumption you've lost. Instead treat the signing key
  as destroyed and start clean. (Mechanics of KEK handling: see
  [incident-response-credential-compromise.md § Scenario B](incident-response-credential-compromise.md).)

---

## Optional: full scratch-instance boot test

To validate a restore *including* KEK-decryption and JWKS without touching the live
service — the strongest non-destructive check — boot a throwaway instance against the
scratch volume from Step 2. Note that aithne needs its full required env set or it exits
at startup, so source the values from the live container (the KEK and contacts key are
never echoed):

```sh
getenv(){ docker inspect lucos_aithne --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n "s/^$1=//p"; }
KEK=$(getenv SIGNING_KEK); CORIGIN=$(getenv LUCOS_CONTACTS_ORIGIN); CKEY=$(getenv KEY_LUCOS_CONTACTS)

docker run -d --name aithne_restore_test -p 127.0.0.1:18099:18099 \
  -e PORT=18099 -e SYSTEM=lucos_aithne -e ENVIRONMENT=development \
  -e APP_ORIGIN=http://127.0.0.1:18099 -e DB_PATH=/data/aithne.db \
  -e LUCOS_CONTACTS_ORIGIN="$CORIGIN" -e KEY_LUCOS_CONTACTS="$CKEY" -e SIGNING_KEK="$KEK" \
  --volume aithne_restore_test:/data \
  lucas42/lucos_aithne:<tag>      # use the tag the live container runs

# Wait for health, then check from the host port:
docker inspect aithne_restore_test --format '{{.State.Health.Status}}'   # want: healthy
curl -s http://127.0.0.1:18099/_info | jq '.checks'
curl -s http://127.0.0.1:18099/.well-known/jwks.json | jq '.keys[] | .kid'

# ALWAYS clean up — the scratch instance shares the host's resources:
docker rm -f aithne_restore_test
docker volume rm aithne_restore_test
unset KEK CORIGIN CKEY      # clear the sourced secrets from the shell session
```

Do **not** set `BOOTSTRAP_ADMIN_CONTACT_ID` on the scratch instance (you don't want it
seeding an admin grant), and bind only to `127.0.0.1` (it has no router domain and must
not be publicly reachable). Before doing any of this on a production host, emit a
`plannedMaintenance` Loganne event so it isn't mistaken for an incident.

---

## See also

- [bootstrap-first-admin.md](bootstrap-first-admin.md) — the no-usable-backup path
  (section C/D).
- [incident-response-credential-compromise.md](incident-response-credential-compromise.md)
  — the compromise (not data-loss) case, and `SIGNING_KEK` re-keying mechanics.
- [`lucos_backups/docs/restore-runbook.md`](https://github.com/lucas42/lucos_backups/blob/main/docs/restore-runbook.md)
  — generic volume-restore mechanics, the Compose-label requirement, and `restore-volume.sh`.
- lucas42/lucos_aithne#240 — the issue that identified this runbook gap.
