# Runbook: rotating or migrating the SIGNING_KEK

**Audience:** the operator with production access to `lucos_aithne` (currently lucas42 only).

The `SIGNING_KEK` is the AES-256-GCM key-encryption key that wraps EC signing private keys
stored in SQLite. Changing it requires one of two subcommands:

| Subcommand | When to use |
|---|---|
| `--migrate-kek` | **One-time only** — upgrading from the legacy raw-bytes scheme to SHA-256 derivation (lucas42/lucos_aithne#244). Do not run again after migration. |
| `--rekey` | **All future rotations** — both old and new KEK use SHA-256 derivation. |

If you are unsure which applies, check the deployment history: any instance deployed before
lucas42/lucos_aithne#244 was merged (2026-06-30) will have raw-bytes-encrypted keys and
needs `--migrate-kek` first.

---

## Prerequisites: names and volumes

The running service uses:
- **Container**: `lucos_aithne`
- **Image**: `lucas42/lucos_aithne`
- **Credential volume**: `lucos_aithne_credential_store` (mounted at `/data` inside the container)
- **Binary path inside image**: `/lucos_aithne`

The image does **not** set a Docker `ENTRYPOINT`. Passing `--migrate-kek` or `--rekey`
directly to `docker run` (without the binary path) replaces the default command entirely
and will fail. Always invoke the binary explicitly:

```sh
docker run --rm ... lucas42/lucos_aithne:latest /lucos_aithne --migrate-kek
```

---

## Quote-wrapping trap (silent failure)

`lucos_creds` stores values with surrounding quotes in the `.env` file (e.g.
`SIGNING_KEK="abc123…"`). Docker injects the value **without** the quotes at runtime.

If you copy the `.env` line verbatim and feed the quoted form to `--migrate-kek` or
`--rekey`, the subcommand derives `sha256('"abc123…"')` — a different key than the
container will derive from `sha256('abc123…')`. The migration exits 0, but the redeployed
container cannot decrypt the signing keys and crash-loops.

**Always use the raw (unquoted) value.** The subcommands now detect quote-wrapped inputs
and exit 1 with a clear error, but the safest approach is:

```sh
# Read the raw value from creds (strip surrounding quotes if present):
SIGNING_KEK=$(scp -P 2202 "creds.l42.eu:lucos_aithne/production/.env" /dev/stdout \
  | grep '^SIGNING_KEK=' | cut -d= -f2- | tr -d '"')
```

---

## Option A — One-time migration from raw-bytes to SHA-256 derivation (`--migrate-kek`)

Run this **once** when deploying the version that introduced SHA-256 KEK derivation
(lucas42/lucos_aithne#244). Do not run it again — use `--rekey` for all subsequent rotations.

```sh
# 1. Generate a fresh high-entropy KEK.
NEW_KEK=$(openssl rand -base64 32)

# 2. Read the current raw KEK value from lucos_creds (unquoted).
OLD_KEK=$(scp -P 2202 "creds.l42.eu:lucos_aithne/production/.env" /dev/stdout \
  | grep '^SIGNING_KEK=' | cut -d= -f2- | tr -d '"')

# 3. Stop the service.
docker stop lucos_aithne

# 4. Run --migrate-kek.
#    SIGNING_KEK = old raw-bytes value; NEW_SIGNING_KEK = new sha256-derived value.
docker run --rm \
  -v lucos_aithne_credential_store:/data \
  -e SIGNING_KEK="$OLD_KEK" \
  -e NEW_SIGNING_KEK="$NEW_KEK" \
  lucas42/lucos_aithne:latest /lucos_aithne --migrate-kek

# 5. If it exits 0: update SIGNING_KEK in lucos_creds to $NEW_KEK.
#    (Only lucas42 can write production credentials.)

# 6. Redeploy — do NOT use docker start (it reuses the old baked-in env).
#    The redeployed container will derive sha256($NEW_KEK) and decrypt successfully.
```

---

## Option B — Routine KEK rotation (`--rekey`)

Use for all future rotations after `--migrate-kek` has been run. Both old and new KEK
values are processed via SHA-256 derivation.

```sh
# 1. Generate a fresh high-entropy KEK.
NEW_KEK=$(openssl rand -base64 32)

# 2. Read the current KEK value from lucos_creds (unquoted).
OLD_KEK=$(scp -P 2202 "creds.l42.eu:lucos_aithne/production/.env" /dev/stdout \
  | grep '^SIGNING_KEK=' | cut -d= -f2- | tr -d '"')

# 3. Stop the service.
docker stop lucos_aithne

# 4. Run --rekey.
docker run --rm \
  -v lucos_aithne_credential_store:/data \
  -e SIGNING_KEK="$OLD_KEK" \
  -e NEW_SIGNING_KEK="$NEW_KEK" \
  lucas42/lucos_aithne:latest /lucos_aithne --rekey

# 5. If it exits 0: update SIGNING_KEK in lucos_creds to $NEW_KEK.

# 6. Redeploy — do NOT use docker start.
```

`--rekey` is atomic: if any key fails decryption under the old KEK, it aborts before
writing anything. A non-zero exit means the credential store is unchanged.

---

## Diagnosing startup failures after a KEK change

If the service crash-loops after a deploy with a new `SIGNING_KEK`, look for one of these
errors in the logs:

| Error message | Likely cause |
|---|---|
| `could not be decrypted under the current SIGNING_KEK … run --migrate-kek` | Signing key was encrypted under a different KEK derivation — either `--migrate-kek` hasn't run yet, or `SIGNING_KEK` is set to the wrong value |
| `decrypt with old KEK failed — verify SIGNING_KEK matches` | Running `--rekey` with the wrong `SIGNING_KEK` |
| `blob too short to contain nonce` | Signing key blob is genuinely corrupt — restore from backup |

If a redeployment reverts the KEK unexpectedly (e.g. CircleCI `LUCOS_DEPLOY_ENV_BASE64`
snapshot overriding the live store on deploy), the old encrypted keys will be inaccessible
until the snapshot is also updated. See the lucos_creds deploy-snapshot caveat in the
codebase memory.

---

## See also

- [incident-response-credential-compromise.md](incident-response-credential-compromise.md) — scenario B (compromised signing key material)
- lucas42/lucos_aithne#244 — the issue that introduced SHA-256 KEK derivation
- lucas42/lucos_aithne#262 — the hardening issue that produced this runbook
