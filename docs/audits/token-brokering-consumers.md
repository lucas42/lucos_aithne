# Token Brokering Consumers Audit

**Date:** 2026-06-09
**Author:** lucos-security
**Issue:** https://github.com/lucas42/lucos_aithne/issues/11
**Feeds:** https://github.com/lucas42/lucos_aithne/issues/12 (decommission gate)

## Background

`lucos_authentication` bundles two unrelated jobs: authenticating users and brokering
third-party OAuth tokens for other services. Per ADR-0001 §8, `lucos_aithne` will be
identity-only — the token-brokering role leaves auth entirely.

This audit enumerates what currently consumes the two token-brokering endpoints in
`lucos_authentication`, to determine what needs rehoming before the old service can be
decommissioned (tracked in lucas42/lucos_aithne#12).

## Endpoints in Scope

### `/apptoken`

```
GET /apptoken?apikey=<trusted_key>&type=<provider>
```

Requires a trusted `apikey` (listed in `appkeys.conf`). Returns a machine-level
OAuth2 access token via the `client_credentials` grant for the named provider
(e.g. Google). Used by services that need to call external APIs using the lucos
application's own credentials (not on behalf of any user).

Response: `{ access_token: "...", client_id: "..." }`

### Trusted `/data`

```
GET /data?token=<user_session_token>&apikey=<trusted_key>
```

Standard `/data` (without `apikey`) returns only identity data (`userinfo` + agent
ID). With a trusted `apikey`, additionally includes the user's OAuth2 `token` field —
i.e. the user's third-party access token (e.g. their Google OAuth token). Used by
services that need to make Google API calls on behalf of the logged-in user.

## Audit Methodology

Searched all repositories in the `lucas42` estate (approximately 80 repos cloned
locally) under `~/sandboxes/`. The commands below are the actual searches run.

**1. Direct `/apptoken` references** — any URL construction or string containing the endpoint:

```bash
grep -rn "apptoken" ~/sandboxes/ 2>/dev/null \
  | grep -v "node_modules|\.git|Binary"
```

**2. `apikey` query parameter usage** — services calling `/data` with a trusted key, plus
any other `apikey`/`appkey` references:

```bash
grep -rn "apikey\|app_key\|appkey\|appkeys" ~/sandboxes/ \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" \
  --include="*.go" --include="*.php" --include="*.yml" --include="*.yaml" \
  --include="*.conf" 2>/dev/null \
  | grep -v "node_modules|\.git|lucos_authentication|lucos_aithne"
```

**3. `authconfig` volume mounts** — Docker services mounting the directory containing
`appkeys.conf`:

```bash
grep -rn "authconfig\|appkeys.conf\|/etc/auth" ~/sandboxes/ \
  --include="docker-compose.yml" --include="Dockerfile" --include="*.sh" \
  2>/dev/null | grep -v "lucos_authentication"
```

**4. Auth app-key environment variables** — env vars that might carry a trusted key:

```bash
grep -rn "AUTH_APIKEY\|AUTH_APP_KEY\|APPKEY\|APP_TOKEN\|KEY_LUCOS_AUTH" \
  ~/sandboxes/ --include="docker-compose.yml" --include="docker-compose.yaml" \
  2>/dev/null | grep -v "lucos_authentication|lucos_aithne"
```

**5. Third-party API usage** — services importing Google / YouTube / other external API
libraries that might imply a dependency on brokered tokens:

```bash
grep -rn "googleapis\|google\.com/oauth\|youtube\|gmail\|GOOGLE_TOKEN" \
  ~/sandboxes/ --include="*.js" --include="*.ts" --include="*.py" \
  --include="*.go" --include="*.php" 2>/dev/null \
  | grep -v "node_modules|\.git|lucos_authentication|lucos_aithne|test|\.md"
```

**6. Standard auth consumers** — to distinguish trusted from untrusted `/data` callers,
also enumerated all services calling `auth.l42.eu` or `AUTH_ORIGIN`:

```bash
grep -rn "auth\.l42\.eu\|AUTH_ORIGIN" ~/sandboxes/ \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" \
  --include="*.go" --include="*.php" --include="*.yml" --include="*.yaml" \
  2>/dev/null \
  | grep -v "node_modules|\.git|lucos_authentication|lucos_aithne|lucos_mockauthentication"
```

## Findings

### `/apptoken` consumers: **None found**

No service in the estate calls `/apptoken`. No code constructs a URL to
`auth.l42.eu/apptoken`. No service mounts an `authconfig` volume or passes an
`apikey` when calling the auth service.

### Trusted `/data` consumers: **None found**

All services that call `/data` do so with only the `token` parameter (standard user
identity validation). None pass an `apikey`.

### Import services use own credentials

The two Google import scripts (`lucos_contacts_googlesync_import` and
`lucos_contacts_gphotos_import`) both use their own credentials directly:
`lucos_contacts_googlesync_import` uses a Google service account
(`PRIVATE_KEY` + `CLIENT_EMAIL` env vars). Neither depends on
`lucos_authentication` for token brokering.

## Caveats

Two runtime secrets could not be inspected:

- **`providers.json`** — configures which OAuth providers are available to
  `lucos_authentication`. The code confirms at least Google is configured (the
  `/_info` check uses a hardcoded Google agentid). Any other providers configured
  here would be potential `/apptoken` candidates — but if no service calls the
  endpoint, no migration is needed regardless.

- **`appkeys.conf`** — lists which trusted keys are registered. The application
  handles a missing file gracefully (logs a warning, continues). The audit found
  no service with a key to register, so this file is likely empty or absent in
  production.

## Conclusion

The third-party token brokering capability exists in `lucos_authentication` code
but is not actively used by any service in the estate. **There are zero consumers
to rehome as part of the `/apptoken` / trusted-`/data` split.**

### Impact on decommission gate (lucas42/lucos_aithne#12)

The token-brokering consumer list produced by this audit is empty. This particular
gate for decommissioning `lucos_authentication` is clear.

The remaining decommission blockers are the standard identity consumers — services
that call `/data?token=<token>` (without `apikey`) to validate user sessions. These
are in scope for the general consumer migration tracked in lucas42/lucos_aithne#12,
not this audit. For reference, the full list of standard identity consumers found
during this audit:

| Service | Language | Auth pattern |
|---|---|---|
| `lucos_media_metadata_manager` | PHP | `GET /data?token=` |
| `lucos_backups` | Python | `GET /data?token=` |
| `lucos_notes` | Node.js | `GET /data?token=` |
| `lucos_photos` | Python | `GET /data?token=` |
| `lucos_contacts` | Python (Django) | `GET /data?token=` |
| `lucos_comhra` | Python | `GET /data?token=` |
| `lucos_arachne` | Node.js | `GET /data?token=` |
| `lucos_loganne` | Node.js | `GET /data?token=` |
| `lucos_media_seinn` | Node.js | `GET /data?token=` |
| `lucos_eolas` | Python (Django) | `GET /data?token=` via `AUTH_ORIGIN` env var |
| `lucos_creds` | Node.js (UI) | `GET /data?token=` |

That's 11 standard identity consumers — the migration target referenced in ADR-0001.
