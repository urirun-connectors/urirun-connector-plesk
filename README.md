# urirun-connector-plesk

Secure Plesk REST API v2 connector for `urirun`. Administrator credentials and
generated API keys never appear in URI payloads, results, or logs.

## URI Process

| URI | Purpose |
| --- | --- |
| `plesk://host/auth/command/bootstrap-api-key` | lease admin login/password from vault, create an API key, store it in vault |
| `plesk://host/auth/query/status` | validate the stored API key |
| `plesk://host/api/query/request` | execute a GET request under `/api/v2/` |
| `plesk://host/api/command/request` | execute POST/PUT/PATCH/DELETE under `/api/v2/` |
| `plesk://host/mailbox/command/create` | create a mailbox with a generated password stored directly in the vault |
| `plesk://host/ftpuser/command/ensure` | rotate system SFTP/FTP password (XML) or ensure additional FTP user; store as `plesk-sftp` / `plesk-ftp` (https origin) |
| `plesk://host/site/query/methods` | probe which deployment transports (SFTP/FTP) are authorized |
| `plesk://host/site/command/sync` | dry-run (default) or apply `www/` → `/httpdocs` tree sync (SFTP preferred, FTP fallback) |
| `plesk://host/site/command/publish` | alias of `site/command/sync` |
| `plesk://host/doctor/query/report` | connector readiness |

### Credentials (`ftpuser/command/ensure`)

Vault entries use **https** origins (the vault rejects `sftp://` / `ftp://`).

| kind | What it does | Default vault ids |
| --- | --- | --- |
| `system` (preferred) | Rotate subscription system FTP password via XML, enable SSH shell, store for SFTP | `plesk-sftp` + mirror `plesk-ftp` |
| `additional` | XML `ftp-user` set/add for a dedicated login | `plesk-ftp` |

Requires vault entry `plesk-subscription` (`username`/`password` of the customer panel login, origin = Plesk base URL including `:8443`).

```json
{
  "uri": "plesk://host/ftpuser/command/ensure",
  "payload": {
    "kind": "system",
    "domain": "subactor.com",
    "base_url": "https://prototypowanie.pl:8443",
    "credential_vault_entry_id": "plesk-sftp",
    "also_ftp_vault_entry_id": "plesk-ftp"
  }
}
```

Note: FTPS data ports are often firewalled on shared hosting; prefer SFTP (`transport: auto` / `sftp`).

## Static site sync (`www` → `httpdocs`)

Canonical URI: `plesk://host/site/command/sync`.

**Safety defaults**

- Always plans locally first (file list + sha256). Never uploads unless
  `apply=true`, `AUTONOMY_MUTATIONS_ENABLED=1`, `PLESK_SYNC_APPLY=1`, a valid
  signed `apply_grant`, matching dry-run `plan_hash`, and an unused `jti`
  (replay → `apply_grant_replay`). Optional `APPLY_GRANT_JTI_STORE` JSON path.
- Source must be a directory named `www` or `docs`, or under
  `PLESK_SYNC_ALLOWED_SOURCES` (colon-separated absolute prefixes).
- Sync is additive overwrite of listed files; it does not delete remote
  `.htaccess` or `.well-known/` (preserve list returned in the result).
- Credentials are leased from the vault; never accepted in the URI payload.

```text
source_dir           local directory (allowlisted www/ or docs/)
remote_path          target path, default /httpdocs
host / sftp_host     Plesk SSH/FTP host
domain               optional subscription/domain label (metadata)
transport            auto | sftp | ftp  (auto prefers SFTP)
apply                false (dry-run) | true (requires gates + grant + plan_hash)
plan_hash            from dry-run response (required on apply)
apply_grant          signed grant from control POST /api/apply-grants
actor / pack_id      optional binding checks against grant claims
sftp_port / ftp_port defaults 22 / 21
sftp_vault_entry_id  default plesk-sftp
ftp_vault_entry_id   default plesk-ftp
credential_origin    e.g. https://host (vault rejects sftp://ftp:// schemes)
host_fingerprint     optional SHA-256 host key pin (hex)
```

Requires `paramiko` (hard dependency since PR6; also baked into the `urirun-node`
image). Do **not** `pip install` paramiko into a running container.

### Transport policy (PR6)

- **Production publish** requires SFTP (`production_publish_ready` in doctor).
  Missing SFTP blocks readiness even when FTP works.
- `transport=auto` prefers SFTP; FTP fallback only when
  `PLESK_SYNC_ALLOW_FTP_FALLBACK=1`.
- Explicit `transport=ftp` apply is denied unless that fallback env is set.
- Timeouts (env-overridable): connect 15s / operation 120s / total budget 180s
  (`PLESK_TRANSPORT_CONNECT_TIMEOUT`, `PLESK_TRANSPORT_OPERATION_TIMEOUT`,
  `PLESK_TRANSPORT_TOTAL_BUDGET`).
- Structured errors: `authentication_failed`, `credential_expired`,
  `transport_connect_timeout`, `transfer_timeout`, `remote_permission_denied`,
  `partial_upload`, `remote_hash_mismatch`, `capability_unavailable`,
  `rate_limited`.

Doctor (`plesk://host/doctor/query/report`) returns capability JSON:

```json
{
  "capabilities": {
    "sftp": { "available": true, "detail": "ok" },
    "ftp": { "available": true, "detail": "ok" },
    "release_activation": false,
    "rollback": false
  },
  "production_publish_ready": true,
  "ftp_fallback_allowed": false,
  "timeouts": { "connect": 15, "operation": 120, "total": 180 }
}
```

Dry-run:

```json
{
  "uri": "plesk://host/site/command/sync",
  "payload": {
    "source_dir": "/home/tom/github/subactor/www",
    "host": "prototypowanie.pl",
    "domain": "subactor.com",
    "apply": false
  }
}
```

Apply (explicit opt-in):

```bash
export PLESK_SYNC_APPLY=1
```

```json
{
  "uri": "plesk://host/site/command/sync",
  "payload": {
    "source_dir": "/home/tom/github/subactor/www",
    "host": "prototypowanie.pl",
    "domain": "subactor.com",
    "apply": true
  }
}
```

## REST API bootstrap

The bootstrap follows the official Plesk flow:

1. lease `username` and `password` from `plesk-admin-bootstrap`;
2. `POST /api/v2/auth/keys` with Basic authentication;
3. store the returned key as `api_key` in `plesk-runtime`;
4. use `X-API-Key` for every subsequent REST request.

Required environment:

```text
PLESK_BASE_URL=https://plesk.example.com:8443
URIRUN_VAULT_URL=http://browser-agent:8087
URIRUN_VAULT_TOKEN=<service token>
PLESK_TLS_VERIFY=true
```

Example process plan:

```urirun:processes
[
  {
    "id": "plesk-authorize",
    "name": "Authorize Plesk API",
    "actor": "system",
    "uri": "plesk://host/auth/command/bootstrap-api-key",
    "payload": {},
    "depends_on": [],
    "human_approval": true
  },
  {
    "id": "plesk-domains",
    "name": "List Plesk domains",
    "actor": "system",
    "uri": "plesk://host/api/query/request",
    "payload": {"path": "/api/v2/domains"},
    "depends_on": ["plesk-authorize"],
    "human_approval": false
  }
]
```

The first step is approved only when a human initially supplies or rotates the
administrator credential in the vault. Later API operations use the generated
key autonomously.
