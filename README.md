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
| `plesk://host/site/command/publish` | upload a local static-site directory to a subscription's `httpdocs` over SFTP, with vault-leased credentials and host-key pinning |
| `plesk://host/doctor/query/report` | connector readiness |

## Static site publication (SFTP)

`plesk://host/site/command/publish` uploads a directory tree (e.g. a built website)
to a Plesk subscription over SFTP. Credentials are leased from the vault, never
passed in the URI payload, and the remote host key is pinned before the password
is sent.

```text
source_dir           local directory to upload (its contents map to remote_path)
remote_path          target path, default /httpdocs
sftp_host            SFTP/SSH host (the Plesk server)
sftp_port            default 22
sftp_vault_entry_id  vault entry holding username + password, default plesk-sftp
credential_origin    sftp://<host> credential scope, default sftp://<sftp_host>
host_fingerprint     optional SHA-256 host key to pin (hex); mismatch aborts
```

Requires the `sftp` extra: `pip install 'urirun-connector-plesk[sftp]'` (pulls `paramiko`).

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
