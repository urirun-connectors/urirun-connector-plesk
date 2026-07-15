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
| `plesk://host/doctor/query/report` | connector readiness |

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
