# urirun-connector-plesk

Secure multi-transport Plesk connector for `urirun`. Administrator credentials and
generated API keys never appear in URI payloads, results, or logs.

## Development

Run the test suite in an isolated environment. In the `if-uri` workspace, use
the adjacent `urirun` checkout so the connector is tested against the current
runtime source:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ../urirun/adapters/python
python -m pip install -e '.[test]'
python -m pytest tests -q
```

CI runs the same suite on Python 3.10 and 3.13. Tests use fakes or loopback
servers and do not contact a real Plesk instance.

## URI Process

| URI | Purpose |
| --- | --- |
| `plesk://host/auth/command/bootstrap-api-key` | lease admin login/password from vault, create an API key, store it in vault |
| `plesk://host/auth/query/acquisition-methods` | describe safe acquisition without returning credentials |
| `plesk://host/auth/query/scopes` | probe and return credential scope evidence by handle |
| `plesk://host/auth/query/status` | validate the stored API key |
| `plesk://host/extensions/query/catalog` | discover installed extensions with the administrator XML API |
| `plesk://host/extensions/query/capabilities` | join installed extensions with reviewed executable profiles |
| `plesk://host/extension/query/call` | invoke a profiled read-only extension XML operation |
| `plesk://host/extension/command/call` | dry-run or execute a profiled extension mutation with gates and a signed grant |
| `plesk://host/subscription/query/capabilities` | verify customer authorization and domain capacity before planning a site |
| `plesk://host/subscription/query/snapshot` | twin-fact snapshot of subscription capacity (one name or list visible to lease) |
| `plesk://host/domain/command/ensure` | dry-run or idempotently add a domain under an existing subscription |
| `plesk://host/dns/query/authority` | detect the authoritative DNS provider using two-resolver NS consensus |
| `plesk://host/dns/query/propagation` | compare expected records and remaining TTL across two public resolvers |
| `plesk://host/dns/command/reconcile` | provider-aware DNS dry-run/apply facade for Plesk or Cloudflare |
| `plesk://host/api/query/request` | execute a GET request under `/api/v2/` |
| `plesk://host/api/command/request` | execute POST/PUT/PATCH/DELETE under `/api/v2/` |
| `plesk://host/mailbox/query/status` | inspect mailbox existence through Plesk API without returning account details |
| `plesk://host/mailbox/command/ensure` | plan/create/rotate a mailbox and provision both IMAP/SMTP vault entries; apply grant required |
| `plesk://host/mailbox/command/create` | compatibility alias for ensure in create-only mode; fail-closed without apply grant |
| `plesk://host/ftpuser/command/ensure` | rotate system SFTP/FTP password (XML) or ensure additional FTP user; store as `plesk-sftp` / `plesk-ftp` (https origin) |
| `plesk://host/site/query/remote-inventory` | bounded read-only SFTP listing; ambiguous `/httpdocs` requires a vault `credential_origin` bound to the requested domain |
| `plesk://host/site/query/docroot` | observe live `www_root`/docroot as `subactor.twin-fact/v1` (read-only; estimated fallback when panel unreachable) |
| `plesk://host/site/query/methods` | probe which deployment transports (SFTP/FTP) are authorized |
| `plesk://host/site/command/sync` | dry-run (default) or apply `www/` → `/httpdocs` tree sync (SFTP preferred, FTP fallback) |
| `plesk://host/site/command/publish` | alias of `site/command/sync` |
| `plesk://host/site/command/release-upload` | upload tree to `releases/rel_…` + write `__subactor_release.json` (does **not** activate) |
| `plesk://host/site/command/release-verify` | verify release meta/hashes; optional `verify_origin` / `verify_public` fingerprint ladder |
| `plesk://host/site/command/publish-verify` | ADR-004 DNS/TLS/HTTPS + content fingerprint DoD (origin via Host / `--resolve`) |
| `plesk://host/site/command/release-activate` | atomically point `current` at a release (symlink or pointer) |
| `plesk://host/site/query/release-current` | report `current` / `previous` release ids |
| `plesk://host/site/command/release-rollback` | activate previous; result `status: rolled_back` |
| `plesk://host/site/command/subdomain-ensure` | idempotent subdomain create under parent webspace (XML; no DNS) |
| `plesk://host/site/command/reverse-proxy-ensure` | preflight/apply a marked nginx reverse-proxy block through pinned root SSH, Plesk CLI, config test and rollback |
| `plesk://host/site/command/ssl-ensure` | ensure origin TLS covers hostname (probe / assign / panel PEM / SSL It LE) |
| `plesk://host/doctor/query/report` | connector readiness (`ssl_ensure`, `letsencrypt`, `publish_verify`, staging note) |

## Dynamic extension model

Local Plesk DNS address records use the reviewed XML API routes
`plesk://host/dns/query/records` and `plesk://host/dns/command/replace`. Replacement is
dry-run by default and removes conflicting A/AAAA/CNAME records only after an exact
plan hash, signed boundary-risk grant, the global mutation gate and
`PLESK_DNS_APPLY=1` have all been verified.
Plesk delete and add calls are executed separately. If the add is rejected after
deletion, the connector attempts to restore the exact removed records and returns
bounded provider error metadata plus the rollback outcome; it never reports the
operation as atomic or verified without the final read-back.
The `host` boundary accepts either a regular FQDN or one literal leftmost wildcard
(`*.example.com`). Embedded, bare and multi-label wildcards are rejected; a wildcard
plan therefore cannot silently expand to or edit sibling DNS objects.

Delegated zones use `plesk://host/dns/query/authority` and
`plesk://host/dns/command/reconcile`. The latter is a Plesk-connector facade, not a
claim that Plesk owns the zone: its receipt always names the detected provider and
nameservers. Cloudflare credentials (`api_token`, `zone_id`) are leased from the
`cloudflare-dns` vault entry for `https://api.cloudflare.com`; payloads and receipts
contain no secret. Cloudflare apply uses the provider batch API and additionally
requires `CLOUDFLARE_DNS_APPLY=1`.
Propagation is observed separately through `plesk://host/dns/query/propagation`; it
compares Cloudflare DNS, Google DNS and (for A/AAAA) the runtime system resolver, so
an API-verified change is not incorrectly reported as globally propagated while
recursive resolvers still hold different values or TTLs.

Subdomain creation follows the same fail-closed lifecycle through
`plesk://host/site/command/subdomain-ensure`: default dry-run, exact plan hash,
single-use boundary grant and `PLESK_SUBDOMAIN_APPLY=1`.

Existing-domain additional nginx directives have no stable Plesk REST/XML write
operation. `site/command/reverse-proxy-ensure` therefore exposes the operation as one
URI while truthfully using the documented root CLI boundary internally. It requires a
public HTTPS upstream that demonstrates an authentication challenge, a separately
scoped `plesk-root-ssh` vault entry, a pinned SHA-256 host key, the master mutation
gate, `PLESK_REVERSE_PROXY_APPLY=1`, an exact plan hash and a single-use boundary
grant. The connector preserves non-managed directives, runs `httpdmng` and `nginx -t`,
reloads only after validation, and restores the previous file when apply fails.

Plesk extensions are runtime objects, not hard-coded connector routes. The connector
discovers their `id`, name, version, release and active state through the official XML
`extension.get` operator. Discovery does not grant authority. The checked-in
`extension_profiles.json` is the policy boundary that maps a known extension operation
to an effect, risk class and transport.

- Unknown installed extensions are returned as `discovery-only`.
- XML calls are built from validated identifiers and scalar arguments; callers cannot
  submit raw XML or shell commands.
- Mutations are dry-run by default and require `AUTONOMY_MUTATIONS_ENABLED=1` (or a
  live mutate lease), `PLESK_EXTENSION_APPLY=1`, an exact `plan_hash`, and a signed,
  single-use apply grant with the profile's risk class.
- An extension-backed GUI feature can delegate to an existing stable URI process. The
  `sslit/certificate-ensure` profile delegates to
  `plesk://host/site/command/ssl-ensure` instead of calling private panel endpoints.
- Root SSH is a separate explicit transport. Subscription SFTP credentials are never
  promoted into Plesk administrator CLI authority.

This separation means installing a new extension immediately changes discovery, while
making it executable remains an explicit, reviewable profile change.
The full transport and lifecycle design is in
[`docs/EXTENSION_CAPABILITY_MODEL.md`](docs/EXTENSION_CAPABILITY_MODEL.md).

`domain/command/ensure` is dry-run by default. A real add requires
`apply=true`, `AUTONOMY_MUTATIONS_ENABLED=1`, and `PLESK_DOMAIN_APPLY=1`.
Unknown subscription limits, exhausted capacity, missing customer authority,
and explicit permission denial all fail closed before the XML `site.add` call.

### SSL ensure (`site/command/ssl-ensure`)

Fail-closed: default is probe-only. Mutate requires `apply=true`,
`AUTONOMY_MUTATIONS_ENABLED=1`, and `PLESK_SSL_APPLY=1`.
Before the direct-origin TLS probe or any ACME action, the connector checks
public A/AAAA state through Cloudflare DNS, Google DNS, and the runtime
resolver. A missing hostname returns `plesk_ssl_dns_dependency_blocked` with
root cause `dns_name_missing` and a read-only DNS reconciliation next action;
no certificate mutation is attempted.

| provider | Behavior |
| --- | --- |
| `auto` (default) | probe → assign known names → panel PEM+SAN → SSL It LE → REST CLI LE |
| `assign` | XML `certificate_name` assign only |
| `panel-pem` | customer panel upload of generated self-signed PEM **with SAN** |
| `panel-selfsigned` | panel “Self-Signed” button (often CN-only, no SAN extension) |
| `letsencrypt` | SSL It! panel install + REST CLI fallback |
| `rest-cli` | `/api/v2/cli/extension/call` (needs admin `plesk-runtime` API key) |

Known panel limits: XML `extension/letsencrypt` returns **1013** (ApiRpc not
implemented); customer REST CLI is **403**. SSL It LE FormData is **domain-only**
(`validateDomain=1`; wildcard/mail flags omitted — PHP treats `"false"` as
truthy and otherwise builds a bad ACME order). On conflict, results include
structured `hitl` (exact panel click). Fallback: `panel-pem` for origin SAN
without public LE.

```json
{
  "uri": "plesk://host/site/command/ssl-ensure",
  "payload": {
    "hostname": "docs.subactor.com",
    "origin_ip": "217.160.250.222",
    "base_url": "https://prototypowanie.pl:8443",
    "provider": "auto",
    "apply": false
  }
}
```

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
- Source must be a directory named `www`, `docs`, or `logo`, or under
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
    "release_activation": true,
    "rollback": true,
    "release_activation_strategies": ["auto", "symlink", "pointer"],
    "ssl_ensure": {
      "available": true,
      "detail": "ok",
      "strategies": ["probe", "assign", "panel_upload_pem", "panel_self_signed", "panel_sslit_le", "rest_cli_le"]
    },
    "letsencrypt": {
      "available": false,
      "detail": "xml_apirpc_unimplemented; rest_cli_needs_admin; panel_sslit_le_san_flags"
    },
    "certificate_assign": true
  },
  "production_publish_ready": true,
  "ftp_fallback_allowed": false,
  "release_activation_default": "auto",
  "timeouts": { "connect": 15, "operation": 120, "total": 180 }
}
```

## Release-based deploy (PR7)

Do **not** treat destructive sync into the live docroot as the only model.
Preferred flow:

```text
release-upload → release-verify → release-activate → (PR8 public verify)
on_fail → release-rollback  (status rolled_back, never fake ok)
```

Layout under `release_root` (default `/httpdocs`):

```text
{release_root}/
  releases/rel_…/
  current → releases/rel_…     # or .release_current.json pointer
  previous → releases/rel_…
```

### Activation strategy (`PLESK_RELEASE_ACTIVATION`)

| Value | Behavior |
| --- | --- |
| `auto` (default) | try SFTP symlink; fall back to JSON pointer files |
| `symlink` | require `current` / `previous` symlinks |
| `pointer` | write `.release_current.json` / `.release_previous.json` |

**Staging note:** Plesk REST “set docroot” / panel API atomic switch is **not**
assumed — it is unknown/unverified on the target host. Recipes call the stable
URIs above; the connector hides symlink vs pointer. Confirm symlink allowance
on the subscription before forcing `symlink` in production. Lab/unit tests use
`LocalReleaseFs` (see `tests/test_release.py`); `mock-plesk` remains the REST
mailbox/site fixture and does not emulate SFTP release FS.

Mutating release URIs keep the same fail-closed gates as sync: master kill
switch, `PLESK_SYNC_APPLY=1`, signed `apply_grant`, `plan_hash`, jti replay,
SFTP readiness.

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
