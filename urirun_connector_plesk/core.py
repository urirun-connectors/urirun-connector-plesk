"""Plesk REST API v2 connector with vault-backed authorization."""
from __future__ import annotations

import base64
import fnmatch
import ftplib
import hashlib
import json
import os
import posixpath
import re
import secrets
import shlex
import ssl
import stat as statmod
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

import urirun

from . import _urirun_compat
from .capabilities import (
    build_capabilities,
    deny_if_sftp_required,
    ftp_fallback_allowed,
    production_publish_ready,
)
from .errors import (
    CAPABILITY_UNAVAILABLE,
    PARTIAL_UPLOAD,
    REMOTE_HASH_MISMATCH,
    map_exception,
)
from .immutable_manifest import build_immutable_manifest, verify_plan_hash
from .connector_result import classify_connector_reason, connector_result
from .apply_grant import (
    autonomy_mutations_enabled,
    clear_mutate_lease_file,
    consume_apply_grant_jti,
    format_intent_pack,
    issue_mutate_lease_file,
    load_mutate_lease,
    mutate_lease_active,
    mutate_lease_allows_apply,
    mutations_gates_open,
    verify_apply_grant,
)
from .timeouts import isolated_execution_timeout, transport_timeouts
from .extensions import (
    extension_call_packet,
    extension_capability_catalog,
    extension_inventory_packet,
    extension_operation_plan,
    load_extension_profiles,
    parse_extension_call,
    parse_extension_cli_inventory,
    parse_extension_inventory,
)
from .dns_providers import (
    CLOUDFLARE_CREDENTIAL_ORIGIN,
    apply_cloudflare_plan,
    cloudflare_plan,
    cloudflare_records,
    resolve_dns_authority,
    resolve_dns_propagation,
)
from .reverse_proxy import (
    assert_public_upstream,
    build_plan as build_reverse_proxy_plan,
    merge_managed_directives,
    normalize_hostname as normalize_reverse_proxy_hostname,
    normalize_upstream,
    probe_upstream,
)

try:  # paramiko ships in urirun-node image (PR6); keep importable if extra absent in lab
    import paramiko
except ImportError:  # pragma: no cover - exercised only where the dep is absent
    paramiko = None

CONNECTOR_ID = "plesk"
conn = _urirun_compat.connector(CONNECTOR_ID, scheme="plesk")
_SAFE_API_PATH = re.compile(r"^/api/v2/[A-Za-z0-9_./-]+$")
_SENSITIVE = re.compile(r"password|secret|token|api.?key|authorization", re.I)
_SAFE_REMOTE = re.compile(r"^/[A-Za-z0-9_./-]*$")
_SKIP_DIRS = {
    ".git", ".venv", "node_modules", "__pycache__", ".planfile", ".secrets",
    ".idea", ".koru", ".ruff_cache", ".code2llm_cache",
}
_SKIP_FILES = {".DS_Store"}
# Repo/deployment junk that must not land in httpdocs (basename or full rel path globs).
_DEFAULT_EXCLUDE = (
    "Dockerfile", "docker-compose.yml", "README.md", ".gitignore", "*.less",
    "tree.sh", "deployment", "deployment/*", "staging-smoke", "staging-smoke/*",
)


def _base_url(value: str = "") -> str:
    raw = value or os.environ.get("PLESK_BASE_URL", "")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}):
        raise RuntimeError("plesk_https_required")
    if not parsed.netloc or parsed.username or parsed.password:
        raise RuntimeError("plesk_base_url_invalid")
    return f"{parsed.scheme}://{parsed.netloc}"


def _ssl_context() -> ssl.SSLContext | None:
    if os.environ.get("PLESK_TLS_VERIFY", "true").lower() in {"0", "false", "no"}:
        return ssl._create_unverified_context()  # explicitly enabled for self-signed Plesk only
    return None


def _request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: Any = None,
    timeout: float = 30,
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "accept": "application/json",
        **({"content-type": "application/json"} if data is not None else {}),
        **(headers or {}),
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_ssl_context()) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            payload = {"error": "http_error"}
        return error.code, payload
    except (urllib.error.URLError, TimeoutError) as error:
        raise RuntimeError("plesk_transport_failed") from error


def _vault_settings(vault_url: str = "") -> tuple[str, str]:
    url = (vault_url or os.environ.get("URIRUN_VAULT_URL", "")).rstrip("/")
    default_reference = "getv://URIRUN_VAULT_TOKEN"
    reference = os.environ.get("URIRUN_VAULT_TOKEN_REF", default_reference).strip()
    if not reference.startswith(("getv://", "secret://", "{getv:", "{secret:")):
        raise RuntimeError("plesk_vault_token_ref_invalid")
    try:
        token = urirun.resolve_secret(
            reference,
            secret_allow=os.environ.get("URIRUN_SECRET_ALLOW", default_reference),
        )
    except KeyError:
        token = ""
    except PermissionError as error:
        raise RuntimeError("plesk_vault_token_ref_denied") from error
    if not url or not token:
        raise RuntimeError("plesk_vault_not_configured")
    return url, token


def _vault_lease(entry_id: str, origin: str, field: str, vault_url: str = "") -> str:
    """Lease a vault field. Test hook: monkeypatch this (no real secrets in unit tests)."""
    url, token = _vault_settings(vault_url)
    try:
        status, data = _request_json(
            f"{url}/internal/vault/{urllib.parse.quote(entry_id, safe='')}/lease",
            method="POST",
            headers={"authorization": f"Bearer {token}"},
            body={"origin": origin, "field": field},
            timeout=transport_timeouts().connect,
        )
    except RuntimeError as error:
        raise RuntimeError(map_exception(error, phase="lease")) from error
    secret = str(data.get("secret") or "")
    if status in {401, 403}:
        raise RuntimeError("plesk_vault_token_rejected")
    if status == 429:
        raise RuntimeError("rate_limited")
    if status != 200 or not secret:
        raise RuntimeError(f"plesk_vault_lease_failed:{field}")
    return secret


def _vault_store(entry_id: str, origin: str, api_key: str, vault_url: str = "") -> str:
    return _vault_store_secrets(entry_id, origin, "Plesk REST API key", {"api_key": api_key}, vault_url)


def _vault_store_secrets(
    entry_id: str, origin: str, label: str, values: dict[str, str], vault_url: str = "",
) -> str:
    url, token = _vault_settings(vault_url)
    status, data = _request_json(
        f"{url}/vault",
        method="POST",
        headers={"authorization": f"Bearer {token}"},
        body={"id": entry_id, "origin": origin, "label": label, "secrets": values},
    )
    if status not in {200, 201}:
        raise RuntimeError("plesk_vault_store_failed")
    return str(data.get("entry", {}).get("id") or entry_id)


def _credential_origin(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"imap", "imaps"} or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("plesk_mailbox_credential_origin_invalid")
    return f"{parsed.scheme}://{parsed.netloc}"


def _smtp_credential_origin(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"smtp", "smtps", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("plesk_mailbox_smtp_credential_origin_invalid")
    return f"{parsed.scheme}://{parsed.netloc}"


def _vault_entry_id(value: str, *, default: str) -> str:
    entry_id = (value or default).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", entry_id):
        raise RuntimeError("plesk_mailbox_vault_entry_invalid")
    return entry_id


def _mail_cli_success(status: int, data: Any) -> bool:
    if not 200 <= status < 300:
        return False
    if not isinstance(data, dict):
        return True
    code = data.get("code", data.get("exit_code", 0))
    try:
        return int(code or 0) == 0
    except (TypeError, ValueError):
        return False


def _mailbox_absent(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    diagnostic = " ".join(str(data.get(key) or "") for key in ("stderr", "error", "message")).lower()
    return any(marker in diagnostic for marker in (
        "does not exist", "doesn't exist", "not found", "no such mail", "unable to find", "unknown mail",
    ))


def _mailbox_probe(
    address: str, *, base_url: str, runtime_vault_entry_id: str, vault_url: str, api_path: str,
) -> tuple[bool, int, Any]:
    status, data = _authorized_request(
        base_url=base_url,
        path=api_path,
        method="POST",
        body={"params": ["--info", address]},
        runtime_vault_entry_id=runtime_vault_entry_id,
        vault_url=vault_url,
    )
    if _mail_cli_success(status, data):
        return True, status, data
    if 200 <= status < 300 and _mailbox_absent(data):
        return False, status, data
    raise RuntimeError(f"plesk_mailbox_status_failed:{status}")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SENSITIVE.search(str(key)) else _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _api_path(path: str) -> str:
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise RuntimeError("plesk_api_path_not_allowed")
    if not _SAFE_API_PATH.fullmatch(parsed.path) or ".." in parsed.path:
        raise RuntimeError("plesk_api_path_not_allowed")
    if not parsed.query:
        return parsed.path

    # Plesk Domain Files API selects the destination with one ``path`` query
    # parameter. Keep every other API query fail-closed so callers cannot use
    # the generic request process to smuggle arbitrary parameters.
    if not re.fullmatch(r"/api/v2/domains/[1-9][0-9]*/fs/content", parsed.path):
        raise RuntimeError("plesk_api_path_not_allowed")
    try:
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as error:
        raise RuntimeError("plesk_api_path_not_allowed") from error
    if len(query) != 1 or query[0][0] != "path":
        raise RuntimeError("plesk_api_path_not_allowed")
    relative = query[0][1]
    if (
        not relative
        or relative.startswith("/")
        or ".." in relative.split("/")
        or "//" in relative
        or not re.fullmatch(r"[A-Za-z0-9_.\/-]+", relative)
    ):
        raise RuntimeError("plesk_api_path_not_allowed")
    return f"{parsed.path}?{urllib.parse.urlencode({'path': relative})}"


def _sftp_origin(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "sftp" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("plesk_sftp_origin_invalid")
    return f"sftp://{parsed.netloc}"


def _sftp_connect(host: str, port: int, username: str, password: str, host_fingerprint: str = ""):
    """Open an authenticated SFTP session, pinning the host key before sending credentials."""
    if paramiko is None:
        raise RuntimeError(CAPABILITY_UNAVAILABLE)
    budgets = transport_timeouts()
    transport = paramiko.Transport((host, port))
    try:
        try:
            transport.start_client(timeout=budgets.connect)
        except Exception as error:
            raise RuntimeError(map_exception(error, phase="connect")) from error
        key = transport.get_remote_server_key()
        fingerprint = hashlib.sha256(key.asbytes()).hexdigest()
        wanted = host_fingerprint.replace(":", "").strip().lower()
        if wanted and wanted != fingerprint.lower():
            raise RuntimeError("plesk_sftp_host_key_mismatch")
        try:
            transport.auth_password(username, password)
        except Exception as error:
            raise RuntimeError(map_exception(error, phase="connect")) from error
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            raise RuntimeError(CAPABILITY_UNAVAILABLE)
    except RuntimeError:
        transport.close()
        raise
    except Exception as error:
        transport.close()
        raise RuntimeError(map_exception(error, phase="connect")) from error
    return transport, sftp, fingerprint


def _sftp_mkdirs(sftp, remote_dir: str, made: set[str]) -> None:
    parts = [p for p in remote_dir.split("/") if p]
    path = ""
    for part in parts:
        path = f"{path}/{part}"
        if path in made:
            continue
        try:
            sftp.stat(path)
        except IOError:
            sftp.mkdir(path)
        made.add(path)


def _sftp_upload_dir(
    sftp,
    source_dir: str,
    remote_path: str,
    exclude: tuple[str, ...] = (),
    *,
    plan: list[dict[str, Any]] | None = None,
    verify_remote_hash: bool = False,
    deadline: float | None = None,
) -> list[str]:
    """Upload every file under source_dir to remote_path, preserving structure."""
    base = os.path.abspath(source_dir)
    made: set[str] = set()
    uploaded: list[str] = []
    patterns = tuple(exclude) if exclude else _DEFAULT_EXCLUDE
    planned_by_path = {item["path"]: item for item in (plan or [])}
    budgets = transport_timeouts()
    op_deadline = time.monotonic() + budgets.operation
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in sorted(dirs) if d not in _SKIP_DIRS and not _excluded(d, patterns)]
        rel = os.path.relpath(root, base)
        remote_dir = remote_path if rel == "." else f"{remote_path}/{rel.replace(os.sep, '/')}"
        _sftp_mkdirs(sftp, remote_dir, made)
        for name in sorted(files):
            if name in _SKIP_FILES:
                continue
            rel_path = name if rel == "." else f"{rel.replace(os.sep, '/')}/{name}"
            if _excluded(rel_path, patterns):
                continue
            now = time.monotonic()
            if (deadline is not None and now > deadline) or now > op_deadline:
                raise RuntimeError(PARTIAL_UPLOAD if uploaded else "transfer_timeout")
            remote_file = f"{remote_dir}/{name}"
            try:
                sftp.put(os.path.join(root, name), remote_file)
            except Exception as error:
                code = map_exception(error, phase="transfer")
                if uploaded:
                    raise RuntimeError(PARTIAL_UPLOAD) from error
                raise RuntimeError(code) from error
            if verify_remote_hash and rel_path in planned_by_path:
                expected = planned_by_path[rel_path].get("sha256") or ""
                if expected:
                    digest = hashlib.sha256()
                    with sftp.open(remote_file, "rb") as handle:
                        for chunk in iter(lambda: handle.read(65536), b""):
                            digest.update(chunk)
                    if digest.hexdigest() != expected:
                        raise RuntimeError(REMOTE_HASH_MISMATCH)
            uploaded.append(rel_path)
    return uploaded


def _ftp_connect(host: str, port: int, username: str, password: str, tls: bool = True):
    """Open an authenticated FTP session (FTPS by default)."""
    budgets = transport_timeouts()
    ftp = ftplib.FTP_TLS() if tls else ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=budgets.connect)
        ftp.login(username, password)
    except Exception as error:
        raise RuntimeError(map_exception(error, phase="connect")) from error
    if tls:
        ftp.prot_p()
    return ftp


def _ftp_mkdirs(ftp, remote_dir: str, made: set[str]) -> None:
    path = ""
    for part in [p for p in remote_dir.split("/") if p]:
        path = f"{path}/{part}"
        if path in made:
            continue
        try:
            ftp.mkd(path)
        except ftplib.error_perm:
            pass  # already exists
        made.add(path)


def _excluded(rel_path: str, patterns: tuple[str, ...]) -> bool:
    """True if rel_path matches any glob (full relative path or basename)."""
    if not patterns:
        return False
    base = rel_path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(base, p) for p in patterns)


def _ftp_upload_dir(
    ftp,
    source_dir: str,
    remote_path: str,
    exclude: tuple[str, ...] = (),
    *,
    deadline: float | None = None,
) -> list[str]:
    base = os.path.abspath(source_dir)
    made: set[str] = set()
    uploaded: list[str] = []
    patterns = tuple(exclude) if exclude else _DEFAULT_EXCLUDE
    budgets = transport_timeouts()
    op_deadline = time.monotonic() + budgets.operation
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in sorted(dirs) if d not in _SKIP_DIRS and not _excluded(d, patterns)]
        rel = os.path.relpath(root, base)
        remote_dir = remote_path if rel == "." else f"{remote_path}/{rel.replace(os.sep, '/')}"
        _ftp_mkdirs(ftp, remote_dir, made)
        for name in sorted(files):
            if name in _SKIP_FILES:
                continue
            rel_path = name if rel == "." else f"{rel.replace(os.sep, '/')}/{name}"
            if _excluded(rel_path, patterns):
                continue
            now = time.monotonic()
            if (deadline is not None and now > deadline) or now > op_deadline:
                raise RuntimeError(PARTIAL_UPLOAD if uploaded else "transfer_timeout")
            try:
                with open(os.path.join(root, name), "rb") as handle:
                    ftp.storbinary(f"STOR {remote_dir}/{name}", handle)
            except Exception as error:
                code = map_exception(error, phase="transfer")
                if uploaded:
                    raise RuntimeError(PARTIAL_UPLOAD) from error
                raise RuntimeError(code) from error
            uploaded.append(rel_path)
    return uploaded


# ── Deployment transport router ──────────────────────────────────────────────
# Detect which file-deployment authorization actually works for this host and
# route the publish through it, instead of assuming a single mechanism.

def _probe_sftp(host: str, port: int, username: str, password: str, host_fingerprint: str = "") -> tuple[bool, str]:
    if paramiko is None:
        return False, "paramiko_missing"
    transport = None
    try:
        transport, sftp, _fp = _sftp_connect(host, port, username, password, host_fingerprint)
        sftp.close()
        return True, "ok"
    except Exception as error:  # auth/host-key/transport failures are all "unavailable"
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        return False, detail
    finally:
        if transport is not None:
            transport.close()


def _probe_ftp(host: str, port: int, username: str, password: str, tls: bool = True) -> tuple[bool, str]:
    ftp = None
    try:
        ftp = _ftp_connect(host, port, username, password, tls)
        return True, "ok"
    except Exception as error:
        return False, type(error).__name__
    finally:
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:
                pass


# transport name -> (default vault entry, default port, probe function signature marker)
_TRANSPORT_ORDER = ("sftp", "ftp")


def _transport_origin(transport: str, host: str, credential_origin: str = "") -> str:
    # Vault only accepts http/https/imap/smtp origins — use https for SFTP/FTP
    # credentials (distinguished by entry id plesk-sftp / plesk-ftp).
    _ = transport
    return credential_origin or f"https://{host}"


def _inventory_scope_error(
    host: str,
    domain: str,
    remote_path: str,
    credential_origin: str = "",
    sftp_vault_entry_id: str = "plesk-sftp",
    vault_url: str = "",
) -> str | None:
    """Reject an ambiguous chroot root unless the vault origin binds it to the domain.

    ``/httpdocs`` has different meanings for different Plesk subscription users.
    The SFTP endpoint hostname alone therefore cannot prove which domain the
    credential opens.  An explicit domain path is self-scoping; the chroot
    shorthand instead requires the effective vault origin hostname to equal
    the requested domain.  This check runs before a credential lease.
    """
    if posixpath.normpath(remote_path) not in {"/", "/httpdocs"}:
        return None
    origin = urllib.parse.urlparse(_transport_origin("sftp", host, credential_origin))
    if origin.hostname and origin.hostname.lower().rstrip(".") == domain.lower().rstrip("."):
        return None
    if _vault_entry_binds_domain(sftp_vault_entry_id, domain):
        return None
    if _vault_entry_scope_binds_domain(
        sftp_vault_entry_id,
        _transport_origin("sftp", host, credential_origin),
        domain,
        vault_url,
    ):
        return None
    return "plesk_site_inventory_scope_unbound"


def _vault_entry_binds_domain(entry_id: str, domain: str) -> bool:
    suffix = re.sub(r"[^a-z0-9]+", "-", str(domain or "").lower()).strip("-")
    return bool(suffix) and str(entry_id or "").lower().endswith(f"-{suffix}")


def _vault_entry_scope_binds_domain(entry_id: str, origin: str, domain: str, vault_url: str = "") -> bool:
    return _vault_entry_scope_metadata(entry_id, origin, domain, vault_url)["ok"]


def _vault_entry_scope_metadata(entry_id: str, origin: str, domain: str, vault_url: str = "") -> dict[str, Any]:
    result = {"entry_id": str(entry_id or ""), "ok": False, "error": None}
    if not result["entry_id"]:
        result["error"] = "deployment_credential_entry_missing"
        return result
    try:
        url, token = _vault_settings(vault_url)
        status, data = _request_json(
            f"{url}/internal/vault/{urllib.parse.quote(entry_id, safe='')}/metadata",
            method="POST",
            headers={"authorization": f"Bearer {token}"},
            body={"origin": origin},
            timeout=transport_timeouts().connect,
        )
    except RuntimeError as error:
        result["error"] = str(error)
        return result
    if status != 200 or not isinstance(data, dict) or data.get("ok") is not True:
        result["error"] = str(data.get("error") or f"http_{status}") if isinstance(data, dict) else f"http_{status}"
        return result
    scope = data.get("scope")
    if not isinstance(scope, dict):
        result["error"] = "deployment_credential_scope_mismatch"
        return result
    operations = {str(item) for item in scope.get("operations") or []}
    targets = {str(item) for item in scope.get("targets") or []}
    result["ok"] = "plesk.site.sync" in operations and f"domain:{str(domain).lower().rstrip('.')}" in targets
    result["error"] = None if result["ok"] else "deployment_credential_scope_mismatch"
    return result


def _deployment_credentials_preflight(
    *,
    host: str,
    domain: str,
    remote_path: str,
    transport: str,
    sftp_vault_entry_id: str,
    ftp_vault_entry_id: str,
    credential_origin: str,
    vault_url: str,
) -> dict[str, Any]:
    _ = remote_path
    if not str(domain or "").strip():
        return {"ok": False, "checked": False, "error": "deployment_credentials_not_ready", "entries": []}
    origin = _transport_origin("sftp", host, credential_origin)
    entries = {
        "sftp": sftp_vault_entry_id,
        "ftp": ftp_vault_entry_id,
    }
    selected = entries.items() if transport == "auto" else [(transport, entries.get(transport, ""))]
    checked = []
    for selected_transport, entry_id in selected:
        metadata = _vault_entry_scope_metadata(str(entry_id or ""), origin, domain, vault_url)
        checked.append({
            "transport": selected_transport,
            "entry_id": metadata["entry_id"],
            "ok": metadata["ok"],
            "error": metadata["error"],
        })
    ok = bool(checked) and all(item["ok"] for item in checked)
    return {"ok": ok, "checked": True, "error": None if ok else "deployment_credentials_not_ready", "entries": checked}


def _sync_scope_error(
    *,
    host: str,
    domain: str,
    remote_path: str,
    transport: str,
    sftp_vault_entry_id: str,
    ftp_vault_entry_id: str,
    credential_origin: str = "",
    credential_scope_verified: bool = False,
) -> str | None:
    """Fail closed when a sync target is not bound to its declared domain."""
    clean_domain = str(domain or "").lower().rstrip(".")
    if not clean_domain:
        return None
    normalized_path = posixpath.normpath(str(remote_path or ""))
    if normalized_path == "/":
        return "plesk_site_sync_scope_mismatch"
    vhost_prefix = "/var/www/vhosts/"
    if normalized_path.startswith(vhost_prefix):
        expected_prefix = f"{vhost_prefix}{clean_domain}/"
        if not normalized_path.startswith(expected_prefix):
            return "plesk_site_sync_scope_mismatch"
        return None
    if normalized_path != "/httpdocs":
        return None
    origin = urllib.parse.urlparse(_transport_origin("sftp", host, credential_origin))
    if origin.hostname and origin.hostname.lower().rstrip(".") == clean_domain:
        return None
    if credential_scope_verified:
        return None
    return "plesk_site_sync_scope_unbound"


def _deployment_binding_digest(binding: dict[str, Any]) -> str:
    body = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _load_registry(path_env: str, schema: str, unavailable: str, invalid: str) -> tuple[dict[str, Any] | None, str | None]:
    registry_path = os.environ.get(path_env, "").strip()
    if not registry_path:
        return None, unavailable
    try:
        with open(registry_path, encoding="utf-8") as handle:
            registry = json.load(handle)
    except (OSError, ValueError):
        return None, unavailable
    if registry.get("schema") != schema or registry.get("version") != 1:
        return None, invalid
    return registry, None


def _registered_source_error(source_ref: str, source_dir: str) -> str | None:
    source_registry, error = _load_registry(
        "PLESK_SITE_RESOURCES_PATH",
        "subactor.site-resources.v1",
        "plesk_site_source_registry_unavailable",
        "plesk_site_source_registry_invalid",
    )
    if error:
        return error
    source_matches = [item for item in source_registry.get("resources") or [] if item.get("id") == source_ref]
    if len(source_matches) != 1:
        return "plesk_site_source_ref_unknown"
    configured_path = str(source_matches[0].get("path") or "").strip()
    if not configured_path or os.path.realpath(source_dir) != os.path.realpath(configured_path):
        return "plesk_site_source_path_mismatch"
    return None


def _deployment_binding_error(
    *,
    source_dir: str,
    source_ref: str,
    deployment_binding_ref: str,
    deployment_binding_hash: str,
    deployment_binding_version: int,
    domain: str,
    host: str,
    remote_path: str,
    credential_origin: str,
    sftp_vault_entry_id: str,
    ftp_vault_entry_id: str,
) -> str | None:
    """Re-resolve the portable non-secret binding and require an exact target."""
    required = os.environ.get("PLESK_DEPLOYMENT_BINDING_REQUIRED", "").strip().lower() in {"1", "true", "yes"}
    binding_ref = str(deployment_binding_ref or "").strip()
    if not binding_ref:
        return "plesk_site_deployment_binding_required" if required else None
    registry, registry_error = _load_registry(
        "PLESK_DEPLOYMENT_BINDINGS_PATH",
        "subactor.deployment-bindings/v1",
        "plesk_site_deployment_registry_unavailable",
        "plesk_site_deployment_registry_invalid",
    )
    if registry_error:
        return registry_error
    matches = [item for item in registry.get("bindings") or [] if item.get("id") == binding_ref]
    if len(matches) != 1:
        return "plesk_site_deployment_binding_unknown"
    binding = matches[0]
    digest = _deployment_binding_digest(binding)
    if not re.fullmatch(r"[a-f0-9]{64}", str(deployment_binding_hash or "")) or not secrets.compare_digest(digest, str(deployment_binding_hash)):
        return "plesk_site_deployment_binding_hash_mismatch"
    try:
        requested_version = int(deployment_binding_version or 0)
        registry_version = int(registry.get("version") or 0)
    except (TypeError, ValueError):
        return "plesk_site_deployment_binding_version_mismatch"
    if requested_version != registry_version:
        return "plesk_site_deployment_binding_version_mismatch"
    target = binding.get("target") or {}
    credential_refs = binding.get("credential_refs") or {}
    expected = {
        "source_ref": binding.get("source_ref"),
        "domain": target.get("domain"),
        "host": target.get("transport_host"),
        "remote_path": target.get("remote_path"),
        "credential_origin": target.get("credential_origin"),
        "sftp_vault_entry_id": credential_refs.get("sftp"),
        "ftp_vault_entry_id": credential_refs.get("ftp"),
    }
    actual = {
        "source_ref": source_ref,
        "domain": domain,
        "host": host,
        "remote_path": remote_path,
        "credential_origin": credential_origin,
        "sftp_vault_entry_id": sftp_vault_entry_id,
        "ftp_vault_entry_id": ftp_vault_entry_id,
    }
    if binding.get("provider") != "plesk" or binding.get("connector_uri") != "plesk://host/site/command/sync":
        return "plesk_site_deployment_binding_provider_mismatch"
    if expected != actual:
        return "plesk_site_deployment_binding_target_mismatch"
    return _registered_source_error(source_ref, source_dir)


def _twin_profile_contract(
    *,
    source_dir: str,
    source_ref: str,
    deployment_binding_ref: str,
    deployment_binding_hash: str,
    deployment_binding_version: int,
    twin_profile_ref: str,
    twin_profile_hash: str,
    twin_profile_version: int,
) -> tuple[str | None, dict[str, Any] | None]:
    """Resolve a production-anchored twin profile without accepting target overrides."""
    deployment_registry, error = _load_registry(
        "PLESK_DEPLOYMENT_BINDINGS_PATH",
        "subactor.deployment-bindings/v1",
        "plesk_site_deployment_registry_unavailable",
        "plesk_site_deployment_registry_invalid",
    )
    if error:
        return error, None
    profiles_registry, error = _load_registry(
        "PLESK_TWIN_PROFILES_PATH",
        "subactor.deployment-twin-profiles/v1",
        "plesk_site_twin_registry_unavailable",
        "plesk_site_twin_registry_invalid",
    )
    if error:
        return error, None
    try:
        if int(deployment_binding_version or 0) != int(deployment_registry.get("version") or 0):
            return "plesk_site_deployment_binding_version_mismatch", None
        if int(twin_profile_version or 0) != int(profiles_registry.get("version") or 0):
            return "plesk_site_twin_profile_version_mismatch", None
    except (TypeError, ValueError):
        return "plesk_site_twin_profile_version_mismatch", None
    bindings = [item for item in deployment_registry.get("bindings") or [] if item.get("id") == deployment_binding_ref]
    if len(bindings) != 1:
        return "plesk_site_deployment_binding_unknown", None
    binding = bindings[0]
    binding_digest = _deployment_binding_digest(binding)
    if not re.fullmatch(r"[a-f0-9]{64}", str(deployment_binding_hash or "")) or not secrets.compare_digest(binding_digest, str(deployment_binding_hash)):
        return "plesk_site_deployment_binding_hash_mismatch", None
    profiles = [item for item in profiles_registry.get("profiles") or [] if item.get("id") == twin_profile_ref]
    if len(profiles) != 1:
        return "plesk_site_twin_profile_unknown", None
    profile = profiles[0]
    profile_digest = _deployment_binding_digest(profile)
    if not re.fullmatch(r"[a-f0-9]{64}", str(twin_profile_hash or "")) or not secrets.compare_digest(profile_digest, str(twin_profile_hash)):
        return "plesk_site_twin_profile_hash_mismatch", None
    target = profile.get("target") or {}
    verification = profile.get("verification") or {}
    isolation = profile.get("isolation") or {}
    domain = str(target.get("domain") or "").lower()
    remote_path = str(target.get("remote_path") or "")
    if (
        binding.get("source_ref") != source_ref
        or profile.get("source_ref") != source_ref
        or profile.get("production_binding_ref") != binding.get("id")
        or profile.get("production_binding_hash") != binding_digest
    ):
        return "plesk_site_twin_profile_binding_mismatch", None
    if (
        binding.get("provider") != "plesk"
        or profile.get("adapter") != "local-release-fs"
        or profile.get("connector_uri") != "plesk://host/site/command/twin-sync"
        or profile.get("runtime_root_ref") != "twin-volume:plesk"
        or isolation != {
            "network_access": "none",
            "production_credentials": "forbidden",
            "writable_scope": "runtime-root-only",
        }
    ):
        return "plesk_site_twin_profile_adapter_mismatch", None
    if not domain.endswith(".test") or domain == ".test":
        return "plesk_site_twin_domain_required", None
    if remote_path != f"/var/www/vhosts/{domain}/httpdocs":
        return "plesk_site_twin_remote_path_invalid", None
    if target.get("effective_docroot") != "/httpdocs":
        return "plesk_site_twin_remote_path_invalid", None
    if (
        verification.get("mode") != "sha256"
        or verification.get("require_source_release_match") is not True
        or not str(verification.get("entrypoint") or "").strip()
        or str(verification.get("entrypoint") or "").startswith("/")
        or ".." in str(verification.get("entrypoint") or "").split("/")
    ):
        return "plesk_site_twin_verification_invalid", None
    source_error = _registered_source_error(source_ref, source_dir)
    if source_error:
        return source_error, None
    return None, {"profile": profile, "binding": binding, "profile_digest": profile_digest}


def _detect_transports(host: str, *, sftp_port: int, ftp_port: int, ftp_tls: bool,
                       sftp_vault_entry_id: str, ftp_vault_entry_id: str,
                       credential_origin: str, host_fingerprint: str, vault_url: str) -> list[dict[str, Any]]:
    """Probe each deployment transport with its vault credentials; return availability."""
    plans = [
        ("sftp", sftp_vault_entry_id, sftp_port),
        ("ftp", ftp_vault_entry_id, ftp_port),
    ]
    results: list[dict[str, Any]] = []
    for name, entry, port in plans:
        origin = _transport_origin(name, host, credential_origin)
        try:
            username = _vault_lease(entry, origin, "username", vault_url)
            password = _vault_lease(entry, origin, "password", vault_url)
        except RuntimeError as error:
            results.append({"transport": name, "available": False, "detail": str(error)})
            continue
        try:
            if name == "sftp":
                ok, detail = _probe_sftp(host, port, username, password, host_fingerprint)
            else:
                ok, detail = _probe_ftp(host, port, username, password, ftp_tls)
        finally:
            username = password = ""
        results.append({"transport": name, "available": ok, "detail": detail})
    return results


@conn.handler("auth/command/bootstrap-api-key", isolated=True, meta={"label": "Exchange Plesk admin login for a vault-backed REST API key"})
def bootstrap_api_key(
    base_url: str = "",
    admin_vault_entry_id: str = "plesk-admin-bootstrap",
    runtime_vault_entry_id: str = "plesk-runtime",
    login: str = "",
    ip: str = "",
    description: str = "urirun autonomous Plesk connector",
    vault_url: str = "",
) -> dict[str, Any]:
    origin = _base_url(base_url)
    try:
        username = _vault_lease(admin_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(admin_vault_entry_id, origin, "password", vault_url)
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        body = {"description": description[:160]}
        if login:
            body["login"] = login
        if ip:
            body["ip"] = ip
        status, data = _request_json(
            f"{origin}/api/v2/auth/keys",
            method="POST",
            headers={"authorization": f"Basic {auth}"},
            body=body,
        )
        api_key = str(data.get("key") or "")
        if status not in {200, 201} or len(api_key) < 8:
            raise RuntimeError(f"plesk_api_key_create_failed:{status}")
        stored_id = _vault_store(runtime_vault_entry_id, origin, api_key, vault_url)
    except RuntimeError as error:
        return urirun.fail(str(error))
    finally:
        username = password = api_key = auth = ""
    return urirun.ok(base_url=origin, vault_entry_id=stored_id, authorized=True, credential_type="api_key")


def _authorized_request(
    *, base_url: str, path: str, method: str, body: Any, runtime_vault_entry_id: str, vault_url: str,
) -> tuple[int, dict[str, Any]]:
    origin = _base_url(base_url)
    api_key = _vault_lease(runtime_vault_entry_id, origin, "api_key", vault_url)
    try:
        return _request_json(
            f"{origin}{_api_path(path)}",
            method=method,
            headers={"X-API-Key": api_key},
            body=body,
        )
    finally:
        api_key = ""


@conn.handler("auth/query/status", isolated=True, meta={"label": "Verify the vault-backed Plesk API key"})
def auth_status(
    base_url: str = "",
    runtime_vault_entry_id: str = "plesk-runtime",
    probe_path: str = "/api/v2/domains",
    vault_url: str = "",
) -> dict[str, Any]:
    try:
        status, _ = _authorized_request(
            base_url=base_url, path=probe_path, method="GET", body=None,
            runtime_vault_entry_id=runtime_vault_entry_id, vault_url=vault_url,
        )
    except RuntimeError as error:
        return urirun.fail(str(error))
    authenticated = 200 <= status < 300
    return urirun.ok(
        schema="subactor.connector-auth-status/v1",
        base_url=_base_url(base_url),
        authorized=authenticated,
        authenticated=authenticated,
        http_status=status,
        credential_handle=runtime_vault_entry_id if authenticated else None,
        credential_type="api_key" if authenticated else None,
        scopes=["plesk.api.v2"] if authenticated else [],
        expires_at=None,
        refreshable=False,
        delegatable=False,
        interactive_consent_required=False,
        secret_value_visible=False,
        principal="organization:plesk-account" if authenticated else None,
        provider="plesk",
        evidence={"provider_probe": authenticated, "scope_probe": False, "evidence_bundle_id": None},
    )


@conn.handler("auth/query/acquisition-methods", isolated=True, meta={"label": "Describe safe Plesk credential acquisition methods"})
def auth_acquisition_methods(
    admin_vault_entry_id: str = "plesk-admin-bootstrap",
    runtime_vault_entry_id: str = "plesk-runtime",
) -> dict[str, Any]:
    return urirun.ok(
        methods=[{
            "type": "api_key",
            "command_uri": "plesk://host/auth/command/bootstrap-api-key",
            "root_credential_handle": admin_vault_entry_id,
            "result_credential_handle": runtime_vault_entry_id,
            "interactive_consent_required": False,
            "mfa_required": False,
            "secret_value_visible": False,
        }],
    )


@conn.handler("auth/query/scopes", isolated=True, meta={"label": "Report Plesk credential scope evidence"})
def auth_scopes(
    base_url: str = "",
    runtime_vault_entry_id: str = "plesk-runtime",
    vault_url: str = "",
) -> dict[str, Any]:
    status = auth_status(base_url=base_url, runtime_vault_entry_id=runtime_vault_entry_id, vault_url=vault_url)
    if not status.get("ok") or not status.get("authenticated"):
        return status
    return urirun.ok(
        schema="subactor.connector-auth-status/v1",
        authenticated=True,
        credential_handle=runtime_vault_entry_id,
        credential_type="api_key",
        scopes=["plesk.api.v2"],
        expires_at=None,
        refreshable=False,
        delegatable=False,
        interactive_consent_required=False,
        secret_value_visible=False,
        principal="organization:plesk-account",
        provider="plesk",
        evidence={"provider_probe": True, "scope_probe": True, "evidence_bundle_id": None},
    )


@conn.handler("api/query/request", isolated=True, meta={"label": "Execute a read-only Plesk REST API request"})
def api_query(
    path: str = "", base_url: str = "", runtime_vault_entry_id: str = "plesk-runtime", vault_url: str = "",
) -> dict[str, Any]:
    try:
        status, data = _authorized_request(
            base_url=base_url, path=path, method="GET", body=None,
            runtime_vault_entry_id=runtime_vault_entry_id, vault_url=vault_url,
        )
    except RuntimeError as error:
        return urirun.fail(str(error))
    if not 200 <= status < 300:
        return urirun.fail(f"plesk_api_request_failed:{status}")
    return urirun.ok(http_status=status, data=_redact(data))


@conn.handler("api/command/request", isolated=True, meta={"label": "Execute a mutating Plesk REST API request"})
def api_command(
    path: str = "", method: str = "POST", body: Any = None, base_url: str = "",
    runtime_vault_entry_id: str = "plesk-runtime", vault_url: str = "",
) -> dict[str, Any]:
    verb = method.upper()
    if verb not in {"POST", "PUT", "PATCH", "DELETE"}:
        return urirun.fail("plesk_api_method_not_allowed")
    try:
        status, data = _authorized_request(
            base_url=base_url, path=path, method=verb, body=body,
            runtime_vault_entry_id=runtime_vault_entry_id, vault_url=vault_url,
        )
    except RuntimeError as error:
        return urirun.fail(str(error))
    if not 200 <= status < 300:
        return urirun.fail(f"plesk_api_request_failed:{status}")
    return urirun.ok(http_status=status, data=_redact(data))


@conn.handler("mailbox/query/status", isolated=True, meta={"label": "Inspect a Plesk mailbox without exposing credentials"})
def mailbox_status(
    email: str = "",
    base_url: str = "",
    runtime_vault_entry_id: str = "plesk-runtime",
    vault_url: str = "",
    api_path: str = "/api/v2/cli/mail/call",
) -> dict[str, Any]:
    address = email.strip().lower()
    if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+", address):
        return urirun.fail("plesk_mailbox_email_invalid", mutation_attempted=False)
    try:
        exists, status, _ = _mailbox_probe(
            address,
            base_url=base_url,
            runtime_vault_entry_id=runtime_vault_entry_id,
            vault_url=vault_url,
            api_path=api_path,
        )
        return urirun.ok(email=address, exists=exists, http_status=status, mutation_attempted=False)
    except RuntimeError as error:
        return urirun.fail(str(error), email=address, mutation_attempted=False)


@conn.handler("mailbox/command/ensure", isolated=True, meta={"label": "Plan or ensure a Plesk mailbox and vault-backed IMAP/SMTP credential"})
def ensure_mailbox(
    email: str = "",
    display_name: str = "",
    credential_vault_entry_id: str = "",
    credential_origin: str = "",
    smtp_vault_entry_id: str = "",
    smtp_credential_origin: str = "",
    rotate_existing: bool = False,
    apply: bool = False,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    base_url: str = "",
    runtime_vault_entry_id: str = "plesk-runtime",
    vault_url: str = "",
    api_path: str = "/api/v2/cli/mail/call",
) -> dict[str, Any]:
    address = email.strip().lower()
    if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+", address):
        return urirun.fail("plesk_mailbox_email_invalid")
    try:
        origin = _credential_origin(credential_origin)
        entry_id = _vault_entry_id(
            credential_vault_entry_id,
            default=f"plesk-mailbox-{hashlib.sha256(address.encode()).hexdigest()[:20]}",
        )
        smtp_entry_id = _vault_entry_id(smtp_vault_entry_id, default=entry_id) if smtp_vault_entry_id else ""
        smtp_origin = _smtp_credential_origin(smtp_credential_origin) if smtp_entry_id else ""
        api_origin = _base_url(base_url)
        exists, probe_status, _ = _mailbox_probe(
            address,
            base_url=base_url,
            runtime_vault_entry_id=runtime_vault_entry_id,
            vault_url=vault_url,
            api_path=api_path,
        )
        action = "rotate" if exists and rotate_existing else "keep" if exists else "create"
        plan_body = {
            "schema": "urirun.plesk-mailbox-ensure-plan/v1",
            "email": address,
            "action": action,
            "credential_vault_entry_id": entry_id,
            "credential_origin": origin,
            "smtp_vault_entry_id": smtp_entry_id or None,
            "smtp_credential_origin": smtp_origin or None,
            "risk_class": "governance",
        }
        digest = hashlib.sha256(json.dumps(plan_body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        plan = {**plan_body, "plan_hash": digest, "artifact_sha256": digest}
        target = f"{api_origin}|mailbox:{address}"
        if action == "keep":
            return urirun.ok(
                email=address, exists=True, created=False, rotated=False, credential_stored=False,
                dry_run=not apply, executed=False, mutation_attempted=False, target=target,
                plan_hash=digest, http_status=probe_status,
            )
        if not apply:
            return urirun.ok(
                email=address, exists=exists, created=False, rotated=False, credential_stored=False,
                dry_run=True, executed=False, mutation_attempted=False, target=target,
                plan=plan, plan_hash=digest, artifact_sha256=digest, http_status=probe_status,
            )
        if not autonomy_mutations_enabled() and not mutate_lease_active():
            return urirun.fail("autonomy_mutations_disabled", dry_run=False, mutation_attempted=False)
        if not mutate_lease_allows_apply("PLESK_MAILBOX_APPLY"):
            return urirun.fail("plesk_mailbox_apply_required", dry_run=False, mutation_attempted=False)
        if plan_hash.strip().lower() != digest:
            return urirun.fail("plan_hash_mismatch", dry_run=False, mutation_attempted=False)
        ok, error, claims = verify_apply_grant(
            apply_grant,
            plan_hash=digest,
            target=target,
            actor=actor,
            intent_pack=format_intent_pack(pack_id, pack_version),
            artifact_sha256=digest,
        )
        if not ok or not claims:
            return urirun.fail(error or "apply_grant_required", dry_run=False, mutation_attempted=False)
        if claims.get("risk_class") != "governance":
            return urirun.fail("apply_grant_risk_class_mismatch", dry_run=False, mutation_attempted=False)
        consumed, replay_error = consume_apply_grant_jti(claims["jti"], claims["expires_at"])
        if not consumed:
            return urirun.fail(replay_error or "apply_grant_replay", dry_run=False, mutation_attempted=False)

        password = f"{secrets.token_urlsafe(24)}!aA9"
        operation = "--update" if action == "rotate" else "--create"
        status, data = _authorized_request(
            base_url=base_url,
            path=api_path,
            method="POST",
            body={"params": [operation, address, "-passwd", password, "-mailbox", "true"]},
            runtime_vault_entry_id=runtime_vault_entry_id,
            vault_url=vault_url,
        )
        if not _mail_cli_success(status, data):
            raise RuntimeError(f"plesk_mailbox_{action}_failed:{status}")
        stored_id = _vault_store_secrets(
            entry_id,
            origin,
            f"Plesk mailbox {address}",
            {"username": address, "password": password},
            vault_url,
        )
        stored_smtp_id = ""
        if smtp_entry_id:
            stored_smtp_id = _vault_store_secrets(
                smtp_entry_id,
                smtp_origin,
                f"Plesk SMTP mailbox {address}",
                {"username": address, "password": password},
                vault_url,
            )
        verified, _, _ = _mailbox_probe(
            address,
            base_url=base_url,
            runtime_vault_entry_id=runtime_vault_entry_id,
            vault_url=vault_url,
            api_path=api_path,
        )
        if not verified:
            raise RuntimeError("plesk_mailbox_verification_failed")
    except RuntimeError as error:
        return urirun.fail(str(error), email=address, dry_run=not apply, mutation_attempted=bool(apply))
    finally:
        password = ""
    return urirun.ok(
        email=address,
        display_name=display_name[:160],
        exists=True,
        created=action == "create",
        rotated=action == "rotate",
        credential_stored=True,
        credential_vault_entry_id=stored_id,
        credential_origin=origin,
        smtp_vault_entry_id=stored_smtp_id or None,
        smtp_credential_origin=smtp_origin or None,
        dry_run=False,
        executed=True,
        mutation_attempted=True,
        verified=True,
        target=target,
        plan_hash=digest,
        grant_jti=claims["jti"],
        api_result=_redact(data),
    )


@conn.handler("mailbox/command/create", isolated=True, meta={"label": "Deprecated alias: plan or create a Plesk mailbox"})
def create_mailbox(**kwargs: Any) -> dict[str, Any]:
    """Backward-compatible URI alias. It is now fail-closed unless apply + grant are supplied."""
    kwargs["rotate_existing"] = False
    return ensure_mailbox(**kwargs)


def _subscription_request(
    *,
    base_url: str,
    path: str,
    method: str,
    body: Any,
    subscription_vault_entry_id: str,
    vault_url: str,
) -> tuple[int, Any]:
    """Customer-scoped REST call using Basic auth from a vault subscription entry."""
    origin = _base_url(base_url)
    username = _vault_lease(subscription_vault_entry_id, origin, "username", vault_url)
    password = _vault_lease(subscription_vault_entry_id, origin, "password", vault_url)
    try:
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        return _request_json(
            f"{origin}{_api_path(path)}",
            method=method,
            headers={"authorization": f"Basic {auth}"},
            body=body,
        )
    finally:
        username = password = auth = ""


def _https_credential_origin(value: str, host: str = "") -> str:
    raw = (value or "").strip() or (f"https://{host}" if host else "")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("plesk_ftp_credential_origin_invalid")
    netloc = parsed.netloc
    return f"https://{netloc}"


def _xml_agent(base_url: str, username: str, password: str, packet: str) -> str:
    """Call Plesk XML API (enterprise/control/agent.php) with HTTP_AUTH_* headers."""
    origin = _base_url(base_url)
    request = urllib.request.Request(
        f"{origin}/enterprise/control/agent.php",
        data=packet.encode("utf-8"),
        method="POST",
        headers={
            "content-type": "text/xml",
            "HTTP_AUTH_LOGIN": username,
            "HTTP_AUTH_PASSWD": password,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=_ssl_context()) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, urllib.error.HTTPError) as error:
        raise RuntimeError("plesk_xml_transport_failed") from error


def _admin_xml(
    *, base_url: str, packet: str, admin_vault_entry_id: str, vault_url: str,
) -> str:
    """Run an administrator-only XML API packet with vault-leased credentials."""
    origin = _base_url(base_url)
    username = password = ""
    try:
        username = _vault_lease(admin_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(admin_vault_entry_id, origin, "password", vault_url)
        return _xml_agent(base_url, username, password, packet)
    finally:
        username = password = ""


def _installed_extension(
    extension_id: str, *, base_url: str, admin_vault_entry_id: str, vault_url: str,
) -> dict[str, Any]:
    raw = _admin_xml(
        base_url=base_url,
        packet=extension_inventory_packet(extension_id),
        admin_vault_entry_id=admin_vault_entry_id,
        vault_url=vault_url,
    )
    rows = parse_extension_inventory(raw)
    if not rows:
        raise RuntimeError("plesk_extension_not_installed")
    if not rows[0]["active"]:
        raise RuntimeError("plesk_extension_inactive")
    return rows[0]


@conn.handler("extensions/query/catalog", isolated=True, meta={"label": "Discover installed Plesk extensions"})
def extension_catalog(
    extension_id: str = "",
    base_url: str = "",
    admin_vault_entry_id: str = "plesk-admin-bootstrap",
    runtime_vault_entry_id: str = "plesk-runtime",
    vault_url: str = "",
) -> dict[str, Any]:
    extensions: list[dict[str, Any]] = []
    xml_error: RuntimeError | None = None
    try:
        raw = _admin_xml(
            base_url=base_url,
            packet=extension_inventory_packet(extension_id.strip().lower()),
            admin_vault_entry_id=admin_vault_entry_id,
            vault_url=vault_url,
        )
        extensions = parse_extension_inventory(raw)
    except RuntimeError as error:
        xml_error = error

    cli_used = False
    api_key = ""
    try:
        origin = _base_url(base_url)
        api_key = _vault_lease(runtime_vault_entry_id, origin, "api_key", vault_url)
        status, data = _request_json(
            f"{origin}/api/v2/cli/extension/call",
            method="POST",
            headers={"X-API-Key": api_key},
            body={"params": ["--list"]},
        )
        if status in {200, 201} and int(data.get("code") or 0) == 0:
            cli_rows = parse_extension_cli_inventory(str(data.get("stdout") or ""))
            if extension_id.strip():
                cli_rows = [row for row in cli_rows if row["id"] == extension_id.strip().lower()]
            merged = {row["id"]: row for row in cli_rows}
            merged.update({row["id"]: row for row in extensions})
            extensions = sorted(merged.values(), key=lambda item: item["id"])
            cli_used = True
    except RuntimeError:
        pass
    finally:
        api_key = ""

    if xml_error is not None and not cli_used:
        return urirun.fail(str(xml_error))
    return urirun.ok(
        schema="urirun.plesk-extension-inventory/v1",
        extensions=extensions,
        installed=len(extensions),
        authority="plesk-administrator",
        source="xml-api:extension.get+rest-cli:extension.--list" if cli_used else "xml-api:extension.get",
    )


@conn.handler("extensions/query/capabilities", isolated=True, meta={"label": "Join installed Plesk extensions with executable profiles"})
def extension_capabilities(
    base_url: str = "",
    admin_vault_entry_id: str = "plesk-admin-bootstrap",
    runtime_vault_entry_id: str = "plesk-runtime",
    vault_url: str = "",
) -> dict[str, Any]:
    inventory = extension_catalog(
        base_url=base_url,
        admin_vault_entry_id=admin_vault_entry_id,
        runtime_vault_entry_id=runtime_vault_entry_id,
        vault_url=vault_url,
    )
    if not inventory.get("ok"):
        return inventory
    return urirun.ok(**extension_capability_catalog(inventory["extensions"]))


@conn.handler("extension/query/call", isolated=True, meta={"label": "Call a profiled read-only Plesk extension operation"})
def extension_query(
    extension_id: str = "",
    operation: str = "",
    arguments: Any = None,
    base_url: str = "",
    admin_vault_entry_id: str = "plesk-admin-bootstrap",
    vault_url: str = "",
) -> dict[str, Any]:
    extension_id = extension_id.strip().lower()
    operation = operation.strip().lower()
    try:
        packet, spec = extension_call_packet(extension_id, operation, arguments, effect="query")
        installed = _installed_extension(
            extension_id,
            base_url=base_url,
            admin_vault_entry_id=admin_vault_entry_id,
            vault_url=vault_url,
        )
        raw = _admin_xml(
            base_url=base_url,
            packet=packet,
            admin_vault_entry_id=admin_vault_entry_id,
            vault_url=vault_url,
        )
        data = parse_extension_call(raw)
    except RuntimeError as error:
        return urirun.fail(str(error))
    return urirun.ok(
        extension=installed,
        operation=operation,
        transport=spec["transport"],
        data=data,
        executed=True,
        mutation_attempted=False,
    )


@conn.handler("extension/command/call", isolated=True, meta={"label": "Plan or execute a profiled Plesk extension mutation"})
def extension_command(
    extension_id: str = "",
    operation: str = "",
    arguments: Any = None,
    apply: bool = False,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    base_url: str = "",
    admin_vault_entry_id: str = "plesk-admin-bootstrap",
    vault_url: str = "",
) -> dict[str, Any]:
    extension_id = extension_id.strip().lower()
    operation = operation.strip().lower()
    try:
        plan, spec = extension_operation_plan(extension_id, operation, arguments)
        origin = _base_url(base_url)
    except RuntimeError as error:
        return urirun.fail(str(error), dry_run=not apply, mutation_attempted=False)
    target = f"{origin}|extension:{extension_id}:{operation}"
    delegated_to = spec.get("uri") if spec.get("transport") == "uri-process" else None
    if not apply:
        return urirun.ok(
            dry_run=True,
            executed=False,
            mutation_attempted=False,
            target=target,
            plan=plan,
            plan_hash=plan["plan_hash"],
            artifact_sha256=plan["artifact_sha256"],
            delegated_to=delegated_to,
        )
    if delegated_to or spec.get("callable") is not True or spec.get("transport") != "xml-extension":
        return urirun.fail(
            "plesk_extension_operation_delegated",
            dry_run=False,
            mutation_attempted=False,
            delegated_to=delegated_to,
        )
    if plan_hash.strip().lower() != plan["plan_hash"]:
        return urirun.fail("plan_hash_mismatch", dry_run=False, mutation_attempted=False)
    if not autonomy_mutations_enabled() and not mutate_lease_active():
        return urirun.fail("autonomy_mutations_disabled", dry_run=False, mutation_attempted=False)
    if os.environ.get("PLESK_EXTENSION_APPLY", "").strip() != "1":
        return urirun.fail("plesk_extension_apply_required", dry_run=False, mutation_attempted=False)
    ok, error, claims = verify_apply_grant(
        apply_grant,
        plan_hash=plan["plan_hash"],
        target=target,
        actor=actor,
        intent_pack=format_intent_pack(pack_id, pack_version),
        artifact_sha256=plan["artifact_sha256"],
    )
    if not ok or not claims:
        return urirun.fail(error or "apply_grant_required", dry_run=False, mutation_attempted=False)
    if claims.get("risk_class") != spec.get("risk_class"):
        return urirun.fail("apply_grant_risk_class_mismatch", dry_run=False, mutation_attempted=False)
    try:
        installed = _installed_extension(
            extension_id,
            base_url=base_url,
            admin_vault_entry_id=admin_vault_entry_id,
            vault_url=vault_url,
        )
        packet, _ = extension_call_packet(extension_id, operation, arguments, effect="command")
    except RuntimeError as preflight_error:
        return urirun.fail(str(preflight_error), dry_run=False, mutation_attempted=False)
    consumed, replay_error = consume_apply_grant_jti(claims["jti"], claims["expires_at"])
    if not consumed:
        return urirun.fail(replay_error or "apply_grant_replay", dry_run=False, mutation_attempted=False)
    try:
        raw = _admin_xml(
            base_url=base_url,
            packet=packet,
            admin_vault_entry_id=admin_vault_entry_id,
            vault_url=vault_url,
        )
        data = parse_extension_call(raw)
    except RuntimeError as call_error:
        return urirun.fail(str(call_error), dry_run=False, mutation_attempted=True)
    return urirun.ok(
        extension=installed,
        operation=operation,
        transport=spec["transport"],
        data=data,
        dry_run=False,
        executed=True,
        mutation_attempted=True,
        verified=True,
        plan_hash=plan["plan_hash"],
        grant_jti=claims["jti"],
    )


def _xml_ok(raw: str) -> bool:
    return "<status>ok</status>" in raw and "<status>error</status>" not in raw


def _xml_props(raw: str) -> dict[str, str]:
    return dict(re.findall(r"<name>([^<]+)</name>\s*<value>([^<]*)</value>", raw))


def _xml_root(raw: str) -> ET.Element:
    try:
        return ET.fromstring(raw)
    except ET.ParseError as error:
        raise RuntimeError("plesk_xml_response_invalid") from error


def _xml_results(raw: str, operation: str) -> list[ET.Element]:
    root = _xml_root(raw)
    return list(root.findall(f".//{operation}/result"))


_DNS_ADDRESS_TYPES = {"A", "AAAA", "CNAME"}


def _dns_site_id(value: Any) -> int:
    try:
        site_id = int(value)
    except (TypeError, ValueError) as error:
        raise RuntimeError("plesk_dns_site_id_invalid") from error
    if site_id <= 0:
        raise RuntimeError("plesk_dns_site_id_invalid")
    return site_id


def _dns_hostname(value: str, *, allow_wildcard: bool = False) -> str:
    host = (value or "").strip().rstrip(".").lower()
    wildcard = host.startswith("*.")
    plain_host = host[2:] if wildcard else host
    if (
        len(host) > 253
        or (wildcard and not allow_wildcard)
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", plain_host)
        or "." not in plain_host
        or any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in plain_host.split("."))
    ):
        raise RuntimeError("plesk_dns_host_invalid")
    return host


def _dns_type(value: str) -> str:
    record_type = (value or "").strip().upper()
    if record_type not in _DNS_ADDRESS_TYPES:
        raise RuntimeError("plesk_dns_record_type_not_allowed")
    return record_type


def _dns_value(record_type: str, value: str) -> str:
    wanted = (value or "").strip().rstrip(".")
    if record_type == "A":
        import ipaddress
        try:
            if ipaddress.ip_address(wanted).version != 4:
                raise ValueError
        except ValueError as error:
            raise RuntimeError("plesk_dns_value_invalid") from error
        return wanted
    if record_type == "AAAA":
        import ipaddress
        try:
            parsed = ipaddress.ip_address(wanted)
            if parsed.version != 6:
                raise ValueError
        except ValueError as error:
            raise RuntimeError("plesk_dns_value_invalid") from error
        return parsed.compressed
    return _dns_hostname(wanted)


def _dns_zone(value: str, host: str = "") -> str:
    zone = _dns_hostname(value)
    if host and host != zone and not host.endswith(f".{zone}"):
        raise RuntimeError("plesk_dns_host_outside_zone")
    return zone


def _dns_ttl(value: Any) -> int:
    try:
        ttl = int(value)
    except (TypeError, ValueError) as error:
        raise RuntimeError("plesk_dns_ttl_invalid") from error
    if ttl != 1 and not 60 <= ttl <= 86400:
        raise RuntimeError("plesk_dns_ttl_invalid")
    return ttl


def _dns_records_packet(site_id: int) -> str:
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<packet><dns><get_rec><filter><site-id>{site_id}</site-id></filter></get_rec></dns></packet>'''


def _dns_parse_records(raw: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    results = _xml_results(raw, "get_rec")
    for result in results:
        if (result.findtext("status") or "").strip() != "ok":
            continue
        data_node = result.find("data")
        data = data_node if data_node is not None else result
        raw_id = (result.findtext("id") or data.findtext("id") or "").strip()
        host = (data.findtext("host") or result.findtext("host") or "").strip().rstrip(".").lower()
        record_type = (data.findtext("type") or result.findtext("type") or "").strip().upper()
        value = (data.findtext("value") or result.findtext("value") or "").strip().rstrip(".")
        opt = (data.findtext("opt") or result.findtext("opt") or "").strip()
        if raw_id.isdigit() and host and record_type:
            records.append({
                "id": int(raw_id),
                "host": host,
                "type": record_type,
                "value": value,
                "opt": opt or None,
            })
    if results and not records and any((node.findtext("status") or "").strip() == "error" for node in results):
        raise RuntimeError("plesk_dns_query_failed")
    return records


def _dns_with_credentials(
    *, site_id: int, base_url: str, username: str, password: str,
) -> list[dict[str, Any]]:
    return _dns_parse_records(_xml_agent(base_url, username, password, _dns_records_packet(site_id)))


def _dns_plan(site_id: int, host: str, record_type: str, value: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    address_records = [row for row in records if row["host"] == host and row["type"] in _DNS_ADDRESS_TYPES]
    exact = [row for row in address_records if row["type"] == record_type and row["value"].rstrip(".").lower() == value.lower()]
    delete = [row for row in address_records if row not in exact[:1]]
    add = not exact
    body = {
        "schema": "urirun.plesk-dns-replace-plan/v1",
        "site_id": site_id,
        "host": host,
        "record_type": record_type,
        "value": value,
        "delete_record_ids": sorted(row["id"] for row in delete),
        "add_record": add,
        "risk_class": "boundary",
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**body, "changed": bool(delete or add), "plan_hash": digest, "artifact_sha256": digest}


def _dns_add_operation(site_id: int, record_type: str, host: str, value: str, opt: str | None = None) -> str:
    optional = f"<opt>{_xml_escape(opt)}</opt>" if opt else ""
    return (
        "<add_rec><site-id>" + str(site_id) + "</site-id><type>" + record_type
        + "</type><host>" + _xml_escape(host) + "</host><value>"
        + _xml_escape(value) + "</value>" + optional + "</add_rec>"
    )


def _dns_packet(operations: str) -> str:
    return f'''<?xml version="1.0" encoding="UTF-8"?><packet><dns>{operations}</dns></packet>'''


def _dns_provider_error(raw: str, operation: str) -> dict[str, Any]:
    """Return bounded Plesk error metadata without reflecting request credentials."""
    for result in _xml_results(raw, operation):
        if (result.findtext("status") or "").strip() != "error":
            continue
        errtext = re.sub(r"[\x00-\x1f\x7f]+", " ", result.findtext("errtext") or "").strip()
        return {
            "operation": operation,
            "errcode": (result.findtext("errcode") or "").strip() or None,
            "errtext": errtext[:300] or None,
        }
    return {"operation": operation, "errcode": None, "errtext": None}


@conn.handler("dns/query/records", isolated=True, meta={"label": "List filtered Plesk DNS records through XML API"})
def dns_records(
    site_id: int = 0,
    host: str = "",
    record_type: str = "",
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    vault_url: str = "",
) -> dict[str, Any]:
    username = password = ""
    try:
        resolved_site_id = _dns_site_id(site_id)
        wanted_host = _dns_hostname(host, allow_wildcard=True) if host else ""
        wanted_type = _dns_type(record_type) if record_type else ""
        origin = _base_url(base_url)
        username = _vault_lease(subscription_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(subscription_vault_entry_id, origin, "password", vault_url)
        rows = _dns_with_credentials(
            site_id=resolved_site_id, base_url=base_url, username=username, password=password,
        )
        if wanted_host:
            rows = [row for row in rows if row["host"] == wanted_host]
        if wanted_type:
            rows = [row for row in rows if row["type"] == wanted_type]
        return urirun.ok(site_id=resolved_site_id, records=rows, count=len(rows), mutation_attempted=False)
    except RuntimeError as error:
        return urirun.fail(str(error), mutation_attempted=False)
    finally:
        username = password = ""


@conn.handler("dns/command/replace", isolated=True, meta={"label": "Plan or atomically replace a Plesk address DNS record"})
def dns_replace(
    site_id: int = 0,
    host: str = "",
    record_type: str = "A",
    value: str = "",
    apply: bool = False,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    vault_url: str = "",
) -> dict[str, Any]:
    username = password = ""
    try:
        resolved_site_id = _dns_site_id(site_id)
        wanted_host = _dns_hostname(host, allow_wildcard=True)
        wanted_type = _dns_type(record_type)
        wanted_value = _dns_value(wanted_type, value)
        origin = _base_url(base_url)
    except RuntimeError as error:
        return urirun.fail(str(error), dry_run=not apply, mutation_attempted=False)

    if apply and not autonomy_mutations_enabled() and not mutate_lease_active():
        return urirun.fail("autonomy_mutations_disabled", dry_run=False, mutation_attempted=False)
    if apply and not mutate_lease_allows_apply("PLESK_DNS_APPLY"):
        return urirun.fail("plesk_dns_apply_required", dry_run=False, mutation_attempted=False)

    try:
        username = _vault_lease(subscription_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(subscription_vault_entry_id, origin, "password", vault_url)
        records = _dns_with_credentials(
            site_id=resolved_site_id, base_url=base_url, username=username, password=password,
        )
        plan = _dns_plan(resolved_site_id, wanted_host, wanted_type, wanted_value, records)
        target = f"{origin}|dns:{resolved_site_id}:{wanted_host}"
        visible = [row for row in records if row["host"] == wanted_host and row["type"] in _DNS_ADDRESS_TYPES]
        if not apply:
            return urirun.ok(
                dry_run=True, executed=False, mutation_attempted=False, target=target,
                existing=visible, plan=plan, plan_hash=plan["plan_hash"],
                artifact_sha256=plan["artifact_sha256"], changed=plan["changed"],
            )
        if not plan["changed"]:
            return urirun.ok(
                dry_run=False, executed=False, mutation_attempted=False, verified=True,
                target=target, existing=visible, plan_hash=plan["plan_hash"], changed=False,
            )
        if plan_hash.strip().lower() != plan["plan_hash"]:
            return urirun.fail("plan_hash_mismatch", dry_run=False, mutation_attempted=False)
        ok, error, claims = verify_apply_grant(
            apply_grant,
            plan_hash=plan["plan_hash"],
            target=target,
            actor=actor,
            intent_pack=format_intent_pack(pack_id, pack_version),
            artifact_sha256=plan["artifact_sha256"],
        )
        if not ok or not claims:
            return urirun.fail(error or "apply_grant_required", dry_run=False, mutation_attempted=False)
        if claims.get("risk_class") != "boundary":
            return urirun.fail("apply_grant_risk_class_mismatch", dry_run=False, mutation_attempted=False)
        consumed, replay_error = consume_apply_grant_jti(claims["jti"], claims["expires_at"])
        if not consumed:
            return urirun.fail(replay_error or "apply_grant_replay", dry_run=False, mutation_attempted=False)

        deleted_records = [row for row in visible if row["id"] in plan["delete_record_ids"]]
        if plan["delete_record_ids"]:
            delete_operations = "".join(
                f"<del_rec><filter><id>{record_id}</id></filter></del_rec>"
                for record_id in plan["delete_record_ids"]
            )
            raw = _xml_agent(base_url, username, password, _dns_packet(delete_operations))
            if not _xml_ok(raw):
                return urirun.fail(
                    "plesk_dns_delete_failed", dry_run=False, mutation_attempted=True,
                    provider_error=_dns_provider_error(raw, "del_rec"), rollback_attempted=False,
                )
        if plan["add_record"]:
            raw = _xml_agent(
                base_url, username, password,
                _dns_packet(_dns_add_operation(resolved_site_id, wanted_type, wanted_host, wanted_value)),
            )
            if not _xml_ok(raw):
                rollback_attempted = bool(deleted_records)
                rollback_ok = False
                if rollback_attempted:
                    restore_operations = "".join(
                        _dns_add_operation(
                            resolved_site_id, row["type"], row["host"], row["value"], row.get("opt"),
                        )
                        for row in deleted_records
                    )
                    restore_raw = _xml_agent(
                        base_url, username, password, _dns_packet(restore_operations),
                    )
                    rollback_ok = _xml_ok(restore_raw)
                return urirun.fail(
                    "plesk_dns_add_failed", dry_run=False, mutation_attempted=True,
                    provider_error=_dns_provider_error(raw, "add_rec"),
                    rollback_attempted=rollback_attempted, rollback_ok=rollback_ok,
                )
        verified_records = _dns_with_credentials(
            site_id=resolved_site_id, base_url=base_url, username=username, password=password,
        )
        remaining = [row for row in verified_records if row["host"] == wanted_host and row["type"] in _DNS_ADDRESS_TYPES]
        verified = (
            len(remaining) == 1
            and remaining[0]["type"] == wanted_type
            and remaining[0]["value"].rstrip(".").lower() == wanted_value.lower()
        )
        if not verified:
            return urirun.fail(
                "plesk_dns_verification_failed", dry_run=False, mutation_attempted=True, records=remaining,
            )
        return urirun.ok(
            dry_run=False, executed=True, mutation_attempted=True, verified=True, changed=True,
            target=target, record=remaining[0], plan_hash=plan["plan_hash"], grant_jti=claims["jti"],
        )
    except RuntimeError as error:
        return urirun.fail(str(error), dry_run=not apply, mutation_attempted=False)
    finally:
        username = password = ""


@conn.handler("dns/query/authority", isolated=True, meta={"label": "Detect authoritative DNS provider with resolver consensus"})
def dns_authority(zone: str = "", instance_id: str = "") -> dict[str, Any]:
    try:
        wanted_zone = _dns_zone(zone)
        authority = resolve_dns_authority(wanted_zone)
        provider = authority.get("provider")
        nameservers = list(authority.get("nameservers") or [])
        consistent = bool(authority.get("consistent"))
        management = (
            "cloudflaredns" if provider == "cloudflare"
            else "plesk" if provider == "plesk"
            else provider
        )
        fact = _twin_fact(
            twin_type="plesk.dns.authority",
            instance_id=(instance_id or wanted_zone).strip() or wanted_zone,
            uri="plesk://host/dns/query/authority",
            payload={
                "hostname": wanted_zone,
                "provider": provider,
                "nameservers": nameservers,
                "management_plane": management,
                "consistent": consistent,
            },
            fact_quality="fresh" if consistent else "stale",
        )
        if not consistent:
            return urirun.fail(
                "dns_authority_inconsistent",
                authority=authority,
                twin_fact=fact,
                mutation_attempted=False,
            )
        return urirun.ok(
            authority=authority,
            provider=provider,
            twin_fact=fact,
            fact_quality=fact["fact_quality"],
            mutation_attempted=False,
        )
    except RuntimeError as error:
        return urirun.fail(str(error), mutation_attempted=False)


@conn.handler("dns/query/propagation", isolated=True, meta={"label": "Compare DNS records and TTLs across public resolvers"})
def dns_propagation(
    host: str = "", record_type: str = "A", expected_value: str = "",
) -> dict[str, Any]:
    try:
        wanted_host = _dns_hostname(host, allow_wildcard=True)
        wanted_type = _dns_type(record_type)
        wanted_value = _dns_value(wanted_type, expected_value) if expected_value else ""
        propagation = resolve_dns_propagation(wanted_host, wanted_type, wanted_value)
        return urirun.ok(
            propagation=propagation,
            propagated=propagation["propagated"],
            consensus=propagation["consensus"],
            mutation_attempted=False,
        )
    except RuntimeError as error:
        return urirun.fail(str(error), mutation_attempted=False)


@conn.handler("dns/command/reconcile", isolated=True, meta={"label": "Reconcile DNS through its authoritative provider"})
def dns_reconcile(
    zone: str = "",
    host: str = "",
    record_type: str = "A",
    value: str = "",
    ttl: int = 1,
    proxied: bool = False,
    expected_provider: str = "",
    site_id: int = 0,
    apply: bool = False,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    cloudflare_vault_entry_id: str = "cloudflare-dns",
    vault_url: str = "",
) -> dict[str, Any]:
    """Expose one DNS control surface without hiding the real authority boundary."""
    token = zone_id = ""
    mutation_attempted = False
    try:
        wanted_host = _dns_hostname(host, allow_wildcard=True)
        wanted_zone = _dns_zone(zone, wanted_host)
        wanted_type = _dns_type(record_type)
        wanted_value = _dns_value(wanted_type, value)
        wanted_ttl = _dns_ttl(ttl)
        requested_provider = expected_provider.strip().lower()
        if requested_provider and requested_provider not in {"cloudflare", "plesk"}:
            raise RuntimeError("dns_expected_provider_invalid")
        authority = resolve_dns_authority(wanted_zone)
        provider = authority["provider"]
        if not authority["consistent"]:
            return urirun.fail(
                "dns_authority_inconsistent", dry_run=not apply, authority=authority,
                mutation_attempted=False,
            )
        if requested_provider and requested_provider != provider:
            return urirun.fail(
                "dns_authoritative_provider_mismatch", dry_run=not apply,
                expected_provider=requested_provider, provider=provider, authority=authority,
                mutation_attempted=False,
            )

        if provider == "plesk":
            result = dns_replace(
                site_id=site_id,
                host=wanted_host,
                record_type=wanted_type,
                value=wanted_value,
                apply=apply,
                plan_hash=plan_hash,
                apply_grant=apply_grant,
                actor=actor,
                pack_id=pack_id,
                pack_version=pack_version,
                base_url=base_url,
                subscription_vault_entry_id=subscription_vault_entry_id,
                vault_url=vault_url,
            )
            return {**result, "provider": "plesk", "authority": authority}
        if provider != "cloudflare":
            return urirun.fail(
                "dns_authoritative_provider_unsupported", dry_run=not apply,
                provider=provider, authority=authority, mutation_attempted=False,
            )

        if apply and not autonomy_mutations_enabled() and not mutate_lease_active():
            return urirun.fail("autonomy_mutations_disabled", dry_run=False, mutation_attempted=False)
        if apply and not mutate_lease_allows_apply("CLOUDFLARE_DNS_APPLY"):
            return urirun.fail("cloudflare_dns_apply_required", dry_run=False, mutation_attempted=False)

        token = _vault_lease(
            cloudflare_vault_entry_id, CLOUDFLARE_CREDENTIAL_ORIGIN, "api_token", vault_url,
        )
        zone_id = _vault_lease(
            cloudflare_vault_entry_id, CLOUDFLARE_CREDENTIAL_ORIGIN, "zone_id", vault_url,
        )
        records = cloudflare_records(zone_id, wanted_zone, wanted_host, token)
        plan = cloudflare_plan(
            wanted_zone, wanted_host, wanted_type, wanted_value, records,
            ttl=wanted_ttl, proxied=bool(proxied),
        )
        target = f"cloudflare://{wanted_zone}/dns:{wanted_host}"
        receipt = {
            "provider": "cloudflare",
            "authority": authority,
            "target": target,
            "existing": records,
            "plan_hash": plan["plan_hash"],
            "artifact_sha256": plan["artifact_sha256"],
            "changed": plan["changed"],
        }
        if not apply:
            return urirun.ok(
                dry_run=True, executed=False, mutation_attempted=False, plan=plan, **receipt,
            )
        if not plan["changed"]:
            return urirun.ok(
                dry_run=False, executed=False, mutation_attempted=False, verified=True, **receipt,
            )
        if plan_hash.strip().lower() != plan["plan_hash"]:
            return urirun.fail("plan_hash_mismatch", dry_run=False, mutation_attempted=False, **receipt)
        ok, error, claims = verify_apply_grant(
            apply_grant,
            plan_hash=plan["plan_hash"],
            target=target,
            actor=actor,
            intent_pack=format_intent_pack(pack_id, pack_version),
            artifact_sha256=plan["artifact_sha256"],
        )
        if not ok or not claims:
            return urirun.fail(error or "apply_grant_required", dry_run=False, mutation_attempted=False, **receipt)
        if claims.get("risk_class") != "boundary":
            return urirun.fail("apply_grant_risk_class_mismatch", dry_run=False, mutation_attempted=False, **receipt)
        consumed, replay_error = consume_apply_grant_jti(claims["jti"], claims["expires_at"])
        if not consumed:
            return urirun.fail(replay_error or "apply_grant_replay", dry_run=False, mutation_attempted=False, **receipt)

        mutation_attempted = True
        apply_cloudflare_plan(zone_id, token, plan)
        verified_records = cloudflare_records(zone_id, wanted_zone, wanted_host, token)
        verified = (
            len(verified_records) == 1
            and verified_records[0]["type"] == wanted_type
            and verified_records[0]["value"].rstrip(".").lower() == wanted_value.lower()
            and verified_records[0]["ttl"] == wanted_ttl
            and verified_records[0]["proxied"] is bool(proxied)
        )
        if not verified:
            return urirun.fail(
                "cloudflare_dns_verification_failed", dry_run=False, mutation_attempted=True,
                provider="cloudflare", authority=authority, target=target, records=verified_records,
                plan_hash=plan["plan_hash"], grant_jti=claims["jti"],
            )
        return urirun.ok(
            dry_run=False, executed=True, mutation_attempted=True, verified=True, changed=True,
            provider="cloudflare", authority=authority, target=target, record=verified_records[0],
            plan_hash=plan["plan_hash"], grant_jti=claims["jti"],
        )
    except RuntimeError as error:
        return urirun.fail(str(error), dry_run=not apply, mutation_attempted=mutation_attempted)
    finally:
        token = zone_id = ""


def _xml_named_values(root: ET.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in root.iter():
        name = node.find("name")
        value = node.find("value")
        if name is not None and value is not None and name.text:
            values[name.text.strip()] = (value.text or "").strip()
    return values


def _limit_value(values: dict[str, str]) -> tuple[int | None, str | None]:
    for key in ("dom", "max_dom", "domains", "max_domains"):
        if key not in values:
            continue
        raw = values[key].strip().lower()
        if raw in {"-1", "unlimited"}:
            return -1, key
        try:
            return int(raw), key
        except ValueError:
            return None, key
    return None, None


def _permission_value(values: dict[str, str]) -> bool | None:
    for key in ("manage_domains", "create_domains", "manage_subdomains"):
        if key not in values:
            continue
        return values[key].strip().lower() in {"1", "true", "on", "yes"}
    return None


def _subscription_capabilities_with_credentials(
    *, base_url: str, subscription: str, username: str, password: str,
) -> dict[str, Any]:
    escaped = _xml_escape(subscription)
    webspace_packet = f'''<?xml version="1.0" encoding="UTF-8"?>
<packet><webspace><get><filter><name>{escaped}</name></filter>
<dataset><gen_info/><limits/><permissions/></dataset></get></webspace></packet>'''
    webspace_raw = _xml_agent(base_url, username, password, webspace_packet)
    webspace_results = _xml_results(webspace_raw, "get")
    if not any((item.findtext("status") or "").strip() == "ok" for item in webspace_results):
        return {"ok": False, "error": "plesk_subscription_not_authorized_or_missing"}
    named = _xml_named_values(_xml_root(webspace_raw))
    domain_limit, limit_key = _limit_value(named)
    permission = _permission_value(named)

    site_packet = f'''<?xml version="1.0" encoding="UTF-8"?>
<packet><site><get><filter><webspace-name>{escaped}</webspace-name></filter>
<dataset><gen_info/></dataset></get></site></packet>'''
    site_raw = _xml_agent(base_url, username, password, site_packet)
    sites = [item for item in _xml_results(site_raw, "get") if (item.findtext("status") or "").strip() == "ok"]
    domains_used = len(sites)
    limit_known = domain_limit is not None
    capacity = limit_known and (domain_limit == -1 or domains_used < domain_limit)
    can_create = capacity and permission is not False
    reason = None
    if permission is False:
        reason = "subscription_domain_permission_denied"
    elif not limit_known:
        reason = "subscription_domain_limit_unknown"
    elif not capacity:
        reason = "subscription_domain_limit_reached"
    return {
        "ok": True,
        "subscription": subscription,
        "authenticated": True,
        "permission": permission,
        "permission_known": permission is not None,
        "domains_used": domains_used,
        "domains_limit": domain_limit,
        "domains_unlimited": domain_limit == -1,
        "limit_name": limit_key,
        "limit_known": limit_known,
        "can_create_domain": can_create,
        "reason": reason,
    }


@conn.handler(
    "subscription/query/capabilities",
    isolated=True,
    meta={"label": "Verify subscription authorization and add-on domain capacity"},
)
def subscription_capabilities(
    subscription: str = "",
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    vault_url: str = "",
) -> dict[str, Any]:
    name = (subscription or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", name):
        return urirun.fail("plesk_subscription_name_invalid")
    username = password = ""
    try:
        origin = _base_url(base_url)
        username = _vault_lease(subscription_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(subscription_vault_entry_id, origin, "password", vault_url)
        result = _subscription_capabilities_with_credentials(
            base_url=base_url, subscription=name, username=username, password=password,
        )
        if not result.get("ok"):
            return urirun.fail(result.get("error") or "plesk_subscription_capability_failed")
        return urirun.ok(**{key: value for key, value in result.items() if key != "ok"})
    except RuntimeError as error:
        return urirun.fail(str(error))
    finally:
        username = password = ""


def _subscription_rows_from_webspace_xml(raw: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in _xml_results(raw, "get"):
        if (result.findtext("status") or "").strip() != "ok":
            continue
        data = result.find("data")
        gen = data.find("gen_info") if data is not None else result.find("gen_info")
        name = ""
        if gen is not None:
            name = (gen.findtext("name") or "").strip().lower()
        if not name:
            name = (result.findtext("name") or "").strip().lower()
        site_id = (result.findtext("id") or "").strip()
        named = _xml_named_values(result if data is None else data)
        domain_limit, _limit_key = _limit_value(named)
        rows.append({
            "id": int(site_id) if site_id.isdigit() else site_id or None,
            "name": name or None,
            "domains_limit": domain_limit,
            "domains_used": None,
        })
    return rows


@conn.handler(
    "subscription/query/snapshot",
    isolated=True,
    meta={"label": "Snapshot subscription capacity as a twin fact (read-only)"},
)
def subscription_query_snapshot(
    subscription: str = "",
    instance_id: str = "",
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    vault_url: str = "",
) -> dict[str, Any]:
    """Observe subscription(s) as ``subactor.twin-fact/v1`` without mutation.

    When ``subscription`` is set, returns a one-row snapshot with used/limit.
    When empty, lists webspaces visible to the leased credential (estimated
    limits when dataset incomplete).
    """
    wanted = (subscription or "").strip().lower()
    if wanted and not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", wanted):
        return urirun.fail("plesk_subscription_name_invalid", mutation_attempted=False)
    username = password = ""
    subscriptions: list[dict[str, Any]] = []
    fact_quality = "fresh"
    observe_error = None
    try:
        origin = _base_url(base_url)
        username = _vault_lease(subscription_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(subscription_vault_entry_id, origin, "password", vault_url)
        if wanted:
            caps = _subscription_capabilities_with_credentials(
                base_url=base_url, subscription=wanted, username=username, password=password,
            )
            if not caps.get("ok"):
                observe_error = caps.get("error") or "plesk_subscription_capability_failed"
                fact_quality = "estimated"
                subscriptions = [{"id": None, "name": wanted, "domains_limit": None, "domains_used": None}]
            else:
                subscriptions = [{
                    "id": caps.get("subscription_id") or caps.get("webspace_id"),
                    "name": wanted,
                    "domains_limit": caps.get("domains_limit"),
                    "domains_used": caps.get("domains_used"),
                }]
        else:
            packet = '''<?xml version="1.0" encoding="UTF-8"?>
<packet><webspace><get><filter/>
<dataset><gen_info/><limits/></dataset></get></webspace></packet>'''
            raw = _xml_agent(base_url, username, password, packet)
            subscriptions = _subscription_rows_from_webspace_xml(raw)
            if not subscriptions:
                observe_error = "plesk_subscription_list_empty"
                fact_quality = "estimated"
    except RuntimeError as error:
        observe_error = str(error) or "plesk_xml_transport_failed"
        fact_quality = "estimated"
        if wanted:
            subscriptions = [{"id": None, "name": wanted, "domains_limit": None, "domains_used": None}]
    finally:
        username = password = ""

    binding = (instance_id or wanted or "plesk-default").strip() or "plesk-default"
    payload = {
        "count": len(subscriptions),
        "subscriptions": subscriptions,
        "observe_error": observe_error,
        "filter_subscription": wanted or None,
    }
    fact = _twin_fact(
        twin_type="plesk.subscription",
        instance_id=binding,
        uri="plesk://host/subscription/query/snapshot",
        payload=payload,
        fact_quality=fact_quality,
    )
    return urirun.ok(
        twin_fact=fact,
        count=len(subscriptions),
        subscriptions=subscriptions,
        fact_quality=fact_quality,
        mutation_attempted=False,
    )


@conn.handler(
    "domain/command/ensure",
    isolated=True,
    meta={"label": "Idempotently ensure an add-on domain under an authorized subscription"},
)
def ensure_domain(
    domain: str = "",
    subscription: str = "",
    document_root: str = "httpdocs",
    apply: bool = False,
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    vault_url: str = "",
) -> dict[str, Any]:
    host = (domain or "").strip().lower()
    webspace = (subscription or "").strip().lower()
    root = (document_root or "httpdocs").strip().strip("/")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", host):
        return urirun.fail("plesk_domain_name_invalid")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", webspace):
        return urirun.fail("plesk_subscription_name_invalid")
    if not root or not re.fullmatch(r"[A-Za-z0-9_./-]+", root) or ".." in root:
        return urirun.fail("plesk_domain_document_root_invalid")
    username = password = ""
    try:
        origin = _base_url(base_url)
        username = _vault_lease(subscription_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(subscription_vault_entry_id, origin, "password", vault_url)
        get_packet = f'''<?xml version="1.0" encoding="UTF-8"?>
<packet><site><get><filter><name>{_xml_escape(host)}</name></filter>
<dataset><gen_info/></dataset></get></site></packet>'''
        existing_raw = _xml_agent(base_url, username, password, get_packet)
        existing = [item for item in _xml_results(existing_raw, "get") if (item.findtext("status") or "").strip() == "ok"]
        if existing:
            site_id = existing[0].findtext("id")
            return urirun.ok(domain=host, subscription=webspace, document_root=root, created=False, existed=True, site_id=int(site_id) if site_id and site_id.isdigit() else None, dry_run=not apply)
        capabilities = _subscription_capabilities_with_credentials(base_url=base_url, subscription=webspace, username=username, password=password)
        if not capabilities.get("ok") or not capabilities.get("can_create_domain"):
            return urirun.fail(capabilities.get("reason") or capabilities.get("error") or "plesk_domain_create_not_authorized", capabilities=capabilities)
        if not apply:
            return urirun.ok(domain=host, subscription=webspace, document_root=root, created=False, existed=False, dry_run=True, authorized=True, capabilities=capabilities)
        if os.environ.get("AUTONOMY_MUTATIONS_ENABLED") != "1" or os.environ.get("PLESK_DOMAIN_APPLY") != "1":
            return urirun.fail("plesk_domain_apply_gate_closed", dry_run=True, domain=host)
        add_packet = f'''<?xml version="1.0" encoding="UTF-8"?>
<packet><site><add><gen_setup><name>{_xml_escape(host)}</name>
<webspace-name>{_xml_escape(webspace)}</webspace-name><htype>vrt_hst</htype></gen_setup>
<hosting><vrt_hst><property><name>www_root</name><value>{_xml_escape(root)}</value></property></vrt_hst></hosting>
</add></site></packet>'''
        raw = _xml_agent(base_url, username, password, add_packet)
        if not _xml_ok(raw):
            return urirun.fail("plesk_domain_add_failed", detail=raw[:400])
        match = re.search(r"<id>(\d+)</id>", raw)
        return urirun.ok(domain=host, subscription=webspace, document_root=root, created=True, existed=False, dry_run=False, site_id=int(match.group(1)) if match else None)
    except RuntimeError as error:
        return urirun.fail(str(error))
    finally:
        username = password = ""


@conn.handler(
    "ftpuser/command/ensure",
    isolated=True,
    meta={"label": "Rotate/store Plesk site FTP|SFTP credentials (XML API; vault https origin)"},
)
def ensure_ftp_user(
    name: str = "",
    home: str = "/",
    domain: str = "",
    kind: str = "system",
    credential_vault_entry_id: str = "plesk-sftp",
    also_ftp_vault_entry_id: str = "plesk-ftp",
    credential_origin: str = "",
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    enable_ssh: bool = True,
    vault_url: str = "",
) -> dict[str, Any]:
    """Ensure deploy credentials exist with a known password stored in the vault.

    Prefer ``kind=system`` (subscription system FTP user + SSH/SFTP). Additional
    FTP accounts use ``kind=additional`` via XML ``ftp-user`` (REST v2 ftpusers is
    unreliable on some Plesk hosts: list succeeds but DELETE/PUT 404).
    """
    mode = (kind or "system").strip().lower()
    if mode not in {"system", "additional"}:
        return urirun.fail("plesk_ftp_kind_invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", credential_vault_entry_id):
        return urirun.fail("plesk_ftp_vault_entry_invalid")
    password = ""
    login = ""
    stored_id = credential_vault_entry_id
    vault_origin = ""
    cust_user = cust_pass = ""
    try:
        origin_api = _base_url(base_url)
        host = urllib.parse.urlparse(origin_api).hostname or ""
        vault_origin = _https_credential_origin(credential_origin, host)
        cust_user = _vault_lease(subscription_vault_entry_id, origin_api, "username", vault_url)
        cust_pass = _vault_lease(subscription_vault_entry_id, origin_api, "password", vault_url)
        domain_name = (domain or "").strip()
        password = f"{secrets.token_urlsafe(20)}aZ9!"

        if mode == "system":
            if not domain_name:
                raise RuntimeError("plesk_ftp_domain_required")
            ssh_prop = (
                "<property><name>ssh</name><value>/bin/bash</value></property>"
                if enable_ssh else ""
            )
            packet = f"""<?xml version="1.0" encoding="UTF-8"?>
<packet>
  <webspace>
    <set>
      <filter><name>{domain_name}</name></filter>
      <values>
        <hosting>
          <vrt_hst>
            <property><name>ftp_password</name><value>{password}</value></property>
            {ssh_prop}
          </vrt_hst>
        </hosting>
      </values>
    </set>
  </webspace>
</packet>"""
            raw = _xml_agent(base_url, cust_user, cust_pass, packet)
            if not _xml_ok(raw):
                raise RuntimeError("plesk_ftp_system_rotate_failed")
            # read back login name
            get_packet = f"""<?xml version="1.0" encoding="UTF-8"?>
<packet>
  <webspace>
    <get>
      <filter><name>{domain_name}</name></filter>
      <dataset><hosting/></dataset>
    </get>
  </webspace>
</packet>"""
            props = _xml_props(_xml_agent(base_url, cust_user, cust_pass, get_packet))
            login = props.get("ftp_login") or ""
            if not login:
                raise RuntimeError("plesk_ftp_system_login_missing")
            stored_id = _vault_store_secrets(
                credential_vault_entry_id, vault_origin,
                f"Plesk system SFTP {domain_name}",
                {"username": login, "password": password}, vault_url,
            )
            if also_ftp_vault_entry_id and also_ftp_vault_entry_id != credential_vault_entry_id:
                _vault_store_secrets(
                    also_ftp_vault_entry_id, vault_origin,
                    f"Plesk system FTP {domain_name}",
                    {"username": login, "password": password}, vault_url,
                )
            return urirun.ok(
                kind="system", name=login, home="/", domain=domain_name,
                created=True, recreated=True, existed=True,
                credential_vault_entry_id=stored_id,
                credential_origin=vault_origin,
                also_ftp_vault_entry_id=also_ftp_vault_entry_id or None,
                transport_hint="sftp",
            )

        # additional dedicated FTP user via XML
        login = (name or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", login):
            raise RuntimeError("plesk_ftp_user_name_invalid")
        home_path = home if home.startswith("/") else f"/{home}"
        if not _SAFE_REMOTE.fullmatch(home_path) or ".." in home_path:
            raise RuntimeError("plesk_ftp_home_invalid")
        # try set-by-name first; on failure add
        set_packet = f"""<?xml version="1.0" encoding="UTF-8"?>
<packet>
  <ftp-user>
    <set>
      <filter><name>{login}</name></filter>
      <values><password>{password}</password><home>{home_path}</home></values>
    </set>
  </ftp-user>
</packet>"""
        raw = _xml_agent(base_url, cust_user, cust_pass, set_packet)
        created_new = False
        if not _xml_ok(raw):
            if not domain_name:
                raise RuntimeError("plesk_ftp_domain_required")
            add_packet = f"""<?xml version="1.0" encoding="UTF-8"?>
<packet>
  <ftp-user>
    <add>
      <name>{login}</name>
      <password>{password}</password>
      <home>{home_path}</home>
      <webspace-name>{domain_name}</webspace-name>
    </add>
  </ftp-user>
</packet>"""
            raw = _xml_agent(base_url, cust_user, cust_pass, add_packet)
            if not _xml_ok(raw):
                raise RuntimeError("plesk_ftp_additional_ensure_failed")
            created_new = True
        stored_id = _vault_store_secrets(
            credential_vault_entry_id, vault_origin,
            f"Plesk FTP {login}",
            {"username": login, "password": password}, vault_url,
        )
        return urirun.ok(
            kind="additional", name=login, home=home_path, domain=domain_name or None,
            created=created_new, recreated=not created_new, existed=not created_new,
            credential_vault_entry_id=stored_id,
            credential_origin=vault_origin,
            transport_hint="ftp",
        )
    except RuntimeError as error:
        return urirun.fail(str(error))
    finally:
        password = cust_pass = cust_user = ""


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


@dataclass
class _SslCtx:
    """Everything a TLS strategy needs, plus the shared attempt log.

    Credentials live here for the duration of one ``ensure_ssl`` call and are
    wiped in its ``finally``.
    """

    host: str
    peer: str
    mode: str
    caps: dict[str, Any]
    probe: dict[str, Any]
    dns_preflight: dict[str, Any]
    attempts: list[dict[str, Any]]
    base_url: str          # as passed in (the XML agent resolves it itself)
    origin_api: str        # resolved REST/panel base
    user: str
    password: str
    site_id: Any
    cert_name: str
    mail: str
    runtime_vault_entry_id: str
    vault_url: str
    api_key: str = ""

    def wipe(self) -> None:
        self.user = self.password = self.api_key = ""

    def finish(self, result: dict[str, Any]) -> dict[str, Any]:
        """Log the attempt and, on success, re-probe and report the new state."""
        from . import ssl_ops

        self.attempts.append({k: result.get(k) for k in ("strategy", "ok", "error", "detail") if k in result})
        if not result.get("ok"):
            return result
        after = ssl_ops.origin_tls_probe(connect_host=self.peer, hostname=self.host)
        return urirun.ok(
            dry_run=False,
            hostname=self.host,
            connect_host=self.peer,
            site_id=self.site_id,
            certificate_name=result.get("certificate_name") or self.cert_name or None,
            strategy=result.get("strategy"),
            created=result.get("strategy") not in {"assign", "probe"},
            probe=after,
            dns_preflight=self.dns_preflight,
            attempts=self.attempts,
            capabilities=self.caps,
            panel_action=result.get("panel_action"),
            san_note=result.get("san_note"),
        )


def _ssl_target(hostname: str, provider: str, origin_ip: str, connect_host: str,
                base_url: str) -> tuple[str, str, str, dict[str, Any] | None]:
    """Validate the request; returns (host, mode, peer, failure-or-None)."""
    host = (hostname or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", host):
        return "", "", "", urirun.fail("plesk_ssl_hostname_invalid")
    mode = (provider or "auto").strip().lower().replace("_", "-")
    if mode not in {"auto", "assign", "panel-pem", "panel-selfsigned", "letsencrypt", "rest-cli"}:
        return host, "", "", urirun.fail("plesk_ssl_provider_invalid")
    peer = (origin_ip or connect_host or "").strip() or urllib.parse.urlparse(_base_url(base_url)).hostname or ""
    if not peer or not re.fullmatch(r"[A-Za-z0-9.:-]+", peer):
        return host, mode, "", urirun.fail("plesk_ssl_connect_host_invalid")
    return host, mode, peer, None


def _ssl_gate(host: str, peer: str, mode: str, apply: bool, probe: dict[str, Any],
              dns_preflight: dict[str, Any],
              caps: dict[str, Any]) -> dict[str, Any] | None:
    """Fail-closed gate: probe-only, permission and already-covered outcomes.

    Returns the response to send back, or None when a mutation may proceed.
    """
    from . import ssl_ops

    if probe.get("ok") and mode == "auto" and not apply:
        return urirun.ok(
            dry_run=True,
            hostname=host,
            connect_host=peer,
            strategy="probe",
            certificate_name=None,
            probe=probe,
            dns_preflight=dns_preflight,
            capabilities=caps,
            note="SAN/CN already covers hostname",
        )
    may_write, apply_error = ssl_ops.ssl_apply_permitted(apply=bool(apply))
    if apply_error:
        return urirun.fail(
            apply_error,
            dry_run=True,
            hostname=host,
            connect_host=peer,
            probe=probe,
            dns_preflight=dns_preflight,
            capabilities=caps,
        )
    if not may_write:
        return urirun.ok(
            dry_run=True,
            hostname=host,
            connect_host=peer,
            probe=probe,
            dns_preflight=dns_preflight,
            capabilities=caps,
            strategies=caps.get("ssl_ensure", {}).get("strategies"),
            note="set apply=true, AUTONOMY_MUTATIONS_ENABLED=1, PLESK_SSL_APPLY=1",
            panel_action=ssl_ops.PANEL_ACTION_LE if mode in {"auto", "letsencrypt"} else None,
        )
    if probe.get("ok") and mode == "auto":
        return urirun.ok(
            dry_run=False,
            hostname=host,
            connect_host=peer,
            strategy="probe",
            created=False,
            probe=probe,
            dns_preflight=dns_preflight,
            capabilities=caps,
        )
    return None


def _ssl_stage_assign(ctx: _SslCtx) -> dict[str, Any] | None:
    """Assign an existing certificate by conventional name (no mutation of certs)."""
    from . import ssl_ops

    names = [ctx.cert_name] if ctx.cert_name else []
    names.extend([f"Lets Encrypt {ctx.host}", f"{ctx.host}-san", f"{ctx.host}-ss"])
    for name in names:
        assigned = ssl_ops.assign_certificate(
            base_url=ctx.base_url,
            username=ctx.user,
            password=ctx.password,
            site_id=ctx.site_id,
            certificate_name=name,
            xml_agent=_xml_agent,
        )
        ctx.attempts.append({k: assigned.get(k) for k in ("strategy", "ok", "error", "detail", "certificate_name")})
        if not assigned.get("ok"):
            continue
        after = ssl_ops.origin_tls_probe(connect_host=ctx.peer, hostname=ctx.host)
        if after.get("ok") or ctx.mode == "assign":
            return urirun.ok(
                dry_run=False,
                hostname=ctx.host,
                connect_host=ctx.peer,
                site_id=ctx.site_id,
                certificate_name=name,
                strategy="assign",
                created=False,
                probe=after,
                attempts=ctx.attempts,
                capabilities=ctx.caps,
                warning=None if after.get("ok") else "assigned_but_san_mismatch",
            )
    if ctx.mode == "assign":
        return urirun.fail(
            "plesk_ssl_assign_failed",
            hostname=ctx.host,
            attempts=ctx.attempts,
            capabilities=ctx.caps,
        )
    return None


def _ssl_stage_panel_pem(ctx: _SslCtx) -> dict[str, Any] | None:
    """Upload a SAN PEM through the panel — preferred autonomous path (no admin)."""
    from . import ssl_ops

    try:
        opener = ssl_ops.panel_login(base_url=ctx.origin_api, username=ctx.user, password=ctx.password)
        pem_name = ctx.cert_name or f"{ctx.host}-san"
        cert_pem, key_pem = ssl_ops.generate_self_signed_pem(ctx.host)
        uploaded = ssl_ops.panel_upload_pem(
            opener=opener,
            base_url=ctx.origin_api,
            site_id=ctx.site_id,
            cert_name=pem_name,
            cert_pem=cert_pem,
            key_pem=key_pem,
        )
        cert_pem = key_pem = ""
        if uploaded.get("ok"):
            assigned = ssl_ops.assign_certificate(
                base_url=ctx.base_url,
                username=ctx.user,
                password=ctx.password,
                site_id=ctx.site_id,
                certificate_name=pem_name,
                xml_agent=_xml_agent,
            )
            if assigned.get("ok"):
                return ctx.finish({**uploaded, "certificate_name": pem_name})
        ctx.attempts.append({k: uploaded.get(k) for k in ("strategy", "ok", "error", "detail")})
    except RuntimeError as error:
        ctx.attempts.append({"strategy": "panel_upload_pem", "ok": False, "error": str(error)})
    if ctx.mode == "panel-pem":
        return urirun.fail(
            "plesk_ssl_panel_upload_failed",
            hostname=ctx.host,
            attempts=ctx.attempts,
            capabilities=ctx.caps,
        )
    return None


def _ssl_stage_panel_selfsigned(ctx: _SslCtx) -> dict[str, Any] | None:
    """Panel self-signed certificate (CN often only — weaker); explicit mode only."""
    from . import ssl_ops

    opener = ssl_ops.panel_login(base_url=ctx.origin_api, username=ctx.user, password=ctx.password)
    ss_name = ctx.cert_name or f"{ctx.host}-ss"
    created = ssl_ops.panel_create_self_signed(
        opener=opener,
        base_url=ctx.origin_api,
        site_id=ctx.site_id,
        hostname=ctx.host,
        cert_name=ss_name,
        email=ctx.mail,
    )
    if created.get("ok"):
        assigned = ssl_ops.assign_certificate(
            base_url=ctx.base_url,
            username=ctx.user,
            password=ctx.password,
            site_id=ctx.site_id,
            certificate_name=ss_name,
            xml_agent=_xml_agent,
        )
        if assigned.get("ok"):
            return ctx.finish({**created, "certificate_name": ss_name})
    return urirun.fail(
        created.get("error") or "plesk_ssl_panel_self_signed_failed",
        hostname=ctx.host,
        detail=created.get("detail"),
        capabilities=ctx.caps,
    )


def _ssl_stage_letsencrypt(ctx: _SslCtx) -> dict[str, Any] | None:
    """Let's Encrypt through the SSL It panel extension."""
    from . import ssl_ops

    try:
        opener = ssl_ops.panel_login(base_url=ctx.origin_api, username=ctx.user, password=ctx.password)
        le = ssl_ops.panel_sslit_letsencrypt(
            opener=opener,
            base_url=ctx.origin_api,
            site_id=ctx.site_id,
            hostname=ctx.host,
        )
        ctx.attempts.append(
            {k: le.get(k) for k in ("strategy", "ok", "error", "detail", "san_mode", "hitl") if k in le}
        )
        if le.get("ok"):
            return ctx.finish(le)
    except RuntimeError as error:
        ctx.attempts.append({"strategy": "panel_sslit_le", "ok": False, "error": str(error)})
    return None


def _ssl_stage_rest_cli(ctx: _SslCtx) -> dict[str, Any] | None:
    """REST CLI with an admin API key — domain-only (-d hostname, no wildcard/mail)."""
    from . import ssl_ops

    try:
        ctx.api_key = _vault_lease(ctx.runtime_vault_entry_id, ctx.origin_api, "api_key", ctx.vault_url)
        le = ssl_ops.rest_cli_letsencrypt(
            base_url=ctx.origin_api,
            api_key=ctx.api_key,
            hostname=ctx.host,
            email=ctx.mail,
            request_json=_request_json,
        )
        ctx.attempts.append({k: le.get(k) for k in ("strategy", "ok", "error", "detail")})
        if le.get("ok"):
            return ctx.finish(le)
    except RuntimeError as error:
        ctx.attempts.append({"strategy": "rest_cli_le", "ok": False, "error": str(error)})
    return None


# TLS strategies in ladder order: which provider modes run them, and the stage.
_SSL_STAGES: list[tuple[set[str], Any]] = [
    ({"auto", "assign"}, _ssl_stage_assign),
    ({"auto", "panel-pem"}, _ssl_stage_panel_pem),
    ({"panel-selfsigned"}, _ssl_stage_panel_selfsigned),
    ({"auto", "letsencrypt"}, _ssl_stage_letsencrypt),
    ({"auto", "rest-cli", "letsencrypt"}, _ssl_stage_rest_cli),
]


def _ssl_exhausted(ctx: _SslCtx) -> dict[str, Any]:
    """No strategy covered the hostname — report the last attempt and the HITL step."""
    from . import ssl_ops

    last = ctx.attempts[-1] if ctx.attempts else {}
    hitl = last.get("hitl") or {**ssl_ops.HITL_LE_DOMAIN_ONLY, "detail": last.get("detail")}
    return urirun.fail(
        last.get("error") or "plesk_ssl_ensure_failed",
        hostname=ctx.host,
        connect_host=ctx.peer,
        site_id=ctx.site_id,
        probe=ctx.probe,
        dns_preflight=ctx.dns_preflight,
        attempts=ctx.attempts,
        capabilities=ctx.caps,
        panel_action=ssl_ops.PANEL_ACTION_LE,
        detail=last.get("detail"),
        hitl=hitl,
        san_mode="domain_only",
    )


@conn.handler(
    "site/command/ssl-ensure",
    isolated=True,
    meta={"label": "Ensure TLS cert covers hostname (assign / panel PEM / SSL It LE)"},
)
def ensure_ssl(
    hostname: str = "",
    connect_host: str = "",
    origin_ip: str = "",
    certificate_name: str = "",
    provider: str = "auto",
    apply: bool = False,
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    runtime_vault_entry_id: str = "plesk-runtime",
    email: str = "",
    vault_url: str = "",
) -> dict[str, Any]:
    """Ensure origin TLS for ``hostname`` (SAN/CN). Default is probe-only (fail-closed).

    Apply requires ``apply=true``, ``AUTONOMY_MUTATIONS_ENABLED=1``, ``PLESK_SSL_APPLY=1``.
    ``provider``: auto | assign | panel-pem | panel-selfsigned | letsencrypt | rest-cli.
    """
    from . import ssl_ops

    host, mode, peer, invalid = _ssl_target(hostname, provider, origin_ip, connect_host, base_url)
    if invalid:
        return invalid

    caps = build_capabilities(paramiko_mod=paramiko)
    dns_preflight = ssl_ops.tls_dns_preflight(host, expected_origin=origin_ip)
    if not dns_preflight.get("ready"):
        cause = str(dns_preflight.get("root_cause") or "dns_observation_inconclusive")
        return urirun.fail(
            "plesk_ssl_dns_dependency_blocked" if cause != "dns_observation_inconclusive"
            else "plesk_ssl_dns_preflight_inconclusive",
            dry_run=not bool(apply),
            hostname=host,
            connect_host=peer,
            root_cause=cause,
            dns_preflight=dns_preflight,
            mutation_attempted=False,
            next_action=dns_preflight.get("next_action"),
        )
    probe = ssl_ops.origin_tls_probe(connect_host=peer, hostname=host)
    gated = _ssl_gate(host, peer, mode, bool(apply), probe, dns_preflight, caps)
    if gated:
        return gated

    attempts: list[dict[str, Any]] = []
    ctx: _SslCtx | None = None
    try:
        origin_api = _base_url(base_url)
        ctx = _SslCtx(
            host=host,
            peer=peer,
            mode=mode,
            caps=caps,
            probe=probe,
            dns_preflight=dns_preflight,
            attempts=attempts,
            base_url=base_url,
            origin_api=origin_api,
            user=_vault_lease(subscription_vault_entry_id, origin_api, "username", vault_url),
            password=_vault_lease(subscription_vault_entry_id, origin_api, "password", vault_url),
            site_id=None,
            cert_name=(certificate_name or "").strip(),
            mail=(email or os.environ.get("PLESK_CUSTOMER_EMAIL") or "agent@subactor.com").strip(),
            runtime_vault_entry_id=runtime_vault_entry_id,
            vault_url=vault_url,
        )
        ctx.site_id = ssl_ops.resolve_site_id(
            base_url=base_url,
            username=ctx.user,
            password=ctx.password,
            hostname=host,
            xml_agent=_xml_agent,
        )
        if ctx.site_id is None:
            return urirun.fail("plesk_ssl_site_not_found", hostname=host, capabilities=caps, dns_preflight=dns_preflight)

        for modes, stage in _SSL_STAGES:
            if mode in modes:
                outcome = stage(ctx)
                if outcome is not None:
                    return outcome
        return _ssl_exhausted(ctx)
    except RuntimeError as error:
        return urirun.fail(str(error), hostname=host, capabilities=caps, attempts=attempts, dns_preflight=dns_preflight)
    finally:
        if ctx is not None:
            ctx.wipe()


@conn.handler(
    "site/command/subdomain-ensure",
    isolated=True,
    meta={"label": "Idempotent Plesk subdomain add under parent webspace (XML API)"},
)
def ensure_subdomain(
    parent_domain: str = "",
    subdomain: str = "",
    www_root: str = "",
    apply: bool = False,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    vault_url: str = "",
) -> dict[str, Any]:
    """Plan or ensure ``subdomain.parent_domain`` exists through XML ``subdomain.add``.

    Does not mutate DNS. Used so docs.subactor.com can be created without ad-hoc scripts.
    """
    parent = (parent_domain or "").strip().lower()
    label = (subdomain or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", parent):
        return urirun.fail("plesk_subdomain_parent_invalid")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", label):
        return urirun.fail("plesk_subdomain_label_invalid")
    root = (www_root or f"{label}.{parent}").strip().lstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", root) or ".." in root:
        return urirun.fail("plesk_subdomain_www_root_invalid")
    fqdn = f"{label}.{parent}"
    try:
        origin_api = _base_url(base_url)
    except RuntimeError as error:
        return urirun.fail(str(error), dry_run=not apply, mutation_attempted=False)
    plan_body = {
        "schema": "urirun.plesk-subdomain-ensure-plan/v1",
        "parent_domain": parent,
        "subdomain": fqdn,
        "www_root": root,
        "risk_class": "boundary",
    }
    digest = hashlib.sha256(json.dumps(plan_body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    plan = {**plan_body, "plan_hash": digest, "artifact_sha256": digest}
    target = f"{origin_api}|subdomain:{fqdn}"
    if apply and not autonomy_mutations_enabled() and not mutate_lease_active():
        return urirun.fail("autonomy_mutations_disabled", dry_run=False, mutation_attempted=False)
    if apply and not mutate_lease_allows_apply("PLESK_SUBDOMAIN_APPLY"):
        return urirun.fail("plesk_subdomain_apply_required", dry_run=False, mutation_attempted=False)
    cust_user = cust_pass = ""
    try:
        cust_user = _vault_lease(subscription_vault_entry_id, origin_api, "username", vault_url)
        cust_pass = _vault_lease(subscription_vault_entry_id, origin_api, "password", vault_url)
        get_packet = f"""<?xml version="1.0" encoding="UTF-8"?>
<packet>
  <subdomain>
    <get><filter><name>{_xml_escape(fqdn)}</name></filter></get>
  </subdomain>
</packet>"""
        existing = _xml_agent(base_url, cust_user, cust_pass, get_packet)
        if _xml_ok(existing) and re.search(r"<id>\d+</id>", existing):
            id_match = re.search(r"<id>(\d+)</id>", existing)
            return urirun.ok(
                created=False,
                existed=True,
                subdomain=fqdn,
                parent_domain=parent,
                www_root=root,
                subdomain_id=int(id_match.group(1)) if id_match else None,
                dry_run=not apply,
                executed=False,
                mutation_attempted=False,
                target=target,
                plan_hash=plan["plan_hash"],
            )
        if not apply:
            return urirun.ok(
                created=False, existed=False, subdomain=fqdn, parent_domain=parent, www_root=root,
                dry_run=True, executed=False, mutation_attempted=False, target=target,
                plan=plan, plan_hash=plan["plan_hash"], artifact_sha256=plan["artifact_sha256"],
            )
        if plan_hash.strip().lower() != plan["plan_hash"]:
            return urirun.fail("plan_hash_mismatch", dry_run=False, mutation_attempted=False)
        ok, error, claims = verify_apply_grant(
            apply_grant, plan_hash=plan["plan_hash"], target=target, actor=actor,
            intent_pack=format_intent_pack(pack_id, pack_version), artifact_sha256=plan["artifact_sha256"],
        )
        if not ok or not claims:
            return urirun.fail(error or "apply_grant_required", dry_run=False, mutation_attempted=False)
        if claims.get("risk_class") != "boundary":
            return urirun.fail("apply_grant_risk_class_mismatch", dry_run=False, mutation_attempted=False)
        consumed, replay_error = consume_apply_grant_jti(claims["jti"], claims["expires_at"])
        if not consumed:
            return urirun.fail(replay_error or "apply_grant_replay", dry_run=False, mutation_attempted=False)
        add_packet = f"""<?xml version="1.0" encoding="UTF-8"?>
<packet>
  <subdomain>
    <add>
      <parent>{_xml_escape(parent)}</parent>
      <name>{_xml_escape(label)}</name>
      <property><name>www_root</name><value>{_xml_escape(root)}</value></property>
    </add>
  </subdomain>
</packet>"""
        raw = _xml_agent(base_url, cust_user, cust_pass, add_packet)
        if not _xml_ok(raw):
            # Race / already exists → treat as idempotent success when get works.
            if "already" in raw.lower() or "exists" in raw.lower():
                return urirun.ok(
                    created=False,
                    existed=True,
                    subdomain=fqdn,
                    parent_domain=parent,
                    www_root=root,
                    note="add reported exists; treated as ensure-ok",
                )
            return urirun.fail("plesk_subdomain_add_failed", detail=raw[:400])
        id_match = re.search(r"<id>(\d+)</id>", raw)
        verified_raw = _xml_agent(base_url, cust_user, cust_pass, get_packet)
        verified_match = re.search(r"<id>(\d+)</id>", verified_raw) if _xml_ok(verified_raw) else None
        if not verified_match:
            return urirun.fail("plesk_subdomain_verification_failed", dry_run=False, mutation_attempted=True)
        return urirun.ok(
            created=True,
            existed=False,
            subdomain=fqdn,
            parent_domain=parent,
            www_root=root,
            subdomain_id=int(verified_match.group(1)),
            dry_run=False,
            executed=True,
            mutation_attempted=True,
            verified=True,
            plan_hash=plan["plan_hash"],
            grant_jti=claims["jti"],
        )
    except RuntimeError as error:
        return urirun.fail(str(error), dry_run=not apply, mutation_attempted=False)
    finally:
        cust_user = cust_pass = ""


def _ssh_command(transport, command: str) -> tuple[int, str]:
    channel = transport.open_session(timeout=transport_timeouts().connect)
    try:
        channel.exec_command(command)
        output = channel.makefile("rb", -1).read(4096).decode("utf-8", errors="replace")
        error = channel.makefile_stderr("rb", -1).read(4096).decode("utf-8", errors="replace")
        code = int(channel.recv_exit_status())
        return code, (output + "\n" + error).strip()[:1000]
    finally:
        channel.close()


@conn.handler(
    "site/command/reverse-proxy-ensure",
    isolated=True,
    meta={"label": "Plan or ensure a Plesk vhost reverse proxy through pinned root SSH/CLI"},
)
def ensure_reverse_proxy(
    hostname: str = "",
    upstream: str = "",
    authentication_required: bool = True,
    authentication_probe_path: str = "/",
    apply: bool = False,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    base_url: str = "",
    root_ssh_host: str = "",
    root_ssh_port: int = 22,
    root_ssh_vault_entry_id: str = "plesk-root-ssh",
    root_ssh_host_fingerprint: str = "",
    vault_url: str = "",
) -> dict[str, Any]:
    """Manage one marked nginx block without pretending Plesk REST/XML can edit it.

    Plesk exposes existing-domain ``vhost_nginx.conf`` changes through the panel
    and root CLI.  Apply therefore requires a separate, origin-bound root SSH
    credential and a pinned host key; subscription SFTP is never elevated.
    """
    try:
        host = normalize_reverse_proxy_hostname(hostname)
        wanted_upstream = normalize_upstream(upstream, hostname=host)
        addresses = assert_public_upstream(wanted_upstream)
        probe = probe_upstream(wanted_upstream, path=authentication_probe_path)
        if not authentication_required:
            return urirun.fail(
                "plesk_reverse_proxy_authentication_required",
                dry_run=not apply, mutation_attempted=False,
            )
        if not probe["authentication_challenge"]:
            return urirun.fail(
                "plesk_reverse_proxy_authentication_not_observed",
                dry_run=not apply, mutation_attempted=False, probe=probe,
            )
        origin = _base_url(base_url)
        plan = build_reverse_proxy_plan(
            host, wanted_upstream, authentication_required=authentication_required,
        )
        target = f"{origin}|reverse-proxy:{host}"
    except RuntimeError as error:
        return urirun.fail(str(error), dry_run=not apply, mutation_attempted=False)

    safe_plan = {key: value for key, value in plan.items() if key != "directives"}
    if not apply:
        return urirun.ok(
            dry_run=True, executed=False, mutation_attempted=False, target=target,
            plan=safe_plan, plan_hash=plan["plan_hash"], artifact_sha256=plan["artifact_sha256"],
            upstream_addresses=addresses, probe=probe,
            required_capability="plesk.root_ssh_cli",
        )
    if not autonomy_mutations_enabled() and not mutate_lease_active():
        return urirun.fail("autonomy_mutations_disabled", dry_run=False, mutation_attempted=False)
    if not mutate_lease_allows_apply("PLESK_REVERSE_PROXY_APPLY"):
        return urirun.fail("plesk_reverse_proxy_apply_required", dry_run=False, mutation_attempted=False)
    if plan_hash.strip().lower() != plan["plan_hash"]:
        return urirun.fail("plan_hash_mismatch", dry_run=False, mutation_attempted=False)
    ok, error, claims = verify_apply_grant(
        apply_grant, plan_hash=plan["plan_hash"], target=target, actor=actor,
        intent_pack=format_intent_pack(pack_id, pack_version),
        artifact_sha256=plan["artifact_sha256"],
    )
    if not ok or not claims:
        return urirun.fail(error or "apply_grant_required", dry_run=False, mutation_attempted=False)
    if claims.get("risk_class") != "boundary":
        return urirun.fail("apply_grant_risk_class_mismatch", dry_run=False, mutation_attempted=False)
    fingerprint = root_ssh_host_fingerprint.replace(":", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        return urirun.fail("plesk_root_ssh_host_key_required", dry_run=False, mutation_attempted=False)
    ssh_host = (root_ssh_host or urllib.parse.urlparse(origin).hostname or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9.-]+", ssh_host):
        return urirun.fail("plesk_root_ssh_host_invalid", dry_run=False, mutation_attempted=False)
    if not 1 <= int(root_ssh_port) <= 65535:
        return urirun.fail("plesk_root_ssh_port_invalid", dry_run=False, mutation_attempted=False)

    username = password = ""
    transport = sftp = None
    mutation_attempted = False
    config_path = f"/var/www/vhosts/system/{host}/conf/vhost_nginx.conf"
    old_content: bytes | None = None
    temp_path = f"{config_path}.subactor-{secrets.token_hex(6)}"
    try:
        username = _vault_lease(root_ssh_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(root_ssh_vault_entry_id, origin, "password", vault_url)
        if username != "root":
            raise RuntimeError("plesk_root_ssh_principal_required")
        transport, sftp, observed_fingerprint = _sftp_connect(
            ssh_host, int(root_ssh_port), username, password, fingerprint,
        )
        try:
            with sftp.open(config_path, "rb") as handle:
                old_content = handle.read()
        except IOError:
            old_content = None
        current = old_content.decode("utf-8") if old_content is not None else ""
        merged = merge_managed_directives(current, plan["directives"]).encode("utf-8")
        if old_content == merged:
            return urirun.ok(
                dry_run=False, executed=False, mutation_attempted=False, verified=True,
                changed=False, target=target, plan_hash=plan["plan_hash"],
                host_fingerprint=observed_fingerprint,
            )
        consumed, replay_error = consume_apply_grant_jti(claims["jti"], claims["expires_at"])
        if not consumed:
            return urirun.fail(replay_error or "apply_grant_replay", dry_run=False, mutation_attempted=False)
        with sftp.open(temp_path, "wb") as handle:
            handle.write(merged)
        sftp.chmod(temp_path, 0o600)
        sftp.posix_rename(temp_path, config_path)
        mutation_attempted = True
        quoted_host = shlex.quote(host)
        commands = [
            f"plesk sbin httpdmng --reconfigure-domain {quoted_host} -no-restart",
            "nginx -t",
            "systemctl reload nginx",
        ]
        evidence = []
        for command in commands:
            code, detail = _ssh_command(transport, command)
            evidence.append({"command": command.split()[0:3], "exit_code": code, "detail": detail})
            if code != 0:
                raise RuntimeError("plesk_reverse_proxy_cli_failed")
        with sftp.open(config_path, "rb") as handle:
            verified_content = handle.read()
        if verified_content != merged:
            raise RuntimeError("plesk_reverse_proxy_verification_failed")
        return urirun.ok(
            dry_run=False, executed=True, mutation_attempted=True, verified=True, changed=True,
            target=target, plan_hash=plan["plan_hash"], grant_jti=claims["jti"],
            host_fingerprint=observed_fingerprint, evidence=evidence, probe=probe,
        )
    except RuntimeError as apply_error:
        rollback_attempted = mutation_attempted and sftp is not None
        rollback_ok = False
        if rollback_attempted:
            try:
                if old_content is None:
                    sftp.remove(config_path)
                else:
                    rollback_path = f"{config_path}.rollback-{secrets.token_hex(6)}"
                    with sftp.open(rollback_path, "wb") as handle:
                        handle.write(old_content)
                    sftp.chmod(rollback_path, 0o600)
                    sftp.posix_rename(rollback_path, config_path)
                code, _detail = _ssh_command(
                    transport,
                    f"plesk sbin httpdmng --reconfigure-domain {shlex.quote(host)} -no-restart",
                )
                rollback_ok = code == 0
            except Exception:
                rollback_ok = False
        return urirun.fail(
            str(apply_error), dry_run=False, mutation_attempted=mutation_attempted,
            rollback_attempted=rollback_attempted, rollback_ok=rollback_ok,
        )
    finally:
        username = password = ""
        if sftp is not None:
            sftp.close()
        if transport is not None:
            transport.close()


def _validate_publish_inputs(source_dir: str, remote_path: str, host: str) -> str:
    if not source_dir or not os.path.isdir(source_dir):
        return "plesk_site_source_dir_invalid"
    if not _SAFE_REMOTE.fullmatch(remote_path) or ".." in remote_path:
        return "plesk_site_remote_path_invalid"
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return "plesk_site_host_invalid"
    return ""


def _validate_port(port: int) -> str:
    try:
        value = int(port)
    except (TypeError, ValueError):
        return "plesk_site_port_invalid"
    if not 1 <= value <= 65535:
        return "plesk_site_port_invalid"
    return ""


_PRESERVE_REMOTE_NAMES = (".htaccess", ".well-known")


def _source_allowed(source_dir: str) -> bool:
    """Allow approved static roots or explicit PLESK_SYNC_ALLOWED_SOURCES prefixes."""
    abs_path = os.path.abspath(source_dir)
    if ".." in source_dir.replace("\\", "/"):
        return False
    raw = os.environ.get("PLESK_SYNC_ALLOWED_SOURCES", "").strip()
    if raw:
        for prefix in raw.split(":"):
            prefix = prefix.strip()
            if not prefix:
                continue
            root = os.path.abspath(prefix)
            if abs_path == root or abs_path.startswith(root + os.sep):
                return True
        return False
    return os.path.basename(abs_path.rstrip(os.sep)) in {"www", "docs", "logo", "public-status"}


def _plan_local_tree(source_dir: str, remote_path: str, exclude: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Build a dry-run upload plan: relative path, size, sha256, remote target."""
    base = os.path.abspath(source_dir)
    patterns = tuple(exclude) if exclude else _DEFAULT_EXCLUDE
    planned: list[dict[str, Any]] = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in sorted(dirs) if d not in _SKIP_DIRS and not _excluded(d, patterns)]
        rel_root = os.path.relpath(root, base)
        for name in sorted(files):
            if name in _SKIP_FILES:
                continue
            rel = name if rel_root == "." else f"{rel_root.replace(os.sep, '/')}/{name}"
            if _excluded(rel, patterns):
                continue
            local = os.path.join(root, name)
            digest = hashlib.sha256()
            with open(local, "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            planned.append({
                "path": rel,
                "bytes": os.path.getsize(local),
                "sha256": digest.hexdigest(),
                "remote": f"{remote_path}/{rel}",
            })
    return planned


def _apply_permitted(
    apply: bool,
    *,
    apply_grant: str = "",
    plan_hash: str = "",
    target: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    artifact_sha256: str = "",
) -> tuple[bool, str | None, dict | None]:
    """Uploads require apply + (kill switches OR session mutate lease) + signed grant (ADR-003)."""
    if not apply:
        return False, None, None
    if not mutations_gates_open():
        if not autonomy_mutations_enabled() and not mutate_lease_active():
            return False, "autonomy_mutations_disabled", None
        return False, "plesk_sync_apply_required", None
    ok, error, claims = verify_apply_grant(
        apply_grant,
        plan_hash=plan_hash,
        target=target,
        actor=actor,
        intent_pack=format_intent_pack(pack_id, pack_version),
        artifact_sha256=artifact_sha256,
    )
    if not ok:
        return False, error or "apply_grant_required", claims
    return True, None, claims


def _publish_over_sftp(
    source_dir,
    remote_path,
    host,
    port,
    username,
    password,
    host_fingerprint,
    exclude=(),
    *,
    plan: list[dict[str, Any]] | None = None,
    verify_remote_hash: bool = False,
):
    budgets = transport_timeouts()
    deadline = time.monotonic() + budgets.total
    transport = None
    try:
        transport, sftp, fingerprint = _sftp_connect(host, port, username, password, host_fingerprint)
        try:
            uploaded = _sftp_upload_dir(
                sftp,
                source_dir,
                remote_path,
                exclude,
                plan=plan,
                verify_remote_hash=verify_remote_hash,
                deadline=deadline,
            )
        finally:
            sftp.close()
    finally:
        if transport is not None:
            transport.close()
    return uploaded, {"host_fingerprint": fingerprint}


def _publish_over_ftp(source_dir, remote_path, host, port, username, password, tls, exclude=()):
    budgets = transport_timeouts()
    deadline = time.monotonic() + budgets.total
    ftp = _ftp_connect(host, port, username, password, tls)
    try:
        uploaded = _ftp_upload_dir(ftp, source_dir, remote_path, exclude, deadline=deadline)
    finally:
        try:
            ftp.quit()
        except Exception:
            pass
    return uploaded, {"tls": bool(tls)}


@conn.handler("site/query/methods", isolated=True, meta={"label": "Detect which file-deployment transports are authorized for a Plesk host"})
def site_methods(
    host: str = "",
    sftp_port: int = 22,
    ftp_port: int = 21,
    ftp_tls: bool = True,
    sftp_vault_entry_id: str = "plesk-sftp",
    ftp_vault_entry_id: str = "plesk-ftp",
    credential_origin: str = "",
    host_fingerprint: str = "",
    vault_url: str = "",
) -> dict[str, Any]:
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return urirun.fail("plesk_site_host_invalid")
    results = _detect_transports(
        host, sftp_port=int(sftp_port), ftp_port=int(ftp_port), ftp_tls=bool(ftp_tls),
        sftp_vault_entry_id=sftp_vault_entry_id, ftp_vault_entry_id=ftp_vault_entry_id,
        credential_origin=credential_origin, host_fingerprint=host_fingerprint, vault_url=vault_url,
    )
    available = [r["transport"] for r in results if r["available"]]
    return urirun.ok(host=host, methods=results, available=available,
                     recommended=(available[0] if available else None))


@conn.handler(
    "site/query/remote-inventory",
    isolated=True,
    meta={"label": "List a bounded SFTP directory without reading file content"},
)
def site_remote_inventory(
    host: str = "",
    domain: str = "",
    remote_path: str = "/",
    sftp_port: int = 22,
    sftp_vault_entry_id: str = "plesk-sftp",
    credential_origin: str = "",
    host_fingerprint: str = "",
    vault_url: str = "",
    max_entries: int = 100,
) -> dict[str, Any]:
    """Read-only, bounded SFTP topology observation; never returns credentials or content."""
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return urirun.fail("plesk_site_host_invalid")
    site_domain = domain.strip().lower()
    if not site_domain or not re.fullmatch(r"[A-Za-z0-9.-]+", site_domain):
        return urirun.fail("plesk_site_domain_invalid")
    if not _SAFE_REMOTE.fullmatch(remote_path) or ".." in remote_path or "//" in remote_path:
        return urirun.fail("plesk_site_remote_path_invalid")
    allowed_roots = (
        "/",
        f"/var/www/vhosts/{site_domain}",
        f"/{site_domain}",
        "/httpdocs",
    )
    if not any(remote_path == root or remote_path.startswith(f"{root}/") for root in allowed_roots):
        return urirun.fail("plesk_site_inventory_scope_denied")
    scope_error = _inventory_scope_error(
        host,
        site_domain,
        remote_path,
        credential_origin,
        sftp_vault_entry_id,
        vault_url,
    )
    if scope_error:
        return urirun.fail(
            scope_error,
            host=host,
            domain=site_domain,
            remote_path=remote_path,
            mutation_attempted=False,
            note="Use an explicit domain path or a vault credential_origin whose hostname equals domain.",
        )
    bad_port = _validate_port(sftp_port)
    if bad_port:
        return urirun.fail(bad_port)
    try:
        limit = max(1, min(int(max_entries), 500))
    except (TypeError, ValueError):
        return urirun.fail("plesk_site_inventory_limit_invalid")

    origin = _transport_origin("sftp", host, credential_origin)
    username = password = ""
    transport = None
    try:
        username = _vault_lease(sftp_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(sftp_vault_entry_id, origin, "password", vault_url)
        transport, sftp, fingerprint = _sftp_connect(
            host, int(sftp_port), username, password, host_fingerprint,
        )
        try:
            directory = sftp.stat(remote_path)
            attrs = sorted(sftp.listdir_attr(remote_path), key=lambda item: item.filename)
            entries = []
            for item in attrs[:limit]:
                mode = int(getattr(item, "st_mode", 0) or 0)
                entries.append({
                    "name": str(item.filename),
                    "type": "directory" if statmod.S_ISDIR(mode) else "file",
                    "bytes": int(getattr(item, "st_size", 0) or 0),
                    "mode": format(mode & 0o777, "03o"),
                })
        finally:
            sftp.close()
        directory_mode = int(getattr(directory, "st_mode", 0) or 0)
        return urirun.ok(
            host=host,
            domain=site_domain,
            transport="sftp",
            remote_path=remote_path,
            exists=True,
            directory=statmod.S_ISDIR(directory_mode),
            mode=format(directory_mode & 0o777, "03o"),
            entries=entries,
            entries_total=len(attrs),
            truncated=len(attrs) > limit,
            host_fingerprint=fingerprint,

        )
    except RuntimeError as error:
        return urirun.fail(str(error), host=host, domain=site_domain, remote_path=remote_path, transport="sftp")
    except Exception as error:
        return urirun.fail(map_exception(error, phase="transfer"), host=host, domain=site_domain, remote_path=remote_path, transport="sftp")
    finally:
        username = password = ""
        if transport is not None:
            transport.close()


_RELEASE_DOCROOT_SEGMENTS = frozenset({"current", "previous", "releases", "release"})


def _rule_docroot(domain: str, main_domain: str = "") -> str:
    name = (domain or "").strip().lower()
    main = (main_domain or "").strip().lower()
    if main and name == main:
        return "/httpdocs"
    return f"/{name}" if name else "/httpdocs"


def _observed_docroot_from_www_root(
    www_root: str, main_domain: str = "", domain: str = "",
) -> str:
    """Derive Plesk docroot folder from absolute www_root.

    Layout: ``/var/www/vhosts/<subscription>/<docroot>[/<release>…]``.
    A trailing ``current``/``previous`` symlink is a release pointer, not the
    docroot itself (live: ``…/subactor.com/docs.subactor.com/current``).
    """
    parts = [part for part in str(www_root or "").rstrip("/").split("/") if part]
    if not parts:
        return ""
    trimmed = list(parts)
    while len(trimmed) > 1 and trimmed[-1].lower() in _RELEASE_DOCROOT_SEGMENTS:
        trimmed.pop()
    subscription = (main_domain or "").strip().lower()
    site = (domain or "").strip().lower()
    if subscription:
        for index, segment in enumerate(trimmed):
            if segment.lower() == subscription and index + 1 < len(trimmed):
                return f"/{trimmed[index + 1]}"
    if site:
        for index, segment in enumerate(trimmed):
            if segment.lower() == site:
                # Subscription folder named like the main domain: docroot is the next
                # segment (usually httpdocs). Subdomain folders match the domain name
                # with no further non-release segment.
                if index + 1 < len(trimmed):
                    return f"/{trimmed[index + 1]}"
                return f"/{segment}"
    return f"/{trimmed[-1]}"


def _twin_fact(*, twin_type: str, instance_id: str, uri: str, payload: dict[str, Any],
               feature_flags: dict[str, bool] | None = None,
               fact_quality: str = "fresh") -> dict[str, Any]:
    """Build subactor.twin-fact/v1 without depending on the Node uri-twin package."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    observed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "schema": "subactor.twin-fact/v1",
        "twin_type": twin_type,
        "instance_id": instance_id,
        "uri": uri,
        "observed_at": observed_at,
        "freshness_ms": 0,
        "snapshot_hash": f"sha256:{hashlib.sha256(body.encode('utf-8')).hexdigest()}",
        "feature_flags": feature_flags or {},
        "payload": payload,
        "fact_quality": fact_quality,
        "redacted": [],
    }


@conn.handler(
    "site/query/docroot",
    isolated=True,
    meta={"label": "Observe Plesk www_root/docroot as a twin fact (read-only)"},
)
def site_query_docroot(
    domain: str = "",
    host: str = "",
    main_domain: str = "",
    declared: str = "",
    instance_id: str = "",
    base_url: str = "",
    subscription_vault_entry_id: str = "plesk-subscription",
    vault_url: str = "",
) -> dict[str, Any]:
    """Read-only docroot observation for uri-twin / reality-check.

    Returns a ``subactor.twin-fact/v1`` envelope. Missing Plesk data does not
    mutate anything: quality falls back to ``estimated`` using the topology rule.
    """
    site = (domain or "").strip().lower()
    if not site or not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", site):
        return urirun.fail("plesk_site_domain_invalid", mutation_attempted=False)
    panel = (host or "").strip().lower() or site
    main = (main_domain or "").strip().lower()
    rule = _rule_docroot(site, main)
    declared_path = (declared or "").strip().rstrip("/") or rule
    declared_effective = declared_path
    declared_vhost_prefix = f"/var/www/vhosts/{site}/"
    if declared_path.startswith(declared_vhost_prefix):
        declared_effective = _observed_docroot_from_www_root(declared_path, main, site)
    binding = (instance_id or panel or "plesk-default").strip() or "plesk-default"
    uri = "plesk://host/site/query/docroot"

    username = password = ""
    observation_ok = False
    www_root = ""
    observed = ""
    observe_reason = ""
    try:
        origin = _base_url(base_url)
        username = _vault_lease(subscription_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(subscription_vault_entry_id, origin, "password", vault_url)
        packet = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f"<packet><site><get><filter><name>{_xml_escape(site)}</name></filter>"
            "<dataset><hosting/></dataset></get></site></packet>"
        )
        raw = _xml_agent(base_url, username, password, packet)
        if not _xml_ok(raw):
            observe_reason = "plesk_site_get_failed"
        else:
            props = _xml_props(raw)
            www_root = (props.get("www_root") or "").strip()
            if not www_root:
                observe_reason = "www_root_absent"
            else:
                observed = _observed_docroot_from_www_root(www_root, main, site)
                observation_ok = bool(observed)
                if not observation_ok:
                    observe_reason = "docroot_unresolved"
    except RuntimeError as error:
        observe_reason = str(error) or "plesk_xml_transport_failed"
    finally:
        username = password = ""

    if observation_ok:
        authority = "observed"
        fact_quality = "fresh"
        within = declared_effective == observed or declared_effective.startswith(f"{observed}/")
        expected = declared_path if within else observed
        decision = "accept" if within else "refuse"
        reason = (
            ""
            if within
            else (
                f"remote_path {declared_path} is not under the docroot Plesk serves "
                f"for {site} ({observed})."
            )
        )
        if observed != rule:
            decision = "refuse"
            reason = (
                f"Plesk serves {site} from {observed} (www_root {www_root}), "
                f"but the rule expected {rule}. Reconcile topology before publishing."
            )
            expected = observed
    else:
        authority = "rule"
        fact_quality = "estimated"
        expected = rule
        within = declared_effective == rule or declared_effective.startswith(f"{rule}/")
        decision = "accept" if within else "refuse"
        reason = (
            observe_reason
            or (
                ""
                if within
                else f"remote_path {declared_path} does not match rule docroot {rule} for {site}"
            )
        )

    payload = {
        "domain": site,
        "host": panel,
        "declared": declared_path,
        "declared_effective_docroot": declared_effective,
        "rule_docroot": rule,
        "observed_docroot": observed or None,
        "observed_www_root": www_root or None,
        "decision": decision,
        "authority": authority,
        "expected_remote_path": expected,
        "reason": reason or None,
        "observe_error": observe_reason or None,
    }
    fact = _twin_fact(
        twin_type="plesk.site.docroot",
        instance_id=binding,
        uri=uri,
        payload=payload,
        fact_quality=fact_quality,
    )
    return urirun.ok(
        twin_fact=fact,
        domain=site,
        docroot=payload.get("observed_docroot") or rule,
        fact_quality=fact_quality,
        authority=authority,
        decision=decision,
        mutation_attempted=False,
    )


def _sync_validate(*, source_dir: str, remote_path: str, host: str, transport: str,
                   sftp_port: int, ftp_port: int) -> str:
    """Return the first input error code, or "" when the request is well-formed."""
    invalid = _validate_publish_inputs(source_dir, remote_path, host)
    if invalid:
        return invalid
    for port in (sftp_port, ftp_port):
        bad = _validate_port(port)
        if bad:
            return bad
    if transport not in {"auto", "sftp", "ftp"}:
        return "plesk_site_transport_invalid"
    if not _source_allowed(source_dir):
        return "plesk_site_source_not_allowlisted"
    return ""


def _sync_apply_gate(*, apply_error: str, may_write: bool, plan: list[dict[str, Any]],
                     manifest: dict[str, Any], host: str, remote_path: str, domain: str,
                     exclude_patterns: tuple[str, ...],
                     grant_claims: dict[str, Any] | None) -> dict[str, Any] | None:
    """Autonomy gate: report the refusal or the dry-run plan; None means proceed."""
    if apply_error:
        return connector_result(
            ok=False,
            reason_code=classify_connector_reason(apply_error),
            reason=apply_error,
            error=apply_error,
            dry_run=True,
            files_planned=len(plan),
            bytes_planned=manifest["bytes_total"],
            plan=plan,
            manifest=manifest,
            plan_hash=manifest["plan_hash"],
            preserve_remote=list(_PRESERVE_REMOTE_NAMES),
            domain=domain or None,
            grant_claims=grant_claims,
        )
    if not may_write:
        return connector_result(
            ok=True,
            dry_run=True,
            host=host,
            remote_path=remote_path,
            domain=domain or None,
            files_planned=len(plan),
            bytes_planned=manifest["bytes_total"],
            plan=plan,
            manifest=manifest,
            plan_hash=manifest["plan_hash"],
            preserve_remote=list(_PRESERVE_REMOTE_NAMES),
            exclude=list(exclude_patterns),
            note="set apply=true, AUTONOMY_MUTATIONS_ENABLED=1, PLESK_SYNC_APPLY=1, plan_hash, and signed apply_grant",
        )
    return None


def _sync_plan_hash_gate(*, plan: list[dict[str, Any]], plan_hash: str, host: str, domain: str,
                         remote_path: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """PR5a: apply must bind to the dry-run plan_hash.

    No free re-scan divergence — a mismatch uploads zero files. Returns
    (failure-or-None, verified manifest).
    """
    matched, verified, mismatch = verify_plan_hash(
        plan=plan,
        expected_plan_hash=plan_hash,
        host=host,
        domain=domain,
        remote_path=remote_path,
    )
    if matched:
        return None, verified
    error = mismatch or "plan_hash_mismatch"
    return connector_result(
        ok=False,
        reason_code=classify_connector_reason(error),
        reason=error,
        error=error,
        dry_run=True,
        files_planned=len(plan),
        bytes_planned=verified["bytes_total"],
        plan=plan,
        manifest=verified,
        plan_hash=verified["plan_hash"],
        files_uploaded=0,
        preserve_remote=list(_PRESERVE_REMOTE_NAMES),
        domain=domain or None,
    ), verified


def _sync_replay_gate(*, grant_claims: dict[str, Any] | None, plan: list[dict[str, Any]],
                      manifest: dict[str, Any], domain: str) -> dict[str, Any] | None:
    """PR5c: consume the grant jti after the gates pass, before any network mutation."""
    claims = grant_claims or {}
    replay_ok, replay_error = consume_apply_grant_jti(claims.get("jti") or "",
                                                     claims.get("expires_at") or "")
    if replay_ok:
        return None
    return urirun.fail(
        replay_error or "apply_grant_replay",
        dry_run=True,
        files_planned=len(plan),
        plan=plan,
        manifest=manifest,
        plan_hash=manifest["plan_hash"],
        files_uploaded=0,
        preserve_remote=list(_PRESERVE_REMOTE_NAMES),
        domain=domain or None,
        grant_claims=grant_claims,
    )


def _sync_capability_denial(caps: dict[str, Any], transport: str) -> dict[str, Any] | None:
    """Production publish: missing SFTP blocks readiness even when FTP is available."""
    deny = deny_if_sftp_required(caps, transport=transport)
    if deny and transport in {"auto", "sftp"} and not caps["sftp"]["available"]:
        return urirun.fail(
            CAPABILITY_UNAVAILABLE,
            capabilities=caps,
            production_publish_ready=False,
            note="SFTP/paramiko required for production publish; FTP-only is not sufficient",
        )
    if transport == "ftp" and deny:
        return urirun.fail(
            CAPABILITY_UNAVAILABLE,
            capabilities=caps,
            production_publish_ready=production_publish_ready(caps),
            note="FTP apply denied unless PLESK_SYNC_ALLOW_FTP_FALLBACK=1",
        )
    return None


def _sync_autodetect(*, host: str, caps: dict[str, Any], sftp_port: int, ftp_port: int,
                     ftp_tls: bool, sftp_vault_entry_id: str, ftp_vault_entry_id: str,
                     credential_origin: str, host_fingerprint: str,
                     vault_url: str) -> tuple[str, list[dict[str, Any]], dict[str, Any] | None]:
    """Probe both transports; returns (chosen, detection, failure-or-None)."""
    detection = _detect_transports(
        host, sftp_port=int(sftp_port), ftp_port=int(ftp_port), ftp_tls=bool(ftp_tls),
        sftp_vault_entry_id=sftp_vault_entry_id, ftp_vault_entry_id=ftp_vault_entry_id,
        credential_origin=credential_origin, host_fingerprint=host_fingerprint, vault_url=vault_url,
    )
    available = [r["transport"] for r in detection if r["available"]]
    if not available:
        return "", detection, urirun.fail(
            "plesk_site_no_authorized_transport", methods=detection, capabilities=caps)
    if "sftp" in available:
        return "sftp", detection, None
    if ftp_fallback_allowed():
        return available[0], detection, None
    return "", detection, urirun.fail(
        CAPABILITY_UNAVAILABLE,
        methods=detection,
        capabilities=caps,
        production_publish_ready=False,
        note="SFTP unavailable; FTP fallback disabled (set PLESK_SYNC_ALLOW_FTP_FALLBACK=1 to allow)",
    )


def _sync_transfer(*, chosen: str, source_dir: str, remote_path: str, host: str, port: int,
                   entry: str, origin: str, vault_url: str, host_fingerprint: str,
                   ftp_tls: bool, exclude_patterns: tuple[str, ...], plan: list[dict[str, Any]],
                   caps: dict[str, Any], detection: list[dict[str, Any]] | None,
                   ) -> tuple[list[Any], dict[str, Any], dict[str, Any] | None]:
    """Lease credentials and upload; returns (uploaded, extra, failure-or-None)."""
    verify_remote_hash = os.environ.get("PLESK_SYNC_VERIFY_REMOTE_HASH", "").strip() == "1"
    username = password = ""
    try:
        username = _vault_lease(entry, origin, "username", vault_url)
        password = _vault_lease(entry, origin, "password", vault_url)
        if chosen == "sftp":
            uploaded, extra = _publish_over_sftp(
                source_dir, remote_path, host, port, username, password, host_fingerprint, exclude_patterns,
                plan=plan, verify_remote_hash=verify_remote_hash,
            )
        else:
            uploaded, extra = _publish_over_ftp(
                source_dir, remote_path, host, port, username, password, bool(ftp_tls), exclude_patterns,
            )
    except RuntimeError as error:
        return [], {}, urirun.fail(str(error), capabilities=caps, transport=chosen, methods=detection)
    except Exception as error:
        return [], {}, urirun.fail(map_exception(error, phase="transfer"), capabilities=caps, transport=chosen)
    finally:
        username = password = ""
    return uploaded, extra, None


def _site_tree_sync(
    *,
    source_dir: str,
    remote_path: str,
    host: str,
    transport: str,
    sftp_port: int,
    ftp_port: int,
    ftp_tls: bool,
    sftp_vault_entry_id: str,
    ftp_vault_entry_id: str,
    credential_origin: str,
    host_fingerprint: str,
    vault_url: str,
    apply: bool,
    domain: str = "",
    exclude: list[str] | None = None,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    recipe_ref: str = "",
    source_ref: str = "",
    deployment_binding_ref: str = "",
    deployment_binding_hash: str = "",
    deployment_binding_version: int = 0,
    enforce_deployment_binding: bool = False,
) -> dict[str, Any]:
    """Plan, gate and (when permitted) apply the local tree onto the remote path."""
    invalid = _sync_validate(source_dir=source_dir, remote_path=remote_path, host=host,
                             transport=transport, sftp_port=sftp_port, ftp_port=ftp_port)
    if invalid:
        return urirun.fail(invalid)
    if enforce_deployment_binding:
        binding_error = _deployment_binding_error(
            source_dir=source_dir,
            source_ref=source_ref,
            deployment_binding_ref=deployment_binding_ref,
            deployment_binding_hash=deployment_binding_hash,
            deployment_binding_version=deployment_binding_version,
            domain=domain,
            host=host,
            remote_path=remote_path,
            credential_origin=credential_origin,
            sftp_vault_entry_id=sftp_vault_entry_id,
            ftp_vault_entry_id=ftp_vault_entry_id,
        )
        if binding_error:
            return urirun.fail(
                binding_error,
                domain=domain,
                remote_path=remote_path,
                deployment_binding_ref=deployment_binding_ref or None,
                mutation_attempted=False,
            )
    requires_scope_preflight = bool(deployment_binding_ref) or (
        bool(str(domain or "").strip()) and posixpath.normpath(str(remote_path or "")) == "/httpdocs"
    )
    credential_preflight = _deployment_credentials_preflight(
        host=host,
        domain=domain,
        remote_path=remote_path,
        transport=transport,
        sftp_vault_entry_id=sftp_vault_entry_id,
        ftp_vault_entry_id=ftp_vault_entry_id,
        credential_origin=credential_origin,
        vault_url=vault_url,
    ) if requires_scope_preflight else None
    if deployment_binding_ref and credential_preflight and not credential_preflight["ok"]:
        return urirun.fail(
            "deployment_credentials_not_ready",
            domain=domain,
            remote_path=remote_path,
            deployment_binding_ref=deployment_binding_ref,
            credential_preflight=credential_preflight,
            mutation_attempted=False,
        )
    scope_error = _sync_scope_error(
        host=host,
        domain=domain,
        remote_path=remote_path,
        transport=transport,
        sftp_vault_entry_id=sftp_vault_entry_id,
        ftp_vault_entry_id=ftp_vault_entry_id,
        credential_origin=credential_origin,
        credential_scope_verified=bool(credential_preflight and credential_preflight["ok"]),
    )
    if scope_error:
        return urirun.fail(scope_error, domain=domain, remote_path=remote_path, mutation_attempted=False)

    exclude_patterns = tuple(exclude) if exclude else _DEFAULT_EXCLUDE
    plan = _plan_local_tree(source_dir, remote_path, exclude_patterns)
    manifest = build_immutable_manifest(
        plan=plan,
        host=host,
        domain=domain,
        remote_path=remote_path,
        pack_id=pack_id,
        pack_version=pack_version,
        recipe_ref=recipe_ref,
    )
    may_write, apply_error, grant_claims = _apply_permitted(
        bool(apply),
        apply_grant=apply_grant,
        plan_hash=plan_hash,
        target=host or "",
        actor=actor,
        pack_id=pack_id,
        pack_version=pack_version,
        # Do not bind grant artifact to recomputed tree here — PR5a plan_hash
        # mismatch is the content gate; optional artifact check is request-driven.
        artifact_sha256="",
    )
    gated = _sync_apply_gate(
        apply_error=apply_error, may_write=may_write, plan=plan, manifest=manifest,
        host=host, remote_path=remote_path, domain=domain,
        exclude_patterns=exclude_patterns, grant_claims=grant_claims,
    )
    if gated is not None:
        return gated

    mismatch, manifest = _sync_plan_hash_gate(
        plan=plan, plan_hash=plan_hash, host=host, domain=domain, remote_path=remote_path)
    if mismatch is not None:
        return mismatch

    replayed = _sync_replay_gate(grant_claims=grant_claims, plan=plan, manifest=manifest, domain=domain)
    if replayed is not None:
        return replayed

    chosen = transport
    detection: list[dict[str, Any]] | None = None
    caps = build_capabilities(paramiko_mod=paramiko)
    denied = _sync_capability_denial(caps, transport)
    if denied is not None:
        return denied
    if transport == "auto":
        chosen, detection, unavailable = _sync_autodetect(
            host=host, caps=caps, sftp_port=sftp_port, ftp_port=ftp_port, ftp_tls=ftp_tls,
            sftp_vault_entry_id=sftp_vault_entry_id, ftp_vault_entry_id=ftp_vault_entry_id,
            credential_origin=credential_origin, host_fingerprint=host_fingerprint,
            vault_url=vault_url,
        )
        if unavailable is not None:
            return unavailable
    if chosen == "sftp" and paramiko is None:
        return urirun.fail(CAPABILITY_UNAVAILABLE, capabilities=caps)

    uploaded, extra, failure = _sync_transfer(
        chosen=chosen, source_dir=source_dir, remote_path=remote_path, host=host,
        port=int(sftp_port) if chosen == "sftp" else int(ftp_port),
        entry=sftp_vault_entry_id if chosen == "sftp" else ftp_vault_entry_id,
        origin=_transport_origin(chosen, host, credential_origin), vault_url=vault_url,
        host_fingerprint=host_fingerprint, ftp_tls=ftp_tls, exclude_patterns=exclude_patterns,
        plan=plan, caps=caps, detection=detection,
    )
    if failure is not None:
        return failure
    return connector_result(
        ok=True,
        executed=True,
        mutation_attempted=True,
        dry_run=False,
        host=host,
        transport=chosen,
        remote_path=remote_path,
        domain=domain or None,
        files_uploaded=len(uploaded),
        bytes_uploaded=manifest["bytes_total"],
        files=uploaded,
        files_planned=len(plan),
        bytes_planned=manifest["bytes_total"],
        manifest=manifest,
        plan_hash=manifest["plan_hash"],
        preserve_remote=list(_PRESERVE_REMOTE_NAMES),
        exclude=list(exclude_patterns),
        methods=detection,
        capabilities=caps,
        grant_jti=(grant_claims or {}).get("jti"),
        **extra,
    )


def _twin_apply_enabled() -> bool:
    return os.environ.get("PLESK_TWIN_APPLY_ENABLED", "").strip().lower() in {"1", "true", "yes"}


def _twin_storage_root(*, create: bool = True) -> str:
    configured = os.environ.get("PLESK_TWIN_ROOT", "").strip()
    if not configured:
        raise RuntimeError("plesk_site_twin_root_invalid")
    root = os.path.realpath(configured)
    if root == os.path.sep:
        raise RuntimeError("plesk_site_twin_root_invalid")
    if create:
        os.makedirs(root, exist_ok=True)
    elif not os.path.isdir(root):
        raise RuntimeError("plesk_site_twin_release_not_found")
    return root


@conn.handler(
    "site/command/twin-sync",
    isolated=True,
    policy={"timeout": isolated_execution_timeout()},
    meta={"label": "Apply a production-anchored site plan into an isolated local digital twin"},
)
def site_twin_sync(
    source_dir: str = "",
    source_ref: str = "",
    deployment_binding_ref: str = "",
    deployment_binding_hash: str = "",
    deployment_binding_version: int = 0,
    twin_profile_ref: str = "",
    twin_profile_hash: str = "",
    twin_profile_version: int = 0,
    apply: bool = False,
    plan_hash: str = "",
    exclude: list[str] | None = None,
) -> dict[str, Any]:
    """Plan or materialize an exact site tree in a network-free twin volume.

    The production binding remains the topology anchor, while the twin profile
    supplies a synthetic ``.test`` destination. No production credential or
    mutation gate is consulted because this route cannot select a network
    transport and writes only below ``PLESK_TWIN_ROOT``.
    """
    contract_error, contract = _twin_profile_contract(
        source_dir=source_dir,
        source_ref=source_ref,
        deployment_binding_ref=deployment_binding_ref,
        deployment_binding_hash=deployment_binding_hash,
        deployment_binding_version=deployment_binding_version,
        twin_profile_ref=twin_profile_ref,
        twin_profile_hash=twin_profile_hash,
        twin_profile_version=twin_profile_version,
    )
    if contract_error:
        return urirun.fail(
            contract_error,
            deployment_binding_ref=deployment_binding_ref or None,
            twin_profile_ref=twin_profile_ref or None,
            mutation_attempted=False,
        )
    profile = contract["profile"]
    target = profile["target"]
    domain = target["domain"]
    remote_path = target["remote_path"]
    if not _source_allowed(source_dir):
        return urirun.fail("plesk_site_source_not_allowlisted", mutation_attempted=False)
    exclude_patterns = tuple(exclude) if exclude else _DEFAULT_EXCLUDE
    plan = _plan_local_tree(source_dir, remote_path, exclude_patterns)
    manifest = build_immutable_manifest(
        plan=plan,
        host="plesk-twin.test",
        domain=domain,
        remote_path=remote_path,
        pack_id="deployment-twin",
        pack_version=str(twin_profile_version),
        recipe_ref=twin_profile_ref,
    )
    common = {
        "execution_plane": "digital-twin",
        "adapter": "local-release-fs",
        "production_binding_ref": deployment_binding_ref,
        "production_binding_hash": deployment_binding_hash,
        "twin_profile_ref": twin_profile_ref,
        "twin_profile_hash": twin_profile_hash,
        "domain": domain,
        "remote_path": remote_path,
        "files_planned": len(plan),
        "bytes_planned": manifest["bytes_total"],
        "plan": plan,
        "manifest": manifest,
        "plan_hash": manifest["plan_hash"],
    }
    if not apply:
        return connector_result(
            ok=True,
            dry_run=True,
            executed=False,
            mutation_attempted=False,
            note="resubmit apply=true with this exact plan_hash to materialize only the isolated twin",
            **common,
        )
    if not _twin_apply_enabled():
        return connector_result(
            ok=False,
            reason="plesk_site_twin_apply_disabled",
            error="plesk_site_twin_apply_disabled",
            dry_run=True,
            executed=False,
            mutation_attempted=False,
            **common,
        )
    mismatch, verified_manifest = _sync_plan_hash_gate(
        plan=plan,
        plan_hash=plan_hash,
        host="plesk-twin.test",
        domain=domain,
        remote_path=remote_path,
    )
    if mismatch is not None:
        return {**mismatch, **common, "manifest": verified_manifest, "plan_hash": verified_manifest["plan_hash"]}

    from .release_ops import (
        LocalReleaseFs,
        RELEASE_META_NAME,
        activate_release,
        build_release_meta,
        release_dir,
        verify_release_local,
    )

    try:
        fs = LocalReleaseFs(_twin_storage_root())
        release_id = f"rel_twin_{manifest['plan_hash'][:16]}"
        destination = release_dir(remote_path, release_id)
        fs.mkdir_p(destination)
        uploaded = []
        for item in plan:
            relative = str(item["path"])
            local_path = os.path.join(os.path.realpath(source_dir), *relative.split("/"))
            with open(local_path, "rb") as handle:
                content = handle.read()
            actual = hashlib.sha256(content).hexdigest()
            if actual != item["sha256"]:
                raise RuntimeError("plesk_site_twin_source_changed")
            virtual_path = f"{destination}/{relative}"
            fs.write_bytes(virtual_path, content)
            written = fs.read_bytes(virtual_path)
            if written is None or hashlib.sha256(written).hexdigest() != item["sha256"]:
                raise RuntimeError("plesk_site_twin_remote_hash_mismatch")
            uploaded.append({"path": relative, "bytes": len(content), "sha256": actual})
        meta = build_release_meta(
            release_id=release_id,
            plan_hash=manifest["plan_hash"],
            host="plesk-twin.test",
            domain=domain,
            files=plan,
            artifact_sha256=manifest.get("source_sha256") or "",
            pack_version=str(twin_profile_version),
        )
        fs.write_bytes(
            f"{destination}/{RELEASE_META_NAME}",
            json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        local_verify = verify_release_local(
            plan=plan,
            release_id=release_id,
            expected_plan_hash=manifest["plan_hash"],
            meta=meta,
        )
        entrypoint = str(profile["verification"]["entrypoint"])
        entrypoint_bytes = fs.read_bytes(f"{destination}/{entrypoint}")
        if entrypoint_bytes is None:
            raise RuntimeError("plesk_site_twin_entrypoint_missing")
        entrypoint_sha256 = hashlib.sha256(entrypoint_bytes).hexdigest()
        planned_entrypoint = next((item for item in plan if item["path"] == entrypoint), None)
        if not planned_entrypoint or entrypoint_sha256 != planned_entrypoint["sha256"]:
            raise RuntimeError("plesk_site_twin_entrypoint_hash_mismatch")
        activation = activate_release(
            fs,
            release_root=remote_path,
            release_id=release_id,
            strategy="symlink",
        )
        receipt_body = {
            "production_binding_hash": deployment_binding_hash,
            "twin_profile_hash": twin_profile_hash,
            "plan_hash": manifest["plan_hash"],
            "source_sha256": manifest.get("source_sha256"),
            "entrypoint": entrypoint,
            "entrypoint_sha256": entrypoint_sha256,
            "release_id": release_id,
        }
        receipt_sha256 = hashlib.sha256(
            json.dumps(receipt_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return connector_result(
            ok=True,
            dry_run=False,
            executed=True,
            mutation_attempted=True,
            verified=True,
            transport="local-release-fs",
            files_uploaded=len(uploaded),
            bytes_uploaded=manifest["bytes_total"],
            files=uploaded,
            release={**activation, **local_verify},
            verification={
                "mode": "sha256",
                "entrypoint": entrypoint,
                "entrypoint_sha256": entrypoint_sha256,
                "source_matches_release": True,
            },
            receipt={**receipt_body, "receipt_sha256": receipt_sha256},
            **common,
        )
    except (OSError, RuntimeError) as error:
        return connector_result(
            ok=False,
            reason=str(error),
            error=str(error),
            dry_run=False,
            executed=True,
            mutation_attempted=True,
            verified=False,
            **common,
        )


@conn.handler(
    "site/query/twin-current",
    isolated=True,
    meta={"label": "Observe and reverify the current isolated deployment twin release"},
)
def site_twin_current(
    source_dir: str = "",
    source_ref: str = "",
    deployment_binding_ref: str = "",
    deployment_binding_hash: str = "",
    deployment_binding_version: int = 0,
    twin_profile_ref: str = "",
    twin_profile_hash: str = "",
    twin_profile_version: int = 0,
    exclude: list[str] | None = None,
) -> dict[str, Any]:
    contract_error, contract = _twin_profile_contract(
        source_dir=source_dir,
        source_ref=source_ref,
        deployment_binding_ref=deployment_binding_ref,
        deployment_binding_hash=deployment_binding_hash,
        deployment_binding_version=deployment_binding_version,
        twin_profile_ref=twin_profile_ref,
        twin_profile_hash=twin_profile_hash,
        twin_profile_version=twin_profile_version,
    )
    if contract_error:
        return urirun.fail(contract_error, mutation_attempted=False)
    profile = contract["profile"]
    target = profile["target"]
    domain = target["domain"]
    remote_path = target["remote_path"]
    from .release_ops import LocalReleaseFs, RELEASE_META_NAME, read_current_state, release_dir
    try:
        fs = LocalReleaseFs(_twin_storage_root(create=False))
        state = read_current_state(fs, remote_path)
        release_id = str(state.get("current") or "")
        if not release_id:
            raise RuntimeError("plesk_site_twin_release_not_found")
        destination = release_dir(remote_path, release_id)
        raw_meta = fs.read_bytes(f"{destination}/{RELEASE_META_NAME}")
        if raw_meta is None:
            raise RuntimeError("plesk_site_twin_release_not_found")
        try:
            meta = json.loads(raw_meta.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise RuntimeError("plesk_site_twin_release_meta_invalid") from error
        exclude_patterns = tuple(exclude) if exclude else _DEFAULT_EXCLUDE
        plan = _plan_local_tree(source_dir, remote_path, exclude_patterns)
        manifest = build_immutable_manifest(
            plan=plan,
            host="plesk-twin.test",
            domain=domain,
            remote_path=remote_path,
        )
        entrypoint = str(profile["verification"]["entrypoint"])
        content = fs.read_bytes(f"{destination}/{entrypoint}")
        planned = next((item for item in plan if item["path"] == entrypoint), None)
        entrypoint_sha256 = hashlib.sha256(content).hexdigest() if content is not None else ""
        source_matches_release = bool(
            planned
            and entrypoint_sha256 == planned["sha256"]
            and meta.get("plan_hash") == manifest["plan_hash"]
            and meta.get("artifact_sha256") == manifest["source_sha256"]
        )
        fact = _twin_fact(
            twin_type="plesk.site.deployment",
            instance_id=twin_profile_ref,
            uri="plesk://host/site/query/twin-current",
            payload={
                "production_binding_ref": deployment_binding_ref,
                "production_binding_hash": deployment_binding_hash,
                "twin_profile_ref": twin_profile_ref,
                "twin_profile_hash": twin_profile_hash,
                "domain": domain,
                "release_id": release_id,
                "plan_hash": manifest["plan_hash"],
                "source_sha256": manifest["source_sha256"],
                "entrypoint": entrypoint,
                "entrypoint_sha256": entrypoint_sha256 or None,
                "source_matches_release": source_matches_release,
            },
            fact_quality="fresh" if source_matches_release else "conflicting",
        )
        if not source_matches_release:
            return urirun.fail(
                "plesk_site_twin_verification_failed",
                mutation_attempted=False,
                twin_fact=fact,
            )
        return urirun.ok(
            mutation_attempted=False,
            verified=True,
            twin_fact=fact,
            current=release_id,
            previous=state.get("previous"),
            activation_strategy=state.get("strategy"),
            plan_hash=manifest["plan_hash"],
            source_sha256=manifest["source_sha256"],
            entrypoint_sha256=entrypoint_sha256,
        )
    except (OSError, RuntimeError) as error:
        return urirun.fail(str(error), mutation_attempted=False)


@conn.handler(
    "site/command/sync",
    isolated=True,
    policy={"timeout": isolated_execution_timeout()},
    meta={"label": "Dry-run (default) or apply www→httpdocs tree sync over SFTP/FTP"},
)
def site_sync(
    source_dir: str = "",
    remote_path: str = "/httpdocs",
    host: str = "",
    sftp_host: str = "",
    transport: str = "auto",
    sftp_port: int = 22,
    ftp_port: int = 21,
    ftp_tls: bool = True,
    sftp_vault_entry_id: str = "plesk-sftp",
    ftp_vault_entry_id: str = "plesk-ftp",
    credential_origin: str = "",
    host_fingerprint: str = "",
    vault_url: str = "",
    apply: bool = False,
    domain: str = "",
    exclude: list[str] | None = None,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    recipe_ref: str = "",
    source_ref: str = "",
    deployment_binding_ref: str = "",
    deployment_binding_hash: str = "",
    deployment_binding_version: int = 0,
) -> dict[str, Any]:
    return _site_tree_sync(
        source_dir=source_dir,
        remote_path=remote_path,
        host=host or sftp_host,
        transport=transport,
        sftp_port=int(sftp_port),
        ftp_port=int(ftp_port),
        ftp_tls=bool(ftp_tls),
        sftp_vault_entry_id=sftp_vault_entry_id,
        ftp_vault_entry_id=ftp_vault_entry_id,
        credential_origin=credential_origin,
        host_fingerprint=host_fingerprint,
        vault_url=vault_url,
        apply=bool(apply),
        domain=domain,
        exclude=exclude,
        plan_hash=plan_hash,
        apply_grant=apply_grant,
        actor=actor,
        pack_id=pack_id,
        pack_version=pack_version,
        recipe_ref=recipe_ref,
        source_ref=source_ref,
        deployment_binding_ref=deployment_binding_ref,
        deployment_binding_hash=deployment_binding_hash,
        deployment_binding_version=deployment_binding_version,
        enforce_deployment_binding=True,
    )


@conn.handler(
    "site/command/publish",
    isolated=True,
    policy={"timeout": isolated_execution_timeout()},
    meta={"label": "Alias of site/command/sync (dry-run by default; apply requires grant + plan_hash)"},
)
def site_publish(
    source_dir: str = "",
    remote_path: str = "/httpdocs",
    host: str = "",
    sftp_host: str = "",
    transport: str = "auto",
    sftp_port: int = 22,
    ftp_port: int = 21,
    ftp_tls: bool = True,
    sftp_vault_entry_id: str = "plesk-sftp",
    ftp_vault_entry_id: str = "plesk-ftp",
    credential_origin: str = "",
    host_fingerprint: str = "",
    vault_url: str = "",
    apply: bool = False,
    domain: str = "",
    exclude: list[str] | None = None,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    recipe_ref: str = "",
    source_ref: str = "",
    deployment_binding_ref: str = "",
    deployment_binding_hash: str = "",
    deployment_binding_version: int = 0,
) -> dict[str, Any]:
    return site_sync(
        source_dir=source_dir,
        remote_path=remote_path,
        host=host,
        sftp_host=sftp_host,
        transport=transport,
        sftp_port=sftp_port,
        ftp_port=ftp_port,
        ftp_tls=ftp_tls,
        sftp_vault_entry_id=sftp_vault_entry_id,
        ftp_vault_entry_id=ftp_vault_entry_id,
        credential_origin=credential_origin,
        host_fingerprint=host_fingerprint,
        vault_url=vault_url,
        apply=apply,
        domain=domain,
        exclude=exclude,
        plan_hash=plan_hash,
        apply_grant=apply_grant,
        actor=actor,
        pack_id=pack_id,
        pack_version=pack_version,
        recipe_ref=recipe_ref,
        source_ref=source_ref,
        deployment_binding_ref=deployment_binding_ref,
        deployment_binding_hash=deployment_binding_hash,
        deployment_binding_version=deployment_binding_version,
    )


def _open_sftp_release_fs(
    *,
    host: str,
    sftp_port: int,
    sftp_vault_entry_id: str,
    credential_origin: str,
    host_fingerprint: str,
    vault_url: str,
):
    """Lease SFTP creds and return (transport, SftpReleaseFs)."""
    from .release_ops import SftpReleaseFs

    if paramiko is None:
        raise RuntimeError(CAPABILITY_UNAVAILABLE)
    origin = _transport_origin("sftp", host, credential_origin)
    username = password = ""
    try:
        username = _vault_lease(sftp_vault_entry_id, origin, "username", vault_url)
        password = _vault_lease(sftp_vault_entry_id, origin, "password", vault_url)
        transport, sftp, fingerprint = _sftp_connect(
            host, int(sftp_port), username, password, host_fingerprint,
        )
    finally:
        username = password = ""
    return transport, SftpReleaseFs(sftp), fingerprint


def _release_mutate_gates(
    *,
    apply: bool,
    apply_grant: str,
    plan_hash: str,
    host: str,
    actor: str,
    pack_id: str,
    pack_version: str,
) -> tuple[bool, str | None, dict | None]:
    return _apply_permitted(
        bool(apply),
        apply_grant=apply_grant,
        plan_hash=plan_hash,
        target=host or "",
        actor=actor,
        pack_id=pack_id,
        pack_version=pack_version,
        artifact_sha256="",
    )


@conn.handler(
    "site/command/release-upload",
    isolated=True,
    meta={"label": "Upload a release tree under releases/rel_… (does not activate)"},
)
def release_upload(
    source_dir: str = "",
    release_root: str = "/httpdocs",
    release_id: str = "",
    host: str = "",
    sftp_host: str = "",
    transport: str = "sftp",
    sftp_port: int = 22,
    sftp_vault_entry_id: str = "plesk-sftp",
    credential_origin: str = "",
    host_fingerprint: str = "",
    vault_url: str = "",
    apply: bool = False,
    domain: str = "",
    exclude: list[str] | None = None,
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    recipe_ref: str = "",
    git_commit: str = "",
) -> dict[str, Any]:
    """Upload into releases/rel_… — never writes the live docroot directly."""
    from .release_ops import (
        RELEASE_META_NAME,
        build_release_meta,
        new_release_id,
        release_dir,
        validate_release_id,
        validate_release_root,
    )

    host = host or sftp_host
    bad_root = validate_release_root(release_root)
    if bad_root:
        return urirun.fail(bad_root)
    rid = release_id or new_release_id()
    bad_id = validate_release_id(rid)
    if bad_id:
        return urirun.fail(bad_id)
    if transport not in {"auto", "sftp"}:
        return urirun.fail("plesk_release_sftp_required")

    remote_path = release_dir(release_root, rid)
    # Reuse tree sync planner/gates with remote_path = releases/rel_…
    planned = _site_tree_sync(
        source_dir=source_dir,
        remote_path=remote_path,
        host=host,
        transport="sftp",
        sftp_port=int(sftp_port),
        ftp_port=21,
        ftp_tls=True,
        sftp_vault_entry_id=sftp_vault_entry_id,
        ftp_vault_entry_id="plesk-ftp",
        credential_origin=credential_origin,
        host_fingerprint=host_fingerprint,
        vault_url=vault_url,
        apply=bool(apply),
        domain=domain,
        exclude=exclude,
        plan_hash=plan_hash,
        apply_grant=apply_grant,
        actor=actor,
        pack_id=pack_id,
        pack_version=pack_version,
        recipe_ref=recipe_ref,
    )
    if not planned.get("ok"):
        return planned

    meta = build_release_meta(
        release_id=rid,
        plan_hash=planned.get("plan_hash") or "",
        host=host,
        domain=domain,
        files=planned.get("plan") or [],
        git_commit=git_commit,
        pack_version=pack_version,
        artifact_sha256=(planned.get("manifest") or {}).get("source_sha256") or "",
    )
    result = {
        **{k: v for k, v in planned.items() if k != "ok"},
        "ok": True,
        "release_id": rid,
        "release_root": release_root,
        "remote_path": remote_path,
        "activated": False,
        "release_meta": meta,
        "note": planned.get("note")
        or ("dry-run only" if planned.get("dry_run") else "uploaded; call release-activate to switch current"),
    }
    if planned.get("dry_run"):
        return result

    # Write release metadata marker into the uploaded tree (best-effort over SFTP).
    try:
        transport_obj, fs, _fp = _open_sftp_release_fs(
            host=host,
            sftp_port=int(sftp_port),
            sftp_vault_entry_id=sftp_vault_entry_id,
            credential_origin=credential_origin,
            host_fingerprint=host_fingerprint,
            vault_url=vault_url,
        )
        try:
            fs.write_bytes(
                f"{remote_path}/{RELEASE_META_NAME}",
                json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("utf-8"),
            )
        finally:
            transport_obj.close()
    except RuntimeError as error:
        return urirun.fail(str(error), release_id=rid, files_uploaded=planned.get("files_uploaded", 0))
    return result


def _meta_field(meta: Any, override: str, *keys: str) -> str:
    """An explicit expectation wins; otherwise take the first key present in meta."""
    if override:
        return override
    if not isinstance(meta, dict):
        return ""
    for key in keys:
        value = meta.get(key)
        if value:
            return str(value)
    return ""


def _read_release_meta(*, host: str, release_root: str, release_id: str, plan_hash: str,
                       sftp_port: int, sftp_vault_entry_id: str, credential_origin: str,
                       host_fingerprint: str, vault_url: str,
                       ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Read the remote release meta over SFTP; returns (meta, verified, failure-or-None)."""
    from .release_ops import RELEASE_META_NAME, release_dir, verify_release_local

    try:
        transport_obj, fs, _fp = _open_sftp_release_fs(
            host=host,
            sftp_port=int(sftp_port),
            sftp_vault_entry_id=sftp_vault_entry_id,
            credential_origin=credential_origin,
            host_fingerprint=host_fingerprint,
            vault_url=vault_url,
        )
        try:
            raw = fs.read_bytes(f"{release_dir(release_root, release_id)}/{RELEASE_META_NAME}")
            meta = json.loads(raw.decode("utf-8")) if raw else {}
            verified = verify_release_local(
                plan=[],
                release_id=release_id,
                expected_plan_hash=plan_hash,
                meta=meta if isinstance(meta, dict) else None,
            )
        finally:
            transport_obj.close()
    except RuntimeError as error:
        return {}, {}, urirun.fail(str(error))
    except (ValueError, UnicodeDecodeError):
        return {}, {}, urirun.fail(REMOTE_HASH_MISMATCH)
    return meta, verified, None


def _release_expectation(*, meta: Any, hostname: str, release_id: str,
                         expected_artifact_sha256: str, expected_source_commit: str,
                         expected_pack_version: str,
                         dns_targets: list[str] | None) -> dict[str, Any]:
    """What the published site must prove, merging caller input with the release meta."""
    return {
        "release_id": release_id,
        "artifact_sha256": _meta_field(meta, expected_artifact_sha256,
                                       "artifact_sha256", "content_sha256"),
        "source_commit": _meta_field(meta, expected_source_commit,
                                     "source_commit", "git_commit"),
        "pack_version": _meta_field(meta, expected_pack_version, "pack_version"),
        "dns_targets": list(dns_targets or []),
        "tls_hostname": hostname,
    }


def _release_verdict(ladder: dict[str, Any], *, host: str, domain: str, release_id: str,
                     release_root: str, verified: dict[str, Any]) -> dict[str, Any]:
    """Turn the ladder outcome into the handler's answer (unverified is a failure)."""
    if not ladder.get("ok"):
        extra = {k: v for k, v in ladder.items() if k not in {"ok", "error"}}
        return urirun.fail(
            ladder.get("error") or "applied_unverified",
            host=host,
            domain=domain or None,
            release_id=release_id,
            **extra,
        )
    return urirun.ok(
        host=host,
        domain=domain or None,
        release_root=release_root,
        **verified,
        publish_verify=ladder,
    )


@conn.handler(
    "site/command/release-verify",
    isolated=True,
    meta={"label": "Verify release hashes; optional origin/public fingerprint (ADR-004)"},
)
def release_verify(
    release_id: str = "",
    release_root: str = "/httpdocs",
    plan_hash: str = "",
    host: str = "",
    sftp_host: str = "",
    sftp_port: int = 22,
    sftp_vault_entry_id: str = "plesk-sftp",
    credential_origin: str = "",
    host_fingerprint: str = "",
    vault_url: str = "",
    domain: str = "",
    verify_origin: bool = False,
    verify_public: bool = False,
    origin_ip: str = "",
    dns_targets: list[str] | None = None,
    expected_artifact_sha256: str = "",
    expected_source_commit: str = "",
    expected_pack_version: str = "",
) -> dict[str, Any]:
    from .release_ops import validate_release_id, validate_release_root
    from .verify_ladder import run_publish_verify_ladder

    host = host or sftp_host
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return urirun.fail("plesk_site_host_invalid")
    bad = validate_release_root(release_root) or validate_release_id(release_id)
    if bad:
        return urirun.fail(bad)

    meta, verified, failure = _read_release_meta(
        host=host, release_root=release_root, release_id=release_id, plan_hash=plan_hash,
        sftp_port=sftp_port, sftp_vault_entry_id=sftp_vault_entry_id,
        credential_origin=credential_origin, host_fingerprint=host_fingerprint,
        vault_url=vault_url,
    )
    if failure is not None:
        return failure

    if not (verify_origin or verify_public):
        return urirun.ok(host=host, domain=domain or None, release_root=release_root, **verified)

    hostname = domain or host
    ladder = run_publish_verify_ladder(
        hostname=hostname,
        expected=_release_expectation(
            meta=meta, hostname=hostname, release_id=release_id,
            expected_artifact_sha256=expected_artifact_sha256,
            expected_source_commit=expected_source_commit,
            expected_pack_version=expected_pack_version,
            dns_targets=dns_targets,
        ),
        origin_ip=origin_ip,
        check_dns_step=bool(dns_targets),
        check_tls_step=True,
        check_origin=bool(verify_origin),
        check_public=bool(verify_public),
        release_files_ok=True,
    )
    return _release_verdict(ladder, host=host, domain=domain, release_id=release_id,
                            release_root=release_root, verified=verified)


@conn.handler(
    "site/command/publish-verify",
    isolated=True,
    meta={"label": "ADR-004 DNS/TLS/HTTPS + content fingerprint verify ladder"},
)
def publish_verify(
    hostname: str = "",
    domain: str = "",
    release_id: str = "",
    artifact_sha256: str = "",
    source_commit: str = "",
    pack_version: str = "",
    origin_ip: str = "",
    dns_targets: list[str] | None = None,
    verify_origin: bool = True,
    verify_public: bool = True,
    check_dns: bool = True,
    check_tls: bool = True,
    release_files_ok: bool = True,
) -> dict[str, Any]:
    """Public/origin verify DoD. Does not mutate DNS (PR9 cutover is separate).

    Staging recommendation: use ``docs-stage.subactor.com`` (or origin_ip + Host)
    before pointing production ``docs.subactor.com`` at Plesk.
    """
    from .verify_ladder import curl_resolve_hint, run_publish_verify_ladder

    host = (hostname or domain or "").strip()
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return urirun.fail("plesk_site_host_invalid")
    if not release_id or not artifact_sha256:
        return urirun.fail("fingerprint_missing", note="release_id and artifact_sha256 required")

    caps = build_capabilities(paramiko_mod=paramiko)
    ladder = run_publish_verify_ladder(
        hostname=host,
        expected={
            "release_id": release_id,
            "artifact_sha256": artifact_sha256,
            "source_commit": source_commit,
            "pack_version": pack_version,
            "dns_targets": list(dns_targets or []),
            "tls_hostname": host,
        },
        origin_ip=origin_ip,
        check_dns_step=bool(check_dns) and bool(dns_targets),
        check_tls_step=bool(check_tls),
        check_origin=bool(verify_origin),
        check_public=bool(verify_public),
        release_files_ok=bool(release_files_ok),
    )
    hint = curl_resolve_hint(host, origin_ip) if origin_ip else None
    if not ladder.get("ok"):
        extra = {k: v for k, v in ladder.items() if k not in {"ok", "error"}}
        return urirun.fail(
            ladder.get("error") or "applied_unverified",
            capabilities=caps,
            curl_resolve=hint,
            staging_note="Prefer docs-stage.subactor.com or origin_ip Host-header preflight before PR9 cutover",
            **extra,
        )
    return urirun.ok(
        capabilities=caps,
        curl_resolve=hint,
        staging_note="Prefer docs-stage.subactor.com for end-to-end rehearsal; production DNS cutover is PR9",
        **ladder,
    )


@conn.handler(
    "site/command/release-activate",
    isolated=True,
    meta={"label": "Atomically activate a release (symlink or pointer; hides strategy)"},
)
def release_activate(
    release_id: str = "",
    release_root: str = "/httpdocs",
    host: str = "",
    sftp_host: str = "",
    sftp_port: int = 22,
    sftp_vault_entry_id: str = "plesk-sftp",
    credential_origin: str = "",
    host_fingerprint: str = "",
    vault_url: str = "",
    apply: bool = False,
    activation_strategy: str = "",
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    domain: str = "",
) -> dict[str, Any]:
    from .release_ops import activate_release, validate_release_id, validate_release_root

    host = host or sftp_host
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return urirun.fail("plesk_site_host_invalid")
    bad = validate_release_root(release_root) or validate_release_id(release_id)
    if bad:
        return urirun.fail(bad)

    if apply and not str(plan_hash or "").strip():
        return urirun.fail("plan_hash_required")
    may_write, apply_error, grant_claims = _release_mutate_gates(
        apply=apply,
        apply_grant=apply_grant,
        plan_hash=plan_hash,
        host=host,
        actor=actor,
        pack_id=pack_id,
        pack_version=pack_version,
    )
    if apply_error:
        return urirun.fail(apply_error, grant_claims=grant_claims)
    if not may_write:
        return urirun.ok(
            dry_run=True,
            release_id=release_id,
            release_root=release_root,
            host=host,
            note="set apply=true + plan_hash (from release-upload) + grant to activate",
        )

    jti = (grant_claims or {}).get("jti") or ""
    expires_at = (grant_claims or {}).get("expires_at") or ""
    replay_ok, replay_error = consume_apply_grant_jti(jti, expires_at)
    if not replay_ok:
        return urirun.fail(replay_error or "apply_grant_replay")

    caps = build_capabilities(paramiko_mod=paramiko)
    if not caps["release_activation"]:
        return urirun.fail(CAPABILITY_UNAVAILABLE, capabilities=caps)

    try:
        transport_obj, fs, fingerprint = _open_sftp_release_fs(
            host=host,
            sftp_port=int(sftp_port),
            sftp_vault_entry_id=sftp_vault_entry_id,
            credential_origin=credential_origin,
            host_fingerprint=host_fingerprint,
            vault_url=vault_url,
        )
        try:
            activated = activate_release(
                fs,
                release_root=release_root,
                release_id=release_id,
                strategy=activation_strategy,
            )
        finally:
            transport_obj.close()
    except RuntimeError as error:
        return urirun.fail(str(error), capabilities=caps)
    return urirun.ok(
        dry_run=False,
        host=host,
        domain=domain or None,
        host_fingerprint=fingerprint,
        capabilities=caps,
        grant_jti=jti or None,
        **activated,
    )


@conn.handler(
    "site/query/release-current",
    isolated=True,
    meta={"label": "Report current and previous release pointers"},
)
def release_current(
    release_root: str = "/httpdocs",
    host: str = "",
    sftp_host: str = "",
    sftp_port: int = 22,
    sftp_vault_entry_id: str = "plesk-sftp",
    credential_origin: str = "",
    host_fingerprint: str = "",
    vault_url: str = "",
    domain: str = "",
) -> dict[str, Any]:
    from .release_ops import read_current_state, validate_release_root

    host = host or sftp_host
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return urirun.fail("plesk_site_host_invalid")
    bad = validate_release_root(release_root)
    if bad:
        return urirun.fail(bad)
    try:
        transport_obj, fs, _fp = _open_sftp_release_fs(
            host=host,
            sftp_port=int(sftp_port),
            sftp_vault_entry_id=sftp_vault_entry_id,
            credential_origin=credential_origin,
            host_fingerprint=host_fingerprint,
            vault_url=vault_url,
        )
        try:
            state = read_current_state(fs, release_root)
        finally:
            transport_obj.close()
    except RuntimeError as error:
        return urirun.fail(str(error))
    return urirun.ok(host=host, domain=domain or None, **state)


@conn.handler(
    "site/command/release-rollback",
    isolated=True,
    meta={"label": "Activate previous release; status rolled_back (not fake ok)"},
)
def release_rollback(
    release_root: str = "/httpdocs",
    previous_release: str = "",
    host: str = "",
    sftp_host: str = "",
    sftp_port: int = 22,
    sftp_vault_entry_id: str = "plesk-sftp",
    credential_origin: str = "",
    host_fingerprint: str = "",
    vault_url: str = "",
    apply: bool = False,
    activation_strategy: str = "",
    plan_hash: str = "",
    apply_grant: str = "",
    actor: str = "",
    pack_id: str = "",
    pack_version: str = "",
    domain: str = "",
) -> dict[str, Any]:
    from .release_ops import rollback_release, validate_release_root

    host = host or sftp_host
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return urirun.fail("plesk_site_host_invalid")
    bad = validate_release_root(release_root)
    if bad:
        return urirun.fail(bad)

    if apply and not str(plan_hash or "").strip():
        return urirun.fail("plan_hash_required")
    may_write, apply_error, grant_claims = _release_mutate_gates(
        apply=apply,
        apply_grant=apply_grant,
        plan_hash=plan_hash,
        host=host,
        actor=actor,
        pack_id=pack_id,
        pack_version=pack_version,
    )
    if apply_error:
        return urirun.fail(apply_error, grant_claims=grant_claims)
    if not may_write:
        return urirun.ok(
            dry_run=True,
            release_root=release_root,
            host=host,
            status="rollback_planned",
            note="set apply=true + plan_hash + grant to rollback",
        )

    jti = (grant_claims or {}).get("jti") or ""
    expires_at = (grant_claims or {}).get("expires_at") or ""
    replay_ok, replay_error = consume_apply_grant_jti(jti, expires_at)
    if not replay_ok:
        return urirun.fail(replay_error or "apply_grant_replay")

    caps = build_capabilities(paramiko_mod=paramiko)
    if not caps["rollback"]:
        return urirun.fail(CAPABILITY_UNAVAILABLE, capabilities=caps)

    try:
        transport_obj, fs, fingerprint = _open_sftp_release_fs(
            host=host,
            sftp_port=int(sftp_port),
            sftp_vault_entry_id=sftp_vault_entry_id,
            credential_origin=credential_origin,
            host_fingerprint=host_fingerprint,
            vault_url=vault_url,
        )
        try:
            rolled = rollback_release(
                fs,
                release_root=release_root,
                strategy=activation_strategy,
                previous_release=previous_release,
            )
        finally:
            transport_obj.close()
    except RuntimeError as error:
        return urirun.fail(str(error), capabilities=caps)

    # Connector op succeeded, but status is rolled_back — never pretend deploy ok.
    return urirun.ok(
        dry_run=False,
        host=host,
        domain=domain or None,
        host_fingerprint=fingerprint,
        capabilities=caps,
        grant_jti=jti or None,
        **rolled,
    )


@conn.handler("plesk://host/doctor/query/report", isolated=True, meta={"label": "Plesk connector readiness report"})
def doctor() -> dict[str, Any]:
    caps = build_capabilities(paramiko_mod=paramiko)
    budgets = transport_timeouts()
    ready = production_publish_ready(caps)
    return {
        "ok": True,
        "connector": CONNECTOR_ID,
        "version": "0.14.0",
        "status": "ready" if ready else "degraded",
        "capabilities": caps,
        "production_publish_ready": ready,
        "ftp_fallback_allowed": ftp_fallback_allowed(),
        "release_activation_default": os.environ.get("PLESK_RELEASE_ACTIVATION", "auto"),
        "timeouts": {
            "connect": budgets.connect,
            "operation": budgets.operation,
            "total": budgets.total,
        },
        "staging_domain_recommendation": "docs-stage.subactor.com",
        "extension_model": {
            "schema": load_extension_profiles()["schema"],
            "discovery": "xml-api:extension.get",
            "execution_policy": "profiled-only",
            "catalog_uri": "plesk://host/extensions/query/capabilities",
        },
        "note": None if ready else "SFTP/paramiko missing — blocks production publish readiness",
    }


def urirun_bindings() -> dict[str, Any]:
    return conn.bindings()


def connector_manifest() -> dict[str, Any]:
    return conn.manifest(_urirun_compat.load_manifest(__package__))


def main(argv: list[str] | None = None) -> int:
    return conn.cli(argv, manifest_prose=_urirun_compat.load_manifest(__package__))


@conn.handler(
    "session/command/mutate-lease",
    isolated=True,
    meta={"label": "Issue or clear founder session mutate lease (TTL handoff)"},
)
def session_mutate_lease(
    action: str = "issue",
    ttl_seconds: int = 3600,
    risk_class: str = "reversible",
    actor: str = "",
    reason: str = "",
) -> dict[str, Any]:
    """Founder chat handoff: write a short-lived mutate lease on this node."""
    act = str(action or "issue").strip().lower()
    if act in {"status", "query"}:
        lease = load_mutate_lease()
        return urirun.ok(active=bool(lease), lease=lease, mutation_attempted=False)
    if act in {"clear", "revoke", "cancel"}:
        result = clear_mutate_lease_file()
        if not result.get("ok"):
            return urirun.fail(str(result.get("error") or "mutate_lease_clear_failed"))
        return urirun.ok(**result, active=False, mutation_attempted=True)
    if act not in {"issue", "grant", "start"}:
        return urirun.fail("mutate_lease_action_invalid")
    result = issue_mutate_lease_file(
        ttl_seconds=ttl_seconds,
        risk_class=risk_class,
        actor=actor,
        reason=reason,
    )
    if not result.get("ok"):
        return urirun.fail(str(result.get("error") or "mutate_lease_issue_failed"))
    return urirun.ok(**result, active=True, mutation_attempted=True)


@conn.handler(
    "session/query/mutate-lease",
    isolated=True,
    meta={"label": "Read founder session mutate lease status"},
)
def session_mutate_lease_status() -> dict[str, Any]:
    lease = load_mutate_lease()
    return urirun.ok(active=bool(lease), lease=lease, mutation_attempted=False)


if __name__ == "__main__":
    raise SystemExit(main())
