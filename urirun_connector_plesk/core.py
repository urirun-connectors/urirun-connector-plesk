"""Plesk REST API v2 connector with vault-backed authorization."""
from __future__ import annotations

import base64
import fnmatch
import ftplib
import hashlib
import json
import os
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
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
from .apply_grant import autonomy_mutations_enabled, consume_apply_grant_jti, format_intent_pack, verify_apply_grant
from .timeouts import transport_timeouts

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
    token = os.environ.get("URIRUN_VAULT_TOKEN", "")
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
        raise RuntimeError("credential_expired")
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


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SENSITIVE.search(str(key)) else _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _api_path(path: str) -> str:
    if not _SAFE_API_PATH.fullmatch(path) or ".." in path:
        raise RuntimeError("plesk_api_path_not_allowed")
    return path


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
    return urirun.ok(base_url=_base_url(base_url), authorized=200 <= status < 300, http_status=status)


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


@conn.handler("mailbox/command/create", isolated=True, meta={"label": "Create a Plesk mailbox and store its generated credential"})
def create_mailbox(
    email: str = "",
    display_name: str = "",
    credential_vault_entry_id: str = "",
    credential_origin: str = "",
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
        entry_id = credential_vault_entry_id or f"plesk-mailbox-{hashlib.sha256(address.encode()).hexdigest()[:20]}"
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", entry_id):
            raise RuntimeError("plesk_mailbox_vault_entry_invalid")
        password = f"{secrets.token_urlsafe(24)}!aA9"
        status, data = _authorized_request(
            base_url=base_url,
            path=api_path,
            method="POST",
            body={"params": ["--create", address, "-passwd", password, "-mailbox", "true"]},
            runtime_vault_entry_id=runtime_vault_entry_id,
            vault_url=vault_url,
        )
        if not 200 <= status < 300:
            raise RuntimeError(f"plesk_mailbox_create_failed:{status}")
        stored_id = _vault_store_secrets(
            entry_id,
            origin,
            f"Plesk mailbox {address}",
            {"username": address, "password": password},
            vault_url,
        )
    except RuntimeError as error:
        return urirun.fail(str(error))
    finally:
        password = ""
    return urirun.ok(
        email=address,
        display_name=display_name[:160],
        created=True,
        credential_vault_entry_id=stored_id,
        credential_origin=origin,
        api_result=_redact(data),
    )


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


def _xml_ok(raw: str) -> bool:
    return "<status>ok</status>" in raw and "<status>error</status>" not in raw


def _xml_props(raw: str) -> dict[str, str]:
    return dict(re.findall(r"<name>([^<]+)</name>\s*<value>([^<]*)</value>", raw))


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
    """Allow www/ or docs/ (or explicit PLESK_SYNC_ALLOWED_SOURCES prefixes)."""
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
    return os.path.basename(abs_path.rstrip(os.sep)) in {"www", "docs"}


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
    """Uploads require apply + master + PLESK gate + valid signed grant (ADR-003)."""
    if not apply:
        return False, None, None
    if not autonomy_mutations_enabled():
        return False, "autonomy_mutations_disabled", None
    if os.environ.get("PLESK_SYNC_APPLY", "").strip() != "1":
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
) -> dict[str, Any]:
    invalid = _validate_publish_inputs(source_dir, remote_path, host)
    if invalid:
        return urirun.fail(invalid)
    for port in (sftp_port, ftp_port):
        bad = _validate_port(port)
        if bad:
            return urirun.fail(bad)
    if transport not in {"auto", "sftp", "ftp"}:
        return urirun.fail("plesk_site_transport_invalid")
    if not _source_allowed(source_dir):
        return urirun.fail("plesk_site_source_not_allowlisted")

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
    if apply_error:
        return urirun.fail(
            apply_error,
            dry_run=True,
            files_planned=len(plan),
            plan=plan,
            manifest=manifest,
            plan_hash=manifest["plan_hash"],
            preserve_remote=list(_PRESERVE_REMOTE_NAMES),
            domain=domain or None,
            grant_claims=grant_claims,
        )
    if not may_write:
        return urirun.ok(
            dry_run=True,
            host=host,
            remote_path=remote_path,
            domain=domain or None,
            files_planned=len(plan),
            plan=plan,
            manifest=manifest,
            plan_hash=manifest["plan_hash"],
            preserve_remote=list(_PRESERVE_REMOTE_NAMES),
            exclude=list(exclude_patterns),
            note="set apply=true, AUTONOMY_MUTATIONS_ENABLED=1, PLESK_SYNC_APPLY=1, plan_hash, and signed apply_grant",
        )

    # PR5a: apply must bind to dry-run plan_hash — no free re-scan divergence / zero upload on mismatch.
    matched, verified, mismatch = verify_plan_hash(
        plan=plan,
        expected_plan_hash=plan_hash,
        host=host,
        domain=domain,
        remote_path=remote_path,
    )
    if not matched:
        return urirun.fail(
            mismatch or "plan_hash_mismatch",
            dry_run=True,
            files_planned=len(plan),
            plan=plan,
            manifest=verified,
            plan_hash=verified["plan_hash"],
            files_uploaded=0,
            preserve_remote=list(_PRESERVE_REMOTE_NAMES),
            domain=domain or None,
        )
    manifest = verified

    # PR5c: consume jti after gates pass, before any network mutation.
    jti = (grant_claims or {}).get("jti") or ""
    expires_at = (grant_claims or {}).get("expires_at") or ""
    replay_ok, replay_error = consume_apply_grant_jti(jti, expires_at)
    if not replay_ok:
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

    chosen = transport
    detection: list[dict[str, Any]] | None = None
    caps = build_capabilities(paramiko_mod=paramiko)

    # Production publish: missing SFTP blocks readiness even if FTP is available.
    deny = deny_if_sftp_required(caps, transport=transport)
    if deny and transport in {"auto", "sftp"}:
        # Explicit transport=ftp handled below when fallback policy is off.
        if not caps["sftp"]["available"]:
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

    if transport == "auto":
        detection = _detect_transports(
            host, sftp_port=int(sftp_port), ftp_port=int(ftp_port), ftp_tls=bool(ftp_tls),
            sftp_vault_entry_id=sftp_vault_entry_id, ftp_vault_entry_id=ftp_vault_entry_id,
            credential_origin=credential_origin, host_fingerprint=host_fingerprint, vault_url=vault_url,
        )
        available = [r["transport"] for r in detection if r["available"]]
        if not available:
            return urirun.fail("plesk_site_no_authorized_transport", methods=detection, capabilities=caps)
        if "sftp" in available:
            chosen = "sftp"
        elif ftp_fallback_allowed():
            chosen = available[0]
        else:
            return urirun.fail(
                CAPABILITY_UNAVAILABLE,
                methods=detection,
                capabilities=caps,
                production_publish_ready=False,
                note="SFTP unavailable; FTP fallback disabled (set PLESK_SYNC_ALLOW_FTP_FALLBACK=1 to allow)",
            )

    if chosen == "sftp" and paramiko is None:
        return urirun.fail(CAPABILITY_UNAVAILABLE, capabilities=caps)

    verify_remote_hash = os.environ.get("PLESK_SYNC_VERIFY_REMOTE_HASH", "").strip() == "1"
    entry = sftp_vault_entry_id if chosen == "sftp" else ftp_vault_entry_id
    port = int(sftp_port) if chosen == "sftp" else int(ftp_port)
    origin = _transport_origin(chosen, host, credential_origin)
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
        return urirun.fail(str(error), capabilities=caps, transport=chosen, methods=detection)
    except Exception as error:
        return urirun.fail(map_exception(error, phase="transfer"), capabilities=caps, transport=chosen)
    finally:
        username = password = ""
    return urirun.ok(
        dry_run=False,
        host=host,
        transport=chosen,
        remote_path=remote_path,
        domain=domain or None,
        files_uploaded=len(uploaded),
        files=uploaded,
        files_planned=len(plan),
        manifest=manifest,
        plan_hash=manifest["plan_hash"],
        preserve_remote=list(_PRESERVE_REMOTE_NAMES),
        exclude=list(exclude_patterns),
        methods=detection,
        capabilities=caps,
        grant_jti=(grant_claims or {}).get("jti"),
        **extra,
    )


@conn.handler(
    "site/command/sync",
    isolated=True,
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
    )


@conn.handler(
    "site/command/publish",
    isolated=True,
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


@conn.handler(
    "site/command/release-verify",
    isolated=True,
    meta={"label": "Verify release hashes (origin/public fingerprint stub → PR8)"},
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
) -> dict[str, Any]:
    from .release_ops import (
        RELEASE_META_NAME,
        release_dir,
        validate_release_id,
        validate_release_root,
        verify_release_local,
    )

    host = host or sftp_host
    if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return urirun.fail("plesk_site_host_invalid")
    bad = validate_release_root(release_root) or validate_release_id(release_id)
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
        return urirun.fail(str(error))
    except (ValueError, UnicodeDecodeError):
        return urirun.fail(REMOTE_HASH_MISMATCH)
    return urirun.ok(host=host, domain=domain or None, release_root=release_root, **verified)


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
        "version": "0.7.0",
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
        "note": None if ready else "SFTP/paramiko missing — blocks production publish readiness",
    }


def urirun_bindings() -> dict[str, Any]:
    return conn.bindings()


def connector_manifest() -> dict[str, Any]:
    return conn.manifest(_urirun_compat.load_manifest(__package__))


def main(argv: list[str] | None = None) -> int:
    return conn.cli(argv, manifest_prose=_urirun_compat.load_manifest(__package__))


if __name__ == "__main__":
    raise SystemExit(main())
