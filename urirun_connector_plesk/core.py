"""Plesk REST API v2 connector with vault-backed authorization."""
from __future__ import annotations

import base64
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import urirun

from . import _urirun_compat

CONNECTOR_ID = "plesk"
conn = _urirun_compat.connector(CONNECTOR_ID, scheme="plesk")
_SAFE_API_PATH = re.compile(r"^/api/v2/[A-Za-z0-9_./-]+$")
_SENSITIVE = re.compile(r"password|secret|token|api.?key|authorization", re.I)


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
    url, token = _vault_settings(vault_url)
    status, data = _request_json(
        f"{url}/internal/vault/{urllib.parse.quote(entry_id, safe='')}/lease",
        method="POST",
        headers={"authorization": f"Bearer {token}"},
        body={"origin": origin, "field": field},
    )
    secret = str(data.get("secret") or "")
    if status != 200 or not secret:
        raise RuntimeError(f"plesk_vault_lease_failed:{field}")
    return secret


def _vault_store(entry_id: str, origin: str, api_key: str, vault_url: str = "") -> str:
    url, token = _vault_settings(vault_url)
    status, data = _request_json(
        f"{url}/vault",
        method="POST",
        headers={"authorization": f"Bearer {token}"},
        body={"id": entry_id, "origin": origin, "label": "Plesk REST API key", "secrets": {"api_key": api_key}},
    )
    if status not in {200, 201}:
        raise RuntimeError("plesk_vault_store_failed")
    return str(data.get("entry", {}).get("id") or entry_id)


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


@conn.handler("plesk://host/doctor/query/report", isolated=True, meta={"label": "Plesk connector readiness report"})
def doctor() -> dict[str, Any]:
    return {"ok": True, "connector": CONNECTOR_ID, "version": "0.1.0", "status": "ready"}


def urirun_bindings() -> dict[str, Any]:
    return conn.bindings()


def connector_manifest() -> dict[str, Any]:
    return conn.manifest(_urirun_compat.load_manifest(__package__))


def main(argv: list[str] | None = None) -> int:
    return conn.cli(argv, manifest_prose=_urirun_compat.load_manifest(__package__))


if __name__ == "__main__":
    raise SystemExit(main())
