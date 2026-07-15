from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import urirun

from urirun_connector_plesk import (
    api_command,
    api_query,
    auth_status,
    bootstrap_api_key,
    connector_manifest,
    urirun_bindings,
)
import urirun_connector_plesk.core as core


ROUTES = {
    "plesk://host/api/command/request",
    "plesk://host/api/query/request",
    "plesk://host/auth/command/bootstrap-api-key",
    "plesk://host/auth/query/status",
    "plesk://host/doctor/query/report",
}


def test_bootstrap_leases_admin_login_and_stores_key_without_returning_it(monkeypatch):
    leased = {"username": "admin", "password": "admin-password"}
    request = {}
    stored = {}

    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url: leased[field])

    def fake_request(url, **kwargs):
        request.update(url=url, **kwargs)
        return 201, {"key": "generated-plesk-key"}

    monkeypatch.setattr(core, "_request_json", fake_request)
    monkeypatch.setattr(
        core,
        "_vault_store",
        lambda entry, origin, api_key, vault_url: stored.update(entry=entry, key=api_key) or entry,
    )

    result = bootstrap_api_key(base_url="https://plesk.example.com:8443")

    assert result["ok"] and result["authorized"]
    assert request["url"].endswith("/api/v2/auth/keys")
    assert request["method"] == "POST"
    assert request["headers"]["authorization"] == "Basic " + base64.b64encode(b"admin:admin-password").decode()
    assert stored == {"entry": "plesk-runtime", "key": "generated-plesk-key"}
    serialized = json.dumps(result)
    assert "admin-password" not in serialized and "generated-plesk-key" not in serialized


def test_query_uses_api_key_and_redacts_sensitive_fields(monkeypatch):
    request = {}
    monkeypatch.setattr(core, "_vault_lease", lambda *args: "vault-api-key")

    def fake_request(url, **kwargs):
        request.update(url=url, **kwargs)
        return 200, {"name": "example.com", "password": "must-not-leak", "nested": {"apiKey": "nope"}}

    monkeypatch.setattr(core, "_request_json", fake_request)
    result = api_query(path="/api/v2/domains", base_url="https://plesk.example.com:8443")

    assert result["ok"] and request["headers"] == {"X-API-Key": "vault-api-key"}
    assert result["data"]["password"] == "[REDACTED]"
    assert result["data"]["nested"]["apiKey"] == "[REDACTED]"
    assert "vault-api-key" not in json.dumps(result)


@pytest.mark.parametrize("method", ["GET", "OPTIONS", "TRACE"])
def test_command_rejects_read_or_unsafe_methods(method):
    assert api_command(path="/api/v2/domains", method=method, base_url="https://plesk.example.com:8443")["ok"] is False


@pytest.mark.parametrize("path", ["/api/v2/../admin", "/api/v1/domains", "https://evil.test/api/v2/domains", "/api/v2/domains?key=x"])
def test_api_path_rejects_escape_or_query_injection(path):
    with pytest.raises(RuntimeError, match="plesk_api_path_not_allowed"):
        core._api_path(path)


def test_base_url_requires_https_except_loopback():
    assert core._base_url("http://127.0.0.1:9000") == "http://127.0.0.1:9000"
    with pytest.raises(RuntimeError, match="plesk_https_required"):
        core._base_url("http://plesk.example.com:8443")
    with pytest.raises(RuntimeError, match="plesk_base_url_invalid"):
        core._base_url("https://admin:password@plesk.example.com:8443")


def test_bindings_contract_and_manifest():
    document = urirun_bindings()
    assert set(document["bindings"]) == ROUTES
    registry = urirun.compile_registry(json.loads(json.dumps(document)))
    assert ROUTES <= {route["uri"] for route in urirun.list_routes(registry)}
    manifest = connector_manifest()
    assert manifest["id"] == "plesk" and set(manifest["routes"]) == ROUTES


def test_end_to_end_bootstrap_then_autonomous_query(monkeypatch):
    state = {
        "admin": {"username": "admin", "password": "human-supplied-password"},
        "runtime_key": "",
        "plesk_calls": [],
    }

    class VaultHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(size) or b"{}")
            assert self.headers["authorization"] == "Bearer vault-service-token"
            if self.path.startswith("/internal/vault/plesk-admin-bootstrap/lease"):
                secret = state["admin"][body["field"]]
                self._json(200, {"secret": secret})
            elif self.path.startswith("/internal/vault/plesk-runtime/lease"):
                self._json(200, {"secret": state["runtime_key"]})
            elif self.path == "/vault":
                state["runtime_key"] = body["secrets"]["api_key"]
                self._json(201, {"entry": {"id": body["id"]}})
            else:
                self._json(404, {"error": "not_found"})

        def _json(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    class PleskHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            state["plesk_calls"].append(("POST", self.path))
            expected = "Basic " + base64.b64encode(b"admin:human-supplied-password").decode()
            assert self.path == "/api/v2/auth/keys" and self.headers["authorization"] == expected
            self._json(201, {"key": "new-runtime-api-key"})

        def do_GET(self):
            state["plesk_calls"].append(("GET", self.path))
            assert self.headers["X-API-Key"] == "new-runtime-api-key"
            self._json(200, [{"id": 1, "name": "example.com"}])

        def _json(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    vault = ThreadingHTTPServer(("127.0.0.1", 0), VaultHandler)
    plesk = ThreadingHTTPServer(("127.0.0.1", 0), PleskHandler)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (vault, plesk)]
    for thread in threads:
        thread.start()
    monkeypatch.setenv("URIRUN_VAULT_TOKEN", "vault-service-token")
    vault_url = f"http://127.0.0.1:{vault.server_port}"
    plesk_url = f"http://127.0.0.1:{plesk.server_port}"
    try:
        bootstrap = bootstrap_api_key(base_url=plesk_url, vault_url=vault_url)
        status = auth_status(base_url=plesk_url, vault_url=vault_url)
        domains = api_query(path="/api/v2/domains", base_url=plesk_url, vault_url=vault_url)
    finally:
        vault.shutdown()
        plesk.shutdown()
        vault.server_close()
        plesk.server_close()

    assert bootstrap["ok"] and status["authorized"] and domains["ok"]
    assert domains["data"] == [{"id": 1, "name": "example.com"}]
    assert state["plesk_calls"] == [
        ("POST", "/api/v2/auth/keys"),
        ("GET", "/api/v2/domains"),
        ("GET", "/api/v2/domains"),
    ]
    assert "new-runtime-api-key" not in json.dumps([bootstrap, status, domains])
