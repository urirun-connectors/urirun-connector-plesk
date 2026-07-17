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
    create_mailbox,
    site_publish,
    urirun_bindings,
)
import urirun_connector_plesk.core as core


ROUTES = {
    "plesk://host/api/command/request",
    "plesk://host/api/query/request",
    "plesk://host/auth/command/bootstrap-api-key",
    "plesk://host/auth/query/status",
    "plesk://host/mailbox/command/create",
    "plesk://host/site/command/publish",
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


def test_mailbox_create_generates_password_and_stores_it_without_returning_it(monkeypatch):
    request = {}
    stored = {}

    def fake_authorized_request(**kwargs):
        request.update(kwargs)
        return 200, {"status": "created"}

    monkeypatch.setattr(core, "_authorized_request", fake_authorized_request)
    monkeypatch.setattr(
        core,
        "_vault_store_secrets",
        lambda entry, origin, label, values, vault_url: stored.update(
            entry=entry, origin=origin, label=label, values=values,
        ) or entry,
    )
    result = create_mailbox(
        email="agent@prototypowanie.pl",
        credential_vault_entry_id="agent-mailbox-runtime",
        credential_origin="imap://mail.prototypowanie.pl",
        base_url="https://plesk.example.com:8443",
    )
    assert result["ok"] and result["created"]
    assert request["path"] == "/api/v2/cli/mail/call"
    assert request["body"]["params"][:2] == ["--create", "agent@prototypowanie.pl"]
    generated = request["body"]["params"][3]
    assert len(generated) >= 24 and stored["values"] == {"username": "agent@prototypowanie.pl", "password": generated}
    assert stored["entry"] == "agent-mailbox-runtime" and stored["origin"] == "imap://mail.prototypowanie.pl"
    assert generated not in json.dumps(result)


def test_mailbox_create_rejects_invalid_email_or_credential_origin():
    assert create_mailbox(email="not-an-email", credential_origin="imap://mail.example.com")["ok"] is False
    assert create_mailbox(email="agent@example.com", credential_origin="https://mail.example.com")["ok"] is False


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


class _FakeSFTP:
    def __init__(self):
        self.puts = []
        self.made = []
        self._existing = set()

    def stat(self, path):
        if path not in self._existing:
            raise IOError("no such file")
        return object()

    def mkdir(self, path):
        self.made.append(path)
        self._existing.add(path)

    def put(self, local, remote):
        self.puts.append((local, remote))

    def close(self):
        pass


class _FakeTransport:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _seed_site(tmp_path):
    (tmp_path / "index.html").write_text("<h1>subactor</h1>", encoding="utf-8")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.css").write_text("body{}", encoding="utf-8")
    (tmp_path / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "pl").mkdir()
    (tmp_path / "pl" / "index.html").write_text("<h1>pl</h1>", encoding="utf-8")


def test_site_publish_uploads_tree_over_sftp_without_leaking_credentials(monkeypatch, tmp_path):
    _seed_site(tmp_path)
    fake_sftp = _FakeSFTP()
    fake_transport = _FakeTransport()
    leases = {"username": "subactor_customer", "password": "s3cr3t-sftp"}

    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url="": leases[field])
    monkeypatch.setattr(
        core, "_sftp_connect",
        lambda host, port, username, password, host_fingerprint="": (fake_transport, fake_sftp, "aa11bb22"),
    )

    result = site_publish(
        source_dir=str(tmp_path),
        remote_path="/httpdocs",
        sftp_host="prototypowanie.pl",
        credential_origin="sftp://prototypowanie.pl",
        sftp_vault_entry_id="plesk-sftp-subactor",
    )

    assert result["ok"] and result["files_uploaded"] == 4
    assert set(result["files"]) == {"index.html", "assets/app.css", "assets/app.js", "pl/index.html"}
    assert result["host_fingerprint"] == "aa11bb22" and result["remote_path"] == "/httpdocs"
    # subdirectories were created remotely
    assert "/httpdocs/assets" in fake_sftp.made and "/httpdocs/pl" in fake_sftp.made
    assert len(fake_sftp.puts) == 4
    # credentials never surface in the result
    assert "s3cr3t-sftp" not in json.dumps(result) and "subactor_customer" not in json.dumps(result)
    assert fake_transport.closed


def test_site_publish_validates_inputs(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "x")
    assert site_publish(source_dir="/no/such/dir", sftp_host="h").get("error") == "plesk_site_source_dir_invalid"
    assert site_publish(source_dir=str(tmp_path), remote_path="httpdocs", sftp_host="h").get("error") == "plesk_site_remote_path_invalid"
    assert site_publish(source_dir=str(tmp_path), remote_path="/a/../b", sftp_host="h").get("error") == "plesk_site_remote_path_invalid"
    assert site_publish(source_dir=str(tmp_path), sftp_host="bad host!").get("error") == "plesk_site_host_invalid"
    assert site_publish(source_dir=str(tmp_path), sftp_host="h", sftp_port=0).get("error") == "plesk_site_port_invalid"


def test_site_publish_requires_paramiko(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "paramiko", None)
    assert site_publish(source_dir=str(tmp_path), sftp_host="h").get("error") == "plesk_sftp_paramiko_missing"


def test_sftp_connect_rejects_host_key_mismatch(monkeypatch):
    class _K:
        def asbytes(self):
            return b"server-key-bytes"

    class _T:
        def __init__(self, addr):
            self.authed = False
        def start_client(self, timeout=0):
            pass
        def get_remote_server_key(self):
            return _K()
        def auth_password(self, u, p):
            self.authed = True
        def close(self):
            pass

    monkeypatch.setattr(core.paramiko, "Transport", _T)
    with pytest.raises(RuntimeError, match="plesk_sftp_host_key_mismatch"):
        core._sftp_connect("h", 22, "u", "p", host_fingerprint="deadbeef")
