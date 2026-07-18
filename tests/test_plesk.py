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
    ensure_ftp_user,
    ensure_ssl,
    ensure_subdomain,
    site_publish,
    site_sync,
    urirun_bindings,
)
import urirun_connector_plesk.core as core
from urirun_connector_plesk.apply_grant import CLOCK_SKEW_SECONDS, issue_apply_grant
from urirun_connector_plesk.apply_grant_replay import reset_default_jti_replay_store


ROUTES = {
    "plesk://host/api/command/request",
    "plesk://host/api/query/request",
    "plesk://host/auth/command/bootstrap-api-key",
    "plesk://host/auth/query/status",
    "plesk://host/mailbox/command/create",
    "plesk://host/ftpuser/command/ensure",
    "plesk://host/site/command/subdomain-ensure",
    "plesk://host/site/command/ssl-ensure",
    "plesk://host/site/command/publish",
    "plesk://host/site/command/sync",
    "plesk://host/site/command/release-upload",
    "plesk://host/site/command/release-verify",
    "plesk://host/site/command/publish-verify",
    "plesk://host/site/command/release-activate",
    "plesk://host/site/command/release-rollback",
    "plesk://host/site/query/release-current",
    "plesk://host/site/query/methods",
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


def test_ensure_ftp_user_recreates_and_stores_without_leaking_password(monkeypatch):
    calls = []
    stored = {}
    leases = {"username": "cust", "password": "cust-pass"}

    def fake_lease(entry, origin, field, vault_url=""):
        return leases[field]

    def fake_xml(base_url, username, password, packet):
        calls.append(packet)
        if "<webspace><set>" in packet.replace("\n", "").replace(" ", ""):
            return "<packet><webspace><set><result><status>ok</status></result></set></webspace></packet>"
        if "<webspace><get>" in packet.replace("\n", "").replace(" ", ""):
            return (
                "<packet><webspace><get><result><status>ok</status>"
                "<name>ftp_login</name><value>subactor_ssh</value>"
                "<name>ftp_password</name><value>ignore</value>"
                "</result></get></webspace></packet>"
            )
        return "<packet><result><status>error</status></result></packet>"

    def fake_store(entry, origin, label, values, vault_url):
        stored[entry] = {"origin": origin, "label": label, "values": dict(values)}
        return entry

    monkeypatch.setattr(core, "_vault_lease", fake_lease)
    monkeypatch.setattr(core, "_xml_agent", fake_xml)
    monkeypatch.setattr(core, "_vault_store_secrets", fake_store)
    result = ensure_ftp_user(
        kind="system",
        domain="subactor.com",
        base_url="https://prototypowanie.pl:8443",
        credential_vault_entry_id="plesk-sftp",
        also_ftp_vault_entry_id="plesk-ftp",
    )
    assert result["ok"] and result["kind"] == "system" and result["name"] == "subactor_ssh"
    assert stored["plesk-sftp"]["origin"] == "https://prototypowanie.pl"
    assert stored["plesk-ftp"]["values"]["username"] == "subactor_ssh"
    assert len(stored["plesk-sftp"]["values"]["password"]) >= 16
    assert stored["plesk-sftp"]["values"]["password"] not in json.dumps(result)
    assert "cust-pass" not in json.dumps(result)


def test_ensure_subdomain_idempotent_when_exists(monkeypatch):
    calls = []

    def fake_lease(entry, origin, field, vault_url=""):
        return {"username": "cust", "password": "cust-pass"}[field]

    def fake_xml(base_url, username, password, packet):
        calls.append(packet)
        if "<subdomain><get>" in packet.replace("\n", "").replace(" ", ""):
            return (
                "<packet><subdomain><get><result><status>ok</status>"
                "<id>308</id><data><name>docs</name></data>"
                "</result></get></subdomain></packet>"
            )
        return "<packet><result><status>error</status></result></packet>"

    monkeypatch.setattr(core, "_vault_lease", fake_lease)
    monkeypatch.setattr(core, "_xml_agent", fake_xml)
    result = ensure_subdomain(
        parent_domain="subactor.com",
        subdomain="docs",
        base_url="https://prototypowanie.pl:8443",
    )
    assert result["ok"] and result["existed"] is True and result["created"] is False
    assert result["subdomain"] == "docs.subactor.com" and result["subdomain_id"] == 308
    assert len(calls) == 1


def test_ensure_subdomain_adds_when_missing(monkeypatch):
    calls = []

    def fake_lease(entry, origin, field, vault_url=""):
        return {"username": "cust", "password": "cust-pass"}[field]

    def fake_xml(base_url, username, password, packet):
        calls.append(packet)
        compact = packet.replace("\n", "").replace(" ", "")
        if "<subdomain><get>" in compact:
            return "<packet><subdomain><get><result><status>error</status></result></get></subdomain></packet>"
        if "<subdomain><add>" in compact:
            return (
                "<packet><subdomain><add><result><status>ok</status>"
                "<id>310</id></result></add></subdomain></packet>"
            )
        return "<packet><result><status>error</status></result></packet>"

    monkeypatch.setattr(core, "_vault_lease", fake_lease)
    monkeypatch.setattr(core, "_xml_agent", fake_xml)
    result = ensure_subdomain(
        parent_domain="subactor.com",
        subdomain="docs-stage",
        base_url="https://prototypowanie.pl:8443",
    )
    assert result["ok"] and result["created"] is True and result["subdomain_id"] == 310
    assert result["www_root"] == "docs-stage.subactor.com"
    assert any("<parent>subactor.com</parent>" in c for c in calls)


def test_ensure_ssl_probe_only_without_apply(monkeypatch):
    monkeypatch.delenv("AUTONOMY_MUTATIONS_ENABLED", raising=False)
    monkeypatch.delenv("PLESK_SSL_APPLY", raising=False)

    def fake_probe(**kwargs):
        return {
            "ok": False,
            "hostname": "docs.subactor.com",
            "connect_host": "217.160.250.222",
            "sans": ["subactor.com"],
            "error": "tls_san_mismatch",
        }

    monkeypatch.setattr("urirun_connector_plesk.ssl_ops.origin_tls_probe", fake_probe)
    result = ensure_ssl(
        hostname="docs.subactor.com",
        origin_ip="217.160.250.222",
        base_url="https://prototypowanie.pl:8443",
        apply=False,
    )
    assert result["ok"] is True and result["dry_run"] is True
    assert "PLESK_SSL_APPLY" in (result.get("note") or "")
    assert result["probe"]["error"] == "tls_san_mismatch"


def test_ensure_ssl_apply_denied_without_env(monkeypatch):
    monkeypatch.delenv("AUTONOMY_MUTATIONS_ENABLED", raising=False)
    monkeypatch.delenv("PLESK_SSL_APPLY", raising=False)
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.origin_tls_probe",
        lambda **kwargs: {"ok": False, "sans": [], "error": "tls_san_mismatch"},
    )
    result = ensure_ssl(
        hostname="docs.subactor.com",
        origin_ip="1.2.3.4",
        base_url="https://plesk.example.com:8443",
        apply=True,
    )
    assert result["ok"] is False
    assert result["error"] == "apply_denied_autonomy_mutations"


def test_ensure_ssl_assign_when_san_ok(monkeypatch):
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_SSL_APPLY", "1")
    monkeypatch.setattr(
        core,
        "_vault_lease",
        lambda entry, origin, field, vault_url="": {"username": "cust", "password": "cust-pass"}[field],
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.origin_tls_probe",
        lambda **kwargs: {
            "ok": True,
            "hostname": "docs.subactor.com",
            "sans": ["docs.subactor.com"],
            "error": None,
        },
    )
    result = ensure_ssl(
        hostname="docs.subactor.com",
        origin_ip="217.160.250.222",
        base_url="https://prototypowanie.pl:8443",
        apply=True,
        provider="auto",
    )
    assert result["ok"] is True and result["strategy"] == "probe"
    assert result["probe"]["sans"] == ["docs.subactor.com"]


def test_ensure_ssl_assign_strategy(monkeypatch):
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_SSL_APPLY", "1")
    monkeypatch.setattr(
        core,
        "_vault_lease",
        lambda entry, origin, field, vault_url="": {"username": "cust", "password": "cust-pass"}[field],
    )
    probes = iter(
        [
            {"ok": False, "sans": [], "error": "tls_san_mismatch"},
            {"ok": True, "sans": ["docs.subactor.com"], "error": None},
        ]
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.origin_tls_probe",
        lambda **kwargs: next(probes),
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.resolve_site_id",
        lambda **kwargs: 308,
    )

    def fake_assign(**kwargs):
        assert kwargs["certificate_name"] == "docs.subactor.com-san"
        return {"ok": True, "strategy": "assign", "certificate_name": kwargs["certificate_name"]}

    monkeypatch.setattr("urirun_connector_plesk.ssl_ops.assign_certificate", fake_assign)
    result = ensure_ssl(
        hostname="docs.subactor.com",
        origin_ip="217.160.250.222",
        certificate_name="docs.subactor.com-san",
        base_url="https://prototypowanie.pl:8443",
        apply=True,
        provider="assign",
    )
    assert result["ok"] is True and result["strategy"] == "assign"
    assert result["certificate_name"] == "docs.subactor.com-san"


def test_sslit_domain_only_fields_omit_wildcard_mail():
    from urirun_connector_plesk import ssl_ops

    fields = ssl_ops.sslit_domain_only_fields(site_id=308, token="tok")
    assert fields["validateDomain"] == "1"
    assert fields["vendorId"] == "letsencrypt.letsencrypt"
    lowered = {k.lower() for k in fields}
    assert "wildcard" not in lowered
    assert not any("mail" in k for k in lowered)
    assert not any("www" in k for k in lowered)
    assert ssl_ops.classify_sslit_le_error(
        "Could not issue a certificate: mail.example is redundant with a wildcard"
    ) == "plesk_ssl_le_san_conflict"


def test_panel_sslit_letsencrypt_posts_domain_only(monkeypatch):
    from urirun_connector_plesk import ssl_ops

    posted: dict = {}

    class FakeResp:
        def __init__(self, body: bytes):
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class FakeOpener:
        def open(self, req, timeout=0):
            url = getattr(req, "full_url", None) or str(req)
            data = getattr(req, "data", None)
            if data is None:
                html = (
                    '<meta name="forgery_protection_token" content="csrf-tok">'
                ).encode()
                return FakeResp(html)
            body = data.decode("utf-8", errors="replace")
            posted["body"] = body
            posted["url"] = url
            return FakeResp(b'{"status":"success","actionMessages":[]}')

    result = ssl_ops.panel_sslit_letsencrypt(
        opener=FakeOpener(),
        base_url="https://plesk.example.com:8443",
        site_id=308,
        hostname="docs.subactor.com",
    )
    assert result["ok"] is True
    assert result["san_mode"] == "domain_only"
    assert "validateDomain" in posted["body"]
    assert "wildcard" not in posted["body"].lower()
    assert "secureMail" not in posted["body"]
    assert "secureWww" not in posted["body"]


def test_doctor_reports_ssl_capabilities(monkeypatch):
    from urirun_connector_plesk import doctor

    report = doctor()
    assert report["capabilities"]["ssl_ensure"]["available"] is True
    assert "panel_upload_pem" in report["capabilities"]["ssl_ensure"]["strategies"]
    assert report["capabilities"]["letsencrypt"]["available"] is False
    assert report["capabilities"]["certificate_assign"] is True
    assert report["version"] == "0.9.0"


def test_transport_origin_defaults_to_https():
    assert core._transport_origin("ftp", "prototypowanie.pl") == "https://prototypowanie.pl"
    assert core._transport_origin("sftp", "h", "https://custom") == "https://custom"


def test_plan_skips_git_and_deployment_junk(tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    (www / "index.html").write_text("ok", encoding="utf-8")
    (www / "Dockerfile").write_text("FROM scratch", encoding="utf-8")
    (www / ".git").mkdir()
    (www / ".git" / "config").write_text("x", encoding="utf-8")
    (www / "deployment").mkdir()
    (www / "deployment" / "PLESK.md").write_text("x", encoding="utf-8")
    plan = core._plan_local_tree(str(www), "/httpdocs")
    paths = {item["path"] for item in plan}
    assert paths == {"index.html"}


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


def _enable_apply(monkeypatch, secret="test-apply-grant-hmac"):
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_SYNC_APPLY", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", secret)
    monkeypatch.delenv("APPLY_GRANT_HMAC_SECRET_NEXT", raising=False)
    monkeypatch.delenv("APPLY_GRANT_JTI_STORE", raising=False)
    reset_default_jti_replay_store()


def _grant_for(dry, host="prototypowanie.pl", **extra):
    issued = issue_apply_grant(
        run_id=extra.get("run_id", "run_test"),
        actor=extra.get("actor", "test-actor"),
        intent_pack=extra.get("intent_pack", "docs@1"),
        plan_hash=dry["plan_hash"],
        artifact_sha256=dry["manifest"]["source_sha256"],
        target=host,
        risk_class="reversible",
        ttl_seconds=extra.get("ttl_seconds", 900),
        jti=extra.get("jti", ""),
        environ={"APPLY_GRANT_HMAC_SECRET": extra.get("secret", "test-apply-grant-hmac")},
        now=extra.get("now"),
    )
    assert issued["ok"], issued
    return issued["grant"]


def test_site_sync_dry_run_plans_without_upload(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    fake_sftp = _FakeSFTP()
    monkeypatch.setattr(
        core, "_sftp_connect",
        lambda *a, **k: (_FakeTransport(), fake_sftp, "aa11bb22"),
    )
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "x")

    result = site_sync(source_dir=str(www), remote_path="/httpdocs", host="prototypowanie.pl")

    assert result["ok"] and result["dry_run"] is True and result["files_planned"] == 4
    assert {item["path"] for item in result["plan"]} == {
        "index.html", "assets/app.css", "assets/app.js", "pl/index.html",
    }
    assert result["plan_hash"] and result["manifest"]["plan_hash"] == result["plan_hash"]
    assert result["manifest"]["files"]
    assert fake_sftp.puts == []


def test_immutable_manifest_stable_and_byte_sensitive(tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    plan = core._plan_local_tree(str(www), "/httpdocs")
    from urirun_connector_plesk.immutable_manifest import build_immutable_manifest, canonical_json

    a = build_immutable_manifest(plan=plan, host="h", domain="d", remote_path="/httpdocs")
    b = build_immutable_manifest(plan=plan, host="h", domain="d", remote_path="/httpdocs")
    assert a["plan_hash"] == b["plan_hash"]
    assert len(a["plan_hash"]) == 64
    # secrets must never appear in manifest keys/values
    blob = canonical_json(a)
    assert "password" not in blob.lower()
    assert "token" not in blob.lower()
    assert "secret" not in blob.lower()

    (www / "index.html").write_text("<h1>changed</h1>", encoding="utf-8")
    plan2 = core._plan_local_tree(str(www), "/httpdocs")
    c = build_immutable_manifest(plan=plan2, host="h", domain="d", remote_path="/httpdocs")
    assert c["plan_hash"] != a["plan_hash"]


def test_site_sync_apply_denies_plan_hash_mismatch_with_zero_upload(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    fake_sftp = _FakeSFTP()
    _enable_apply(monkeypatch)
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no lease")))
    monkeypatch.setattr(
        core, "_sftp_connect",
        lambda *a, **k: (_FakeTransport(), fake_sftp, "aa11bb22"),
    )
    dry = site_sync(source_dir=str(www), host="prototypowanie.pl", remote_path="/httpdocs")
    grant = _grant_for(dry)
    (www / "index.html").write_text("<h1>tampered</h1>", encoding="utf-8")
    result = site_sync(
        source_dir=str(www),
        host="prototypowanie.pl",
        remote_path="/httpdocs",
        apply=True,
        transport="sftp",
        plan_hash=dry["plan_hash"],
        apply_grant=grant,
        actor="test-actor",
        pack_id="docs",
        pack_version="1",
    )
    assert result.get("error") == "plan_hash_mismatch"
    assert result.get("files_uploaded", 0) == 0
    assert fake_sftp.puts == []


def test_site_sync_apply_requires_env(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    monkeypatch.delenv("PLESK_SYNC_APPLY", raising=False)
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "test-apply-grant-hmac")
    result = site_sync(
        source_dir=str(www), host="prototypowanie.pl", apply=True, transport="sftp",
        plan_hash="deadbeef",
    )
    assert result.get("error") == "plesk_sync_apply_required"
    assert result.get("dry_run") is True
    assert result.get("plan_hash")


def test_site_sync_apply_requires_master_kill_switch(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    monkeypatch.setenv("PLESK_SYNC_APPLY", "1")
    monkeypatch.delenv("AUTONOMY_MUTATIONS_ENABLED", raising=False)
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "test-apply-grant-hmac")
    dry = site_sync(source_dir=str(www), host="prototypowanie.pl")
    result = site_sync(
        source_dir=str(www), host="prototypowanie.pl", apply=True, transport="sftp",
        plan_hash=dry["plan_hash"], apply_grant=_grant_for(dry),
    )
    assert result.get("error") == "autonomy_mutations_disabled"


def test_site_sync_apply_requires_grant(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch)
    dry = site_sync(source_dir=str(www), host="prototypowanie.pl")
    result = site_sync(
        source_dir=str(www), host="prototypowanie.pl", apply=True, transport="sftp",
        plan_hash=dry["plan_hash"],
    )
    assert result.get("error") == "apply_grant_required"


def test_site_sync_apply_denies_wrong_target_grant(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch)
    dry = site_sync(source_dir=str(www), host="prototypowanie.pl")
    grant = _grant_for(dry, host="evil.example")
    result = site_sync(
        source_dir=str(www), host="prototypowanie.pl", apply=True, transport="sftp",
        plan_hash=dry["plan_hash"], apply_grant=grant, actor="test-actor",
        pack_id="docs", pack_version="1",
    )
    assert result.get("error") == "apply_grant_target_mismatch"


def test_site_sync_apply_denies_expired_grant(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch)
    dry = site_sync(source_dir=str(www), host="prototypowanie.pl")
    past = __import__("time").time() - (CLOCK_SKEW_SECONDS + 120)
    grant = _grant_for(dry, ttl_seconds=1, now=past)
    result = site_sync(
        source_dir=str(www), host="prototypowanie.pl", apply=True, transport="sftp",
        plan_hash=dry["plan_hash"], apply_grant=grant, actor="test-actor",
        pack_id="docs", pack_version="1",
    )
    assert result.get("error") == "apply_grant_expired"


def test_site_sync_apply_denies_bad_signer(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch, secret="verifier-secret")
    dry = site_sync(source_dir=str(www), host="prototypowanie.pl")
    grant = _grant_for(dry, secret="other-issuer-secret")
    result = site_sync(
        source_dir=str(www), host="prototypowanie.pl", apply=True, transport="sftp",
        plan_hash=dry["plan_hash"], apply_grant=grant, actor="test-actor",
        pack_id="docs", pack_version="1",
    )
    assert result.get("error") == "apply_grant_signature_invalid"
    blob = json.dumps(result)
    assert "verifier-secret" not in blob and "other-issuer-secret" not in blob


def test_site_publish_uploads_tree_over_sftp_without_leaking_credentials(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    fake_sftp = _FakeSFTP()
    fake_transport = _FakeTransport()
    leases = {"username": "subactor_customer", "password": "s3cr3t-sftp"}

    _enable_apply(monkeypatch)
    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url="": leases[field])
    monkeypatch.setattr(
        core, "_sftp_connect",
        lambda host, port, username, password, host_fingerprint="": (fake_transport, fake_sftp, "aa11bb22"),
    )

    dry = site_sync(
        source_dir=str(www),
        remote_path="/httpdocs",
        sftp_host="prototypowanie.pl",
    )
    grant = _grant_for(dry)
    result = site_publish(
        source_dir=str(www),
        remote_path="/httpdocs",
        sftp_host="prototypowanie.pl",
        credential_origin="sftp://prototypowanie.pl",
        sftp_vault_entry_id="plesk-sftp-subactor",
        transport="sftp",
        apply=True,
        plan_hash=dry["plan_hash"],
        apply_grant=grant,
        actor="test-actor",
        pack_id="docs",
        pack_version="1",
    )

    assert result["ok"] and result["dry_run"] is False and result["files_uploaded"] == 4
    assert result["plan_hash"] == dry["plan_hash"]
    assert set(result["files"]) == {"index.html", "assets/app.css", "assets/app.js", "pl/index.html"}
    assert result["host_fingerprint"] == "aa11bb22" and result["remote_path"] == "/httpdocs"
    assert "/httpdocs/assets" in fake_sftp.made and "/httpdocs/pl" in fake_sftp.made
    assert len(fake_sftp.puts) == 4
    assert "s3cr3t-sftp" not in json.dumps(result) and "subactor_customer" not in json.dumps(result)
    assert "test-apply-grant-hmac" not in json.dumps(result)
    assert fake_transport.closed


def test_site_publish_apply_grant_jti_replay_denied(monkeypatch, tmp_path):
    """PR5c: first apply OK; same jti → apply_grant_replay with zero second upload; new jti OK."""
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    fake_sftp = _FakeSFTP()
    leases = {"username": "u", "password": "p"}
    _enable_apply(monkeypatch)
    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url="": leases[field])
    monkeypatch.setattr(
        core, "_sftp_connect",
        lambda *a, **k: (_FakeTransport(), fake_sftp, "aa11bb22"),
    )
    dry = site_sync(source_dir=str(www), sftp_host="prototypowanie.pl")
    grant_a = _grant_for(dry, jti="replay-jti-fixed")

    first = site_publish(
        source_dir=str(www),
        sftp_host="prototypowanie.pl",
        transport="sftp",
        apply=True,
        plan_hash=dry["plan_hash"],
        apply_grant=grant_a,
        actor="test-actor",
        pack_id="docs",
        pack_version="1",
    )
    assert first["ok"] and first["dry_run"] is False
    assert first["files_uploaded"] == 4
    puts_after_first = len(fake_sftp.puts)

    second = site_publish(
        source_dir=str(www),
        sftp_host="prototypowanie.pl",
        transport="sftp",
        apply=True,
        plan_hash=dry["plan_hash"],
        apply_grant=grant_a,
        actor="test-actor",
        pack_id="docs",
        pack_version="1",
    )
    assert second.get("error") == "apply_grant_replay"
    assert second.get("files_uploaded", 0) == 0
    assert len(fake_sftp.puts) == puts_after_first

    grant_b = _grant_for(dry, jti="replay-jti-other")
    third = site_publish(
        source_dir=str(www),
        sftp_host="prototypowanie.pl",
        transport="sftp",
        apply=True,
        plan_hash=dry["plan_hash"],
        apply_grant=grant_b,
        actor="test-actor",
        pack_id="docs",
        pack_version="1",
    )
    assert third["ok"] and third["dry_run"] is False
    assert len(fake_sftp.puts) == puts_after_first + 4


def test_site_publish_apply_without_plan_hash_denied(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    fake_sftp = _FakeSFTP()
    _enable_apply(monkeypatch)
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no lease")))
    monkeypatch.setattr(
        core, "_sftp_connect",
        lambda *a, **k: (_FakeTransport(), fake_sftp, "aa"),
    )
    dry = site_sync(source_dir=str(www), sftp_host="prototypowanie.pl")
    grant = _grant_for(dry)
    result = site_publish(
        source_dir=str(www), sftp_host="prototypowanie.pl", transport="sftp", apply=True,
        apply_grant=grant, actor="test-actor", pack_id="docs", pack_version="1",
    )
    assert result.get("error") == "plan_hash_mismatch"
    assert fake_sftp.puts == []


def test_site_publish_validates_inputs(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    monkeypatch.setenv("PLESK_SYNC_ALLOWED_SOURCES", str(tmp_path))
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "x")
    assert site_publish(source_dir="/no/such/dir", sftp_host="h").get("error") == "plesk_site_source_dir_invalid"
    assert site_publish(source_dir=str(www), remote_path="httpdocs", sftp_host="h").get("error") == "plesk_site_remote_path_invalid"
    assert site_publish(source_dir=str(www), remote_path="/a/../b", sftp_host="h").get("error") == "plesk_site_remote_path_invalid"
    assert site_publish(source_dir=str(www), sftp_host="bad host!").get("error") == "plesk_site_host_invalid"
    assert site_publish(source_dir=str(www), sftp_host="h", sftp_port=0).get("error") == "plesk_site_port_invalid"


def test_site_publish_requires_paramiko(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch)
    monkeypatch.setattr(core, "paramiko", None)
    dry = site_sync(source_dir=str(www), sftp_host="h")
    grant = _grant_for(dry, host="h")
    assert site_publish(
        source_dir=str(www), sftp_host="h", transport="sftp", apply=True, plan_hash=dry["plan_hash"],
        apply_grant=grant, actor="test-actor", pack_id="docs", pack_version="1",
    ).get("error") == "capability_unavailable"


def test_doctor_reports_sftp_capability_and_timeouts(monkeypatch):
    from urirun_connector_plesk import doctor

    monkeypatch.delenv("PLESK_SYNC_ALLOW_FTP_FALLBACK", raising=False)
    monkeypatch.setenv("PLESK_TRANSPORT_CONNECT_TIMEOUT", "15")
    monkeypatch.setenv("PLESK_TRANSPORT_OPERATION_TIMEOUT", "120")
    monkeypatch.setenv("PLESK_TRANSPORT_TOTAL_BUDGET", "180")
    report = doctor()
    assert report["ok"] is True
    assert report["capabilities"]["sftp"]["available"] is True
    assert report["capabilities"]["ftp"]["available"] is True
    assert report["capabilities"]["release_activation"] is True
    assert report["capabilities"]["rollback"] is True
    assert report["production_publish_ready"] is True
    assert report["timeouts"] == {"connect": 15.0, "operation": 120.0, "total": 180.0}

    monkeypatch.setattr(core, "paramiko", None)
    degraded = doctor()
    assert degraded["production_publish_ready"] is False
    assert degraded["capabilities"]["sftp"]["available"] is False
    assert degraded["capabilities"]["sftp"]["detail"] == "paramiko_missing"
    assert degraded["capabilities"]["release_activation"] is False
    assert degraded["capabilities"]["rollback"] is False
    assert degraded["status"] == "degraded"


def test_ftp_apply_denied_without_fallback_policy(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch)
    monkeypatch.delenv("PLESK_SYNC_ALLOW_FTP_FALLBACK", raising=False)
    dry = site_sync(source_dir=str(www), sftp_host="prototypowanie.pl")
    grant = _grant_for(dry)
    result = site_publish(
        source_dir=str(www), sftp_host="prototypowanie.pl", transport="ftp", apply=True,
        plan_hash=dry["plan_hash"], apply_grant=grant, actor="test-actor", pack_id="docs", pack_version="1",
    )
    assert result.get("error") == "capability_unavailable"
    assert result.get("files_uploaded", 0) == 0 or "files_uploaded" not in result


def test_auto_falls_back_to_ftp_when_policy_allows(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch)
    monkeypatch.setenv("PLESK_SYNC_ALLOW_FTP_FALLBACK", "1")

    class _Ftp:
        def __init__(self):
            self.puts = []
        def mkd(self, path):
            pass
        def storbinary(self, cmd, handle):
            self.puts.append(cmd)
        def quit(self):
            pass
        def prot_p(self):
            pass

    fake = _Ftp()
    monkeypatch.setattr(core, "_detect_transports", lambda *a, **k: [
        {"transport": "sftp", "available": False, "detail": "paramiko_missing"},
        {"transport": "ftp", "available": True, "detail": "ok"},
    ])
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "x")
    monkeypatch.setattr(core, "_ftp_connect", lambda *a, **k: fake)
    monkeypatch.setattr(core, "_ftp_upload_dir", lambda *a, **k: ["index.html"])

    dry = site_sync(source_dir=str(www), sftp_host="prototypowanie.pl")
    grant = _grant_for(dry)
    result = site_publish(
        source_dir=str(www), sftp_host="prototypowanie.pl", transport="auto", apply=True,
        plan_hash=dry["plan_hash"], apply_grant=grant, actor="test-actor", pack_id="docs", pack_version="1",
    )
    assert result["ok"] and result["transport"] == "ftp"


def test_auto_denies_ftp_only_without_fallback(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch)
    monkeypatch.delenv("PLESK_SYNC_ALLOW_FTP_FALLBACK", raising=False)
    monkeypatch.setattr(core, "_detect_transports", lambda *a, **k: [
        {"transport": "sftp", "available": False, "detail": "authentication_failed"},
        {"transport": "ftp", "available": True, "detail": "ok"},
    ])
    dry = site_sync(source_dir=str(www), sftp_host="prototypowanie.pl")
    grant = _grant_for(dry)
    result = site_publish(
        source_dir=str(www), sftp_host="prototypowanie.pl", transport="auto", apply=True,
        plan_hash=dry["plan_hash"], apply_grant=grant, actor="test-actor", pack_id="docs", pack_version="1",
    )
    assert result.get("error") == "capability_unavailable"
    assert result.get("production_publish_ready") is False


def test_map_exception_structured_codes():
    from urirun_connector_plesk.errors import map_exception

    assert map_exception(TimeoutError(), phase="connect") == "transport_connect_timeout"
    assert map_exception(TimeoutError(), phase="transfer") == "transfer_timeout"
    assert map_exception(RuntimeError("plesk_sftp_paramiko_missing")) == "capability_unavailable"

    class AuthenticationException(Exception):
        pass

    assert map_exception(AuthenticationException("bad")) == "authentication_failed"


def test_vault_lease_maps_expired_and_rate_limited(monkeypatch):
    monkeypatch.setattr(core, "_vault_settings", lambda vault_url="": ("http://vault", "tok"))

    def expired(url, **kwargs):
        return 401, {}

    monkeypatch.setattr(core, "_request_json", expired)
    with pytest.raises(RuntimeError, match="credential_expired"):
        core._vault_lease("plesk-sftp", "https://h", "password")

    def limited(url, **kwargs):
        return 429, {}

    monkeypatch.setattr(core, "_request_json", limited)
    with pytest.raises(RuntimeError, match="rate_limited"):
        core._vault_lease("plesk-sftp", "https://h", "password")


def test_sftp_partial_upload_structured_error(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch)

    class _BoomSFTP:
        def __init__(self):
            self.puts = []
            self.made = []
        def stat(self, path):
            raise IOError("missing")
        def mkdir(self, path):
            self.made.append(path)
        def put(self, local, remote):
            if len(self.puts) >= 1:
                raise PermissionError("permission denied")
            self.puts.append(remote)
        def close(self):
            pass

    fake = _BoomSFTP()
    monkeypatch.setattr(
        core, "_sftp_connect",
        lambda *a, **k: (type("T", (), {"close": lambda self: None})(), fake, "fp"),
    )
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "x")
    dry = site_sync(source_dir=str(www), sftp_host="prototypowanie.pl")
    grant = _grant_for(dry)
    result = site_publish(
        source_dir=str(www), sftp_host="prototypowanie.pl", transport="sftp", apply=True,
        plan_hash=dry["plan_hash"], apply_grant=grant, actor="test-actor", pack_id="docs", pack_version="1",
    )
    assert result.get("error") == "partial_upload"


def test_remote_hash_mismatch(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    (www / "index.html").write_text("hello", encoding="utf-8")
    _enable_apply(monkeypatch)
    monkeypatch.setenv("PLESK_SYNC_VERIFY_REMOTE_HASH", "1")

    class _FakeFile:
        def __init__(self, data: bytes):
            self._data = data
            self._pos = 0
        def read(self, n=-1):
            if self._pos >= len(self._data):
                return b""
            chunk = self._data[self._pos:] if n < 0 else self._data[self._pos:self._pos + n]
            self._pos += len(chunk)
            return chunk
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    class _HashSFTP:
        def stat(self, path):
            raise IOError("missing")
        def mkdir(self, path):
            pass
        def put(self, local, remote):
            pass
        def open(self, path, mode="rb"):
            return _FakeFile(b"WRONG")
        def close(self):
            pass

    monkeypatch.setattr(
        core, "_sftp_connect",
        lambda *a, **k: (type("T", (), {"close": lambda self: None})(), _HashSFTP(), "fp"),
    )
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "x")
    dry = site_sync(source_dir=str(www), sftp_host="prototypowanie.pl")
    grant = _grant_for(dry)
    result = site_publish(
        source_dir=str(www), sftp_host="prototypowanie.pl", transport="sftp", apply=True,
        plan_hash=dry["plan_hash"], apply_grant=grant, actor="test-actor", pack_id="docs", pack_version="1",
    )
    assert result.get("error") == "remote_hash_mismatch"


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


def test_site_sync_rejects_non_www_source(tmp_path):
    other = tmp_path / "not-www"
    other.mkdir()
    (other / "index.html").write_text("x", encoding="utf-8")
    result = site_sync(source_dir=str(other), host="prototypowanie.pl")
    assert result.get("error") == "plesk_site_source_not_allowlisted"


def test_site_sync_allows_docs_basename(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "index.html").write_text("<h1>docs</h1>", encoding="utf-8")
    result = site_sync(source_dir=str(docs), host="prototypowanie.pl", domain="docs.subactor.com")
    assert result["ok"] and result["dry_run"] is True
    assert result["files_planned"] == 1
    assert result.get("domain") == "docs.subactor.com"


def test_site_sync_allows_logo_basename(tmp_path):
    logo = tmp_path / "logo"
    logo.mkdir()
    (logo / "index.html").write_text("<h1>logo</h1>", encoding="utf-8")
    result = site_sync(source_dir=str(logo), host="prototypowanie.pl", domain="logo.subactor.com")
    assert result["ok"] and result["dry_run"] is True
    assert result["files_planned"] == 1
    assert result.get("domain") == "logo.subactor.com"
