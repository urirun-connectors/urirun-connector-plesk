from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import urirun

from urirun_connector_plesk import (
    api_command,
    api_query,
    auth_acquisition_methods,
    auth_scopes,
    auth_status,
    bootstrap_api_key,
    connector_manifest,
    create_mailbox,
    ensure_mailbox,
    ensure_reverse_proxy,
    mailbox_status,
    dns_authority,
    dns_propagation,
    dns_reconcile,
    dns_records,
    dns_replace,
    ensure_ftp_user,
    ensure_ssl,
    ensure_subdomain,
    ensure_domain,
    extension_capabilities,
    extension_catalog,
    extension_command,
    extension_query,
    subscription_capabilities,
    subscription_query_snapshot,
    site_publish,
    site_query_docroot,
    site_remote_inventory,
    site_sync,
    site_twin_current,
    site_twin_sync,
    urirun_bindings,
)
import urirun_connector_plesk.core as core
from urirun_connector_plesk.apply_grant import CLOCK_SKEW_SECONDS, issue_apply_grant
from urirun_connector_plesk.apply_grant_replay import reset_default_jti_replay_store
from urirun_connector_plesk.connector_result import CONNECTOR_RESULT_SCHEMA
from urirun_connector_plesk.dns_providers import tls_dns_preflight
from urirun_connector_plesk.reverse_proxy import (
    BEGIN_MARKER,
    END_MARKER,
    managed_directives,
    merge_managed_directives,
    normalize_upstream,
)


ROUTES = {
    "plesk://host/api/command/request",
    "plesk://host/api/query/request",
    "plesk://host/auth/command/bootstrap-api-key",
    "plesk://host/auth/query/acquisition-methods",
    "plesk://host/auth/query/scopes",
    "plesk://host/auth/query/status",
    "plesk://host/account/query/subscriptions",
    "plesk://host/extensions/query/catalog",
    "plesk://host/extensions/query/capabilities",
    "plesk://host/extension/query/call",
    "plesk://host/extension/command/call",
    "plesk://host/subscription/query/capabilities",
    "plesk://host/subscription/query/snapshot",
    "plesk://host/domain/command/ensure",
    "plesk://host/dns/query/records",
    "plesk://host/dns/query/authority",
    "plesk://host/dns/query/propagation",
    "plesk://host/dns/command/replace",
    "plesk://host/dns/command/reconcile",
    "plesk://host/mailbox/command/create",
    "plesk://host/mailbox/command/ensure",
    "plesk://host/mailbox/query/status",
    "plesk://host/ftpuser/command/ensure",
    "plesk://host/site/command/subdomain-ensure",
    "plesk://host/site/command/reverse-proxy-ensure",
    "plesk://host/site/command/ssl-ensure",
    "plesk://host/site/command/publish",
    "plesk://host/site/command/sync",
    "plesk://host/site/command/twin-sync",
    "plesk://host/site/command/release-upload",
    "plesk://host/site/command/release-verify",
    "plesk://host/site/command/publish-verify",
    "plesk://host/site/command/release-activate",
    "plesk://host/site/command/release-rollback",
    "plesk://host/site/query/release-current",
    "plesk://host/site/query/methods",
    "plesk://host/site/query/docroot",
    "plesk://host/site/query/remote-inventory",
    "plesk://host/site/query/twin-current",
    "plesk://host/session/query/mutate-lease",
    "plesk://host/session/command/mutate-lease",
    "plesk://host/doctor/query/report",
}


def test_reverse_proxy_dry_run_requires_reachable_authenticated_https_upstream(monkeypatch):
    monkeypatch.setattr(core, "assert_public_upstream", lambda _url: ["203.0.113.10"])
    monkeypatch.setattr(core, "probe_upstream", lambda _url, path="/": {
        "url": f"https://founder-origin.example.net{path}",
        "status": 401,
        "reachable": True,
        "authentication_challenge": True,
    })
    result = ensure_reverse_proxy(
        hostname="founder.subactor.com",
        upstream="https://founder-origin.example.net",
        base_url="https://plesk.example.test:8443",
        apply=False,
    )
    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["executed"] is False
    assert result["required_capability"] == "plesk.root_ssh_cli"
    assert result["plan"]["transport"] == "plesk-root-ssh-cli"
    assert "directives" not in result["plan"]


def test_reverse_proxy_rejects_placeholder_loop_and_missing_authentication(monkeypatch):
    assert ensure_reverse_proxy(
        hostname="founder.subactor.com", upstream="pending:reachable-subactor-control",
    )["ok"] is False
    assert ensure_reverse_proxy(
        hostname="founder.subactor.com", upstream="https://founder.subactor.com",
    )["error"] == "plesk_reverse_proxy_upstream_loop"
    monkeypatch.setattr(core, "assert_public_upstream", lambda _url: ["203.0.113.10"])
    monkeypatch.setattr(core, "probe_upstream", lambda _url, path="/": {
        "url": "https://open.example.net/", "status": 200, "reachable": True,
        "authentication_challenge": False,
    })
    result = ensure_reverse_proxy(
        hostname="founder.subactor.com", upstream="https://open.example.net",
        base_url="https://plesk.example.test:8443",
    )
    assert result["error"] == "plesk_reverse_proxy_authentication_not_observed"


def test_reverse_proxy_managed_block_preserves_other_plesk_directives():
    first = managed_directives("founder.subactor.com", "https://origin-one.example.net")
    merged = merge_managed_directives("client_max_body_size 2m;\n", first)
    assert merged.startswith("client_max_body_size 2m;")
    assert merged.count(BEGIN_MARKER) == 1
    replacement = managed_directives("founder.subactor.com", "https://origin-two.example.net")
    updated = merge_managed_directives(merged, replacement)
    assert "origin-one.example.net" not in updated
    assert "origin-two.example.net" in updated
    assert updated.count(END_MARKER) == 1
    with pytest.raises(RuntimeError, match="managed_block_corrupt"):
        merge_managed_directives(BEGIN_MARKER, replacement)


def test_reverse_proxy_upstream_must_be_an_external_https_origin():
    with pytest.raises(RuntimeError, match="https_required"):
        normalize_upstream("http://origin.example.net", hostname="founder.subactor.com")
    with pytest.raises(RuntimeError, match="origin_required"):
        normalize_upstream("https://origin.example.net/path", hostname="founder.subactor.com")


def test_remote_inventory_is_bounded_and_does_not_return_credentials(monkeypatch):
    class Attr:
        def __init__(self, filename, mode, size=0):
            self.filename, self.st_mode, self.st_size = filename, mode, size

    class Sftp:
        def stat(self, path):
            assert path == "/httpdocs"
            return Attr("httpdocs", 0o40755)

        def listdir_attr(self, path):
            assert path == "/httpdocs"
            return [Attr("index.html", 0o100644, 123), Attr("assets", 0o40755)]

        def close(self):
            pass

    class Transport:
        def close(self):
            pass

    monkeypatch.setattr(core, "_vault_lease", lambda _entry, _origin, field, _vault: {"username": "u", "password": "p"}[field])
    monkeypatch.setattr(core, "_sftp_connect", lambda *_args: (Transport(), Sftp(), "sha256:abc"))
    result = site_remote_inventory(
        host="plesk.example.com", domain="example.com", remote_path="/httpdocs", max_entries=1,
        credential_origin="https://example.com",
    )
    assert result["ok"] and result["entries_total"] == 2 and result["truncated"] is True
    assert result["entries"] == [{"name": "assets", "type": "directory", "bytes": 0, "mode": "755"}]
    serialized = json.dumps(result)
    assert '"u"' not in serialized and '"p"' not in serialized


def test_remote_inventory_denies_unbound_chroot_root_before_leasing_credentials(monkeypatch):
    monkeypatch.setattr(core, "_vault_lease", lambda *_args: pytest.fail("vault must not be touched"))
    result = site_remote_inventory(
        host="plesk.example.com", domain="example.com", remote_path="/",
    )
    assert result["ok"] is False
    assert result["error"] == "plesk_site_inventory_scope_unbound"


def test_remote_inventory_accepts_domain_bound_chroot_root(monkeypatch):
    class Sftp:
        def stat(self, path):
            assert path == "/"
            return type("Directory", (), {"st_mode": 0o40750})()

        def listdir_attr(self, path):
            assert path == "/"
            return []

        def close(self):
            pass

    class Transport:
        def close(self):
            pass

    monkeypatch.setattr(core, "_vault_lease", lambda *_args: "leased")
    monkeypatch.setattr(core, "_sftp_connect", lambda *_args: (Transport(), Sftp(), "sha256:bound"))
    result = site_remote_inventory(
        host="plesk.example.com",
        domain="customer.example.com",
        remote_path="/",
        sftp_vault_entry_id="plesk-sftp-customer-example-com",
    )
    assert result["ok"] is True
    assert result["entries_total"] == 0


def test_remote_inventory_denies_ambiguous_httpdocs_before_leasing_credentials(monkeypatch):
    monkeypatch.setattr(core, "_vault_lease", lambda *_args: pytest.fail("vault must not be touched"))
    result = site_remote_inventory(
        host="plesk.example.com",
        domain="customer.example.com",
        remote_path="/httpdocs",
    )
    assert result["ok"] is False
    assert result["error"] == "plesk_site_inventory_scope_unbound"
    assert result["mutation_attempted"] is False


def test_remote_inventory_accepts_domain_bound_chroot_origin(monkeypatch):
    class Attr:
        filename = "index.html"
        st_mode = 0o100644
        st_size = 10

    class Sftp:
        def stat(self, _path):
            return type("Directory", (), {"st_mode": 0o40750})()

        def listdir_attr(self, _path):
            return [Attr()]

        def close(self):
            pass

    class Transport:
        def close(self):
            pass

    monkeypatch.setattr(core, "_vault_lease", lambda *_args: "leased")
    monkeypatch.setattr(core, "_sftp_connect", lambda *_args: (Transport(), Sftp(), "sha256:bound"))
    result = site_remote_inventory(
        host="plesk.example.com",
        domain="customer.example.com",
        remote_path="/httpdocs",
        credential_origin="https://customer.example.com",
    )
    assert result["ok"] is True
    assert result["entries_total"] == 1


def test_bootstrap_leases_admin_login_and_stores_key_without_returning_it(monkeypatch):
    reset_default_jti_replay_store()
    leased = {"username": "admin", "password": "admin-password", "api_key": "generated-plesk-key"}
    requests = []
    stored = {}

    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url: leased[field])

    def fake_request(url, **kwargs):
        requests.append({"url": url, **kwargs})
        if url.endswith("/api/v2/auth/keys"):
            return 201, {"key": "generated-plesk-key"}
        return 200, []

    monkeypatch.setattr(core, "_request_json", fake_request)
    monkeypatch.setattr(
        core,
        "_vault_store",
        lambda entry, origin, api_key, vault_url: stored.update(entry=entry, key=api_key) or entry,
    )

    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_API_KEY_APPLY", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "bootstrap-test-secret")
    dry_run = bootstrap_api_key(base_url="https://plesk.example.com:8443")
    assert dry_run["ok"] and dry_run["dry_run"] and requests == [] and stored == {}
    issued = issue_apply_grant(
        run_id="PLF-346",
        actor="authority:founder",
        intent_pack="plesk-api-key-bootstrap@1",
        plan_hash=dry_run["plan_hash"],
        artifact_sha256=dry_run["artifact_sha256"],
        target=dry_run["target"],
        risk_class="governance",
    )
    result = bootstrap_api_key(
        base_url="https://plesk.example.com:8443",
        apply=True,
        plan_hash=dry_run["plan_hash"],
        apply_grant=issued["grant"],
        actor="authority:founder",
        pack_id="plesk-api-key-bootstrap",
        pack_version="1",
    )

    assert result["ok"] and result["authorized"]
    assert requests[0]["url"].endswith("/api/v2/auth/keys")
    assert requests[0]["method"] == "POST"
    assert requests[0]["headers"]["authorization"] == "Basic " + base64.b64encode(b"admin:admin-password").decode()
    assert requests[1]["url"].endswith("/api/v2/domains")
    assert stored == {"entry": "plesk-runtime", "key": "generated-plesk-key"}
    serialized = json.dumps(result)
    assert "admin-password" not in serialized and "generated-plesk-key" not in serialized

    replay = bootstrap_api_key(
        base_url="https://plesk.example.com:8443",
        apply=True,
        plan_hash=dry_run["plan_hash"],
        apply_grant=issued["grant"],
        actor="authority:founder",
        pack_id="plesk-api-key-bootstrap",
        pack_version="1",
    )
    assert replay["ok"] is False and replay["error"] == "apply_grant_replay"
    assert len(requests) == 2


def test_bootstrap_api_key_fails_closed_without_apply_authority(monkeypatch):
    calls = []
    monkeypatch.setattr(core, "_vault_lease", lambda *_args: calls.append("lease") or "secret")
    monkeypatch.setattr(core, "_request_json", lambda *_args, **_kwargs: calls.append("request") or (201, {"key": "secret-key"}))

    dry_run = bootstrap_api_key(base_url="https://plesk.example.com:8443")
    assert dry_run["ok"] and dry_run["dry_run"] and calls == []

    denied = bootstrap_api_key(
        base_url="https://plesk.example.com:8443",
        apply=True,
        plan_hash=dry_run["plan_hash"],
    )
    assert denied["ok"] is False
    assert denied["error"] == "autonomy_mutations_disabled"
    assert calls == []


def test_auth_conformance_returns_handles_and_never_secret_values(monkeypatch):
    monkeypatch.setattr(core, "_authorized_request", lambda **kwargs: (200, []))
    status = auth_status(base_url="https://plesk.example.com:8443")
    scopes = auth_scopes(base_url="https://plesk.example.com:8443")
    methods = auth_acquisition_methods()

    assert status["schema"] == "subactor.connector-auth-status/v1"
    assert status["authenticated"] and status["credential_handle"] == "plesk-runtime"
    assert status["secret_value_visible"] is False
    assert status["evidence"] == {"provider_probe": True, "scope_probe": False, "evidence_bundle_id": None}
    assert scopes["evidence"]["scope_probe"] is True
    assert methods["methods"][0]["root_credential_handle"] == "plesk-admin-bootstrap"
    serialized = json.dumps({"status": status, "scopes": scopes, "methods": methods})
    assert "password" not in serialized and "api_key_value" not in serialized


def test_manifest_routes_match_runtime_bindings():
    manifest = connector_manifest()
    assert set(manifest["routes"]) == ROUTES
    assert manifest["authConformance"] == {
        "schema": "subactor.connector-auth-status/v1",
        "statusRoute": "plesk://host/auth/query/status",
        "scopesRoute": "plesk://host/auth/query/scopes",
        "acquisitionMethodsRoute": "plesk://host/auth/query/acquisition-methods",
        "bootstrapRoute": "plesk://host/auth/command/bootstrap-api-key",
        "secretValueVisible": False,
    }


def _dns_xml(records):
    rows = "".join(
        "<result><status>ok</status><id>{id}</id><data><type>{type}</type><host>{host}</host>"
        "<value>{value}</value></data></result>".format(**row)
        for row in records
    )
    return f"<packet><dns><get_rec>{rows}</get_rec></dns></packet>"


def test_dns_records_filters_exact_host_without_exposing_credentials(monkeypatch):
    leased = {"username": "subscription-user", "password": "subscription-password"}
    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url: leased[field])
    monkeypatch.setattr(
        core,
        "_xml_agent",
        lambda *args: _dns_xml([
            {"id": 7, "type": "CNAME", "host": "status.example.com.", "value": "old.example.net."},
            {"id": 8, "type": "A", "host": "other.example.com", "value": "192.0.2.8"},
        ]),
    )
    result = dns_records(site_id=185, host="status.example.com", base_url="https://plesk.example.com:8443")
    assert result["ok"] and result["count"] == 1
    assert result["records"][0] == {
        "id": 7, "type": "CNAME", "host": "status.example.com", "value": "old.example.net", "opt": None,
    }
    serialized = json.dumps(result)
    assert "subscription-user" not in serialized and "subscription-password" not in serialized


def test_dns_records_accepts_only_a_leftmost_wildcard(monkeypatch):
    monkeypatch.setattr(core, "_vault_lease", lambda *args: "vault-value")
    monkeypatch.setattr(
        core, "_xml_agent", lambda *args: _dns_xml([{
            "id": 12, "type": "CNAME", "host": "*.subactor.com.", "value": "subactor.github.io.",
        }]),
    )
    result = dns_records(
        site_id=185, host="*.subactor.com", base_url="https://plesk.example.com:8443",
    )
    assert result["ok"] and result["records"][0]["host"] == "*.subactor.com"
    for invalid in ("foo.*.subactor.com", "**.subactor.com", "*", "*.localhost"):
        denied = dns_records(site_id=185, host=invalid, base_url="https://plesk.example.com:8443")
        assert denied["ok"] is False and denied["error"] == "plesk_dns_host_invalid"


def test_dns_replace_plans_wildcard_cname_to_address_without_expanding_scope(monkeypatch):
    monkeypatch.setattr(core, "_vault_lease", lambda *args, **kwargs: "vault-value")
    monkeypatch.setattr(
        core, "_xml_agent", lambda *args: _dns_xml([{
            "id": 12, "type": "CNAME", "host": "*.subactor.com", "value": "subactor.github.io",
        }]),
    )
    result = dns_replace(
        site_id=185, host="*.subactor.com", record_type="A", value="217.160.250.222",
        base_url="https://plesk.example.com:8443",
    )
    assert result["ok"] and result["plan"]["host"] == "*.subactor.com"
    assert result["plan"]["delete_record_ids"] == [12] and result["plan"]["add_record"] is True


def test_dns_replace_dry_run_builds_stable_conflict_free_plan(monkeypatch):
    monkeypatch.setattr(core, "_vault_lease", lambda *args, **kwargs: "vault-value")
    monkeypatch.setattr(
        core, "_xml_agent", lambda *args: _dns_xml([
            {"id": 7, "type": "CNAME", "host": "status.example.com", "value": "old.example.net"},
            {"id": 9, "type": "AAAA", "host": "status.example.com", "value": "2001:db8::1"},
        ]),
    )
    first = dns_replace(
        site_id=185, host="status.example.com", value="192.0.2.10",
        base_url="https://plesk.example.com:8443",
    )
    second = dns_replace(
        site_id=185, host="status.example.com", value="192.0.2.10",
        base_url="https://plesk.example.com:8443",
    )
    assert first["ok"] and first["dry_run"] and first["changed"]
    assert first["plan"]["delete_record_ids"] == [7, 9] and first["plan"]["add_record"] is True
    assert first["plan_hash"] == second["plan_hash"] and len(first["plan_hash"]) == 64


def test_dns_replace_apply_fails_closed_before_credentials(monkeypatch):
    monkeypatch.delenv("AUTONOMY_MUTATIONS_ENABLED", raising=False)
    monkeypatch.delenv("PLESK_DNS_APPLY", raising=False)
    monkeypatch.setattr(core, "_vault_lease", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no lease")))
    result = dns_replace(
        site_id=185, host="status.example.com", value="192.0.2.10", apply=True,
        base_url="https://plesk.example.com:8443",
    )
    assert not result["ok"] and result["error"] == "autonomy_mutations_disabled"
    assert result["mutation_attempted"] is False


def test_dns_replace_apply_requires_grant_and_verifies_result(monkeypatch):
    reset_default_jti_replay_store()
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_DNS_APPLY", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "dns-test-secret")
    monkeypatch.setattr(core, "_vault_lease", lambda *args, **kwargs: "vault-value")
    state = [{"id": 7, "type": "CNAME", "host": "status.example.com", "value": "old.example.net"}]
    packets = []

    def xml_agent(base_url, username, password, packet):
        packets.append(packet)
        if "<get_rec>" in packet:
            return _dns_xml(state)
        if "<del_rec>" in packet:
            assert "<del_rec><filter><id>7</id>" in packet
            state[:] = []
            return "<packet><dns><del_rec><result><status>ok</status></result></del_rec></dns></packet>"
        assert "<add_rec><site-id>185</site-id><type>A</type>" in packet
        state[:] = [{"id": 10, "type": "A", "host": "status.example.com", "value": "192.0.2.10"}]
        return "<packet><dns><add_rec><result><status>ok</status><id>10</id></result></add_rec></dns></packet>"

    monkeypatch.setattr(core, "_xml_agent", xml_agent)
    dry = dns_replace(
        site_id=185, host="status.example.com", value="192.0.2.10",
        base_url="https://plesk.example.com:8443",
    )
    issued = issue_apply_grant(
        run_id="dns-run", actor="test-actor", intent_pack="plesk-dns@1",
        plan_hash=dry["plan_hash"], artifact_sha256=dry["artifact_sha256"], target=dry["target"],
        risk_class="boundary", jti="dns-once",
        environ={"APPLY_GRANT_HMAC_SECRET": "dns-test-secret"},
    )
    result = dns_replace(
        site_id=185, host="status.example.com", value="192.0.2.10", apply=True,
        plan_hash=dry["plan_hash"], apply_grant=issued["grant"], actor="test-actor",
        pack_id="plesk-dns", pack_version="1", base_url="https://plesk.example.com:8443",
    )
    assert result["ok"] and result["executed"] and result["verified"]
    assert result["record"]["value"] == "192.0.2.10" and len(packets) == 5


def test_dns_replace_compensates_deleted_record_when_add_fails(monkeypatch):
    reset_default_jti_replay_store()
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_DNS_APPLY", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "dns-test-secret")
    monkeypatch.setattr(core, "_vault_lease", lambda *args, **kwargs: "vault-value")
    state = [{"id": 7, "type": "CNAME", "host": "status.example.com", "value": "old.example.net", "opt": None}]

    def xml_agent(base_url, username, password, packet):
        if "<get_rec>" in packet:
            return _dns_xml(state)
        if "<del_rec>" in packet:
            state[:] = []
            return "<packet><dns><del_rec><result><status>ok</status></result></del_rec></dns></packet>"
        if "<type>A</type>" in packet:
            return "<packet><dns><add_rec><result><status>error</status><errcode>1019</errcode><errtext>Invalid record</errtext></result></add_rec></dns></packet>"
        assert "<type>CNAME</type>" in packet and "<value>old.example.net</value>" in packet
        state[:] = [{"id": 8, "type": "CNAME", "host": "status.example.com", "value": "old.example.net", "opt": None}]
        return "<packet><dns><add_rec><result><status>ok</status><id>8</id></result></add_rec></dns></packet>"

    monkeypatch.setattr(core, "_xml_agent", xml_agent)
    dry = dns_replace(site_id=185, host="status.example.com", value="192.0.2.10", base_url="https://plesk.example.com:8443")
    issued = issue_apply_grant(
        run_id="dns-rollback", actor="test-actor", intent_pack="plesk-dns@1",
        plan_hash=dry["plan_hash"], artifact_sha256=dry["artifact_sha256"], target=dry["target"],
        risk_class="boundary", jti="dns-rollback-once",
        environ={"APPLY_GRANT_HMAC_SECRET": "dns-test-secret"},
    )
    result = dns_replace(
        site_id=185, host="status.example.com", value="192.0.2.10", apply=True,
        plan_hash=dry["plan_hash"], apply_grant=issued["grant"], actor="test-actor",
        pack_id="plesk-dns", pack_version="1", base_url="https://plesk.example.com:8443",
    )
    assert result["ok"] is False and result["error"] == "plesk_dns_add_failed"
    assert result["provider_error"] == {"operation": "add_rec", "errcode": "1019", "errtext": "Invalid record"}
    assert result["rollback_attempted"] is True and result["rollback_ok"] is True
    assert state[0]["type"] == "CNAME"


def _authority(provider="cloudflare", *, consistent=True):
    nameservers = ["alice.ns.cloudflare.com", "bob.ns.cloudflare.com"] if provider == "cloudflare" else ["ns1.example.net"]
    return {
        "zone": "example.com", "provider": provider, "nameservers": nameservers,
        "consistent": consistent, "observations": [],
    }


def test_dns_authority_reports_provider_consensus(monkeypatch):
    monkeypatch.setattr(core, "resolve_dns_authority", lambda zone: _authority())
    result = dns_authority(zone="example.com")
    assert result["ok"] and result["provider"] == "cloudflare"
    assert result["authority"]["consistent"] is True
    assert result["twin_fact"]["schema"] == "subactor.twin-fact/v1"
    assert result["twin_fact"]["twin_type"] == "plesk.dns.authority"
    assert result["twin_fact"]["payload"]["provider"] == "cloudflare"
    assert result["twin_fact"]["payload"]["management_plane"] == "cloudflaredns"
    assert result["fact_quality"] == "fresh"


def test_subscription_query_snapshot_emits_twin_fact(monkeypatch):
    monkeypatch.setattr(core, "_base_url", lambda _url: "https://plesk.example.test:8443")
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "secret")
    monkeypatch.setattr(
        core,
        "_subscription_capabilities_with_credentials",
        lambda **kwargs: {
            "ok": True,
            "subscription": "prototypowanie.pl",
            "domains_used": 3,
            "domains_limit": 10,
            "webspace_id": 42,
        },
    )
    result = subscription_query_snapshot(
        subscription="prototypowanie.pl",
        instance_id="panel-demo",
        base_url="https://plesk.example.test:8443",
    )
    assert result["ok"] is True
    assert result["mutation_attempted"] is False
    assert result["fact_quality"] == "fresh"
    assert result["count"] == 1
    fact = result["twin_fact"]
    assert fact["uri"] == "plesk://host/subscription/query/snapshot"
    assert fact["twin_type"] == "plesk.subscription"
    assert fact["payload"]["subscriptions"][0]["domains_used"] == 3


def test_subscription_query_snapshot_estimates_on_transport_failure(monkeypatch):
    monkeypatch.setattr(core, "_base_url", lambda _url: "https://plesk.example.test:8443")
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "secret")
    monkeypatch.setattr(
        core,
        "_subscription_capabilities_with_credentials",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("plesk_xml_transport_failed")),
    )
    result = subscription_query_snapshot(subscription="prototypowanie.pl")
    assert result["ok"] is True
    assert result["fact_quality"] == "estimated"
    assert result["twin_fact"]["payload"]["observe_error"] == "plesk_xml_transport_failed"


def test_dns_propagation_exposes_resolver_consensus_and_ttl(monkeypatch):
    observation = {
        "host": "status.example.com", "record_type": "A", "expected_value": "192.0.2.10",
        "consensus": True, "propagated": True, "ttl_min": 120, "ttl_max": 300,
        "observations": [],
    }
    monkeypatch.setattr(core, "resolve_dns_propagation", lambda *args: observation)
    result = dns_propagation(
        host="status.example.com", record_type="A", expected_value="192.0.2.10",
    )
    assert result["ok"] and result["propagated"] and result["consensus"]
    assert result["propagation"]["ttl_min"] == 120


def test_dns_reconcile_fails_closed_on_provider_mismatch_before_vault(monkeypatch):
    monkeypatch.setattr(core, "resolve_dns_authority", lambda zone: _authority())
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: pytest.fail("vault must not be touched"))
    result = dns_reconcile(
        zone="example.com", host="status.example.com", value="192.0.2.10",
        expected_provider="plesk",
    )
    assert not result["ok"] and result["error"] == "dns_authoritative_provider_mismatch"
    assert result["provider"] == "cloudflare" and result["mutation_attempted"] is False


def test_dns_reconcile_cloudflare_dry_run_uses_vault_and_returns_provider_receipt(monkeypatch):
    record_id = "a" * 32
    leases = {"api_token": "top-secret-token", "zone_id": "b" * 32}
    monkeypatch.setattr(core, "resolve_dns_authority", lambda zone: _authority())
    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url: leases[field])
    monkeypatch.setattr(core, "cloudflare_records", lambda *a: [{
        "id": record_id, "host": "status.example.com", "type": "CNAME",
        "value": "old.example.net", "ttl": 1, "proxied": False,
    }])
    result = dns_reconcile(
        zone="example.com", host="status.example.com", value="192.0.2.10",
        expected_provider="cloudflare",
    )
    assert result["ok"] and result["dry_run"] and result["changed"]
    assert result["provider"] == "cloudflare"
    assert result["plan"]["delete_record_ids"] == [record_id]
    assert result["plan"]["create_record"] is True
    serialized = json.dumps(result)
    assert "top-secret-token" not in serialized and leases["zone_id"] not in serialized


def test_dns_reconcile_cloudflare_wildcard_targets_only_the_literal_record(monkeypatch):
    record_id = "a" * 32
    leases = {"api_token": "top-secret-token", "zone_id": "b" * 32}
    monkeypatch.setattr(core, "resolve_dns_authority", lambda zone: _authority())
    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url: leases[field])
    monkeypatch.setattr(core, "cloudflare_records", lambda zone_id, zone, host, token: [{
        "id": record_id, "host": host, "type": "CNAME",
        "value": "subactor.github.io", "ttl": 1, "proxied": False,
    }])
    result = dns_reconcile(
        zone="subactor.com", host="*.subactor.com", record_type="A",
        value="217.160.250.222", expected_provider="cloudflare",
    )
    assert result["ok"] and result["dry_run"]
    assert result["plan"]["host"] == "*.subactor.com"
    assert result["plan"]["delete_record_ids"] == [record_id]
    assert result["target"] == "cloudflare://subactor.com/dns:*.subactor.com"


def test_dns_reconcile_cloudflare_apply_is_granted_batched_and_verified(monkeypatch):
    reset_default_jti_replay_store()
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("CLOUDFLARE_DNS_APPLY", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "dns-provider-secret")
    leases = {"api_token": "top-secret-token", "zone_id": "b" * 32}
    state = [{
        "id": "a" * 32, "host": "status.example.com", "type": "CNAME",
        "value": "old.example.net", "ttl": 1, "proxied": False,
    }]
    applied = []
    monkeypatch.setattr(core, "resolve_dns_authority", lambda zone: _authority())
    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url: leases[field])
    monkeypatch.setattr(core, "cloudflare_records", lambda *a: list(state))

    def fake_apply(zone_id, token, plan):
        applied.append(plan)
        state[:] = [{
            "id": "c" * 32, "host": plan["host"], "type": plan["record_type"],
            "value": plan["value"], "ttl": plan["ttl"], "proxied": plan["proxied"],
        }]

    monkeypatch.setattr(core, "apply_cloudflare_plan", fake_apply)
    dry = dns_reconcile(zone="example.com", host="status.example.com", value="192.0.2.10")
    issued = issue_apply_grant(
        run_id="provider-dns-run", actor="test-actor", intent_pack="provider-dns@1",
        plan_hash=dry["plan_hash"], artifact_sha256=dry["artifact_sha256"], target=dry["target"],
        risk_class="boundary", jti="provider-dns-once",
        environ={"APPLY_GRANT_HMAC_SECRET": "dns-provider-secret"},
    )
    result = dns_reconcile(
        zone="example.com", host="status.example.com", value="192.0.2.10", apply=True,
        plan_hash=dry["plan_hash"], apply_grant=issued["grant"], actor="test-actor",
        pack_id="provider-dns", pack_version="1",
    )
    assert result["ok"] and result["executed"] and result["verified"]
    assert result["provider"] == "cloudflare" and len(applied) == 1
    assert result["record"]["value"] == "192.0.2.10"


def _extensions_xml():
    return """<packet><extension><get>
      <result><status>ok</status><details><id>git</id><name>Git Manager</name><version>1.2.3</version><release>42</release><active>true</active></details></result>
      <result><status>ok</status><details><id>third-party</id><name>Third Party</name><version>2.0</version><release>7</release><active>true</active></details></result>
      <result><status>ok</status><details><id>sslit</id><name>SSL It!</name><version>1.0</version><release>8</release><active>true</active></details></result>
    </get></extension></packet>"""


def test_extension_catalog_discovers_runtime_objects_without_granting_unknown_operations(monkeypatch):
    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url="": "vault-value")
    monkeypatch.setattr(core, "_xml_agent", lambda *args: _extensions_xml())
    monkeypatch.setattr(core, "_request_json", lambda *args, **kwargs: (403, {}))

    inventory = extension_catalog(base_url="https://plesk.example.com:8443")
    capabilities = extension_capabilities(base_url="https://plesk.example.com:8443")

    assert inventory["ok"] and inventory["installed"] == 3
    assert capabilities["ok"] and capabilities["profiled"] == 2
    assert capabilities["unknown"] == ["third-party"]
    unknown = next(item for item in capabilities["extensions"] if item["id"] == "third-party")
    assert unknown["execution_policy"] == "discovery-only" and unknown["operations"] == []
    sslit = next(item for item in capabilities["extensions"] if item["id"] == "sslit")
    assert sslit["operations"][0]["uri"] == "plesk://host/site/command/ssl-ensure"
    assert "vault-value" not in json.dumps({"inventory": inventory, "capabilities": capabilities})


def test_extension_catalog_merges_rest_cli_inventory_when_xml_is_incomplete(monkeypatch):
    monkeypatch.setattr(core, "_vault_lease", lambda entry, origin, field, vault_url="": "vault-value")
    monkeypatch.setattr(core, "_xml_agent", lambda *args: _extensions_xml())
    monkeypatch.setattr(core, "_request_json", lambda *args, **kwargs: (200, {
        "code": 0,
        "stdout": "cloudflaredns - DNS Integration for Cloudflare®\ngit - Git\n",
        "stderr": "",
    }))

    inventory = extension_catalog(base_url="https://plesk.example.com:8443")

    assert inventory["ok"] and inventory["installed"] == 4
    assert any(item["id"] == "cloudflaredns" for item in inventory["extensions"])
    assert inventory["source"] == "xml-api:extension.get+rest-cli:extension.--list"
    assert "vault-value" not in json.dumps(inventory)


def test_profiled_extension_query_builds_structured_xml_and_redacts_output(monkeypatch):
    sent = {}
    monkeypatch.setattr(core, "_installed_extension", lambda *args, **kwargs: {"id": "git", "active": True})

    def fake_admin_xml(**kwargs):
        sent["packet"] = kwargs["packet"]
        return """<packet><extension><call><result><status>ok</status><git><get><repository><name>repo</name><password>nope</password></repository></get></git></result></call></extension></packet>"""

    monkeypatch.setattr(core, "_admin_xml", fake_admin_xml)
    result = extension_query(
        extension_id="git",
        operation="get",
        arguments={"domain": "example.com<unsafe"},
        base_url="https://plesk.example.com:8443",
    )
    assert result["ok"] and result["executed"] and not result["mutation_attempted"]
    assert "<domain>example.com&lt;unsafe</domain>" in sent["packet"]
    assert result["data"]["git"]["get"]["repository"]["password"] == "[REDACTED]"
    assert "nope" not in json.dumps(result)


def test_extension_query_rejects_unprofiled_operation_and_unknown_arguments(monkeypatch):
    monkeypatch.setattr(core, "_installed_extension", lambda *args, **kwargs: {"id": "git", "active": True})
    unknown = extension_query(
        extension_id="git", operation="status", base_url="https://plesk.example.com:8443",
    )
    injected = extension_query(
        extension_id="git", operation="get", arguments={"raw_xml": "<remove/>"},
        base_url="https://plesk.example.com:8443",
    )
    assert not unknown["ok"] and "not_profiled" in unknown["error"]
    assert not injected["ok"] and "arguments_not_allowed" in injected["error"]


def test_extension_command_is_dry_run_and_delegates_sslit_to_canonical_uri():
    git = extension_command(
        extension_id="git",
        operation="remove",
        arguments={"domain": "example.com", "name": "repo"},
        base_url="https://plesk.example.com:8443",
    )
    sslit = extension_command(
        extension_id="sslit",
        operation="certificate-ensure",
        arguments={"hostname": "founder.subactor.com"},
        base_url="https://plesk.example.com:8443",
    )
    assert git["ok"] and git["dry_run"] and not git["executed"]
    assert len(git["plan_hash"]) == 64 and git["plan"]["risk_class"] == "boundary"
    assert sslit["ok"] and sslit["delegated_to"] == "plesk://host/site/command/ssl-ensure"


def test_extension_command_apply_fails_closed_before_credentials(monkeypatch):
    monkeypatch.delenv("AUTONOMY_MUTATIONS_ENABLED", raising=False)
    monkeypatch.delenv("PLESK_EXTENSION_APPLY", raising=False)
    dry = extension_command(
        extension_id="git",
        operation="remove",
        arguments={"domain": "example.com", "name": "repo"},
        base_url="https://plesk.example.com:8443",
    )
    monkeypatch.setattr(core, "_vault_lease", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no lease")))
    denied = extension_command(
        extension_id="git",
        operation="remove",
        arguments={"domain": "example.com", "name": "repo"},
        apply=True,
        plan_hash=dry["plan_hash"],
        base_url="https://plesk.example.com:8443",
    )
    assert not denied["ok"] and denied["error"] == "autonomy_mutations_disabled"
    assert denied["mutation_attempted"] is False


def test_extension_command_requires_exact_boundary_grant_and_consumes_it_once(monkeypatch):
    reset_default_jti_replay_store()
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_EXTENSION_APPLY", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "extension-test-secret")
    arguments = {"domain": "example.com", "name": "repo"}
    dry = extension_command(
        extension_id="git", operation="remove", arguments=arguments,
        base_url="https://plesk.example.com:8443",
    )
    issued = issue_apply_grant(
        run_id="extension-run",
        actor="test-actor",
        intent_pack="plesk-extension@1",
        plan_hash=dry["plan_hash"],
        artifact_sha256=dry["artifact_sha256"],
        target=dry["target"],
        risk_class="boundary",
        jti="extension-once",
        environ={"APPLY_GRANT_HMAC_SECRET": "extension-test-secret"},
    )
    assert issued["ok"]
    monkeypatch.setattr(core, "_installed_extension", lambda *args, **kwargs: {"id": "git", "active": True})
    monkeypatch.setattr(
        core,
        "_admin_xml",
        lambda **kwargs: "<packet><extension><call><result><status>ok</status><git><remove/></git></result></call></extension></packet>",
    )
    payload = dict(
        extension_id="git", operation="remove", arguments=arguments, apply=True,
        plan_hash=dry["plan_hash"], apply_grant=issued["grant"], actor="test-actor",
        pack_id="plesk-extension", pack_version="1",
        base_url="https://plesk.example.com:8443",
    )
    first = extension_command(**payload)
    second = extension_command(**payload)
    assert first["ok"] and first["executed"] and first["verified"]
    assert not second["ok"] and second["error"] == "apply_grant_replay"


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


def test_api_path_allows_only_bounded_domain_file_content_path():
    assert (
        core._api_path("/api/v2/domains/321/fs/content?path=assets/app.js")
        == "/api/v2/domains/321/fs/content?path=assets%2Fapp.js"
    )
    for path in (
        "/api/v2/domains/321/fs/content?path=../secret",
        "/api/v2/domains/321/fs/content?path=/httpdocs/index.php",
        "/api/v2/domains/321/fs/content?path=index.php&overwrite=1",
        "/api/v2/domains/0/fs/content?path=index.php",
    ):
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
    assert document["bindings"]["plesk://host/site/command/sync"]["policy"]["timeout"] == 195.0
    assert document["bindings"]["plesk://host/site/command/publish"]["policy"]["timeout"] == 195.0
    for uri in ("plesk://host/site/command/sync", "plesk://host/site/command/publish"):
        webspace = document["bindings"][uri]["inputSchema"]["properties"]["deployment_webspace"]
        assert webspace["type"] == "string"
        assert webspace["default"] == ""
    registry = urirun.compile_registry(json.loads(json.dumps(document)))
    assert ROUTES <= {route["uri"] for route in urirun.list_routes(registry)}
    manifest = connector_manifest()
    assert manifest["id"] == "plesk" and set(manifest["routes"]) == ROUTES


def test_twin_sync_declares_reversible_local_volume_effect():
    contracts = json.loads(
        (Path(core.__file__).with_name("contracts.json")).read_text(encoding="utf-8")
    )

    assert contracts["contracts"]["site/command/twin-sync"] == {
        "version": "v1",
        "effect": "command",
        "reversible": True,
    }


def test_mailbox_status_uses_read_only_info_call(monkeypatch):
    request = {}
    monkeypatch.setattr(
        core,
        "_authorized_request",
        lambda **kwargs: request.update(kwargs) or (200, {"code": 0, "stdout": "Mailbox: true"}),
    )
    result = mailbox_status(email="hello@subactor.com", base_url="https://plesk.example.com:8443")
    assert result["ok"] and result["exists"] and result["mutation_attempted"] is False
    assert request["body"] == {"params": ["--info", "hello@subactor.com"]}


def test_mailbox_ensure_generates_password_and_stores_imap_and_smtp_without_returning_it(monkeypatch):
    request = {}
    stored = {}
    probes = iter([(False, 200, {}), (False, 200, {}), (True, 200, {})])

    def fake_authorized_request(**kwargs):
        request.update(kwargs)
        return 200, {"code": 0, "stdout": "created"}

    monkeypatch.setattr(core, "_authorized_request", fake_authorized_request)
    def fake_store(entry, origin, label, values, vault_url, scope=None):
        stored[entry] = {"origin": origin, "label": label, "values": dict(values), "scope": scope}
        return entry

    monkeypatch.setattr(core, "_vault_store_secrets", fake_store)
    monkeypatch.setattr(core, "_vault_entry_scope_metadata", lambda *args, **kwargs: {"ok": True, "error": None})
    monkeypatch.setattr(core, "_mailbox_probe", lambda *_args, **_kwargs: next(probes))
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_MAILBOX_APPLY", "1")
    monkeypatch.setenv("TOKEN_PEPPER", "mailbox-test-secret")
    dry_run = ensure_mailbox(
        email="hello@subactor.com",
        credential_vault_entry_id="agent-mailbox-runtime",
        credential_origin="imap://mail.prototypowanie.pl",
        smtp_vault_entry_id="smtp-system-email",
        smtp_credential_origin="https://prototypowanie.pl",
        base_url="https://plesk.example.com:8443",
    )
    issued = issue_apply_grant(
        run_id="PLF-345",
        actor="authority:founder",
        intent_pack="mailbox.customer-intake@1",
        plan_hash=dry_run["plan_hash"],
        artifact_sha256=dry_run["artifact_sha256"],
        target=dry_run["target"],
        risk_class="governance",
    )
    result = ensure_mailbox(
        email="hello@subactor.com",
        credential_vault_entry_id="agent-mailbox-runtime",
        credential_origin="imap://mail.prototypowanie.pl",
        smtp_vault_entry_id="smtp-system-email",
        smtp_credential_origin="https://prototypowanie.pl",
        base_url="https://plesk.example.com:8443",
        apply=True,
        plan_hash=dry_run["plan_hash"],
        apply_grant=issued["grant"],
        actor="authority:founder",
        pack_id="mailbox.customer-intake",
        pack_version="1",
    )
    assert result["ok"] and result["created"]
    assert request["path"] == "/api/v2/cli/mail/call"
    assert request["body"]["params"][:2] == ["--create", "hello@subactor.com"]
    generated = request["body"]["params"][3]
    assert len(generated) >= 24
    assert stored["smtp-system-email"]["values"] == {"username": "hello@subactor.com", "password": generated}
    assert stored["agent-mailbox-runtime"]["origin"] == "imap://mail.prototypowanie.pl"
    assert stored["smtp-system-email"]["origin"] == "https://prototypowanie.pl"
    assert generated not in json.dumps(result)


def test_mailbox_create_rejects_invalid_email_or_credential_origin():
    assert create_mailbox(email="not-an-email", credential_origin="imap://mail.example.com")["ok"] is False
    assert create_mailbox(email="agent@example.com", credential_origin="https://mail.example.com")["ok"] is False


def test_ensure_ftp_user_plans_then_applies_with_one_shot_grant_without_leaking_password(monkeypatch):
    reset_default_jti_replay_store()
    monkeypatch.delenv("APPLY_GRANT_JTI_STORE", raising=False)
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

    def fake_store(entry, origin, label, values, vault_url, scope=None):
        stored[entry] = {
            "origin": origin,
            "label": label,
            "values": dict(values),
            "scope": scope,
        }
        return entry

    monkeypatch.setattr(core, "_vault_lease", fake_lease)
    monkeypatch.setattr(core, "_xml_agent", fake_xml)
    monkeypatch.setattr(core, "_vault_store_secrets", fake_store)
    monkeypatch.setattr(
        core,
        "_vault_entry_scope_metadata",
        lambda *args, **kwargs: {"ok": True, "error": None},
    )
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_CREDENTIAL_APPLY", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "credential-test-secret")
    shared_domains = ["docs.subactor.com", "founder.subactor.com", "docs.subactor.com"]

    dry = ensure_ftp_user(
        kind="system",
        domain="subactor.com",
        scope_domains=shared_domains,
        base_url="https://prototypowanie.pl:8443",
        credential_vault_entry_id="plesk-sftp",
        also_ftp_vault_entry_id="plesk-ftp",
    )
    assert dry["ok"] and dry["dry_run"] and not dry["mutation_attempted"]
    assert len(dry["plan_hash"]) == 64 and calls == [] and stored == {}

    denied = ensure_ftp_user(
        kind="system", domain="subactor.com",
        scope_domains=shared_domains,
        base_url="https://prototypowanie.pl:8443",
        credential_vault_entry_id="plesk-sftp",
        also_ftp_vault_entry_id="plesk-ftp",
        apply=True, plan_hash=dry["plan_hash"], actor="authority:founder",
        pack_id="plesk-deployment-credential", pack_version="1",
    )
    assert not denied["ok"] and (denied.get("error") or denied.get("reason")) == "apply_grant_required"
    assert calls == [] and stored == {}

    issued = issue_apply_grant(
        run_id="PLF-CREDENTIAL-1",
        actor="authority:founder",
        intent_pack="plesk-deployment-credential@1",
        plan_hash=dry["plan_hash"],
        artifact_sha256=dry["artifact_sha256"],
        target=dry["target"],
        risk_class="governance",
        jti="credential-once",
    )
    result = ensure_ftp_user(
        kind="system", domain="subactor.com",
        scope_domains=shared_domains,
        base_url="https://prototypowanie.pl:8443",
        credential_vault_entry_id="plesk-sftp",
        also_ftp_vault_entry_id="plesk-ftp",
        apply=True, plan_hash=dry["plan_hash"], apply_grant=issued["grant"],
        actor="authority:founder", pack_id="plesk-deployment-credential", pack_version="1",
    )
    assert result["ok"] and result["kind"] == "system" and result["name"] == "subactor_ssh"
    assert result["verified"] and result["grant_jti"] == "credential-once"
    assert result["webspace"] == "subactor.com"
    assert result["scope_domains"] == [
        "docs.subactor.com", "founder.subactor.com", "subactor.com",
    ]
    assert stored["plesk-sftp"]["origin"] == "https://prototypowanie.pl"
    assert stored["plesk-ftp"]["values"]["username"] == "subactor_ssh"
    assert stored["plesk-sftp"]["scope"] == {
        "operations": ["plesk.site.sync"],
        "targets": [
            "domain:docs.subactor.com",
            "domain:founder.subactor.com",
            "domain:subactor.com",
        ],
    }
    assert stored["plesk-ftp"]["scope"] == stored["plesk-sftp"]["scope"]
    assert len(stored["plesk-sftp"]["values"]["password"]) >= 16
    assert stored["plesk-sftp"]["values"]["password"] not in json.dumps(result)
    assert "cust-pass" not in json.dumps(result)
    assert any("<name>subactor.com</name>" in packet for packet in calls)

    replay = ensure_ftp_user(
        kind="system", domain="subactor.com",
        scope_domains=shared_domains,
        base_url="https://prototypowanie.pl:8443",
        credential_vault_entry_id="plesk-sftp",
        also_ftp_vault_entry_id="plesk-ftp",
        apply=True, plan_hash=dry["plan_hash"], apply_grant=issued["grant"],
        actor="authority:founder", pack_id="plesk-deployment-credential", pack_version="1",
    )
    assert not replay["ok"] and (replay.get("error") or replay.get("reason")) == "apply_grant_replay"


def test_ensure_ftp_user_rejects_invalid_or_excessive_scope_domains():
    invalid = ensure_ftp_user(
        kind="system",
        domain="subactor.com",
        scope_domains=["../outside", "founder.subactor.com"],
    )
    assert not invalid["ok"] and invalid["error"] == "plesk_ftp_scope_domains_invalid"

    excessive = ensure_ftp_user(
        kind="system",
        domain="subactor.com",
        scope_domains=[f"site-{index}.subactor.com" for index in range(65)],
    )
    assert not excessive["ok"] and excessive["error"] == "plesk_ftp_scope_domains_invalid"


def test_ensure_ftp_user_system_rotate_uses_parent_webspace_for_subdomain(monkeypatch):
    reset_default_jti_replay_store()
    monkeypatch.delenv("APPLY_GRANT_JTI_STORE", raising=False)
    calls = []

    def fake_lease(entry, origin, field, vault_url=""):
        return {"username": "cust", "password": "cust-pass"}[field]

    def fake_xml(base_url, username, password, packet):
        calls.append(packet)
        if "<webspace><set>" in packet.replace("\n", "").replace(" ", ""):
            assert "<name>subactor.com</name>" in packet
            assert "wydruk.subactor.com" not in packet.replace("<value>", "")
            return "<packet><webspace><set><result><status>ok</status></result></set></webspace></packet>"
        if "<webspace><get>" in packet.replace("\n", "").replace(" ", ""):
            assert "<name>subactor.com</name>" in packet
            return (
                "<packet><webspace><get><result><status>ok</status>"
                "<name>ftp_login</name><value>subactor_ssh</value>"
                "</result></get></webspace></packet>"
            )
        return "<packet><result><status>error</status></result></packet>"

    monkeypatch.setattr(core, "_vault_lease", fake_lease)
    monkeypatch.setattr(core, "_xml_agent", fake_xml)
    monkeypatch.setattr(core, "_vault_store_secrets", lambda *a, **k: a[0])
    monkeypatch.setattr(
        core,
        "_vault_entry_scope_metadata",
        lambda *args, **kwargs: {"ok": True, "error": None},
    )
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_CREDENTIAL_APPLY", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "credential-test-secret")

    dry = ensure_ftp_user(
        kind="system",
        domain="wydruk.subactor.com",
        webspace="subactor.com",
        base_url="https://prototypowanie.pl:8443",
        credential_vault_entry_id="plesk-sftp-wydruk-subactor-com",
        also_ftp_vault_entry_id="plesk-ftp-wydruk-subactor-com",
    )
    assert dry["ok"] and dry["webspace"] == "subactor.com"
    assert dry["plan"]["webspace"] == "subactor.com"
    assert dry["plan"]["domain"] == "wydruk.subactor.com"

    issued = issue_apply_grant(
        run_id="PLF-9516",
        actor="authority:founder",
        intent_pack="plesk-deployment-credential@1",
        plan_hash=dry["plan_hash"],
        artifact_sha256=dry["artifact_sha256"],
        target=dry["target"],
        risk_class="governance",
        jti="wydruk-webspace-once",
    )
    result = ensure_ftp_user(
        kind="system",
        domain="wydruk.subactor.com",
        webspace="subactor.com",
        base_url="https://prototypowanie.pl:8443",
        credential_vault_entry_id="plesk-sftp-wydruk-subactor-com",
        also_ftp_vault_entry_id="plesk-ftp-wydruk-subactor-com",
        apply=True,
        plan_hash=dry["plan_hash"],
        apply_grant=issued["grant"],
        actor="authority:founder",
        pack_id="plesk-deployment-credential",
        pack_version="1",
    )
    assert result["ok"] and result["webspace"] == "subactor.com"
    assert any("<name>subactor.com</name>" in packet for packet in calls)


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


def test_ensure_subdomain_is_dry_run_when_missing(monkeypatch):
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
    assert result["ok"] and result["created"] is False and result["dry_run"] is True
    assert result["www_root"] == "docs-stage.subactor.com"
    assert len(calls) == 1 and len(result["plan_hash"]) == 64


def test_ensure_subdomain_apply_requires_grant_and_verifies(monkeypatch):
    reset_default_jti_replay_store()
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_SUBDOMAIN_APPLY", "1")
    monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "subdomain-test-secret")
    monkeypatch.setattr(core, "_vault_lease", lambda *args, **kwargs: "vault-value")
    exists = {"value": False}

    def fake_xml(base_url, username, password, packet):
        compact = packet.replace("\n", "").replace(" ", "")
        if "<subdomain><get>" in compact:
            if exists["value"]:
                return "<packet><subdomain><get><result><status>ok</status><id>310</id></result></get></subdomain></packet>"
            return "<packet><subdomain><get><result><status>error</status></result></get></subdomain></packet>"
        assert "<subdomain><add>" in compact
        exists["value"] = True
        return "<packet><subdomain><add><result><status>ok</status><id>310</id></result></add></subdomain></packet>"

    monkeypatch.setattr(core, "_xml_agent", fake_xml)
    dry = ensure_subdomain(
        parent_domain="subactor.com", subdomain="docs-stage", base_url="https://prototypowanie.pl:8443",
    )
    issued = issue_apply_grant(
        run_id="subdomain-run", actor="test-actor", intent_pack="plesk-subdomain@1",
        plan_hash=dry["plan_hash"], artifact_sha256=dry["artifact_sha256"], target=dry["target"],
        risk_class="boundary", jti="subdomain-once",
        environ={"APPLY_GRANT_HMAC_SECRET": "subdomain-test-secret"},
    )
    result = ensure_subdomain(
        parent_domain="subactor.com", subdomain="docs-stage", apply=True,
        plan_hash=dry["plan_hash"], apply_grant=issued["grant"], actor="test-actor",
        pack_id="plesk-subdomain", pack_version="1", base_url="https://prototypowanie.pl:8443",
    )
    assert result["ok"] and result["created"] and result["verified"] and result["subdomain_id"] == 310


def _subscription_xml(limit="10", permission="true"):
    return (
        "<packet><webspace><get><result><status>ok</status><id>7</id>"
        f"<limits><limit><name>dom</name><value>{limit}</value></limit></limits>"
        f"<permissions><permission><name>manage_domains</name><value>{permission}</value></permission></permissions>"
        "</result></get></webspace></packet>"
    )


def _sites_xml(count=2):
    rows="".join(f"<result><status>ok</status><id>{index+10}</id></result>" for index in range(count))
    return f"<packet><site><get>{rows}</get></site></packet>"


def test_subscription_capability_reads_customer_scope_and_domain_limit(monkeypatch):
    calls=[]
    monkeypatch.setattr(core,"_vault_lease",lambda entry,origin,field,vault_url="": {"username":"customer","password":"pw"}[field])
    def fake_xml(base_url,username,password,packet):
        calls.append(packet)
        return _subscription_xml() if "<webspace>" in packet else _sites_xml(2)
    monkeypatch.setattr(core,"_xml_agent",fake_xml)
    result=subscription_capabilities(subscription="prototypowanie.pl",base_url="https://plesk.example.com:8443")
    assert result["ok"] and result["authenticated"] and result["can_create_domain"]
    assert result["domains_used"]==2 and result["domains_limit"]==10
    assert "pw" not in json.dumps(result) and len(calls)==2


def test_domain_ensure_dry_run_never_mutates(monkeypatch):
    calls=[]
    monkeypatch.setattr(core,"_vault_lease",lambda entry,origin,field,vault_url="": {"username":"customer","password":"pw"}[field])
    def fake_xml(base_url,username,password,packet):
        calls.append(packet)
        if "<webspace>" in packet:
            return _subscription_xml()
        if "<webspace-name>" in packet:
            return _sites_xml(1)
        return "<packet><site><get><result><status>error</status></result></get></site></packet>"
    monkeypatch.setattr(core,"_xml_agent",fake_xml)
    result=ensure_domain(domain="autonomicznosc.pl",subscription="prototypowanie.pl",apply=False,base_url="https://plesk.example.com:8443")
    assert result["ok"] and result["dry_run"] and result["authorized"] and not result["created"]
    assert all("<add>" not in packet for packet in calls)


def test_domain_ensure_fails_closed_at_capacity_or_apply_gate(monkeypatch):
    monkeypatch.delenv("AUTONOMY_MUTATIONS_ENABLED",raising=False)
    monkeypatch.delenv("PLESK_DOMAIN_APPLY",raising=False)
    monkeypatch.setattr(core,"_vault_lease",lambda entry,origin,field,vault_url="": {"username":"customer","password":"pw"}[field])
    def at_capacity(base_url,username,password,packet):
        if "<webspace>" in packet:
            return _subscription_xml(limit="1")
        if "<webspace-name>" in packet:
            return _sites_xml(1)
        return "<packet><site><get><result><status>error</status></result></get></site></packet>"
    monkeypatch.setattr(core,"_xml_agent",at_capacity)
    denied=ensure_domain(domain="autonomicznosc.pl",subscription="prototypowanie.pl",apply=False,base_url="https://plesk.example.com:8443")
    assert not denied["ok"] and "limit_reached" in denied["error"]
    def has_capacity(base_url,username,password,packet):
        if "<webspace>" in packet:
            return _subscription_xml(limit="2")
        if "<webspace-name>" in packet:
            return _sites_xml(1)
        return "<packet><site><get><result><status>error</status></result></get></site></packet>"
    monkeypatch.setattr(core,"_xml_agent",has_capacity)
    gated=ensure_domain(domain="autonomicznosc.pl",subscription="prototypowanie.pl",apply=True,base_url="https://plesk.example.com:8443")
    assert not gated["ok"] and gated["error"]=="plesk_domain_apply_gate_closed"


def test_domain_ensure_apply_creates_site_only_with_both_gates(monkeypatch):
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED","1")
    monkeypatch.setenv("PLESK_DOMAIN_APPLY","1")
    monkeypatch.setattr(core,"_vault_lease",lambda entry,origin,field,vault_url="": {"username":"customer","password":"pw"}[field])
    def fake_xml(base_url,username,password,packet):
        if "<site><add>" in packet:
            return "<packet><site><add><result><status>ok</status><id>99</id></result></add></site></packet>"
        if "<webspace>" in packet:
            return _subscription_xml(limit="2")
        if "<webspace-name>" in packet:
            return _sites_xml(1)
        return "<packet><site><get><result><status>error</status></result></get></site></packet>"
    monkeypatch.setattr(core,"_xml_agent",fake_xml)
    result=ensure_domain(domain="autonomicznosc.pl",subscription="prototypowanie.pl",apply=True,base_url="https://plesk.example.com:8443")
    assert result["ok"] and result["created"] and result["site_id"]==99 and not result["dry_run"]


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
    _ssl_dns_ready(monkeypatch)
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
    _ssl_dns_ready(monkeypatch)
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
    _ssl_dns_ready(monkeypatch)
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
    _ssl_dns_ready(monkeypatch)
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
    assert report["capabilities"]["extensions"]["available"] is True
    assert report["capabilities"]["extensions"]["detail"] == "xml_extension_get; profiled_execution_only"
    assert report["version"] == "0.14.0"


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


def test_resolve_release_write_path_redirects_to_current():
    write, extra = core._resolve_release_write_path("/docs.subactor.com", current_exists=True)
    assert write == "/docs.subactor.com/current"
    assert extra["release_layout_redirect"] == "current"
    assert extra["write_remote_path"] == write

    same, empty = core._resolve_release_write_path("/docs.subactor.com/current", current_exists=True)
    assert same == "/docs.subactor.com/current"
    assert empty == {}

    flat, empty2 = core._resolve_release_write_path("/httpdocs", current_exists=False)
    assert flat == "/httpdocs"
    assert empty2 == {}


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
    monkeypatch.setenv("URIRUN_VAULT_TOKEN_REF", "getv://URIRUN_VAULT_TOKEN")
    vault_url = f"http://127.0.0.1:{vault.server_port}"
    plesk_url = f"http://127.0.0.1:{plesk.server_port}"
    try:
        monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
        monkeypatch.setenv("PLESK_API_KEY_APPLY", "1")
        monkeypatch.setenv("APPLY_GRANT_HMAC_SECRET", "bootstrap-integration-secret")
        dry = bootstrap_api_key(base_url=plesk_url, vault_url=vault_url)
        issued = issue_apply_grant(
            run_id="PLF-bootstrap-integration",
            actor="authority:founder",
            intent_pack="plesk-api-key-bootstrap@1",
            plan_hash=dry["plan_hash"],
            artifact_sha256=dry["artifact_sha256"],
            target=dry["target"],
            risk_class="governance",
        )
        bootstrap = bootstrap_api_key(
            base_url=plesk_url,
            vault_url=vault_url,
            apply=True,
            plan_hash=dry["plan_hash"],
            apply_grant=issued["grant"],
            actor="authority:founder",
            pack_id="plesk-api-key-bootstrap",
            pack_version="1",
        )
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


def test_site_sync_requires_and_revalidates_portable_deployment_binding(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    binding = {
        "id": "deployment:autonomicznosc-pl:production",
        "environment": "production",
        "source_ref": "workspace:autonomicznosc-pl",
        "provider": "plesk",
        "connector_uri": "plesk://host/site/command/sync",
        "target": {
            "domain": "autonomicznosc.pl",
            "webspace": "autonomicznosc.pl",
            "transport_host": "prototypowanie.pl",
            "credential_origin": "https://prototypowanie.pl",
            "remote_path": "/var/www/vhosts/autonomicznosc.pl/httpdocs",
            "effective_docroot": "/httpdocs",
            "path_mode": "absolute-vhost",
            "docroot_main_domain": "autonomicznosc.pl",
        },
        "credential_refs": {
            "sftp": "plesk-sftp-autonomicznosc-pl",
            "ftp": "plesk-ftp-autonomicznosc-pl",
        },
        "verification": {"url": "https://autonomicznosc.pl/", "mode": "sha256", "entrypoint": "index.html"},
    }
    registry_path = tmp_path / "deployment-bindings.json"
    registry_path.write_text(json.dumps({"schema": "subactor.deployment-bindings/v1", "version": 1, "bindings": [binding]}), encoding="utf-8")
    source_registry_path = tmp_path / "site-resources.json"
    source_registry_path.write_text(json.dumps({
        "schema": "subactor.site-resources.v1",
        "version": 1,
        "resources": [{"id": binding["source_ref"], "path": str(www), "domain": binding["target"]["domain"]}],
    }), encoding="utf-8")
    monkeypatch.setenv("PLESK_DEPLOYMENT_BINDING_REQUIRED", "1")
    monkeypatch.setenv("PLESK_DEPLOYMENT_BINDINGS_PATH", str(registry_path))
    monkeypatch.setenv("PLESK_SITE_RESOURCES_PATH", str(source_registry_path))
    monkeypatch.setenv("PLESK_SYNC_ALLOWED_SOURCES", str(tmp_path))
    digest = core._deployment_binding_digest(binding)
    payload = {
        "source_dir": str(www),
        "source_ref": binding["source_ref"],
        "deployment_binding_ref": binding["id"],
        "deployment_binding_hash": digest,
        "deployment_binding_version": 1,
        "remote_path": binding["target"]["remote_path"],
        "host": binding["target"]["transport_host"],
        "domain": binding["target"]["domain"],
        "deployment_webspace": binding["target"]["webspace"],
        "credential_origin": binding["target"]["credential_origin"],
        "sftp_vault_entry_id": binding["credential_refs"]["sftp"],
        "ftp_vault_entry_id": binding["credential_refs"]["ftp"],
    }

    monkeypatch.setattr(core, "_vault_settings", lambda _vault_url="": ("http://vault", "token"))
    monkeypatch.setattr(
        core,
        "_request_json",
        lambda *args, **kwargs: (404, {"ok": False, "error": "vault_entry_not_found"}),
    )
    not_ready = site_sync(**payload)
    assert not_ready["ok"] is False
    assert not_ready["error"] == "deployment_credentials_not_ready"
    assert not_ready["mutation_attempted"] is False
    assert {item["entry_id"] for item in not_ready["credential_preflight"]["entries"]} == {
        binding["credential_refs"]["sftp"], binding["credential_refs"]["ftp"],
    }

    monkeypatch.setattr(
        core,
        "_request_json",
        lambda *args, **kwargs: (200, {
            "ok": True,
            "scope": {"operations": ["plesk.site.sync"], "targets": ["domain:autonomicznosc.pl"]},
        }),
    )
    accepted = site_sync(**payload)
    assert accepted["ok"] is True and accepted["dry_run"] is True

    missing = site_sync(source_dir=str(www), remote_path=payload["remote_path"], host=payload["host"], domain=payload["domain"])
    assert missing["ok"] is False
    assert missing["error"] == "plesk_site_deployment_binding_required"

    changed = site_sync(**{**payload, "remote_path": "/httpdocs"})
    assert changed["ok"] is False
    assert changed["error"] == "plesk_site_deployment_binding_target_mismatch"
    assert changed["mutation_attempted"] is False

    changed_webspace = site_sync(**{**payload, "deployment_webspace": "other.example"})
    assert changed_webspace["ok"] is False
    assert changed_webspace["error"] == "plesk_site_deployment_binding_target_mismatch"
    assert changed_webspace["mutation_attempted"] is False

    invalid_version = site_sync(**{**payload, "deployment_binding_version": "not-a-version"})
    assert invalid_version["ok"] is False
    assert invalid_version["error"] == "plesk_site_deployment_binding_version_mismatch"
    assert invalid_version["mutation_attempted"] is False

    other_source = tmp_path / "wrong-site"
    other_source.mkdir()
    _seed_site(other_source)
    changed_source = site_sync(**{**payload, "source_dir": str(other_source)})
    assert changed_source["ok"] is False
    assert changed_source["error"] == "plesk_site_source_path_mismatch"
    assert changed_source["mutation_attempted"] is False


def test_site_twin_sync_materializes_verified_release_without_vault_or_network(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    binding = {
        "id": "deployment:autonomicznosc-pl:production",
        "environment": "production",
        "source_ref": "workspace:autonomicznosc-pl",
        "provider": "plesk",
        "connector_uri": "plesk://host/site/command/sync",
        "target": {"domain": "autonomicznosc.pl"},
    }
    binding_hash = core._deployment_binding_digest(binding)
    profile = {
        "id": "deployment-twin:autonomicznosc-pl",
        "source_ref": binding["source_ref"],
        "production_binding_ref": binding["id"],
        "production_binding_hash": binding_hash,
        "connector_uri": "plesk://host/site/command/twin-sync",
        "adapter": "local-release-fs",
        "runtime_root_ref": "twin-volume:plesk",
        "isolation": {"network_access": "none", "production_credentials": "forbidden", "writable_scope": "runtime-root-only"},
        "target": {
            "domain": "autonomicznosc-pl.twin.test",
            "remote_path": "/var/www/vhosts/autonomicznosc-pl.twin.test/httpdocs",
            "effective_docroot": "/httpdocs",
        },
        "verification": {"mode": "sha256", "entrypoint": "index.html", "require_source_release_match": True},
    }
    profile_hash = core._deployment_binding_digest(profile)
    deployment_registry = tmp_path / "deployment-bindings.json"
    deployment_registry.write_text(json.dumps({
        "schema": "subactor.deployment-bindings/v1", "version": 1, "bindings": [binding],
    }), encoding="utf-8")
    twin_registry = tmp_path / "deployment-twins.json"
    twin_registry.write_text(json.dumps({
        "schema": "subactor.deployment-twin-profiles/v1", "version": 1, "profiles": [profile],
    }), encoding="utf-8")
    source_registry = tmp_path / "site-resources.json"
    source_registry.write_text(json.dumps({
        "schema": "subactor.site-resources.v1", "version": 1,
        "resources": [{"id": binding["source_ref"], "path": str(www)}],
    }), encoding="utf-8")
    twin_root = tmp_path / "twin"
    monkeypatch.setenv("PLESK_DEPLOYMENT_BINDINGS_PATH", str(deployment_registry))
    monkeypatch.setenv("PLESK_TWIN_PROFILES_PATH", str(twin_registry))
    monkeypatch.setenv("PLESK_SITE_RESOURCES_PATH", str(source_registry))
    monkeypatch.setenv("PLESK_SYNC_ALLOWED_SOURCES", str(tmp_path))
    monkeypatch.setenv("PLESK_TWIN_ROOT", str(twin_root))
    monkeypatch.setenv("PLESK_TWIN_APPLY_ENABLED", "1")
    monkeypatch.setattr(core, "_vault_lease", lambda *_args: pytest.fail("twin must not lease production credentials"))
    payload = {
        "source_dir": str(www),
        "source_ref": binding["source_ref"],
        "deployment_binding_ref": binding["id"],
        "deployment_binding_hash": binding_hash,
        "deployment_binding_version": 1,
        "twin_profile_ref": profile["id"],
        "twin_profile_hash": profile_hash,
        "twin_profile_version": 1,
    }

    dry = site_twin_sync(**payload)
    assert dry["ok"] is True and dry["dry_run"] is True and dry["executed"] is False
    assert dry["execution_plane"] == "digital-twin"
    assert not twin_root.exists()

    mismatch = site_twin_sync(**payload, apply=True, plan_hash="0" * 64)
    assert mismatch["ok"] is False and mismatch["reason"] == "plan_hash_mismatch"
    assert mismatch["mutation_attempted"] is False
    assert not twin_root.exists()

    applied = site_twin_sync(**payload, apply=True, plan_hash=dry["plan_hash"])
    assert applied["ok"] is True and applied["executed"] is True and applied["verified"] is True
    assert applied["transport"] == "local-release-fs"
    assert applied["verification"]["source_matches_release"] is True
    assert applied["verification"]["entrypoint_sha256"] == next(
        item["sha256"] for item in dry["plan"] if item["path"] == "index.html"
    )
    current = twin_root / "var/www/vhosts/autonomicznosc-pl.twin.test/httpdocs/current"
    assert current.is_symlink()
    assert (current / "index.html").read_text(encoding="utf-8") == "<h1>subactor</h1>"
    assert len(applied["receipt"]["receipt_sha256"]) == 64

    observed = site_twin_current(**payload)
    assert observed["ok"] is True and observed["verified"] is True
    assert observed["current"] == applied["release"]["release_id"]
    assert observed["twin_fact"]["twin_type"] == "plesk.site.deployment"
    assert observed["twin_fact"]["payload"]["source_matches_release"] is True


def test_site_twin_sync_refuses_untrusted_profile_before_writing(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    binding = {
        "id": "deployment:site:production", "environment": "production",
        "source_ref": "workspace:site", "provider": "plesk",
        "connector_uri": "plesk://host/site/command/sync", "target": {"domain": "site.example"},
    }
    binding_hash = core._deployment_binding_digest(binding)
    profile = {
        "id": "deployment-twin:site", "source_ref": "workspace:site",
        "production_binding_ref": binding["id"], "production_binding_hash": binding_hash,
        "connector_uri": "plesk://host/site/command/twin-sync", "adapter": "local-release-fs",
        "runtime_root_ref": "twin-volume:plesk",
        "isolation": {"network_access": "none", "production_credentials": "forbidden", "writable_scope": "runtime-root-only"},
        "target": {"domain": "site.example.com", "remote_path": "/var/www/vhosts/site.example.com/httpdocs", "effective_docroot": "/httpdocs"},
        "verification": {"mode": "sha256", "entrypoint": "index.html", "require_source_release_match": True},
    }
    deployment_registry = tmp_path / "bindings.json"
    deployment_registry.write_text(json.dumps({"schema": "subactor.deployment-bindings/v1", "version": 1, "bindings": [binding]}))
    twin_registry = tmp_path / "twins.json"
    twin_registry.write_text(json.dumps({"schema": "subactor.deployment-twin-profiles/v1", "version": 1, "profiles": [profile]}))
    source_registry = tmp_path / "sources.json"
    source_registry.write_text(json.dumps({"schema": "subactor.site-resources.v1", "version": 1, "resources": [{"id": "workspace:site", "path": str(www)}]}))
    twin_root = tmp_path / "twin"
    monkeypatch.setenv("PLESK_DEPLOYMENT_BINDINGS_PATH", str(deployment_registry))
    monkeypatch.setenv("PLESK_TWIN_PROFILES_PATH", str(twin_registry))
    monkeypatch.setenv("PLESK_SITE_RESOURCES_PATH", str(source_registry))
    monkeypatch.setenv("PLESK_SYNC_ALLOWED_SOURCES", str(tmp_path))
    monkeypatch.setenv("PLESK_TWIN_ROOT", str(twin_root))
    result = site_twin_sync(
        source_dir=str(www), source_ref="workspace:site",
        deployment_binding_ref=binding["id"], deployment_binding_hash=binding_hash,
        deployment_binding_version=1, twin_profile_ref=profile["id"],
        twin_profile_hash=core._deployment_binding_digest(profile), twin_profile_version=1,
    )
    assert result["ok"] is False and result["error"] == "plesk_site_twin_domain_required"
    assert result["mutation_attempted"] is False and not twin_root.exists()


def test_site_sync_rejects_ambiguous_httpdocs_for_unbound_domain(tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)

    result = site_sync(
        source_dir=str(www),
        remote_path="/httpdocs",
        host="prototypowanie.pl",
        domain="autonomicznosc.pl",
        credential_origin="https://prototypowanie.pl",
    )

    assert result["ok"] is False
    assert result["error"] == "plesk_site_sync_scope_unbound"
    assert result["mutation_attempted"] is False


def test_site_sync_rejects_httpdocs_when_only_entry_names_bind_domain(tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)

    result = site_sync(
        source_dir=str(www),
        remote_path="/httpdocs",
        host="prototypowanie.pl",
        domain="autonomicznosc.pl",
        credential_origin="https://prototypowanie.pl",
        sftp_vault_entry_id="plesk-sftp-autonomicznosc-pl",
        ftp_vault_entry_id="plesk-ftp-autonomicznosc-pl",
    )

    assert result["ok"] is False
    assert result["error"] == "plesk_site_sync_scope_unbound"
    assert result["mutation_attempted"] is False


def test_site_sync_rejects_unbound_chroot_root(tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)

    result = site_sync(
        source_dir=str(www),
        remote_path="/",
        host="prototypowanie.pl",
        domain="autonomicznosc.pl",
        credential_origin="https://prototypowanie.pl",
    )

    assert result["ok"] is False
    assert result["error"] == "plesk_site_sync_scope_mismatch"
    assert result["mutation_attempted"] is False


def test_site_sync_rejects_chroot_root_even_with_domain_bound_transport_entries(tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)

    result = site_sync(
        source_dir=str(www),
        remote_path="/",
        host="prototypowanie.pl",
        domain="autonomicznosc.pl",
        credential_origin="https://prototypowanie.pl",
        sftp_vault_entry_id="plesk-sftp-autonomicznosc-pl",
        ftp_vault_entry_id="plesk-ftp-autonomicznosc-pl",
    )

    assert result["ok"] is False
    assert result["error"] == "plesk_site_sync_scope_mismatch"
    assert result["mutation_attempted"] is False


def test_site_sync_accepts_generic_httpdocs_only_with_vault_domain_scope(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    monkeypatch.setattr(core, "_vault_settings", lambda _url="": ("https://vault.example", "service-token"))
    monkeypatch.setattr(core, "_request_json", lambda *args, **kwargs: (200, {
        "ok": True,
        "scope": {"operations": ["plesk.site.sync"], "targets": ["domain:subactor.com"]},
    }))

    result = site_sync(
        source_dir=str(www),
        remote_path="/httpdocs",
        host="prototypowanie.pl",
        domain="subactor.com",
        credential_origin="https://prototypowanie.pl",
    )

    assert result["ok"] is True
    assert result["dry_run"] is True


def test_site_sync_rejects_absolute_vhost_path_for_another_domain(tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)

    result = site_sync(
        source_dir=str(www),
        remote_path="/var/www/vhosts/subactor.com/httpdocs",
        host="prototypowanie.pl",
        domain="autonomicznosc.pl",
    )

    assert result["ok"] is False
    assert result["error"] == "plesk_site_sync_scope_mismatch"


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
    assert result["schema"] == CONNECTOR_RESULT_SCHEMA
    assert result["reason_code"] == "AUTHORITY_REQUIRED"
    assert result["executed"] is False
    assert result["verified"] is False
    assert result["mutation_attempted"] is False
    assert result["files_uploaded"] == 0
    assert result["bytes_uploaded"] == 0


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
    with pytest.raises(RuntimeError, match="plesk_vault_token_rejected"):
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
    result = site_sync(source_dir=str(docs), host="prototypowanie.pl", domain="docs.subactor.com", remote_path="/docs.subactor.com")
    assert result["ok"] and result["dry_run"] is True
    assert result["files_planned"] == 1
    assert result.get("domain") == "docs.subactor.com"


def test_site_sync_allows_logo_basename(tmp_path):
    logo = tmp_path / "logo"
    logo.mkdir()
    (logo / "index.html").write_text("<h1>logo</h1>", encoding="utf-8")
    result = site_sync(source_dir=str(logo), host="prototypowanie.pl", domain="logo.subactor.com", remote_path="/logo.subactor.com")
    assert result["ok"] and result["dry_run"] is True
    assert result["files_planned"] == 1
    assert result.get("domain") == "logo.subactor.com"


def test_site_sync_allows_sanitized_public_status_basename(tmp_path):
    status = tmp_path / "public-status"
    status.mkdir()
    (status / "health.php").write_text("<?php echo '{}';", encoding="utf-8")
    result = site_sync(source_dir=str(status), host="prototypowanie.pl", domain="status.subactor.com", remote_path="/status.subactor.com")
    assert result["ok"] and result["dry_run"] is True
    assert result["files_planned"] == 1


def _ssl_dns_ready(monkeypatch):
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.tls_dns_preflight",
        lambda hostname, expected_origin="": {
            "schema": "urirun.plesk-tls-dns-preflight/v1",
            "hostname": hostname,
            "ready": True,
            "root_cause": None,
            "addresses": [expected_origin] if expected_origin else ["203.0.113.10"],
            "expected_origin": expected_origin or None,
            "origin_matches": True,
            "blocks": [],
            "next_action": None,
            "observations": [],
        },
    )


def _ssl_apply_env(monkeypatch, probe_results):
    """Common wiring for a full ssl-ensure ladder run under apply."""
    monkeypatch.setenv("AUTONOMY_MUTATIONS_ENABLED", "1")
    monkeypatch.setenv("PLESK_SSL_APPLY", "1")
    monkeypatch.setattr(
        core,
        "_vault_lease",
        lambda entry, origin, field, vault_url="": {
            "username": "cust", "password": "cust-pass", "api_key": "admin-key"
        }[field],
    )
    probes = iter(probe_results)
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.origin_tls_probe", lambda **kwargs: next(probes)
    )
    _ssl_dns_ready(monkeypatch)
    monkeypatch.setattr("urirun_connector_plesk.ssl_ops.resolve_site_id", lambda **kwargs: 308)


def test_tls_dns_preflight_identifies_missing_name_as_the_root_cause():
    def missing(_host, record_type, _expected):
        return {
            "observations": [
                {"resolver": "cloudflare", "ok": False, "records": [], "error": "dns_name_not_found"},
                {"resolver": "google", "ok": False, "records": [], "error": "dns_name_not_found"},
                {"resolver": "runtime-system", "ok": False, "records": [], "error": "dns_system_resolver_failed"},
            ],
            "record_type": record_type,
        }

    result = tls_dns_preflight("www.subactor.com", "217.160.250.222", resolver=missing)
    assert result["ready"] is False
    assert result["root_cause"] == "dns_name_missing"
    assert result["blocks"] == ["acme_domain_validation", "tls_certificate_issuance"]
    assert result["next_action"]["payload"]["host"] == "www.subactor.com"


def test_ensure_ssl_stops_before_tls_or_acme_when_public_dns_is_missing(monkeypatch):
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.tls_dns_preflight",
        lambda *_args, **_kwargs: {
            "ready": False,
            "root_cause": "dns_name_missing",
            "blocks": ["acme_domain_validation", "tls_certificate_issuance"],
            "next_action": {"uri": "plesk://host/dns/query/propagation"},
        },
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.origin_tls_probe",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("TLS probe must wait for DNS")),
    )
    result = ensure_ssl(
        hostname="www.subactor.com",
        origin_ip="217.160.250.222",
        base_url="https://prototypowanie.pl:8443",
        apply=True,
    )
    assert result["ok"] is False
    assert result["error"] == "plesk_ssl_dns_dependency_blocked"
    assert result["root_cause"] == "dns_name_missing"
    assert result["mutation_attempted"] is False


def test_ensure_ssl_auto_walks_ladder_until_a_strategy_covers_the_host(monkeypatch):
    """auto: assign → panel PEM → SSL It LE; the first success wins and is re-probed."""
    mismatch = {"ok": False, "sans": [], "error": "tls_san_mismatch"}
    covered = {"ok": True, "sans": ["docs.subactor.com"], "error": None}
    # initial probe, per-assign-attempt probes are not reached (assign fails), final re-probe
    _ssl_apply_env(monkeypatch, [mismatch, covered])
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.assign_certificate",
        lambda **kwargs: {"ok": False, "strategy": "assign", "error": "certificate_not_found"},
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.panel_login",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("panel_login_failed")),
    )
    called = {}

    def fake_rest_cli(**kwargs):
        called["api_key"] = kwargs["api_key"]
        return {"ok": True, "strategy": "rest_cli_le", "certificate_name": "Lets Encrypt docs.subactor.com"}

    monkeypatch.setattr("urirun_connector_plesk.ssl_ops.rest_cli_letsencrypt", fake_rest_cli)

    result = ensure_ssl(
        hostname="docs.subactor.com",
        origin_ip="217.160.250.222",
        base_url="https://prototypowanie.pl:8443",
        apply=True,
    )
    assert result["ok"] is True and result["strategy"] == "rest_cli_le"
    assert result["created"] is True and result["probe"] == covered
    assert called["api_key"] == "admin-key"
    # every rung that ran is logged in order, panel failures included
    strategies = [a.get("strategy") for a in result["attempts"]]
    assert strategies[:3] == ["assign", "assign", "assign"]      # cert-name candidates
    assert "panel_upload_pem" in strategies and "rest_cli_le" in strategies


def test_ensure_ssl_auto_reports_hitl_when_every_strategy_fails(monkeypatch):
    """Exhausted ladder fails closed with the panel action a human has to take."""
    mismatch = {"ok": False, "sans": [], "error": "tls_san_mismatch"}
    _ssl_apply_env(monkeypatch, [mismatch])
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.assign_certificate",
        lambda **kwargs: {"ok": False, "strategy": "assign", "error": "certificate_not_found"},
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.panel_login",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("panel_login_failed")),
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.rest_cli_letsencrypt",
        lambda **kwargs: {"ok": False, "strategy": "rest_cli_le", "error": "le_domain_only",
                          "detail": "wildcard not allowed"},
    )

    result = ensure_ssl(
        hostname="docs.subactor.com",
        origin_ip="217.160.250.222",
        base_url="https://prototypowanie.pl:8443",
        apply=True,
    )
    assert result["ok"] is False and result["error"] == "le_domain_only"
    assert result["san_mode"] == "domain_only" and result["hitl"]
    assert result["site_id"] == 308


def test_ensure_ssl_explicit_provider_does_not_fall_through(monkeypatch):
    """provider=panel-pem stops at its own rung instead of trying Let's Encrypt."""
    mismatch = {"ok": False, "sans": [], "error": "tls_san_mismatch"}
    _ssl_apply_env(monkeypatch, [mismatch])
    monkeypatch.setattr(
        "urirun_connector_plesk.ssl_ops.panel_login",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("panel_login_failed")),
    )

    def unreachable(**kwargs):  # pragma: no cover - must not run
        raise AssertionError("letsencrypt attempted for provider=panel-pem")

    monkeypatch.setattr("urirun_connector_plesk.ssl_ops.panel_sslit_letsencrypt", unreachable)
    monkeypatch.setattr("urirun_connector_plesk.ssl_ops.rest_cli_letsencrypt", unreachable)

    result = ensure_ssl(
        hostname="docs.subactor.com",
        origin_ip="217.160.250.222",
        base_url="https://prototypowanie.pl:8443",
        apply=True,
        provider="panel-pem",
    )
    assert result["ok"] is False and result["error"] == "plesk_ssl_panel_upload_failed"


def test_site_query_docroot_emits_twin_fact_from_xml(monkeypatch):
    xml = """<?xml version="1.0"?>
    <packet><site><get><result><status>ok</status>
    <data><hosting><vrt_hst>
    <property><name>www_root</name><value>/var/www/vhosts/subactor.com/docs.subactor.com</value></property>
    </vrt_hst></hosting></data></result></get></site></packet>"""
    monkeypatch.setattr(
        "urirun_connector_plesk.core._vault_lease",
        lambda *args, **kwargs: "secret",
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.core._xml_agent",
        lambda *args, **kwargs: xml,
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.core._base_url",
        lambda _url: "https://plesk.example.test:8443",
    )
    result = site_query_docroot(
        domain="docs.subactor.com",
        host="subactor.com",
        main_domain="subactor.com",
        declared="/docs.subactor.com",
        instance_id="panel-demo",
        base_url="https://plesk.example.test:8443",
    )
    assert result["ok"] is True
    assert result["mutation_attempted"] is False
    assert result["fact_quality"] == "fresh"
    assert result["authority"] == "observed"
    fact = result["twin_fact"]
    assert fact["schema"] == "subactor.twin-fact/v1"
    assert fact["twin_type"] == "plesk.site.docroot"
    assert fact["uri"] == "plesk://host/site/query/docroot"
    assert fact["payload"]["observed_docroot"] == "/docs.subactor.com"
    assert fact["snapshot_hash"].startswith("sha256:")


def test_site_query_docroot_strips_release_current_symlink(monkeypatch):
    xml = """<?xml version="1.0"?>
    <packet><site><get><result><status>ok</status>
    <data><hosting><vrt_hst>
    <property><name>www_root</name>
    <value>/var/www/vhosts/subactor.com/docs.subactor.com/current</value></property>
    </vrt_hst></hosting></data></result></get></site></packet>"""
    monkeypatch.setattr(
        "urirun_connector_plesk.core._vault_lease",
        lambda *args, **kwargs: "secret",
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.core._xml_agent",
        lambda *args, **kwargs: xml,
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.core._base_url",
        lambda _url: "https://plesk.example.test:8443",
    )
    # No main_domain — must still resolve domain folder, not trailing "current".
    result = site_query_docroot(
        domain="docs.subactor.com",
        declared="/docs.subactor.com",
        base_url="https://plesk.example.test:8443",
    )
    assert result["ok"] is True
    assert result["authority"] == "observed"
    assert result["twin_fact"]["payload"]["observed_docroot"] == "/docs.subactor.com"
    assert result["twin_fact"]["payload"]["decision"] == "accept"


def test_site_query_docroot_main_domain_uses_httpdocs(monkeypatch):
    xml = """<?xml version="1.0"?>
    <packet><site><get><result><status>ok</status>
    <data><hosting><vrt_hst>
    <property><name>www_root</name>
    <value>/var/www/vhosts/subactor.com/httpdocs</value></property>
    </vrt_hst></hosting></data></result></get></site></packet>"""
    monkeypatch.setattr(
        "urirun_connector_plesk.core._vault_lease",
        lambda *args, **kwargs: "secret",
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.core._xml_agent",
        lambda *args, **kwargs: xml,
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.core._base_url",
        lambda _url: "https://plesk.example.test:8443",
    )
    result = site_query_docroot(
        domain="subactor.com",
        main_domain="subactor.com",
        declared="/httpdocs",
        base_url="https://plesk.example.test:8443",
    )
    assert result["ok"] is True
    assert result["twin_fact"]["payload"]["observed_docroot"] == "/httpdocs"
    assert result["twin_fact"]["payload"]["decision"] == "accept"
    assert result["twin_fact"]["payload"]["rule_docroot"] == "/httpdocs"


def test_site_query_docroot_accepts_same_domain_absolute_vhost_path(monkeypatch):
    xml = """<?xml version="1.0"?>
    <packet><site><get><result><status>ok</status>
    <data><hosting><vrt_hst>
    <property><name>www_root</name>
    <value>/var/www/vhosts/autonomicznosc.pl/httpdocs</value></property>
    </vrt_hst></hosting></data></result></get></site></packet>"""
    monkeypatch.setattr("urirun_connector_plesk.core._vault_lease", lambda *args, **kwargs: "secret")
    monkeypatch.setattr("urirun_connector_plesk.core._xml_agent", lambda *args, **kwargs: xml)
    monkeypatch.setattr("urirun_connector_plesk.core._base_url", lambda _url: "https://plesk.example.test:8443")

    result = site_query_docroot(
        domain="autonomicznosc.pl",
        main_domain="autonomicznosc.pl",
        declared="/var/www/vhosts/autonomicznosc.pl/httpdocs",
        base_url="https://plesk.example.test:8443",
    )

    payload = result["twin_fact"]["payload"]
    assert result["ok"] is True
    assert payload["decision"] == "accept"
    assert payload["declared_effective_docroot"] == "/httpdocs"
    assert payload["expected_remote_path"] == "/var/www/vhosts/autonomicznosc.pl/httpdocs"


def test_site_query_docroot_estimates_when_panel_unreachable(monkeypatch):
    monkeypatch.setattr(
        "urirun_connector_plesk.core._vault_lease",
        lambda *args, **kwargs: "secret",
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.core._xml_agent",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("plesk_xml_transport_failed")),
    )
    monkeypatch.setattr(
        "urirun_connector_plesk.core._base_url",
        lambda _url: "https://plesk.example.test:8443",
    )
    result = site_query_docroot(domain="docs.subactor.com", main_domain="subactor.com")
    assert result["ok"] is True
    assert result["fact_quality"] == "estimated"
    assert result["authority"] == "rule"
    assert result["twin_fact"]["payload"]["rule_docroot"] == "/docs.subactor.com"
