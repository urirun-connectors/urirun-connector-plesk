from __future__ import annotations

import json

from urirun_connector_plesk import dns_providers


def test_authority_requires_two_resolvers_to_agree(monkeypatch):
    monkeypatch.setattr(
        dns_providers,
        "_doh_nameservers",
        lambda zone, endpoint: ["alice.ns.cloudflare.com", "bob.ns.cloudflare.com"],
    )
    result = dns_providers.resolve_dns_authority("example.com")
    assert result["consistent"] is True
    assert result["provider"] == "cloudflare"
    assert len(result["observations"]) == 2


def test_authority_disagreement_fails_closed(monkeypatch):
    monkeypatch.setattr(
        dns_providers,
        "_doh_nameservers",
        lambda zone, endpoint: (["alice.ns.cloudflare.com"] if "cloudflare" in endpoint else ["ns1.example.net"]),
    )
    result = dns_providers.resolve_dns_authority("example.com")
    assert result["consistent"] is False
    assert result["provider"] == "inconsistent"
    assert result["nameservers"] == []


def test_propagation_compares_values_but_reports_ttl_range(monkeypatch):
    ttls = iter((120, 300))
    monkeypatch.setattr(
        dns_providers,
        "_doh_records",
        lambda name, record_type, endpoint: [{"value": "192.0.2.10", "ttl": next(ttls)}],
    )
    result = dns_providers.resolve_dns_propagation("status.example.com", "A", "192.0.2.10")
    assert result["consensus"] and result["propagated"]
    assert result["ttl_min"] == 120 and result["ttl_max"] == 300


def test_cloudflare_record_query_verifies_zone_and_redacts_token(monkeypatch):
    calls = []

    def fake_request(url, **kwargs):
        calls.append((url, kwargs))
        if url.endswith("/zones/" + "a" * 32):
            return 200, {"success": True, "result": {"name": "example.com"}}
        return 200, {"success": True, "result": [{
            "id": "b" * 32, "name": "status.example.com", "type": "A",
            "content": "192.0.2.10", "ttl": 300, "proxied": False,
        }]}

    monkeypatch.setattr(dns_providers, "_json_request", fake_request)
    rows = dns_providers.cloudflare_records("a" * 32, "example.com", "status.example.com", "secret")
    assert rows[0]["value"] == "192.0.2.10"
    assert all(call[1]["headers"]["authorization"] == "Bearer secret" for call in calls)
    assert "secret" not in json.dumps(rows)


def test_cloudflare_batch_deletes_conflicts_before_create(monkeypatch):
    sent = {}
    monkeypatch.setattr(
        dns_providers,
        "_json_request",
        lambda url, **kwargs: sent.update(url=url, **kwargs) or (200, {"success": True}),
    )
    plan = dns_providers.cloudflare_plan(
        "example.com", "status.example.com", "A", "192.0.2.10",
        [{
            "id": "b" * 32, "host": "status.example.com", "type": "CNAME",
            "value": "old.example.net", "ttl": 1, "proxied": False,
        }],
    )
    dns_providers.apply_cloudflare_plan("a" * 32, "secret", plan)
    assert sent["method"] == "POST" and sent["url"].endswith("/dns_records/batch")
    assert sent["body"]["deletes"] == [{"id": "b" * 32}]
    assert sent["body"]["posts"][0]["content"] == "192.0.2.10"
