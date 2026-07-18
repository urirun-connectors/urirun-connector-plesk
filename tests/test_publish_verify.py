"""PR8 publish verify ladder tests (mocked DNS/TLS/HTTP — no live docs.subactor.com)."""
from __future__ import annotations

import json

from urirun_connector_plesk.verify_ladder import (
    DNS_MISMATCH,
    FINGERPRINT_STALE,
    HTTPS_STATUS_UNEXPECTED,
    TLS_SAN_MISMATCH,
    VerifyExpectation,
    compare_fingerprints,
    curl_resolve_hint,
    hostname_matches_san,
    run_publish_verify_ladder,
)
from urirun_connector_plesk.core import publish_verify as publish_verify_handler
from urirun_connector_plesk.release_ops import build_release_meta


def _marker(**overrides):
    base = {
        "release_id": "rel_new",
        "artifact_sha256": "abc123",
        "source_commit": "deadbeef",
        "built_at": "2026-07-18T00:00:00Z",
        "pack_version": "1",
        "cache_control": "no-store",
    }
    base.update(overrides)
    return base


def _fetch_factory(payload: dict, *, status: int = 200, cache_control: str = "no-store"):
    body = json.dumps(payload).encode()

    def fetcher(url, *, host_header="", resolve_ip="", timeout=10.0):
        return {
            "ok": status == 200,
            "status": status,
            "body": body,
            "cache_control": cache_control,
            "url": url,
            "resolved_to": resolve_ip or None,
            "error": None if status == 200 else HTTPS_STATUS_UNEXPECTED,
        }

    return fetcher


def test_build_release_meta_emits_adr004_fields():
    meta = build_release_meta(
        release_id="rel_x",
        plan_hash="ph",
        host="h",
        git_commit="cafebabe",
        pack_version="2",
        files=[{"path": "a", "sha256": "11"}],
    )
    assert meta["release_id"] == "rel_x"
    assert meta["artifact_sha256"]
    assert meta["source_commit"] == "cafebabe"
    assert meta["pack_version"] == "2"
    assert meta["built_at"]
    assert meta["cache_control"] == "no-store"
    assert meta["content_sha256"] == meta["artifact_sha256"]
    assert meta["git_commit"] == "cafebabe"


def test_compare_stale_fingerprint():
    expected = VerifyExpectation(release_id="rel_new", artifact_sha256="abc123")
    observed = _marker(release_id="rel_old", artifact_sha256="old")
    out = compare_fingerprints(expected, observed)
    assert out["ok"] is False
    assert out["error"] == FINGERPRINT_STALE


def test_hostname_matches_san_wildcard():
    assert hostname_matches_san("docs.subactor.com", ["*.subactor.com"])
    assert not hostname_matches_san("subactor.com", ["*.subactor.com"])
    assert hostname_matches_san("docs.subactor.com", ["docs.subactor.com"])


def test_ladder_stale_dns():
    expected = VerifyExpectation(
        release_id="rel_new",
        artifact_sha256="abc123",
        dns_targets=["203.0.113.10"],
        tls_hostname="docs.subactor.com",
    )
    out = run_publish_verify_ladder(
        hostname="docs.subactor.com",
        expected=expected,
        origin_ip="203.0.113.10",
        check_origin=False,
        check_public=False,
        check_tls_step=False,
        public_resolver=lambda h: ["185.199.108.153"],
        authoritative_resolver=lambda h: ["185.199.108.153"],
        release_files_ok=True,
    )
    assert out["ok"] is False
    assert out["status"] == "applied_unverified"
    assert out["error"] == DNS_MISMATCH


def test_ladder_bad_san():
    expected = VerifyExpectation(
        release_id="rel_new",
        artifact_sha256="abc123",
        tls_hostname="docs.subactor.com",
    )
    out = run_publish_verify_ladder(
        hostname="docs.subactor.com",
        expected=expected,
        origin_ip="203.0.113.10",
        check_origin=False,
        check_public=False,
        check_dns_step=False,
        tls_inspector=lambda host, port, sni: {
            "ok": True,
            "sans": ["wrong.example", "pages.github.io"],
        },
        release_files_ok=True,
    )
    assert out["ok"] is False
    assert out["status"] == "applied_unverified"
    assert out["error"] == TLS_SAN_MISMATCH


def test_ladder_200_with_old_fingerprint():
    expected = VerifyExpectation(release_id="rel_new", artifact_sha256="abc123")
    stale = _marker(release_id="rel_old", artifact_sha256="zzzz")
    out = run_publish_verify_ladder(
        hostname="docs.subactor.com",
        expected=expected,
        check_dns_step=False,
        check_tls_step=False,
        check_origin=False,
        check_public=True,
        http_fetcher=_fetch_factory(stale, status=200),
        release_files_ok=True,
    )
    assert out["ok"] is False
    assert out["status"] == "applied_unverified"
    assert out["error"] == FINGERPRINT_STALE
    assert out["https_ok"] is True


def test_ladder_origin_resolve_success():
    expected = VerifyExpectation(
        release_id="rel_new",
        artifact_sha256="abc123",
        source_commit="deadbeef",
        pack_version="1",
    )
    marker = _marker()
    calls = []

    def fetcher(url, *, host_header="", resolve_ip="", timeout=10.0):
        calls.append({"url": url, "host_header": host_header, "resolve_ip": resolve_ip})
        return {
            "ok": True,
            "status": 200,
            "body": json.dumps(marker).encode(),
            "cache_control": "no-store",
            "url": url,
            "resolved_to": resolve_ip,
        }

    out = run_publish_verify_ladder(
        hostname="docs.subactor.com",
        expected=expected,
        origin_ip="203.0.113.10",
        check_dns_step=False,
        check_tls_step=False,
        check_origin=True,
        check_public=False,
        http_fetcher=fetcher,
        release_files_ok=True,
    )
    assert out["ok"] is True
    assert out["status"] == "origin_verified"
    assert out["origin_verified"] is True
    assert calls[0]["resolve_ip"] == "203.0.113.10"
    assert calls[0]["host_header"] == "docs.subactor.com"


def test_ladder_full_success_mocked():
    expected = VerifyExpectation(
        release_id="rel_new",
        artifact_sha256="abc123",
        source_commit="deadbeef",
        pack_version="1",
        dns_targets=["203.0.113.10"],
        tls_hostname="docs.subactor.com",
    )
    marker = _marker()
    out = run_publish_verify_ladder(
        hostname="docs.subactor.com",
        expected=expected,
        origin_ip="203.0.113.10",
        check_origin=True,
        check_public=True,
        public_resolver=lambda h: ["203.0.113.10"],
        authoritative_resolver=lambda h: ["203.0.113.10"],
        tls_inspector=lambda host, port, sni: {"ok": True, "sans": ["docs.subactor.com"]},
        http_fetcher=_fetch_factory(marker),
        release_files_ok=True,
    )
    assert out["ok"] is True
    assert out["status"] == "publicly_verified"
    assert out["dns_target_verified"] and out["tls_verified"] and out["content_verified"]


def test_publish_verify_handler_requires_fingerprint():
    result = publish_verify_handler(hostname="docs.subactor.com")
    assert result.get("ok") is not True
    assert result.get("error") == "fingerprint_missing"


def test_curl_resolve_hint():
    hint = curl_resolve_hint("docs.subactor.com", "203.0.113.10")
    assert "--resolve docs.subactor.com:443:203.0.113.10" in hint
    assert "/__subactor_release.json" in hint


def test_handler_stale_fingerprint_with_injected_fetcher(monkeypatch):
    import urirun_connector_plesk.verify_ladder as vl

    stale = _marker(release_id="rel_old", artifact_sha256="old")
    real = vl.run_publish_verify_ladder

    def fake_ladder(**kwargs):
        kwargs = {
            **kwargs,
            "http_fetcher": _fetch_factory(stale),
            "check_dns_step": False,
            "check_tls_step": False,
            "check_origin": False,
            "check_public": True,
        }
        return real(**kwargs)

    monkeypatch.setattr(vl, "run_publish_verify_ladder", fake_ladder)

    result = publish_verify_handler(
        hostname="docs.subactor.com",
        release_id="rel_new",
        artifact_sha256="abc123",
        verify_origin=False,
        verify_public=True,
        check_dns=False,
        check_tls=False,
    )
    assert result.get("ok") is False
    assert result.get("status") == "applied_unverified"
    assert result.get("error") == FINGERPRINT_STALE
