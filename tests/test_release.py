"""PR7 release-based deploy unit tests (local FS + handler mocks)."""
from __future__ import annotations

import json

import urirun_connector_plesk.core as core
from urirun_connector_plesk.apply_grant import issue_apply_grant
from urirun_connector_plesk.apply_grant_replay import reset_default_jti_replay_store
from urirun_connector_plesk.release_ops import (
    LocalReleaseFs,
    RELEASE_META_NAME,
    activate_release,
    build_release_meta,
    new_release_id,
    read_current_state,
    rollback_release,
    verify_release_local,
)
from urirun_connector_plesk import (
    doctor,
    release_activate,
    release_current,
    release_rollback,
    release_upload,
    release_verify,
    connector_manifest,
)


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
        artifact_sha256=(dry.get("manifest") or {}).get("source_sha256") or extra.get("artifact_sha256", "x"),
        target=host,
        risk_class=extra.get("risk_class", "reversible"),
        jti=extra.get("jti", ""),
        ttl_seconds=extra.get("ttl_seconds", 900),
        now=extra.get("now"),
        environ={"APPLY_GRANT_HMAC_SECRET": extra.get("secret", "test-apply-grant-hmac")},
    )
    assert issued["ok"], issued
    return issued["grant"]


def _issue(plan_hash, host="prototypowanie.pl", **extra):
    issued = issue_apply_grant(
        run_id=extra.get("run_id", "run_test"),
        actor=extra.get("actor", "test-actor"),
        intent_pack=extra.get("intent_pack", "docs@1"),
        plan_hash=plan_hash,
        artifact_sha256=extra.get("artifact_sha256", "artifact"),
        target=host,
        risk_class="reversible",
        environ={"APPLY_GRANT_HMAC_SECRET": "test-apply-grant-hmac"},
    )
    assert issued["ok"], issued
    return issued["grant"]


def test_new_release_id_shape():
    rid = new_release_id(now=0)
    assert rid.startswith("rel_")
    assert "T" in rid


def test_local_activate_symlink_and_rollback(tmp_path):
    fs = LocalReleaseFs(str(tmp_path))
    root = "/site"
    for rid in ("rel_001", "rel_002"):
        path = f"{root}/releases/{rid}"
        fs.mkdir_p(path)
        meta = build_release_meta(release_id=rid, plan_hash=f"hash-{rid}", host="h.example")
        fs.write_bytes(
            f"{path}/{RELEASE_META_NAME}",
            json.dumps(meta).encode(),
        )

    first = activate_release(fs, release_root=root, release_id="rel_001", strategy="symlink")
    assert first["current"] == "rel_001" and first["activation_strategy"] == "symlink"
    assert read_current_state(fs, root)["current"] == "rel_001"

    second = activate_release(fs, release_root=root, release_id="rel_002", strategy="symlink")
    assert second["current"] == "rel_002" and second["previous"] == "rel_001"

    rolled = rollback_release(fs, release_root=root, strategy="symlink")
    assert rolled["status"] == "rolled_back"
    assert rolled["current"] == "rel_001"
    assert rolled["rolled_back_from"] == "rel_002"
    assert rolled["verify"]["origin"] == "pending"


def test_local_activate_pointer_fallback(tmp_path):
    fs = LocalReleaseFs(str(tmp_path))
    root = "/site"
    path = f"{root}/releases/rel_ptr"
    fs.mkdir_p(path)
    fs.write_bytes(
        f"{path}/{RELEASE_META_NAME}",
        json.dumps(build_release_meta(release_id="rel_ptr", plan_hash="p", host="h")).encode(),
    )
    out = activate_release(fs, release_root=root, release_id="rel_ptr", strategy="pointer")
    assert out["activation_strategy"] == "pointer"
    state = read_current_state(fs, root)
    assert state["current"] == "rel_ptr"
    assert state["strategy"] == "pointer"


def test_verify_release_local_requires_meta():
    try:
        verify_release_local(plan=[], release_id="rel_x", meta=None)
        assert False, "expected missing meta"
    except RuntimeError as err:
        assert str(err) == "plesk_release_not_found"


def test_doctor_reports_release_capabilities(monkeypatch):
    monkeypatch.delenv("PLESK_SYNC_ALLOW_FTP_FALLBACK", raising=False)
    report = doctor()
    assert report["capabilities"]["release_activation"] is True
    assert report["capabilities"]["rollback"] is True
    assert "symlink" in report["capabilities"]["release_activation_strategies"]
    assert report["version"] == "0.11.0"
    assert report["capabilities"]["publish_verify"] is True
    assert report["staging_domain_recommendation"] == "docs-stage.subactor.com"

    monkeypatch.setattr(core, "paramiko", None)
    degraded = doctor()
    assert degraded["capabilities"]["release_activation"] is False
    assert degraded["capabilities"]["rollback"] is False


def test_release_upload_dry_run_plans_under_releases(tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    result = release_upload(
        source_dir=str(www),
        host="prototypowanie.pl",
        release_root="/httpdocs",
        release_id="rel_test_dry",
        apply=False,
    )
    assert result["ok"] and result["dry_run"] is True
    assert result["release_id"] == "rel_test_dry"
    assert result["activated"] is False
    assert result["remote_path"] == "/httpdocs/releases/rel_test_dry"
    assert result["plan_hash"]
    assert all(item["remote"].startswith("/httpdocs/releases/rel_test_dry/") for item in result["plan"])


def test_release_upload_apply_writes_meta(monkeypatch, tmp_path):
    www = tmp_path / "www"
    www.mkdir()
    _seed_site(www)
    _enable_apply(monkeypatch)

    class MetaFs:
        def __init__(self):
            self.writes = {}

        def write_bytes(self, path, data):
            self.writes[path] = data

    meta_fs = MetaFs()
    transport = type("T", (), {"close": lambda self: None})()

    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "x")
    monkeypatch.setattr(
        core,
        "_publish_over_sftp",
        lambda *a, **k: (["index.html"], {"host_fingerprint": "fp"}),
    )
    monkeypatch.setattr(core, "_open_sftp_release_fs", lambda **k: (transport, meta_fs, "fp"))

    dry = release_upload(
        source_dir=str(www), host="prototypowanie.pl",
        release_root="/httpdocs", release_id="rel_up_1", apply=False,
    )
    grant = _grant_for(dry)
    applied = release_upload(
        source_dir=str(www),
        host="prototypowanie.pl",
        release_root="/httpdocs",
        release_id="rel_up_1",
        apply=True,
        transport="sftp",
        plan_hash=dry["plan_hash"],
        apply_grant=grant,
        actor="test-actor",
        pack_id="docs",
        pack_version="1",
    )
    assert applied["ok"] and applied["dry_run"] is False
    assert applied["release_id"] == "rel_up_1"
    assert applied["activated"] is False
    meta_path = "/httpdocs/releases/rel_up_1/__subactor_release.json"
    assert meta_path in meta_fs.writes
    meta = json.loads(meta_fs.writes[meta_path])
    assert meta["release_id"] == "rel_up_1"
    assert meta["plan_hash"] == dry["plan_hash"]
    assert meta["artifact_sha256"]
    assert meta["cache_control"] == "no-store"
    assert meta["pack_version"] == "1"
    assert meta["built_at"]


def test_release_activate_and_rollback_handlers(monkeypatch, tmp_path):
    _enable_apply(monkeypatch)
    local = LocalReleaseFs(str(tmp_path))
    root = "/httpdocs"
    for rid, ph in (("rel_a", "hash-a"), ("rel_b", "hash-b")):
        path = f"{root}/releases/{rid}"
        local.mkdir_p(path)
        local.write_bytes(
            f"{path}/{RELEASE_META_NAME}",
            json.dumps(build_release_meta(release_id=rid, plan_hash=ph, host="h")).encode(),
        )

    transport = type("T", (), {"close": lambda self: None})()
    monkeypatch.setattr(core, "_open_sftp_release_fs", lambda **k: (transport, local, "fp"))
    monkeypatch.setattr(core, "_vault_lease", lambda *a, **k: "x")

    grant_a = _issue("hash-a")
    act_a = release_activate(
        release_id="rel_a",
        release_root=root,
        host="prototypowanie.pl",
        apply=True,
        activation_strategy="symlink",
        plan_hash="hash-a",
        apply_grant=grant_a,
        actor="test-actor",
        pack_id="docs",
        pack_version="1",
    )
    assert act_a["ok"] and act_a["current"] == "rel_a"

    grant_b = _issue("hash-b", run_id="run2")
    act_b = release_activate(
        release_id="rel_b",
        release_root=root,
        host="prototypowanie.pl",
        apply=True,
        activation_strategy="symlink",
        plan_hash="hash-b",
        apply_grant=grant_b,
        actor="test-actor",
        pack_id="docs",
        pack_version="1",
    )
    assert act_b["ok"] and act_b["current"] == "rel_b" and act_b["previous"] == "rel_a"

    cur = release_current(release_root=root, host="prototypowanie.pl")
    assert cur["ok"] and cur["current"] == "rel_b"

    grant_rb = _issue("hash-a", run_id="run3")
    rolled = release_rollback(
        release_root=root,
        host="prototypowanie.pl",
        apply=True,
        activation_strategy="symlink",
        plan_hash="hash-a",
        apply_grant=grant_rb,
        actor="test-actor",
        pack_id="docs",
        pack_version="1",
    )
    assert rolled["ok"] is True
    assert rolled["status"] == "rolled_back"
    assert rolled["current"] == "rel_a"
    assert rolled["verify"]["origin"] == "pending"


def test_release_activate_denies_without_gates(monkeypatch):
    monkeypatch.delenv("AUTONOMY_MUTATIONS_ENABLED", raising=False)
    monkeypatch.delenv("PLESK_SYNC_APPLY", raising=False)
    result = release_activate(
        release_id="rel_x",
        host="prototypowanie.pl",
        apply=True,
        plan_hash="abc",
        apply_grant="nope",
    )
    assert result.get("ok") is not True
    assert result.get("error")


def test_release_verify_reads_meta(monkeypatch, tmp_path):
    local = LocalReleaseFs(str(tmp_path))
    root = "/httpdocs"
    path = f"{root}/releases/rel_v"
    local.mkdir_p(path)
    meta = build_release_meta(
        release_id="rel_v", plan_hash="ph", host="h",
        files=[{"path": "a", "sha256": "1"}],
    )
    local.write_bytes(f"{path}/{RELEASE_META_NAME}", json.dumps(meta).encode())
    transport = type("T", (), {"close": lambda self: None})()
    monkeypatch.setattr(core, "_open_sftp_release_fs", lambda **k: (transport, local, "fp"))
    out = release_verify(release_id="rel_v", release_root=root, host="h.example", plan_hash="ph")
    assert out["ok"] and out["origin_verify"] == "files_only"
    assert out["release_id"] == "rel_v"


def test_manifest_lists_release_routes():
    routes = set(connector_manifest().get("routes") or [])
    for uri in (
        "plesk://host/site/command/release-upload",
        "plesk://host/site/command/release-verify",
        "plesk://host/site/command/publish-verify",
        "plesk://host/site/command/release-activate",
        "plesk://host/site/command/release-rollback",
        "plesk://host/site/query/release-current",
    ):
        assert uri in routes
