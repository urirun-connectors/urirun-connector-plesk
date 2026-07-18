"""Immutable dry-run manifest + plan_hash (ADR-003 / PR5a).

plan_hash = SHA-256 hex of canonical JSON over
{source_sha256, files[{path,sha256}], deletes, target}
with fixed key order and separators=(',', ':'). No release_id in the hash body.
Secrets must never appear in the manifest.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Stable JSON for hashing: insertion-order keys, no whitespace."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def source_tree_hash(files: list[dict[str, str]]) -> str:
    """SHA-256 of canonical JSON of sorted [{path, sha256}, ...]."""
    ordered = [
        {"path": item["path"], "sha256": item["sha256"]}
        for item in sorted(files, key=lambda row: row["path"])
    ]
    return hashlib.sha256(canonical_json(ordered).encode("utf-8")).hexdigest()


def build_immutable_manifest(
    *,
    plan: list[dict[str, Any]],
    host: str = "",
    domain: str = "",
    remote_path: str = "/httpdocs",
    deletes: list[str] | None = None,
    pack_id: str = "",
    pack_version: str = "",
    recipe_ref: str = "",
    max_files: int | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Build manifest + plan_hash. Metadata outside the hash body is optional."""
    files = [
        {"path": str(item["path"]), "sha256": str(item["sha256"])}
        for item in sorted(plan, key=lambda row: str(row["path"]))
    ]
    deletes_sorted = sorted(str(item) for item in (deletes or []))
    tree_hash = source_tree_hash(files)
    target = {
        "host": host or "",
        "domain": domain or "",
        "remote_path": remote_path or "",
    }
    # Fixed key order for plan_hash body (ADR-003 immutable manifest).
    hash_body = {
        "source_sha256": tree_hash,
        "files": files,
        "deletes": deletes_sorted,
        "target": target,
    }
    plan_hash = hashlib.sha256(canonical_json(hash_body).encode("utf-8")).hexdigest()
    bytes_total = sum(int(item.get("bytes") or 0) for item in plan)
    manifest: dict[str, Any] = {
        "source_sha256": tree_hash,
        "files": files,
        "deletes": deletes_sorted,
        "target": target,
        "plan_hash": plan_hash,
        "files_planned": len(files),
        "bytes_total": bytes_total,
    }
    if pack_id:
        manifest["pack_id"] = pack_id
    if pack_version:
        manifest["pack_version"] = pack_version
    if recipe_ref:
        manifest["recipe_ref"] = recipe_ref
    if max_files is not None:
        manifest["max_files"] = int(max_files)
    if max_bytes is not None:
        manifest["max_bytes"] = int(max_bytes)
    return manifest


def verify_plan_hash(
    *,
    plan: list[dict[str, Any]],
    expected_plan_hash: str,
    host: str = "",
    domain: str = "",
    remote_path: str = "/httpdocs",
    deletes: list[str] | None = None,
) -> tuple[bool, dict[str, Any], str | None]:
    """Recompute manifest from current plan; deny if expected hash missing or differs."""
    manifest = build_immutable_manifest(
        plan=plan,
        host=host,
        domain=domain,
        remote_path=remote_path,
        deletes=deletes,
    )
    expected = (expected_plan_hash or "").strip().lower()
    if not expected or expected != manifest["plan_hash"]:
        return False, manifest, "plan_hash_mismatch"
    return True, manifest, None
