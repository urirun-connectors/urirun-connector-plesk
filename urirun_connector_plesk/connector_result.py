"""Domain-neutral Subactor connector result envelope v1."""
from __future__ import annotations

import re
from typing import Any

CONNECTOR_RESULT_SCHEMA = "subactor.connector-result.v1"

_AUTHORITY_ERRORS = {
    "autonomy_mutations_disabled",
    "plesk_sync_apply_required",
    "apply_grant_required",
    "apply_grant_expired",
    "apply_grant_replay",
    "apply_grant_secret_missing",
    "apply_grant_signature_invalid",
    "apply_grant_target_mismatch",
    "apply_grant_actor_mismatch",
    "apply_grant_intent_pack_mismatch",
}


def classify_connector_reason(reason: str | None) -> str | None:
    value = str(reason or "").strip()
    if value in _AUTHORITY_ERRORS:
        return "AUTHORITY_REQUIRED"
    if value == "capability_unavailable":
        return "CAPABILITY_UNAVAILABLE"
    if value in {"plan_hash_mismatch", "plan_hash_missing"}:
        return "PLAN_HASH_MISMATCH"
    if not value:
        return None
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    return normalized or "CONNECTOR_FAILED"


def _count(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("connector_result_counter_invalid")
    try:
        number = int(value or 0)
    except (TypeError, ValueError) as error:
        raise ValueError("connector_result_counter_invalid") from error
    if number < 0 or number != value:
        raise ValueError("connector_result_counter_invalid")
    return number


def connector_result(
    *,
    ok: bool,
    executed: bool = False,
    verified: bool = False,
    dry_run: bool | None = None,
    reason_code: str | None = None,
    reason: str | None = None,
    mutation_attempted: bool | None = None,
    files_planned: int = 0,
    files_uploaded: int = 0,
    bytes_planned: int = 0,
    bytes_uploaded: int = 0,
    plan_hash: str | None = None,
    evidence_bundle_id: str | None = None,
    retryable: bool = False,
    **details: Any,
) -> dict[str, Any]:
    if not isinstance(ok, bool):
        raise TypeError("connector_result_ok_required")
    did_execute = bool(executed)
    code = reason_code or classify_connector_reason(reason)
    if not ok and not code:
        raise ValueError("connector_result_reason_code_required")
    result = dict(details)
    result.update({
        "schema": CONNECTOR_RESULT_SCHEMA,
        "ok": ok,
        "executed": did_execute,
        "verified": bool(verified) if did_execute else False,
        "dry_run": (not did_execute) if dry_run is None else bool(dry_run),
        "reason_code": code,
        "reason": None if reason is None else str(reason),
        "mutation_attempted": bool(mutation_attempted) if did_execute else False,
        "files_planned": _count(files_planned),
        "files_uploaded": _count(files_uploaded) if did_execute else 0,
        "bytes_planned": _count(bytes_planned),
        "bytes_uploaded": _count(bytes_uploaded) if did_execute else 0,
        "plan_hash": plan_hash or None,
        "evidence_bundle_id": evidence_bundle_id or None,
        "retryable": bool(retryable),
    })
    return result
