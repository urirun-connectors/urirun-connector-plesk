"""Signed apply grant issue + verify (ADR-003 / PR5b).

Compact HS256: base64url(header).base64url(payload).base64url(sig)
Canonical claim key order (string values):
  run_id, actor, intent_pack, plan_hash, artifact_sha256, target,
  expires_at, risk_class, jti, iat

Secrets: APPLY_GRANT_HMAC_SECRET || TOKEN_PEPPER; NEXT for rotation.
jti issued for PR5c replay store (not enforced here).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any

APPLY_GRANT_ALG = "HS256"
APPLY_GRANT_TYP = "apply-grant"
DEFAULT_TTL_SECONDS = 15 * 60
MAX_TTL_SECONDS = 60 * 60
CLOCK_SKEW_SECONDS = 60
RISK_CLASSES = frozenset({"read_only", "reversible", "boundary", "governance"})
CLAIM_KEYS = (
    "run_id",
    "actor",
    "intent_pack",
    "plan_hash",
    "artifact_sha256",
    "target",
    "expires_at",
    "risk_class",
    "jti",
    "iat",
)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def resolve_apply_grant_secrets(environ: dict[str, str] | None = None) -> dict[str, str | None]:
    env = environ if environ is not None else os.environ
    primary = (env.get("APPLY_GRANT_HMAC_SECRET") or env.get("TOKEN_PEPPER") or "").strip()
    nxt = (env.get("APPLY_GRANT_HMAC_SECRET_NEXT") or "").strip()
    source = None
    if (env.get("APPLY_GRANT_HMAC_SECRET") or "").strip():
        source = "APPLY_GRANT_HMAC_SECRET"
    elif (env.get("TOKEN_PEPPER") or "").strip():
        source = "TOKEN_PEPPER"
    return {"primary": primary or None, "next": nxt or None, "source": source}


def format_intent_pack(pack_id: str = "", pack_version: str = "") -> str:
    pid = (pack_id or "").strip()
    ver = (pack_version or "").strip()
    if not pid:
        return ""
    return f"{pid}@{ver}" if ver else pid


def canonical_grant_claims(data: dict[str, Any] | None) -> dict[str, str]:
    src = data or {}
    return {key: str(src.get(key) or "") for key in CLAIM_KEYS}


def signing_payload(claims: dict[str, str]) -> str:
    return json.dumps(canonical_grant_claims(claims), ensure_ascii=False, separators=(",", ":"))


def _sign(secret: str, signing_input: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse_expires(value: str) -> float | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def issue_apply_grant(
    *,
    run_id: str,
    actor: str,
    plan_hash: str,
    artifact_sha256: str,
    target: str,
    intent_pack: str = "",
    pack_id: str = "",
    pack_version: str = "",
    risk_class: str = "reversible",
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    jti: str = "",
    now: float | None = None,
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = environ if environ is not None else os.environ
    secrets_map = resolve_apply_grant_secrets(env)
    if not secrets_map["primary"]:
        return {"ok": False, "error": "apply_grant_secret_missing"}

    ttl = int(ttl_seconds)
    if ttl <= 0:
        return {"ok": False, "error": "apply_grant_ttl_invalid"}
    if ttl > MAX_TTL_SECONDS:
        return {"ok": False, "error": "apply_grant_ttl_exceeds_max"}

    risk = (risk_class or "reversible").strip()
    if risk not in RISK_CLASSES:
        return {"ok": False, "error": "apply_grant_risk_class_invalid"}

    pack = (intent_pack or format_intent_pack(pack_id, pack_version)).strip()
    required = {
        "run_id": (run_id or "").strip(),
        "actor": (actor or "").strip(),
        "intent_pack": pack,
        "plan_hash": (plan_hash or "").strip(),
        "artifact_sha256": (artifact_sha256 or "").strip(),
        "target": (target or "").strip(),
    }
    for key, value in required.items():
        if not value:
            return {"ok": False, "error": f"apply_grant_{key}_required"}

    now_ts = time.time() if now is None else float(now)
    exp_ts = now_ts + ttl
    claims = canonical_grant_claims({
        **required,
        "expires_at": _iso(exp_ts),
        "risk_class": risk,
        "jti": (jti or "").strip() or _b64url_encode(secrets.token_bytes(16)),
        "iat": _iso(now_ts),
    })

    header = {"alg": APPLY_GRANT_ALG, "typ": APPLY_GRANT_TYP}
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = _b64url_encode(signing_payload(claims).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}"
    sig = _sign(secrets_map["primary"], signing_input)
    grant = f"{signing_input}.{_b64url_encode(sig)}"
    return {"ok": True, "grant": grant, "claims": claims, "expires_at": claims["expires_at"], "jti": claims["jti"]}


def verify_apply_grant(
    token: str,
    *,
    plan_hash: str = "",
    target: str = "",
    actor: str = "",
    intent_pack: str = "",
    pack_id: str = "",
    pack_version: str = "",
    artifact_sha256: str = "",
    now: float | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[bool, str | None, dict[str, str] | None]:
    """Return (ok, error_code, claims). Fail-closed."""
    env = environ if environ is not None else os.environ
    secrets_map = resolve_apply_grant_secrets(env)
    if not secrets_map["primary"] and not secrets_map["next"]:
        return False, "apply_grant_secret_missing", None

    raw = (token or "").strip()
    if not raw:
        return False, "apply_grant_required", None

    parts = raw.split(".")
    if len(parts) != 3:
        return False, "apply_grant_signature_invalid", None
    header_part, payload_part, sig_part = parts

    try:
        header = json.loads(_b64url_decode(header_part).decode("utf-8"))
    except Exception:
        return False, "apply_grant_signature_invalid", None
    if not isinstance(header, dict) or header.get("alg") != APPLY_GRANT_ALG:
        return False, "apply_grant_signature_invalid", None

    try:
        payload_text = _b64url_decode(payload_part).decode("utf-8")
        parsed = json.loads(payload_text)
    except Exception:
        return False, "apply_grant_signature_invalid", None
    if not isinstance(parsed, dict):
        return False, "apply_grant_signature_invalid", None

    claims = canonical_grant_claims(parsed)
    signing_input = f"{header_part}.{payload_part}"
    try:
        sig = _b64url_decode(sig_part)
    except Exception:
        return False, "apply_grant_signature_invalid", None

    matched = False
    for secret in (secrets_map["primary"], secrets_map["next"]):
        if secret and hmac.compare_digest(_sign(secret, signing_input), sig):
            matched = True
            break
    if not matched:
        return False, "apply_grant_signature_invalid", None

    exp = _parse_expires(claims["expires_at"])
    if exp is None:
        return False, "apply_grant_signature_invalid", claims
    now_ts = time.time() if now is None else float(now)
    if now_ts > exp + CLOCK_SKEW_SECONDS:
        return False, "apply_grant_expired", claims

    expect_plan = (plan_hash or "").strip().lower()
    if expect_plan and expect_plan != claims["plan_hash"].lower():
        return False, "apply_grant_plan_hash_mismatch", claims

    expect_target = (target or "").strip()
    if expect_target and expect_target != claims["target"]:
        return False, "apply_grant_target_mismatch", claims

    expect_artifact = (artifact_sha256 or "").strip().lower()
    if expect_artifact and expect_artifact != claims["artifact_sha256"].lower():
        return False, "apply_grant_artifact_mismatch", claims

    expect_actor = (actor or "").strip()
    if expect_actor and expect_actor != claims["actor"]:
        return False, "apply_grant_actor_mismatch", claims

    expect_pack = (intent_pack or format_intent_pack(pack_id, pack_version)).strip()
    if expect_pack and expect_pack != claims["intent_pack"]:
        return False, "apply_grant_pack_mismatch", claims

    if claims["risk_class"] not in RISK_CLASSES or not claims["jti"]:
        return False, "apply_grant_signature_invalid", claims

    return True, None, claims


def autonomy_mutations_enabled(environ: dict[str, str] | None = None) -> bool:
    env = environ if environ is not None else os.environ
    return (env.get("AUTONOMY_MUTATIONS_ENABLED") or "").strip() == "1"
