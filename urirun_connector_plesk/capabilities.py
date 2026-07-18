"""Connector capability readiness (PR6).

Production publish packs require SFTP even when FTP is available.
FTP fallback is opt-in via PLESK_SYNC_ALLOW_FTP_FALLBACK=1.
"""
from __future__ import annotations

import os
from typing import Any

from .errors import CAPABILITY_UNAVAILABLE


def paramiko_available(paramiko_mod: Any) -> bool:
    return paramiko_mod is not None


def ftp_fallback_allowed() -> bool:
    """Controlled SFTP→FTP fallback; off by default for production-safe apply."""
    return os.environ.get("PLESK_SYNC_ALLOW_FTP_FALLBACK", "").strip() == "1"


def require_sftp_for_apply(*, transport: str, production: bool | None = None) -> bool:
    """True when apply must use SFTP (no FTP-only path).

    - Explicit transport=ftp is allowed only when FTP fallback policy is on
      (lab / non-prod). Otherwise apply with transport=ftp is denied.
    - transport=auto / sftp always require SFTP capability when fallback is off.
    """
    if production is None:
        production = os.environ.get("PLESK_PRODUCTION_PUBLISH", "").strip() == "1"
    if production:
        return True
    if transport == "ftp":
        return not ftp_fallback_allowed()
    # auto / sftp: require SFTP unless fallback explicitly enabled
    return not ftp_fallback_allowed()


def build_capabilities(*, paramiko_mod: Any, release_activation: bool = False, rollback: bool = False) -> dict[str, Any]:
    sftp_ok = paramiko_available(paramiko_mod)
    return {
        "sftp": {
            "available": sftp_ok,
            "detail": "ok" if sftp_ok else "paramiko_missing",
        },
        "ftp": {
            "available": True,  # stdlib ftplib always present
            "detail": "ok",
        },
        "release_activation": bool(release_activation),  # PR7
        "rollback": bool(rollback),  # PR7
    }


def production_publish_ready(capabilities: dict[str, Any]) -> bool:
    """Missing SFTP blocks production readiness even if FTP is available."""
    sftp = capabilities.get("sftp") or {}
    return bool(sftp.get("available"))


def deny_if_sftp_required(capabilities: dict[str, Any], *, transport: str) -> str | None:
    """Return structured error code when SFTP is required but unavailable."""
    if not require_sftp_for_apply(transport=transport):
        return None
    if production_publish_ready(capabilities):
        if transport == "ftp" and require_sftp_for_apply(transport=transport):
            return CAPABILITY_UNAVAILABLE
        return None
    return CAPABILITY_UNAVAILABLE
