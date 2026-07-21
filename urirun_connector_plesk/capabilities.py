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


def build_capabilities(
    *,
    paramiko_mod: Any,
    release_activation: bool | None = None,
    rollback: bool | None = None,
    publish_verify: bool | None = None,
    ssl_ensure: bool | None = None,
    letsencrypt: bool | None = None,
) -> dict[str, Any]:
    sftp_ok = paramiko_available(paramiko_mod)
    # PR7: release activate/rollback available whenever SFTP transport is.
    release_ok = sftp_ok if release_activation is None else bool(release_activation)
    rollback_ok = sftp_ok if rollback is None else bool(rollback)
    # PR8: DNS/TLS/fingerprint ladder is stdlib — always available as capability.
    verify_ok = True if publish_verify is None else bool(publish_verify)
    # SSL ensure: assign + panel PEM paths are customer-capable; LE needs panel/admin.
    ssl_ok = True if ssl_ensure is None else bool(ssl_ensure)
    # LE via XML ApiRpc is unimplemented (1013); REST CLI needs admin key; panel SSL It works with caveats.
    le_ok = False if letsencrypt is None else bool(letsencrypt)
    return {
        "sftp": {
            "available": sftp_ok,
            "detail": "ok" if sftp_ok else "paramiko_missing",
        },
        "ftp": {
            "available": True,  # stdlib ftplib always present
            "detail": "ok",
        },
        "release_activation": release_ok,
        "rollback": rollback_ok,
        "release_activation_strategies": ["auto", "symlink", "pointer"],
        "publish_verify": verify_ok,
        "dns_preflight": verify_ok,
        "tls_san_check": verify_ok,
        "content_fingerprint": verify_ok,
        "ssl_ensure": {
            "available": ssl_ok,
            "detail": "ok" if ssl_ok else "unavailable",
            "strategies": [
                "probe",
                "assign",
                "panel_upload_pem",
                "panel_self_signed",
                "panel_sslit_le",
                "rest_cli_le",
            ],
        },
        "letsencrypt": {
            "available": le_ok,
            "detail": (
                "ok"
                if le_ok
                else (
                    "xml_apirpc_unimplemented; rest_cli_needs_admin; "
                    "panel_sslit_le_domain_only (omit wildcard/mail SANs)"
                )
            ),
        },
        "certificate_assign": True,
        "extensions": {
            "available": True,
            "detail": "xml_extension_get; profiled_execution_only",
            "discovery_route": "plesk://host/extensions/query/catalog",
            "capability_route": "plesk://host/extensions/query/capabilities",
            "query_route": "plesk://host/extension/query/call",
            "command_route": "plesk://host/extension/command/call",
        },
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
