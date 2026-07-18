"""Structured transport / sync error codes (PR6).

Orchestrator maps these to retry / rollback / escalate — avoid opaque timeouts.
"""
from __future__ import annotations

import errno
import socket
from typing import Any

# Canonical codes (autonomy-recommended-solution §7.3 + PR6 goals).
AUTHENTICATION_FAILED = "authentication_failed"
CREDENTIAL_EXPIRED = "credential_expired"
TRANSPORT_CONNECT_TIMEOUT = "transport_connect_timeout"
TRANSFER_TIMEOUT = "transfer_timeout"
REMOTE_PERMISSION_DENIED = "remote_permission_denied"
PARTIAL_UPLOAD = "partial_upload"
REMOTE_HASH_MISMATCH = "remote_hash_mismatch"
CAPABILITY_UNAVAILABLE = "capability_unavailable"
RATE_LIMITED = "rate_limited"

# Legacy aliases still emitted where useful for ops grep.
PARAMIKO_MISSING = "capability_unavailable"  # was plesk_sftp_paramiko_missing


def map_exception(exc: BaseException, *, phase: str = "op") -> str:
    """Map low-level exceptions to structured codes. phase: connect | transfer | lease."""
    name = type(exc).__name__
    msg = str(exc).lower()

    if isinstance(exc, TimeoutError) or name in {"TimeoutError", "socket.timeout"}:
        return TRANSPORT_CONNECT_TIMEOUT if phase == "connect" else TRANSFER_TIMEOUT
    if isinstance(exc, socket.timeout):
        return TRANSPORT_CONNECT_TIMEOUT if phase == "connect" else TRANSFER_TIMEOUT

    # paramiko / ftplib auth
    if name in {"AuthenticationException", "BadAuthenticationType", "PasswordRequiredException"}:
        return AUTHENTICATION_FAILED
    if "auth" in msg and ("fail" in msg or "denied" in msg or "invalid" in msg):
        return AUTHENTICATION_FAILED

    if name in {"PermissionError", "error_perm"} or "permission denied" in msg:
        return REMOTE_PERMISSION_DENIED
    if isinstance(exc, OSError) and getattr(exc, "errno", None) in {errno.EACCES, errno.EPERM}:
        return REMOTE_PERMISSION_DENIED

    if "429" in msg or "rate limit" in msg or "too many" in msg:
        return RATE_LIMITED

    if phase == "lease":
        if "401" in msg or "403" in msg or "expired" in msg or "revoked" in msg:
            return CREDENTIAL_EXPIRED
        if "timeout" in msg:
            return TRANSPORT_CONNECT_TIMEOUT

    if "paramiko" in msg and "missing" in msg:
        return CAPABILITY_UNAVAILABLE
    if name == "RuntimeError":
        text = str(exc)
        if text in {
            AUTHENTICATION_FAILED,
            CREDENTIAL_EXPIRED,
            TRANSPORT_CONNECT_TIMEOUT,
            TRANSFER_TIMEOUT,
            REMOTE_PERMISSION_DENIED,
            PARTIAL_UPLOAD,
            REMOTE_HASH_MISMATCH,
            CAPABILITY_UNAVAILABLE,
            RATE_LIMITED,
            "plesk_sftp_paramiko_missing",
            "plesk_sftp_host_key_mismatch",
        }:
            if text == "plesk_sftp_paramiko_missing":
                return CAPABILITY_UNAVAILABLE
            return text

    if "timed out" in msg or "timeout" in msg:
        return TRANSPORT_CONNECT_TIMEOUT if phase == "connect" else TRANSFER_TIMEOUT

    return f"plesk_site_sync_failed:{name}"


def fail_payload(code: str, **extra: Any) -> dict[str, Any]:
    """Minimal structured fail body (urirun.fail wraps similarly)."""
    return {"ok": False, "error": code, **extra}
