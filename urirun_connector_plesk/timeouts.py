"""Configurable transport budgets for Plesk SFTP/FTP (PR6).

Defaults match autonomy-recommended-solution §7.2 — not a single hard 30s.
Override via env (seconds, float-capable):

  PLESK_TRANSPORT_CONNECT_TIMEOUT   default 15
  PLESK_TRANSPORT_OPERATION_TIMEOUT default 120
  PLESK_TRANSPORT_TOTAL_BUDGET      default 180
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class TransportTimeouts:
    connect: float = 15.0
    operation: float = 120.0
    total: float = 180.0


def transport_timeouts() -> TransportTimeouts:
    connect = _env_float("PLESK_TRANSPORT_CONNECT_TIMEOUT", 15.0)
    operation = _env_float("PLESK_TRANSPORT_OPERATION_TIMEOUT", 120.0)
    total = _env_float("PLESK_TRANSPORT_TOTAL_BUDGET", 180.0)
    # Total must cover at least one connect + one op; clamp upward if misconfigured.
    if total < connect + min(operation, 30.0):
        total = connect + operation
    return TransportTimeouts(connect=connect, operation=operation, total=total)


def isolated_execution_timeout(headroom: float = 15.0) -> float:
    """Outer urirun subprocess deadline for a full transport operation.

    The isolated runner defaults to 30 seconds, which is shorter than the
    connector's declared SFTP/FTP operation and total budgets. Keep the outer
    deadline slightly above the connector-owned total budget so the connector
    can return its typed timeout/partial-upload result instead of being killed
    by the generic runner.
    """
    return transport_timeouts().total + max(1.0, float(headroom))
