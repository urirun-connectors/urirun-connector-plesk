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
