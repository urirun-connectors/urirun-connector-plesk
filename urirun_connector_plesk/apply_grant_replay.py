"""Apply-grant jti replay store (ADR-003 / PR5c).

TTL for a consumed jti is grant expiry + CLOCK_SKEW.
Second consume → apply_grant_replay.
Path via APPLY_GRANT_JTI_STORE (JSON file) or process memory.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime

APPLY_GRANT_REPLAY_ERROR = "apply_grant_replay"
CLOCK_SKEW_SECONDS = 60
MAX_TTL_SECONDS = 60 * 60

_lock = threading.Lock()
_memory: dict[str, float] = {}
_default_file_store: "FileJtiReplayStore | None" = None


def _parse_expires(value: str | float | int | None) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    text = (value or "").strip() if isinstance(value, str) else ""
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def jti_retention_until(expires_at: str | float | int | None, *, now: float | None = None) -> float:
    now_ts = time.time() if now is None else float(now)
    exp = _parse_expires(expires_at)
    if exp is None:
        return now_ts + MAX_TTL_SECONDS + CLOCK_SKEW_SECONDS
    return exp + CLOCK_SKEW_SECONDS


def _purge(entries: dict[str, float], now: float) -> None:
    dead = [k for k, until in entries.items() if not isinstance(until, (int, float)) or until <= now]
    for key in dead:
        del entries[key]


class MemoryJtiReplayStore:
    def __init__(self, entries: dict[str, float] | None = None) -> None:
        self.entries = entries if entries is not None else {}

    def consume(self, jti: str, expires_at: str | float | int | None, *, now: float | None = None) -> tuple[bool, str | None]:
        key = (jti or "").strip()
        if not key:
            return False, "apply_grant_signature_invalid"
        now_ts = time.time() if now is None else float(now)
        with _lock:
            _purge(self.entries, now_ts)
            if key in self.entries:
                return False, APPLY_GRANT_REPLAY_ERROR
            self.entries[key] = jti_retention_until(expires_at, now=now_ts)
            return True, None

    def has(self, jti: str, *, now: float | None = None) -> bool:
        now_ts = time.time() if now is None else float(now)
        with _lock:
            _purge(self.entries, now_ts)
            return (jti or "").strip() in self.entries


class FileJtiReplayStore:
    def __init__(self, filename: str) -> None:
        self.filename = filename

    def _load(self) -> dict[str, float]:
        try:
            with open(self.filename, encoding="utf-8") as handle:
                parsed = json.load(handle)
        except FileNotFoundError:
            return {}
        entries = parsed.get("entries") if isinstance(parsed, dict) else None
        if not isinstance(entries, dict):
            return {}
        out: dict[str, float] = {}
        for key, until in entries.items():
            try:
                out[str(key)] = float(until)
            except (TypeError, ValueError):
                continue
        return out

    def _save(self, entries: dict[str, float]) -> None:
        directory = os.path.dirname(self.filename) or "."
        os.makedirs(directory, exist_ok=True)
        temp = f"{self.filename}.{os.getpid()}.{time.time_ns()}.tmp"
        payload = {"schema": "apply-grant-jti-replay-1", "entries": entries}
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temp, 0o600)
        os.replace(temp, self.filename)

    def consume(self, jti: str, expires_at: str | float | int | None, *, now: float | None = None) -> tuple[bool, str | None]:
        key = (jti or "").strip()
        if not key:
            return False, "apply_grant_signature_invalid"
        now_ts = time.time() if now is None else float(now)
        with _lock:
            entries = self._load()
            _purge(entries, now_ts)
            if key in entries:
                return False, APPLY_GRANT_REPLAY_ERROR
            entries[key] = jti_retention_until(expires_at, now=now_ts)
            self._save(entries)
            return True, None

    def has(self, jti: str, *, now: float | None = None) -> bool:
        now_ts = time.time() if now is None else float(now)
        with _lock:
            entries = self._load()
            _purge(entries, now_ts)
            return (jti or "").strip() in entries


def resolve_jti_replay_store(
    store: MemoryJtiReplayStore | FileJtiReplayStore | None = None,
    *,
    environ: dict[str, str] | None = None,
) -> MemoryJtiReplayStore | FileJtiReplayStore:
    if store is not None:
        return store
    env = environ if environ is not None else os.environ
    path = (env.get("APPLY_GRANT_JTI_STORE") or "").strip()
    if path:
        global _default_file_store
        if _default_file_store is None or _default_file_store.filename != path:
            _default_file_store = FileJtiReplayStore(path)
        return _default_file_store
    return MemoryJtiReplayStore(_memory)


def reset_default_jti_replay_store() -> MemoryJtiReplayStore:
    """Test helper — clear process-default memory entries."""
    global _default_file_store
    with _lock:
        _memory.clear()
        _default_file_store = None
    return MemoryJtiReplayStore(_memory)


def consume_apply_grant_jti(
    jti: str,
    expires_at: str | float | int | None,
    *,
    store: MemoryJtiReplayStore | FileJtiReplayStore | None = None,
    environ: dict[str, str] | None = None,
    now: float | None = None,
) -> tuple[bool, str | None]:
    replay = resolve_jti_replay_store(store, environ=environ)
    return replay.consume(jti, expires_at, now=now)
