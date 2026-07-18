"""Release-based deploy ops (PR7).

Layout under ``release_root`` (recipe-facing; hides symlink vs pointer):

```
{release_root}/
  releases/
    rel_…/
      …files…
      __subactor_release.json
  current          # symlink → releases/rel_…  OR pointer file
  previous         # symlink → releases/rel_…  OR pointer file
```

Activation strategy (``PLESK_RELEASE_ACTIVATION``):

- ``symlink`` — SFTP symlink for ``current`` / ``previous`` (preferred).
- ``pointer`` — JSON pointer files (``.release_current.json`` /
  ``.release_previous.json``). Used when host denies symlinks.
- ``auto`` (default) — try symlink, fall back to pointer.

Plesk REST “set docroot” is **not** assumed; staging hosts that need API
docroot switch should set strategy explicitly once verified. Recipes only call
``release-upload`` / ``release-verify`` / ``release-activate`` /
``release-current`` / ``release-rollback``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from typing import Any, Callable

RELEASE_META_NAME = "__subactor_release.json"
POINTER_CURRENT = ".release_current.json"
POINTER_PREVIOUS = ".release_previous.json"
LINK_CURRENT = "current"
LINK_PREVIOUS = "previous"
_SAFE_RELEASE_ID = re.compile(r"^rel_[A-Za-z0-9_-]+$")
_SAFE_ROOT = re.compile(r"^/[A-Za-z0-9_./-]*$")


def new_release_id(now: float | None = None) -> str:
    ts = time.gmtime(time.time() if now is None else now)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", ts)
    return f"rel_{stamp}_{secrets.token_hex(4)}"


def activation_strategy(explicit: str = "") -> str:
    raw = (explicit or os.environ.get("PLESK_RELEASE_ACTIVATION", "auto")).strip().lower()
    if raw not in {"auto", "symlink", "pointer"}:
        return "auto"
    return raw


def validate_release_root(release_root: str) -> str | None:
    if not release_root or not _SAFE_ROOT.fullmatch(release_root) or ".." in release_root:
        return "plesk_release_root_invalid"
    return None


def validate_release_id(release_id: str) -> str | None:
    if not release_id or not _SAFE_RELEASE_ID.fullmatch(release_id):
        return "plesk_release_id_invalid"
    return None


def release_dir(release_root: str, release_id: str) -> str:
    root = release_root.rstrip("/") or ""
    return f"{root}/releases/{release_id}"


def build_release_meta(
    *,
    release_id: str,
    plan_hash: str,
    host: str,
    domain: str = "",
    files: list[dict[str, Any]] | None = None,
    git_commit: str = "",
    content_sha256: str = "",
) -> dict[str, Any]:
    planned = files or []
    if not content_sha256 and planned:
        digest = hashlib.sha256()
        for item in planned:
            digest.update(f"{item.get('path', '')}:{item.get('sha256', '')}\n".encode())
        content_sha256 = digest.hexdigest()
    return {
        "release_id": release_id,
        "plan_hash": plan_hash,
        "host": host,
        "domain": domain or None,
        "git_commit": git_commit or None,
        "content_sha256": content_sha256 or None,
        "files": len(planned),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def pointer_payload(release_id: str, path: str) -> bytes:
    return json.dumps(
        {"release_id": release_id, "path": path, "strategy": "pointer"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def parse_pointer(raw: bytes | str | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    try:
        data = json.loads(raw if isinstance(raw, str) else raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    rid = str(data.get("release_id") or "")
    if validate_release_id(rid):
        return None
    return data


class ReleaseFs:
    """Minimal remote FS ops used by activate / current / rollback."""

    def mkdir_p(self, path: str) -> None:  # pragma: no cover - protocol
        raise NotImplementedError

    def write_bytes(self, path: str, data: bytes) -> None:  # pragma: no cover
        raise NotImplementedError

    def read_bytes(self, path: str) -> bytes | None:  # pragma: no cover
        raise NotImplementedError

    def exists(self, path: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    def remove(self, path: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def symlink(self, target: str, link_path: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def readlink(self, path: str) -> str | None:  # pragma: no cover
        raise NotImplementedError

    def listdir(self, path: str) -> list[str]:  # pragma: no cover
        raise NotImplementedError


class LocalReleaseFs(ReleaseFs):
    """Filesystem-backed release store for unit tests / lab."""

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    def _abs(self, path: str) -> str:
        rel = path.lstrip("/")
        return os.path.join(self.root, rel)

    def mkdir_p(self, path: str) -> None:
        os.makedirs(self._abs(path), exist_ok=True)

    def write_bytes(self, path: str, data: bytes) -> None:
        abs_path = self._abs(path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "wb") as handle:
            handle.write(data)

    def read_bytes(self, path: str) -> bytes | None:
        abs_path = self._abs(path)
        if not os.path.lexists(abs_path):
            return None
        if os.path.islink(abs_path):
            return None
        if not os.path.isfile(abs_path):
            return None
        with open(abs_path, "rb") as handle:
            return handle.read()

    def exists(self, path: str) -> bool:
        return os.path.lexists(self._abs(path))

    def remove(self, path: str) -> None:
        abs_path = self._abs(path)
        if os.path.islink(abs_path) or os.path.isfile(abs_path):
            os.unlink(abs_path)
        elif os.path.isdir(abs_path):
            os.rmdir(abs_path)

    def symlink(self, target: str, link_path: str) -> None:
        abs_link = self._abs(link_path)
        os.makedirs(os.path.dirname(abs_link), exist_ok=True)
        if os.path.lexists(abs_link):
            os.unlink(abs_link)
        os.symlink(target, abs_link)

    def readlink(self, path: str) -> str | None:
        abs_path = self._abs(path)
        if not os.path.islink(abs_path):
            return None
        return os.readlink(abs_path)

    def listdir(self, path: str) -> list[str]:
        abs_path = self._abs(path)
        if not os.path.isdir(abs_path):
            return []
        return sorted(os.listdir(abs_path))


class SftpReleaseFs(ReleaseFs):
    """SFTP-backed release store (paramiko SFTPClient)."""

    def __init__(self, sftp):
        self.sftp = sftp

    def mkdir_p(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        cur = ""
        for part in parts:
            cur = f"{cur}/{part}"
            try:
                self.sftp.stat(cur)
            except OSError:
                self.sftp.mkdir(cur)

    def write_bytes(self, path: str, data: bytes) -> None:
        parent = path.rsplit("/", 1)[0] or "/"
        if parent != "/":
            self.mkdir_p(parent)
        with self.sftp.open(path, "wb") as handle:
            handle.write(data)

    def read_bytes(self, path: str) -> bytes | None:
        try:
            with self.sftp.open(path, "rb") as handle:
                return handle.read()
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        try:
            self.sftp.stat(path)
            return True
        except OSError:
            return False

    def remove(self, path: str) -> None:
        try:
            self.sftp.remove(path)
        except OSError:
            pass

    def symlink(self, target: str, link_path: str) -> None:
        parent = link_path.rsplit("/", 1)[0] or "/"
        if parent != "/":
            self.mkdir_p(parent)
        if self.exists(link_path):
            self.remove(link_path)
        self.sftp.symlink(target, link_path)

    def readlink(self, path: str) -> str | None:
        try:
            return self.sftp.readlink(path)
        except (OSError, AttributeError):
            return None

    def listdir(self, path: str) -> list[str]:
        try:
            return sorted(self.sftp.listdir(path))
        except OSError:
            return []


def _join_root(release_root: str, name: str) -> str:
    root = release_root.rstrip("/") or ""
    return f"{root}/{name}"


def read_current_state(fs: ReleaseFs, release_root: str) -> dict[str, Any]:
    """Resolve current/previous via symlink or pointer files."""
    current_link = _join_root(release_root, LINK_CURRENT)
    previous_link = _join_root(release_root, LINK_PREVIOUS)
    cur_target = fs.readlink(current_link)
    prev_target = fs.readlink(previous_link)
    strategy = "symlink" if cur_target else None

    current_id = None
    previous_id = None
    if cur_target:
        current_id = cur_target.rstrip("/").rsplit("/", 1)[-1]
    if prev_target:
        previous_id = prev_target.rstrip("/").rsplit("/", 1)[-1]

    if not current_id:
        ptr = parse_pointer(fs.read_bytes(_join_root(release_root, POINTER_CURRENT)))
        if ptr:
            current_id = ptr["release_id"]
            strategy = "pointer"
    if not previous_id:
        ptr = parse_pointer(fs.read_bytes(_join_root(release_root, POINTER_PREVIOUS)))
        if ptr:
            previous_id = ptr["release_id"]
            strategy = strategy or "pointer"

    return {
        "current": current_id,
        "previous": previous_id,
        "strategy": strategy,
        "release_root": release_root,
    }


def activate_release(
    fs: ReleaseFs,
    *,
    release_root: str,
    release_id: str,
    strategy: str = "auto",
) -> dict[str, Any]:
    """Atomically activate ``release_id``; demote prior current → previous."""
    bad = validate_release_id(release_id) or validate_release_root(release_root)
    if bad:
        raise RuntimeError(bad)

    target_path = release_dir(release_root, release_id)
    # Relative symlink targets keep the tree relocatable.
    rel_target = f"releases/{release_id}"
    meta = fs.read_bytes(f"{target_path}/{RELEASE_META_NAME}")
    if meta is None and not fs.exists(target_path):
        raise RuntimeError("plesk_release_not_found")

    state = read_current_state(fs, release_root)
    old_current = state.get("current")
    chosen = activation_strategy(strategy)
    previous_after = old_current if old_current and old_current != release_id else state.get("previous")

    def _via_symlink() -> dict[str, Any]:
        current_link = _join_root(release_root, LINK_CURRENT)
        previous_link = _join_root(release_root, LINK_PREVIOUS)
        if previous_after:
            fs.symlink(f"releases/{previous_after}", previous_link)
        elif fs.exists(previous_link):
            fs.remove(previous_link)
        fs.symlink(rel_target, current_link)
        # Clear pointer leftovers so reads prefer symlink.
        for name in (POINTER_CURRENT, POINTER_PREVIOUS):
            ptr = _join_root(release_root, name)
            if fs.exists(ptr):
                fs.remove(ptr)
        return {
            "activation_strategy": "symlink",
            "current": release_id,
            "previous": previous_after,
        }

    def _via_pointer() -> dict[str, Any]:
        fs.write_bytes(
            _join_root(release_root, POINTER_CURRENT),
            pointer_payload(release_id, rel_target),
        )
        if previous_after:
            fs.write_bytes(
                _join_root(release_root, POINTER_PREVIOUS),
                pointer_payload(previous_after, f"releases/{previous_after}"),
            )
        return {
            "activation_strategy": "pointer",
            "current": release_id,
            "previous": previous_after,
        }

    if chosen == "pointer":
        return {**_via_pointer(), "release_root": release_root, "release_id": release_id}
    if chosen == "symlink":
        return {**_via_symlink(), "release_root": release_root, "release_id": release_id}

    # auto: prefer symlink, fall back when host denies it
    try:
        return {**_via_symlink(), "release_root": release_root, "release_id": release_id}
    except (OSError, AttributeError, NotImplementedError):
        return {**_via_pointer(), "release_root": release_root, "release_id": release_id}


def rollback_release(
    fs: ReleaseFs,
    *,
    release_root: str,
    strategy: str = "auto",
    previous_release: str = "",
) -> dict[str, Any]:
    """Activate previous release. Returns status ``rolled_back`` on success."""
    state = read_current_state(fs, release_root)
    target = previous_release or state.get("previous")
    if not target:
        raise RuntimeError("plesk_release_no_previous")
    if target == state.get("current"):
        raise RuntimeError("plesk_release_rollback_noop")
    activated = activate_release(
        fs, release_root=release_root, release_id=target, strategy=strategy,
    )
    return {
        **activated,
        "status": "rolled_back",
        "rolled_back_from": state.get("current"),
        "verify": {"origin": "stub", "note": "public/origin fingerprint verify is PR8"},
    }


def verify_release_local(
    *,
    plan: list[dict[str, Any]],
    release_id: str,
    expected_plan_hash: str = "",
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Hash-level verify of an uploaded release plan (path hooks; origin stub)."""
    if not meta or not meta.get("release_id"):
        raise RuntimeError("plesk_release_not_found")
    if meta.get("release_id") != release_id:
        raise RuntimeError("remote_hash_mismatch")
    if expected_plan_hash and meta.get("plan_hash") and meta["plan_hash"] != expected_plan_hash:
        raise RuntimeError("remote_hash_mismatch")
    missing = [item["path"] for item in plan if not item.get("sha256")]
    if missing:
        raise RuntimeError("remote_hash_mismatch")
    return {
        "ok": True,
        "release_id": release_id,
        "files_verified": len(plan) if plan else int(meta.get("files") or 0),
        "plan_hash": meta.get("plan_hash") or expected_plan_hash or None,
        "origin_verify": "stub",
        "note": "path/hash verify only; public HTTPS fingerprint is PR8",
    }


def with_fs_session(
    open_fs: Callable[[], tuple[Any, ReleaseFs]],
    fn: Callable[[ReleaseFs], dict[str, Any]],
) -> dict[str, Any]:
    """Run ``fn`` with a ReleaseFs; close transport if open_fs returns one."""
    transport, fs = open_fs()
    try:
        return fn(fs)
    finally:
        close = getattr(transport, "close", None)
        if callable(close):
            close()
