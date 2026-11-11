#!/usr/bin/env python3
"""Idle ticket takeover and the autonomy state board (new-project.idle-takeover/v1).

A ticket whose writer shows no activity for ``coordination.idleTakeover.idleMinutes``
may be taken over by another agent through the change-lease CAS:
``expire`` -> ``release`` -> a fresh ``claimed`` lease with a higher fencing token.
The policy lives only in the governance manifest; without it takeover is disabled.

Activity is the newest of the lease heartbeat, the branch commit, any dirty file
in the ticket worktree and the ticket's continuity events. A live process whose
working directory is inside the worktree always counts as activity. Dirty work is
stored as a content-addressed snapshot before ownership moves; the worktree itself
is never reset. Frozen publication phases, integrated tickets, worktrees outside
the wellmanifest/worktrees v5 layout and invalid leases are reported, never taken
over.

Every observation rewrites the board ``.subactor/cache/autonomy-board.{json,md}``
in the primary checkout: owner, idle time, state, the canonical worktree and lease
paths and links to the project, branch, README, pull request and issue list, so
the next agent can pick work without reconstructing the state from chat.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:  # Exclusive lease transition lock: fcntl on POSIX, msvcrt on Windows.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None
    import msvcrt

SCHEMA = "new-project.idle-takeover/v1"
BOARD_SCHEMA = "new-project.autonomy-board/v1"
# Runtime namespaces this module owns; all lie under the root-ignored
# wellmanifest/worktrees operational directories (cache, snapshots, receipts).
BOARD_DIR = ".subactor/cache"
SNAPSHOT_DIR = ".subactor/snapshots/idle-takeover"
RECEIPT_DIR = ".subactor/receipts/idle-takeover"
CONTINUITY_MANIFEST = ".subactor/manifest.json"
POLICY_MANIFESTS = (".governance/manifest.json", "governance/manifest.hub.json")
POLICY_FIELDS = ("enabled", "idleMinutes", "leaseMinutes")
# Bounded inputs: a snapshot larger than this needs a human handoff, and only the
# newest part of the append-only continuity stream is read.
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_CONTINUITY_BYTES = 8 * 1024 * 1024
# Layout fallbacks for pinned lease contracts older than new-project 0.20.120,
# which do not export the wellmanifest/worktrees v5 roots yet.
LEGACY_LAYOUT = {"WORKTREES_ROOT": ".worktrees", "LEASE_ROOT": ".subactor/leases", "MAX_LEASE_BYTES": 65536}
TICKET_RE = re.compile(r"ticket-[0-9]{3,}")
IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}")
# Forge URL shapes for the board; the host comes from the origin remote.
FORGE_PATHS = {"branch": "tree/{branch}", "readme": "blob/{branch}/project/{ticket}/README.md",
               "pull": "pull/{number}", "pullSearch": "pulls?q=head%3A{branch}",
               "pulls": "pulls", "issues": "issues"}


def pinned_module(primary: Path | None, name: str):
    """Load the repository's own pinned .governance copy; fall back to the sibling script."""
    pinned = primary / ".governance" / name if primary else None
    source = pinned if pinned and pinned.is_file() else Path(__file__).resolve().parent / name
    module_name = f"idle_takeover_{Path(name).stem}"
    spec = importlib.util.spec_from_file_location(module_name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def lease_runtime(primary: Path | None = None):
    """Validate leases with the repository's own pinned contract."""
    return pinned_module(primary, "change_lease_check.py")


def contract(runtime) -> dict[str, Any]:
    """Layout and phase vocabulary come from the pinned change-lease contract (SSOT)."""
    layout = {key: getattr(runtime, key, value) for key, value in LEGACY_LAYOUT.items()}
    frozen, expirable = set(runtime.FROZEN_PHASES), set(runtime.TRANSITIONS["expire"])
    released_from = set(runtime.TRANSITIONS["release"])
    terminal = set(runtime.PHASES) - expirable - released_from | (released_from - {"expired"} - expirable)
    return dict(layout, frozen=frozen, terminal=terminal,
                takeover=(expirable - frozen) | (released_from - terminal))


def git(root: Path, *args: str, check: bool = True) -> str:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    result = subprocess.run(["git", "-C", str(root), *args], env=env, capture_output=True, text=True, check=check)
    return result.stdout.strip()


def utc(value: str | None) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.utcoffset() is not None else None


def stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None


def primary_checkout(root: Path) -> Path:
    """wellmanifest/worktrees rule 1: the primary is the first registered worktree, never a linked one."""
    rows = git(root, "worktree", "list", "--porcelain").split("\n\n")
    return Path(rows[0].splitlines()[0].split(" ", 1)[1]).resolve()


def manifest_policy(primary: Path) -> dict[str, Any]:
    """The governance manifest is the only source of the policy; absent or malformed means disabled.

    Validity is decided by the pinned governance_check.idle_takeover_policy_valid,
    the same closed check the manifest gate applies (exact bool, bounded positive
    integers, lease longer than the idle threshold)."""
    valid = getattr(pinned_module(primary, "governance_check.py"), "idle_takeover_policy_valid", None)
    for relative in POLICY_MANIFESTS:
        manifest = read_json(primary / relative)
        if manifest is None:
            continue
        configured = manifest.get("coordination", {}).get("idleTakeover") if isinstance(manifest, dict) else None
        if valid is not None and valid(configured) and configured["enabled"] is True:
            return {key: configured[key] for key in POLICY_FIELDS} | {"source": relative}
        return {"enabled": False, "idleMinutes": None, "leaseMinutes": None, "source": relative}
    return {"enabled": False, "idleMinutes": None, "leaseMinutes": None, "source": None}


def worktrees(primary: Path) -> dict[str, dict[str, str]]:
    found = {}
    for row in git(primary, "worktree", "list", "--porcelain").split("\n\n"):
        fields = dict(line.split(" ", 1) for line in row.splitlines() if " " in line)
        branch = fields.get("branch", "")
        if "/ticket/" in branch:
            found[branch] = {"path": fields["worktree"], "head": fields.get("HEAD", "")}
    return found


def leases(primary: Path, layout: dict[str, Any]) -> list[tuple[Path, dict[str, Any]]]:
    directory = primary / layout["LEASE_ROOT"]
    loaded = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > layout["MAX_LEASE_BYTES"]:
                raise ValueError("Lease must be a bounded regular file")
            value = json.loads(path.read_text(encoding="utf-8"))
            loaded.append((path, value if isinstance(value, dict) else {}))
        except (OSError, ValueError):
            loaded.append((path, {}))
    return loaded


def canonical_layout(primary: Path, lease_path: Path, lease: dict[str, Any], tree: dict[str, str] | None,
                     layout: dict[str, Any]) -> dict[str, Any]:
    """wellmanifest/worktrees v5 rules 2, 3 and 7: path, lease stem and branch name one delivery unit."""
    worktree_id = str(lease.get("worktreeId", ""))
    ticket, _, slug = worktree_id.partition("--")
    expected_path = primary / layout["WORKTREES_ROOT"] / worktree_id
    expected_lease = primary / layout["LEASE_ROOT"] / f"{worktree_id}.json"
    expected_branch = f"refs/heads/ticket/{ticket.removeprefix('ticket-')}-{slug}"
    problems = []
    if not TICKET_RE.fullmatch(ticket) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
        problems.append("worktreeId")
    if lease_path != expected_lease:
        problems.append("leasePath")
    if lease.get("branchRef") != expected_branch or lease.get("ticketId") != ticket:
        problems.append("branch")
    if tree and Path(tree["path"]) != expected_path:
        problems.append("worktreePath")
    if any(part.is_symlink() for part in (expected_path, *expected_path.parents) if part != part.parent and part.is_relative_to(primary)):
        problems.append("symlink")
    return {"worktreePath": str(expected_path), "leasePath": str(expected_lease),
            "branch": expected_branch.removeprefix("refs/heads/"), "problems": problems}


def continuity_times(primary: Path) -> dict[str, datetime]:
    """Newest checkpoint per ticket from the stream the continuity manifest declares."""
    manifest = read_json(primary / CONTINUITY_MANIFEST)
    relative = manifest.get("continuity", {}).get("eventStreamPath") if isinstance(manifest, dict) else None
    latest: dict[str, datetime] = {}
    stream = primary / relative if isinstance(relative, str) else None
    if stream is None or not stream.is_file():
        return latest
    with stream.open("rb") as handle:
        size = handle.seek(0, os.SEEK_END)
        handle.seek(max(0, size - MAX_CONTINUITY_BYTES))
        lines = handle.read().decode("utf-8", "replace").splitlines()
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        checkpoint = event.get("checkpoint") if isinstance(event, dict) else None
        if isinstance(checkpoint, dict):
            ticket, moment = checkpoint.get("ticket"), utc(checkpoint.get("recordedAt"))
            if isinstance(ticket, str) and moment and moment > latest.get(ticket, moment - timedelta(seconds=1)):
                latest[ticket] = moment
    return latest


def live_processes(path: Path) -> list[int]:
    """Processes whose cwd is inside the worktree (Linux /proc only; elsewhere none are observed)."""
    proc, own, pids = Path("/proc"), {os.getpid(), os.getppid()}, []
    if not proc.is_dir():
        return pids
    target = str(path.resolve())
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) in own:
            continue
        try:
            cwd = os.readlink(entry / "cwd")
        except OSError:
            continue
        if cwd == target or cwd.startswith(target + os.sep):
            pids.append(int(entry.name))
    return sorted(pids)


def dirty_paths(worktree: Path) -> list[str]:
    raw = subprocess.run(["git", "-C", str(worktree), "status", "--porcelain", "-z", "--untracked-files=all"],
                         capture_output=True, check=True).stdout.decode("utf-8", "surrogateescape")
    paths, entries = [], raw.split("\0")
    index = 0
    while index < len(entries):
        entry = entries[index]
        if len(entry) > 3:
            paths.append(entry[3:])
            # Porcelain -z: a rename or copy in either status column is followed
            # by its source path as a separate record.
            if set(entry[:2]) & {"R", "C"}:
                index += 1
                if index < len(entries) and entries[index]:
                    paths.append(entries[index])
        index += 1
    return sorted(set(paths))


def integrated(primary: Path, head: str, target: str) -> bool:
    """A ticket HEAD already contained in the target branch needs release, not takeover."""
    if not re.fullmatch(r"[0-9a-f]{40}", head or ""):
        return False
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    # Any target ref that contains HEAD is enough; a stale remote ref must not hide a local merge.
    return any(
        git(primary, "rev-parse", "-q", "--verify", ref, check=False)
        and subprocess.run(["git", "-C", str(primary), "merge-base", "--is-ancestor", head, ref], env=env).returncode == 0
        for ref in (f"refs/remotes/origin/{target}", f"refs/heads/{target}"))


def web_url(primary: Path) -> str | None:
    remote = git(primary, "remote", "get-url", "origin", check=False)
    match = re.fullmatch(r"(?:https?://|ssh://)?(?:[^@/]+@)?([^/:]+)[:/](.+?)(?:\.git)?/?", remote)
    return f"https://{match[1]}/{match[2]}" if match else None


def links(base: str | None, branch: str | None, ticket: str, pull_request: Any) -> dict[str, str | None]:
    if not base:
        return {"project": None, "branch": None, "readme": None, "pullRequest": None, "issues": None}
    name = branch.removeprefix("refs/heads/") if branch else None
    number = re.search(r"([0-9]+)$", str(pull_request)) if pull_request else None
    url = lambda key, **values: f"{base}/{FORGE_PATHS[key].format(**values)}"  # noqa: E731
    return {
        "project": base,
        "branch": url("branch", branch=name) if name else None,
        "readme": url("readme", branch=name, ticket=ticket) if name else None,
        "pullRequest": url("pull", number=number[1]) if number else (url("pullSearch", branch=name) if name else None),
        "issues": url("issues"),
    }


def classify(lease, phase, invalid, layout_record, tree, dirty, pids, last, now, policy, rules, primary) -> str:
    if invalid:
        return "INVALID_LEASE"
    if layout_record["problems"]:
        return "NONCANONICAL_LAYOUT"
    if pids or (last and policy["enabled"] and now - last < timedelta(minutes=policy["idleMinutes"])):
        return "ACTIVE"
    if not policy["enabled"]:
        return "POLICY_DISABLED"
    if phase in rules["frozen"] or lease.get("publicationFrozen"):
        return "IDLE_FROZEN"
    if not tree:
        return "IDLE_NO_WORKTREE"
    if not dirty and integrated(primary, tree["head"], str(lease.get("targetBranch", "main"))):
        return "IDLE_INTEGRATED"
    if phase not in rules["takeover"]:
        return "IDLE_NOT_TAKEABLE"
    return "IDLE_TAKEOVER_ELIGIBLE"


def observe(root: Path, now: datetime | None = None, runtime=None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    primary = primary_checkout(root)
    runtime = runtime or lease_runtime(primary)
    rules, policy = contract(runtime), manifest_policy(primary)
    trees, continuity, base = worktrees(primary), continuity_times(primary), web_url(primary)
    entries = []
    for path, lease in leases(primary, rules):
        ticket = str(lease.get("ticketId", path.stem.split("--")[0]))
        phase = str(lease.get("phase", "unknown"))
        if phase in rules["terminal"]:
            continue
        tree = trees.get(str(lease.get("branchRef")))
        record = canonical_layout(primary, path, lease, tree, rules)
        activity = {"heartbeat": utc(lease.get("heartbeatAt")), "continuity": continuity.get(ticket)}
        dirty, pids = [], []
        if tree and Path(tree["path"]).is_dir():
            worktree = Path(tree["path"])
            activity["commit"] = utc(git(worktree, "log", "-1", "--format=%cI", check=False))
            dirty = dirty_paths(worktree)
            times = [(worktree / item).stat().st_mtime for item in dirty if (worktree / item).is_file()]
            activity["dirtyFile"] = datetime.fromtimestamp(max(times), timezone.utc) if times else None
            pids = live_processes(worktree)
        known = {key: value for key, value in activity.items() if value}
        source, last = max(known.items(), key=lambda item: item[1]) if known else (None, None)
        invalid = bool(runtime.validate_lease(lease)) if lease else True
        entries.append({
            "ticket": ticket,
            "state": classify(lease, phase, invalid, record, tree, dirty, pids, last, now, policy, rules, primary),
            "ownerActor": lease.get("ownerActor"), "ownerSession": lease.get("ownerSession"), "phase": phase,
            "leaseRevision": lease.get("leaseRevision"), "fencingToken": lease.get("fencingToken"),
            "leasePath": str(path), "worktree": tree["path"] if tree else None,
            "canonicalWorktree": record["worktreePath"], "layoutProblems": record["problems"],
            "branchRef": lease.get("branchRef"), "lastActivityAt": stamp(last) if last else None,
            "lastActivitySource": source, "idleMinutes": int((now - last).total_seconds() // 60) if last else None,
            "livePids": pids, "dirtyPaths": dirty[:50], "dirtyCount": len(dirty),
            "links": links(base, lease.get("branchRef"), ticket, lease.get("pullRequest")),
        })
    entries.sort(key=lambda item: (item["state"], item["idleMinutes"] if item["idleMinutes"] is not None else -1))
    return {"schema": BOARD_SCHEMA, "observedAt": stamp(now), "primaryCheckout": str(primary),
            "worktreesRoot": str(primary / rules["WORKTREES_ROOT"]), "leaseRoot": str(primary / rules["LEASE_ROOT"]),
            "project": base, "issues": f"{base}/{FORGE_PATHS['issues']}" if base else None,
            "pullRequests": f"{base}/{FORGE_PATHS['pulls']}" if base else None, "policy": policy,
            "grantsAuthority": False, "tickets": entries}


BACKGROUND_STATES = {"IDLE_NO_WORKTREE", "INVALID_LEASE", "IDLE_INTEGRATED", "NONCANONICAL_LAYOUT"}


def board_markdown(board: dict[str, Any]) -> str:
    def link(label: str, url: str | None) -> str:
        return f"[{label}]({url})" if url else "-"
    primary = Path(board["primaryCheckout"])
    def local(path: str | None) -> str:
        return f"`{Path(path).relative_to(primary)}`" if path and Path(path).is_relative_to(primary) else (f"`{path}`" if path else "-")
    policy = board["policy"]
    rule = (f"Idle takeover after {policy['idleMinutes']} min (from `{policy['source']}`)." if policy["enabled"]
            else f"Idle takeover disabled (`coordination.idleTakeover` in `{policy['source']}`).")
    lines = [
        "# Autonomy board", "",
        f"Observed {board['observedAt']} in `{board['primaryCheckout']}`. {rule} Advisory state; it grants no authority.", "",
        f"Project: {link('repository', board['project'])} · {link('pull requests', board['pullRequests'])} · {link('issues', board['issues'])}", "",
        f"Worktrees: `{board['worktreesRoot']}` · leases: `{board['leaseRoot']}` (wellmanifest/worktrees v5). "
        "Work only in the worktree a lease names; never create one by hand.", "",
        "| Ticket | State | Owner | Phase | Idle | Last activity | Dirty | Worktree | Links |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    background = [item for item in board["tickets"] if item["state"] in BACKGROUND_STATES]
    for item in (item for item in board["tickets"] if item["state"] not in BACKGROUND_STATES):
        idle = "-" if item["idleMinutes"] is None else f"{item['idleMinutes']} min"
        refs = " · ".join(link(name, item["links"][key]) for name, key in
                          (("branch", "branch"), ("README", "readme"), ("PR", "pullRequest")))
        lines.append(f"| {item['ticket']} | {item['state']} | {item['ownerActor']} | {item['phase']} | {idle} "
                     f"| {item['lastActivitySource'] or '-'} | {item['dirtyCount']} | {local(item['worktree'])} | {refs} |")
    if background:
        lines += ["", f"{len(background)} further leases are integrated, have no ticket worktree, break the worktree "
                  "layout or fail the pinned lease contract: "
                  + ", ".join(f"{item['ticket']} ({item['state']}, {item['ownerActor']})" for item in background[:40])
                  + (" …" if len(background) > 40 else "") + ". Reconcile them; they are never taken over automatically."]
    eligible = [item for item in board["tickets"] if item["state"] == "IDLE_TAKEOVER_ELIGIBLE"]
    if eligible:
        lines += ["", "## Takeover candidates", ""]
        lines += [f"- `{item['ticket']}` in {local(item['worktree'])}: `python3 .governance/idle_takeover.py takeover "
                  f"--ticket {item['ticket']} --actor <agent> --session <session>`" for item in eligible]
    return "\n".join(lines) + "\n"


def sync_directory(path: Path) -> None:
    """Persist rename/creation ordering where directory fsync is supported."""
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    created = False
    try:
        with temporary.open("xb") as handle:
            created = True
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        # A failed exclusive open must not remove an existing attempt's file.
        if created:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass  # Successful replacement already consumed the temporary.


@contextmanager
def lease_lock(lease_path: Path):
    """Serialize every idle-takeover transition of one lease; a held lock refuses, never waits."""
    lock = lease_path.with_name(lease_path.name + ".lock")
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            if fcntl:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:  # pragma: no cover - Windows
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise PermissionError("Another transition holds this lease; re-observe.") from error
        yield
    finally:
        os.close(descriptor)


def write_board(board: dict[str, Any]) -> Path:
    directory = Path(board["primaryCheckout"]) / BOARD_DIR
    write_atomic(directory / "autonomy-board.json", (json.dumps(board, indent=2, sort_keys=True) + "\n").encode())
    write_atomic(directory / "autonomy-board.md", board_markdown(board).encode())
    return directory / "autonomy-board.md"


def file_identity(path: Path) -> tuple[int, int, int, int]:
    status = path.stat()
    return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns


def snapshot(primary: Path, entry: dict[str, Any]) -> dict[str, Any] | None:
    """Content-addressed tar of the dirty files plus the tracked diff; the worktree stays untouched."""
    if not entry["dirtyCount"]:
        return None
    worktree = Path(entry["worktree"])
    buffer, total = io.BytesIO(), 0
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        def add(name: str, data: bytes) -> None:
            nonlocal total
            total += len(data)
            if total > MAX_SNAPSHOT_BYTES:
                raise ValueError("Dirty work exceeds the bounded snapshot size; hand off instead.")
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            archive.addfile(info, io.BytesIO(data))
        diff = subprocess.run(["git", "-C", str(worktree), "diff", "--binary", "HEAD"], capture_output=True, check=True).stdout
        add("tracked.diff", diff)
        for item in dirty_paths(worktree):
            path = worktree / item
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()
                add("files/" + item, data)
    data = buffer.getvalue()
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Dirty work exceeds the bounded snapshot size; hand off instead.")
    digest = hashlib.sha256(data).hexdigest()
    target = primary / SNAPSHOT_DIR / entry["ticket"] / f"{digest}.tar"
    if not target.exists():
        write_atomic(target, data)
    return {"ref": f"snapshot:idle-takeover/{entry['ticket']}/{digest}", "sha256": digest,
            "path": str(target), "paths": entry["dirtyPaths"], "headSha": git(worktree, "rev-parse", "HEAD")}


def takeover(root: Path, ticket: str, actor: str, session: str, now: datetime | None = None) -> dict[str, Any]:
    if not TICKET_RE.fullmatch(ticket) or not IDENTITY_RE.fullmatch(actor) or not IDENTITY_RE.fullmatch(session):
        raise ValueError("Exact ticket, actor and session identities are required.")
    runtime = lease_runtime(primary_checkout(root))
    now = now or datetime.now(timezone.utc)
    board = observe(root, now, runtime)
    write_board(board)
    entry = next((item for item in board["tickets"] if item["ticket"] == ticket), None)
    if entry is None:
        raise PermissionError(f"{ticket} is NO_LIVE_LEASE; idle takeover needs IDLE_TAKEOVER_ELIGIBLE.")
    with lease_lock(Path(entry["leasePath"])):
        # Decide again under the lock: the first observation only located the lease.
        return locked_takeover(root, ticket, actor, session, now, runtime)


def locked_takeover(root: Path, ticket: str, actor: str, session: str, now: datetime, runtime) -> dict[str, Any]:
    board = observe(root, now, runtime)
    entry = next((item for item in board["tickets"] if item["ticket"] == ticket), None)
    if entry is None or entry["state"] != "IDLE_TAKEOVER_ELIGIBLE":
        state = entry["state"] if entry else "NO_LIVE_LEASE"
        raise PermissionError(f"{ticket} is {state}; idle takeover needs IDLE_TAKEOVER_ELIGIBLE.")
    if entry["ownerActor"] == actor and entry["ownerSession"] == session:
        raise PermissionError(f"{ticket} is already held by this session; heartbeat instead of taking over.")
    primary, lease_path = Path(board["primaryCheckout"]), Path(entry["leasePath"])
    original, identity = lease_path.read_bytes(), file_identity(lease_path)
    lease = json.loads(original)
    snap = snapshot(primary, entry)
    authority = (f"policy:{SCHEMA};idleMinutes={entry['idleMinutes']};limit={board['policy']['idleMinutes']};"
                 f"lastActivity={entry['lastActivityAt']}" + (f";snapshot={snap['sha256']}" if snap else ""))
    receipts, current, sequence = [], dict(lease), int(lease.get("eventSequence", 0))
    for action in (["expire"] if current["phase"] != "expired" else []) + ["release"]:
        request = {"schema": runtime.REQUEST_SCHEMA, "requestId": f"idle-takeover-{action}-{stamp(now)}",
                   "leaseId": current["leaseId"], "action": action, "expectedRevision": current["leaseRevision"],
                   "expectedFencingToken": current["fencingToken"], "expectedPhase": current["phase"],
                   "requestedBy": actor, "idempotencyKey": f"{ticket}:{current['fencingToken']}:{action}",
                   "targetHeadSha": None, "replacementReceiptRef": None, "authorityRef": authority,
                   "requestedAt": stamp(now)}
        receipt, errors = runtime.evaluate_transition(current, request)
        if errors:
            raise PermissionError(f"{action} rejected: {errors[0]['code']} {errors[0]['message']}")
        receipts.append(receipt)
        sequence += 1
        current.update(phase=receipt["phaseAfter"], leaseRevision=receipt["leaseRevision"],
                       fencingToken=receipt["fencingToken"], previousReceiptRef=receipt["receiptRef"], eventSequence=sequence)
    worktree = Path(entry["worktree"])
    claimed = dict(current, ownerActor=actor, ownerSession=session, phase="claimed",
                   leaseRevision=current["leaseRevision"] + 1, fencingToken=current["fencingToken"] + 1,
                   issuedAt=stamp(now), heartbeatAt=stamp(now),
                   expiresAt=stamp(now + timedelta(minutes=board["policy"]["leaseMinutes"])),
                   headSha=git(worktree, "rev-parse", "HEAD"), eventSequence=sequence + 1)
    errors = runtime.validate_lease(claimed)
    if errors:
        raise ValueError(f"Claimed lease is invalid: {errors[0]['message']}")
    # wellmanifest/worktrees rules 9-10: a machine-readable result names the exact
    # ticket, branch, worktree and lease; the agent takes its paths only from here.
    record = {"schema": SCHEMA, "ticket": ticket, "takenOverAt": stamp(now),
              "branch": entry["branchRef"].removeprefix("refs/heads/"), "worktreePath": str(worktree),
              "leasePath": str(lease_path),
              "writerEnvironment": {"NEW_PROJECT_WRITER_ACTOR": actor, "NEW_PROJECT_WRITER_SESSION": session,
                                    "NEW_PROJECT_LEASE_REVISION": str(claimed["leaseRevision"]),
                                    "NEW_PROJECT_FENCING_TOKEN": str(claimed["fencingToken"])},
              "previousOwner": {"actor": lease["ownerActor"], "session": lease["ownerSession"],
                                "leaseRevision": lease["leaseRevision"], "fencingToken": lease["fencingToken"]},
              "newOwner": {"actor": actor, "session": session, "leaseRevision": claimed["leaseRevision"],
                           "fencingToken": claimed["fencingToken"]},
              "idle": {"minutes": entry["idleMinutes"], "lastActivityAt": entry["lastActivityAt"],
                       "source": entry["lastActivitySource"]},
              "authorityRef": authority, "snapshot": snap, "receipts": receipts}
    # Compare-and-swap under the lease lock, immediately before the receipt and
    # the replacement; the fencing token rejects any writer that bypassed the lock.
    if lease_path.read_bytes() != original or file_identity(lease_path) != identity:
        raise PermissionError("Lease changed during takeover (compare-and-swap lost); re-observe.")
    trace = primary / RECEIPT_DIR / f"{ticket}.jsonl"
    claimed_bytes = (json.dumps(claimed, indent=2, sort_keys=True) + "\n").encode()
    prepared = {"schema": "new-project.idle-takeover-prepare/v1", "state": "prepared",
                "grantsAuthority": False, "beforeSha256": hashlib.sha256(original).hexdigest(),
                "afterSha256": hashlib.sha256(claimed_bytes).hexdigest(),
                "lease": claimed, "record": record}
    prepared_bytes = (json.dumps(prepared, sort_keys=True) + "\n").encode()
    digest = hashlib.sha256(prepared_bytes).hexdigest()
    pending = trace.with_name(f"{ticket}.{digest}.prepared.json")
    if pending.exists():
        if pending.read_bytes() != prepared_bytes:
            raise PermissionError("Prepared handoff changed; preserve it and reconcile.")
    else:
        write_atomic(pending, prepared_bytes)
    # Preparing recovery data is an I/O boundary: compare the original lease
    # again immediately before replacement. Prepared data grants no authority.
    if lease_path.read_bytes() != original or file_identity(lease_path) != identity:
        raise PermissionError("Lease changed while preparing takeover (compare-and-swap lost); re-observe.")
    write_atomic(lease_path, claimed_bytes)
    if lease_path.read_bytes() != claimed_bytes:
        raise PermissionError("Replaced lease changed; preserve prepared recovery data and reconcile.")
    # Publish success only after the matching lease is applied. If append fails,
    # the prepared record binds both hashes for explicit controller recovery.
    with trace.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    sync_directory(trace.parent)
    try:
        pending.unlink()
    except OSError:
        pass  # Final lease and success trace are committed; stale prepare is harmless.
    record["board"] = str(write_board(observe(root, now, runtime)))
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=Path("."))
    commands = parser.add_subparsers(dest="command", required=True)
    show = commands.add_parser("observe", help="classify ticket leases and rewrite the autonomy board")
    show.add_argument("--format", choices=("json", "md"), default="md")
    show.add_argument("--no-write", action="store_true", help="print only; do not rewrite the board")
    take = commands.add_parser("takeover", help="take over an IDLE_TAKEOVER_ELIGIBLE ticket")
    take.add_argument("--ticket", required=True)
    take.add_argument("--actor", required=True)
    take.add_argument("--session", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "observe":
            board = observe(args.root)
            if not args.no_write:
                write_board(board)
            sys.stdout.write(json.dumps(board, indent=2) + "\n" if args.format == "json" else board_markdown(board))
            return 0
        record = takeover(args.root, args.ticket, args.actor, args.session)
        sys.stdout.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
        return 0
    except PermissionError as error:
        sys.stderr.write(f"GOV-IDLE-TAKEOVER-001: {error}\n")
        return 1
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.stderr.write(f"GOV-IDLE-TAKEOVER-002: {error}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
