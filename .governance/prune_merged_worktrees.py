#!/usr/bin/env python3
"""Prune clean integrated checkouts while preserving changed or declined refs.

The caller must separately verify ownership, released writers and cleanup
permission. Git removal releases only the exact checkout registration. Branch
cleanup verifies the integration target and expected branch tip atomically;
this helper never forces deletion or globally prunes other registrations.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def git_cmd(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def get_worktrees(repo: Path) -> list[dict[str, str]]:
    res = git_cmd(repo, "worktree", "list", "--porcelain")
    if res.returncode != 0:
        raise RuntimeError(f"git worktree list failed: {res.stderr}")

    worktrees: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            if current:
                worktrees.append(current)
                current = {}
            continue
        parts = line.split(" ", 1)
        key = parts[0]
        val = parts[1] if len(parts) > 1 else ""
        current[key] = val
    if current:
        worktrees.append(current)
    return worktrees


def is_worktree_clean(path: Path) -> bool:
    # Ignored files may contain unique data, so retain their checkout too.
    res = git_cmd(path, "status", "--porcelain", "--untracked-files=all", "--ignored")
    return res.returncode == 0 and not res.stdout.strip()


def is_ancestor(repo: Path, commit: str, target: str) -> bool:
    res = git_cmd(repo, "merge-base", "--is-ancestor", commit, target)
    return res.returncode == 0


def _commit(repo: Path, ref: str) -> str | None:
    result = git_cmd(repo, "rev-parse", "--verify", ref + "^{commit}")
    value = result.stdout.strip()
    if result.returncode == 0 and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        return value
    return None


def _target(repo: Path, name: str) -> tuple[str, str, str]:
    if name.startswith(("refs/heads/", "refs/remotes/")):
        candidates = [(name, name)]
    elif name.startswith("origin/"):
        candidates = [(name, "refs/remotes/" + name)]
    else:
        candidates = [("origin/" + name, "refs/remotes/origin/" + name),
                      (name, "refs/heads/" + name)]
    for display, full in candidates:
        if full.startswith("refs/remotes/") and "/" not in full.removeprefix("refs/remotes/"):
            continue
        if git_cmd(repo, "check-ref-format", full).returncode != 0:
            continue
        if git_cmd(repo, "symbolic-ref", "--quiet", full).returncode == 0:
            raise ValueError("Target must identify a direct branch reference, not a symbolic alias")
        sha = _commit(repo, full)
        if sha is not None:
            return display, full, sha
    raise ValueError(f"Target branch '{name}' not found in {repo}")


def _checkout_matches(path: Path, head: str, branch: str) -> bool:
    if _commit(path, "HEAD") != head:
        return False
    symbolic = git_cmd(path, "symbolic-ref", "--quiet", "HEAD")
    if symbolic.returncode not in (0, 1):
        return False
    return (symbolic.stdout.strip() if symbolic.returncode == 0 else "") == branch


def _delete_exact_branch(
    repo: Path, branch: str, head: str, target: str, target_sha: str,
) -> subprocess.CompletedProcess[str]:
    # Prepare locks both exact names and verifies their expected OIDs. Inspect
    # their direct/symbolic type while those locks are held, before committing.
    command = ["git", "-C", str(repo), "update-ref", "--no-deref", "--stdin"]
    transaction = (f"start\nverify {target} {target_sha}\n"
                   f"delete {branch} {head}\nprepare\n")
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as errors:
        try:
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=errors, text=True, encoding="utf-8", errors="replace",
            )
        except OSError as error:
            return subprocess.CompletedProcess(command, 1, "", str(error))
        prefix = ""
        output = ""
        declined = None
        try:
            process.stdin.write(transaction)
            process.stdin.flush()
            prefix = process.stdout.readline() + process.stdout.readline()
            if prefix != "start: ok\nprepare: ok\n":
                declined = "reference transaction preparation failed"
            else:
                for ref in (target, branch):
                    if git_cmd(repo, "symbolic-ref", "--quiet", ref).returncode != 1:
                        declined = "reference became symbolic or could not be verified under lock"
                        break
            if not declined:
                try:
                    if any(item.get("branch") == branch for item in get_worktrees(repo)):
                        declined = "branch remains checked out elsewhere"
                except RuntimeError as error:
                    declined = f"could not verify other checkout registrations: {error}"
            if process.poll() is None:
                process.stdin.write("abort\n" if declined else "commit\n")
                process.stdin.flush()
            output, _ = process.communicate()
        except (OSError, ValueError) as error:
            declined = f"reference transaction outcome unconfirmed: {error}"
        finally:
            if process.poll() is None or (process.stdout and not process.stdout.closed):
                if process.poll() is None:
                    try:
                        process.stdin.write("abort\n")
                        process.stdin.flush()
                    except (OSError, ValueError):
                        pass
                try:
                    remaining, _ = process.communicate(timeout=5)
                    output += remaining or ""
                except subprocess.TimeoutExpired:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    for stream in (process.stdin, process.stdout):
                        if stream and not stream.closed:
                            stream.close()
                    declined = "reference transaction interrupted; reconcile refs before retry"
        errors.seek(0)
        detail = errors.read()
        if declined:
            return subprocess.CompletedProcess(command, 1, prefix + output, declined + ": " + detail)
        if process.returncode == 0 and "commit: ok\n" not in output:
            return subprocess.CompletedProcess(command, 1, prefix + output, "commit outcome unconfirmed: " + detail)
        return subprocess.CompletedProcess(command, process.returncode, prefix + output, detail)


def prune_merged_worktrees(
    repo: Path, target_branch: str = "main", dry_run: bool = False
) -> dict[str, Any]:
    target_ref, target_full, target_sha = _target(repo, target_branch)
    wts = get_worktrees(repo)
    if not wts:
        return {"pruned": [], "skipped": []}
    target_name = (target_full.removeprefix("refs/heads/")
                   if target_full.startswith("refs/heads/")
                   else target_full.removeprefix("refs/remotes/").split("/", 1)[1])
    pruned: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for wt in wts[1:]:
        path = Path(wt.get("worktree", ""))
        head = wt.get("HEAD", "")
        branch = wt.get("branch", "")
        name = branch.removeprefix("refs/heads/") if branch else None

        def skip(reason: str, **extra: Any) -> None:
            skipped.append({"path": str(path), "branch": name, "reason": reason, **extra})

        if not path.exists():
            skip("directory missing")
            continue
        if branch and (not branch.startswith("refs/heads/")
                       or git_cmd(repo, "check-ref-format", branch).returncode != 0):
            skip("invalid branch reference")
            continue
        if name == target_name or branch == target_full:
            skip("target branch checkout")
            continue
        if not is_worktree_clean(path):
            skip("dirty (uncommitted, untracked or ignored data)")
            continue
        if not is_ancestor(repo, head, target_sha):
            skip(f"not merged into {target_ref}", head=head)
            continue
        if (_commit(repo, target_full) != target_sha
                or not _checkout_matches(path, head, branch)
                or (branch and _commit(repo, branch) != head)):
            skip("checkout, branch or target changed since observation")
            continue
        if dry_run:
            pruned.append({"path": str(path), "branch": name, "action": "would_remove"})
            continue
        # Git also refuses removal if tracked/untracked data appeared after
        # inspection; never turn its refusal into a force removal.
        removed = git_cmd(repo, "worktree", "remove", str(path))
        if removed.returncode != 0:
            skip(f"remove failed: {removed.stderr.strip()}")
            continue
        if branch:
            deleted = _delete_exact_branch(repo, branch, head, target_full, target_sha)
            if deleted.returncode != 0:
                skip(f"branch cleanup declined or unconfirmed: {deleted.stderr.strip()}")
        pruned.append({"path": str(path), "branch": name, "action": "removed"})
    return {"target": target_ref, "pruned": pruned, "skipped": skipped}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prune linked worktrees that are clean and already merged."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path.cwd(),
        help="Path to repository (default: current directory)",
    )
    parser.add_argument(
        "--target-branch", default="main", help="Target branch to check ancestry against (default: main)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Report what would be pruned without changing anything"
    )
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args(argv)

    try:
        report = prune_merged_worktrees(
            args.repo.resolve(), target_branch=args.target_branch, dry_run=args.dry_run
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Target branch: {report['target']}")
        print(f"Pruned ({len(report['pruned'])}):")
        for item in report["pruned"]:
            print(f"  - {item['path']} ({item.get('branch', 'detached')}) -> {item['action']}")
        print(f"Skipped ({len(report['skipped'])}):")
        for item in report["skipped"]:
            print(f"  - {item['path']} ({item.get('branch', 'detached')}): {item['reason']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
