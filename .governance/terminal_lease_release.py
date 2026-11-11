#!/usr/bin/env python3
"""Explicit current-owner release after recorded merged delivery; never takeover.

This POSIX local-single-clone controller does not repair invalid projections,
remove worktrees, infer owner death, or approve publication. Plan is read-only.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

REQUEST_SCHEMA = 'new-project.terminal-owner-release/v1'
FIELDS = {'schema', 'requestId', 'worktreeId', 'ownerActor', 'ownerSession', 'ownerHandoff',
          'expectedRevision', 'expectedFencingToken', 'expectedLeaseSha256', 'terminalReceiptRef'}
MAX_BYTES = 1024 * 1024


def require(condition, message):
    if not condition:
        raise PermissionError(message)


def sibling(name):
    spec = importlib.util.spec_from_file_location('_terminal_owner_' + name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = value
    spec.loader.exec_module(value)
    return value


canonical = sibling('change_lease_check')
activity = sibling('ticket_activity')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git(root, *args, check=True):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    result = subprocess.run(['git', '-C', str(root), *args], env=env, capture_output=True, timeout=20)
    if check:
        require(result.returncode == 0, 'git_observation_unavailable')
    return result.stdout.decode().strip()


@contextmanager
def directory(path, create=False):
    """Keep all parents anchored; operations use the held directory descriptor."""
    require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'posix_controller_required')
    path = Path(os.path.abspath(path))
    require('..' not in path.parts, 'unsafe_path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors = [os.open(path.anchor, flags)]
    try:
        for part in path.parts[1:]:
            if create:
                try: os.mkdir(part, 0o700, dir_fd=descriptors[-1])
                except FileExistsError: pass
            descriptors.append(os.open(part, flags, dir_fd=descriptors[-1]))
        def verify():
            for parent, child, part in zip(descriptors, descriptors[1:], path.parts[1:]):
                named, held = os.stat(part, dir_fd=parent, follow_symlinks=False), os.fstat(child)
                require(stat.S_ISDIR(named.st_mode) and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino), 'directory_identity_changed')
        verify()
        yield descriptors[-1], verify
    finally:
        for descriptor in reversed(descriptors): os.close(descriptor)


def read_at(fd, name, limit=MAX_BYTES, private=False):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and (not private or info.st_nlink == 1), 'regular_private_file_required')
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'input_exceeds_bound')
    return raw


def read_path(path):
    with directory(path.parent) as (fd, verify):
        raw = read_at(fd, path.name)
        verify()
        return decode(raw)


@contextmanager
def lease_lock(fd, name, verify):
    import fcntl
    descriptor = os.open(name + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe_lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def verify_lock():
            verify()
            named = os.stat(name + '.lock', dir_fd=fd, follow_symlinks=False)
            require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1
                    and (named.st_dev, named.st_ino) == (info.st_dev, info.st_ino), 'lock_identity_changed')
        verify_lock()
        yield verify_lock
    finally:
        os.close(descriptor)


def atomic_at(fd, name, raw, exclusive=False):
    temporary = '.terminal-' + secrets.token_hex(12)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        else:
            os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try: os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError: pass


def _replace_lease(fd, name, raw):
    atomic_at(fd, name, raw)


def request_identity(request):
    require(isinstance(request, dict) and set(request) == FIELDS, 'invalid_request_fields')
    require(request['schema'] == REQUEST_SCHEMA and request['ownerHandoff'] is True, 'explicit_owner_handoff_required')
    for key in ('ownerActor', 'ownerSession', 'requestId', 'terminalReceiptRef'):
        require(isinstance(request[key], str) and 0 < len(request[key]) <= 160, 'invalid_request_identity')
    for key in ('expectedRevision', 'expectedFencingToken'):
        require(type(request[key]) is int and request[key] > 0, 'invalid_request_fencing')
    require(isinstance(request['expectedLeaseSha256'], str) and re.fullmatch('[0-9a-f]{64}', request['expectedLeaseSha256']), 'invalid_request_digest')
    value = request['worktreeId']
    match = re.fullmatch(r'(ticket-([0-9]{3,}))--([a-z0-9]+(?:-[a-z0-9]+)*)', value) if isinstance(value, str) else None
    require(match is not None, 'invalid_worktree_identity')
    return match[1], 'refs/heads/ticket/' + match[2] + '-' + match[3]


def _verify_terminal(root, request, lease):
    # Activity receipts establish landed delivery, not approval authority. The
    # current owner explicitly relinquishes only its own already-finished lease.
    with activity.ActivityReadBatch(root):
        policy = activity.load_policy(root)
        rows = activity._validate_registry(activity._load(activity.registry_path(root, policy)), activity.repository_ref(root))
        receipt = next((r for r in rows if r['receiptRef'] == request['terminalReceiptRef']), None)
        require(receipt is not None and receipt['ticket'] == lease['ticketId']
                and receipt['outcome'] == 'merged' and receipt['targetBranch'] == lease['targetBranch'], 'matching_merged_receipt_required')
        rule = policy['terminalOutcomes'].get('merged')
        require(rule and rule.get('releasesReservation') is True
                and activity._terminal_verified(root, receipt, rule, activity._target_ref(root, receipt['targetBranch'])), 'terminal_delivery_unverified')
        if lease['phase'] in {'approved', 'merged', 'closed'}:
            require(lease['headSha'] == receipt['headSha'], 'publication_head_mismatch')
        tree = root / '.worktrees' / lease['worktreeId']
        branch_head = git(root, 'rev-parse', '--verify', lease['branchRef'], check=False)
        if not branch_head and lease['phase'] in {'claimed', 'editing', 'validating'}:
            # An allocation head is the accepted base, not the later published
            # commit. Explicit owner handoff may release an already-removed
            # delivery, but may neither remove nor normalize remaining state.
            require(not os.path.lexists(tree), 'terminal_checkout_still_present')
            require(not git(root, 'for-each-ref', '--format=%(refname)', lease['branchRef']),
                    'terminal_ref_still_present')
            registrations = git(root, 'worktree', 'list', '--porcelain', '-z')
            require(not any('worktree ' + str(tree) in fields or 'branch ' + lease['branchRef'] in fields
                            for fields in (row.split('\0') for row in registrations.split('\0\0'))),
                    'terminal_checkout_still_registered')
            require(lease['headSha'] is not None
                    and git(root, '--no-replace-objects', 'merge-base', lease['headSha'], receipt['headSha'])
                    == lease['headSha'], 'terminal_allocation_base_unverified')
        else:
            require((branch_head or lease['headSha']) == receipt['headSha'], 'terminal_head_mismatch')
        if tree.exists():
            with directory(tree): pass
            require(git(tree, 'rev-parse', 'HEAD') == receipt['headSha']
                    and git(tree, 'symbolic-ref', 'HEAD') == lease['branchRef']
                    and not git(tree, 'status', '--porcelain', '--untracked-files=all'), 'worktree_has_unpublished_work')
        return receipt


def replacement(lease, request, stamp):
    require(not canonical.validate_lease(lease), 'invalid_canonical_lease')
    phase = lease['phase']
    if phase in {'claimed', 'editing', 'validating'}: actions = ['cancel', 'release']
    elif phase == 'approved': actions = ['record-merge', 'close', 'release']
    elif phase == 'merged': actions = ['close', 'release']
    elif phase in {'closed', 'cancelled'}: actions = ['release']
    else: raise PermissionError('phase_requires_existing_controller_reconciliation')
    current, receipts = dict(lease), []
    for action in actions:
        transition = {'schema': canonical.REQUEST_SCHEMA, 'requestId': sha(encoded(request)) + '-' + action,
            'leaseId': current['leaseId'], 'action': action, 'expectedRevision': current['leaseRevision'],
            'expectedFencingToken': current['fencingToken'], 'expectedPhase': current['phase'],
            'requestedBy': request['ownerActor'], 'idempotencyKey': request['requestId'] + ':' + action,
            'targetHeadSha': current['headSha'], 'replacementReceiptRef': None,
            'authorityRef': request['terminalReceiptRef'], 'requestedAt': stamp}
        receipt, errors = canonical.evaluate_transition(current, transition)
        require(not errors and receipt is not None, 'canonical_transition_refused')
        current.update(phase=receipt['phaseAfter'], leaseRevision=receipt['leaseRevision'],
            fencingToken=receipt['fencingToken'], eventSequence=current['eventSequence'] + 1,
            publicationFrozen=receipt['phaseAfter'] in canonical.FROZEN_PHASES, previousReceiptRef=receipt['receiptRef'])
        receipts.append(receipt)
    require(not canonical.validate_lease(current), 'invalid_release_result')
    return current, receipts


def _execute(root, request, fd, verify, name, apply):
    raw = read_at(fd, name, canonical.MAX_LEASE_BYTES, private=True)
    current = decode(raw)
    require(not canonical.validate_lease(current), 'invalid_canonical_lease')
    ticket, branch = request_identity(request)
    expected = {'ticketId': ticket, 'worktreeId': request['worktreeId'], 'branchRef': branch,
        'repositoryRef': 'local/' + sha(str(root).encode()),
        'ownerActor': request['ownerActor'], 'ownerSession': request['ownerSession']}
    require(all(current[k] == v for k, v in expected.items()), 'current_owner_or_repository_mismatch')
    journal_path = root / '.subactor/receipts/terminal-owner-release' / (sha(encoded(request)) + '.json')
    if journal_path.exists() or journal_path.is_symlink():
        journal = read_path(journal_path)
        original = base64.b64decode(journal['original'], validate=True)
        require(journal['request'] == request and sha(original) == request['expectedLeaseSha256'], 'journal_request_mismatch')
        prior = decode(original)
        require(prior['leaseRevision'] == request['expectedRevision']
                and prior['fencingToken'] == request['expectedFencingToken'], 'journal_fencing_mismatch')
        target, receipts = replacement(prior, request, journal['stamp'])
        require(journal['replacement'] == target and journal['transitions'] == receipts, 'journal_transition_mismatch')
        if raw == encoded(target):
            return {'status': 'idempotent', 'leaseRevision': target['leaseRevision'], 'fencingToken': target['fencingToken']}
        require(raw == original, 'journal_lease_compare_and_swap_lost')
    else:
        require(sha(raw) == request['expectedLeaseSha256'] and current['leaseRevision'] == request['expectedRevision']
                and current['fencingToken'] == request['expectedFencingToken'], 'lease_compare_and_swap_lost')
        stamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        target, receipts = replacement(current, request, stamp)
        journal = {'schema': REQUEST_SCHEMA, 'request': request, 'original': base64.b64encode(raw).decode(),
                   'replacement': target, 'transitions': receipts, 'stamp': stamp}
    _verify_terminal(root, request, current)
    verify()
    require(read_at(fd, name, canonical.MAX_LEASE_BYTES, private=True) == raw, 'lease_compare_and_swap_lost')
    if not apply:
        return {'status': 'planned', 'grantsAuthority': False, 'actions': [r['action'] for r in receipts]}
    with directory(journal_path.parent, create=True) as (journal_fd, verify_journal):
        try: atomic_at(journal_fd, journal_path.name, encoded(journal), exclusive=True)
        except FileExistsError:
            require(read_at(journal_fd, journal_path.name) == encoded(journal), 'journal_changed')
        verify_journal()
        verify()
        require(read_at(fd, name, canonical.MAX_LEASE_BYTES, private=True) == raw, 'lease_compare_and_swap_lost')
        _replace_lease(fd, name, encoded(target))
        verify()
    return {'status': 'released', 'leaseRevision': target['leaseRevision'], 'fencingToken': target['fencingToken'],
            'receipt': str(journal_path), 'worktreeCleanup': 'separate_controller_required'}


def release_owner(root, request, *, apply=False, actor=None, session=None):
    request_identity(request)
    require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'posix_controller_required')
    if apply:
        require(actor == request['ownerActor'] and session == request['ownerSession'], 'invoking_owner_context_required')
    root = Path(root).absolute()
    with directory(root): pass
    root = Path(git(root, 'worktree', 'list', '--porcelain').splitlines()[0].removeprefix('worktree '))
    require(root.is_absolute(), 'primary_checkout_unavailable')
    policy = root / '.governance/ticket-allocation.json'
    if not policy.exists(): policy = root / 'governance/ticket-allocation.json'
    config = read_path(policy)
    require(isinstance(config, dict) and set(config) == {'$schema', 'schema', 'mode'}
            and config['schema'] == 'new-project.ticket-allocation/v1'
            and config['mode'] == 'local-single-clone', 'registered_controller_required')
    with directory(root / '.subactor/leases') as (fd, verify_directory):
        def verify():
            verify_directory()
            require(read_path(policy) == config, 'controller_policy_changed')
        name = request['worktreeId'] + '.json'
        if apply:
            with lease_lock(fd, name, verify) as verify_lock:
                return _execute(root, request, fd, verify_lock, name, True)
        return _execute(root, request, fd, verify, name, False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(release_owner(args.root, read_path(args.request.absolute()), apply=args.apply,
            actor=os.environ.get('NEW_PROJECT_WRITER_ACTOR'), session=os.environ.get('NEW_PROJECT_WRITER_SESSION'))))
        return 0
    except (OSError, ValueError, TypeError, KeyError, PermissionError, subprocess.SubprocessError, activity.ActivityError):
        print('GOV-CHANGE-LEASE-002: terminal owner release refused; preserve evidence and reconcile the exact owner, CAS, receipt and controller.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
