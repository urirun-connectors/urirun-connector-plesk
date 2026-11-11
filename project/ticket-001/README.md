# Ticket 001: Adopt native governance for Plesk ingress delivery

- **ID**: ticket-001
- **Owner**: agent:codex-mobile-20261111
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: the user requested continuation, tests and
protected merges for Heyasa mesh and Plesk domain 427,
`heyasa.prototypowanie.pl`. Parent request: PLF-26506 on
http://127.0.0.1:18769.

Adopt the independently published native governance package 0.20.144 at
8724674cfa7eebf0c64df2db63ff528ad8dbd159 through its canonical updater.
The exact 135 installer-owned paths and four absent required seeds were
qualified before allocation. Preserve unrelated untracked scaffold/docs/error
files and historical refs in the primary checkout. This ticket creates no
product runtime feature or public ingress activation. The canonical atomic
adoption binding also requires the existing `pyproject.toml` to declare the
same standard pin and load the governance pytest plugin. Its dependency
declarations and package metadata remain unchanged.

## Acceptance criteria

- [x] AC-01: Native managed files and immutable lock match the exact published
  package; required native allocator, hooks and checks work in this checkout.
- [x] AC-02: Existing product source, dependency declarations and unrelated
  primary files remain unchanged; the packaging delta contains only the
  canonical governance pin and pytest plugin binding.
- [x] AC-03: Native governance and existing connector regression tests pass.
- [ ] AC-04: Publication uses exact-head OneDev and independent Validator
  evidence after protected executor enrollment; installation is not approval.

## Validation and dependencies

Canonical migration preflight: 135 planned changes and no missing prerequisites.
First allocation admitted the exact installer-owned dirty digest with zero
scope blockers. Native governance passes with zero errors and warnings;
159 connector regression tests pass through the independently approved full
Wellman, explicitly reusing this repository's primary virtual environment.
Writer fencing and the two-checkout overlap guard pass. Two optional root
launcher aliases are omitted, preserving the original M delivery budget and
the complete managed-file closure. Protected policy must explicitly bind
those optional omissions before CI admission.

Validator admission was independently merged in subactor/validator-agent PR791.
OneDev PR962 has merged. Plesk executor enrollment remains a separate
dependency; OneDev ticket897 currently reserves its shared configuration.
Independent exact-head CI and protected publication remain pending.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
