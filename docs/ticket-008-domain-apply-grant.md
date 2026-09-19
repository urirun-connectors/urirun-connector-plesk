# Ticket 008: domain-scoped site sync grants

Issue: https://github.com/urirun-connectors/urirun-connector-plesk/issues/8

Site sync previously checked a signed grant against the transport host even when the requested target was a domain. Recover the existing local fix to use the declared domain, with host fallback when no domain is provided. Keep plan hash, deployment scope and replay validation in place.

Acceptance: a matching domain grant succeeds; another domain or transport-host grant for a declared domain fails before upload; host-only requests remain supported. Use fake SFTP and temporary local files, with no live publication. Reproduce the original test failure before applying the source fix; run the full test suite and configured GitHub CI before merge.

Original dirty files remain untouched in the primary checkout. Three original local commits are patch-equivalent to PR7 and its merged tree. Work proceeds only in ticket008's isolated worktree, with one writer; no adopted lease controller was found (the host layout record is not a fencing lease).
