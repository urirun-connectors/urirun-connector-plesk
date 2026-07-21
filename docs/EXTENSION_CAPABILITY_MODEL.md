# Plesk extension capability model

## Problem

Plesk is not one uniform API. Core objects and installed extensions expose different
surfaces, permissions and stability guarantees. A button visible in the panel does not
prove that a supported remote endpoint exists for the current customer account.

The connector therefore separates runtime discovery from execution authority.

## Layers

| Layer | Purpose | Authority | Policy |
| --- | --- | --- | --- |
| REST v2 | Core administrator objects and CLI wrappers | administrator API key | Path is restricted to `/api/v2/`; secrets stay in vault |
| XML API | Broad core object coverage and extension operator | administrator, reseller or customer depending on operator | Structured packets only; no caller-provided XML |
| Extension XML | Installed extension inventory and documented extension operations | Plesk administrator | Operation must exist in `extension_profiles.json` |
| SFTP/FTPS | Subscription file deployment | subscription system user | Never treated as Plesk server administrator access |
| Root SSH/CLI | Server utilities and extension CLI unavailable remotely | separate root credential | Not implemented by the subscription transport; future adapter must use an argv allowlist |
| Panel/GUI | Human-only or unstable extension flows | authenticated panel session | Handoff or a dedicated reviewed adapter; private endpoints are not generic API |

## Dynamic object

`plesk://host/extensions/query/catalog` returns the authoritative installed state:

```json
{
  "id": "sslit",
  "name": "SSL It!",
  "version": "...",
  "release": 123,
  "active": true
}
```

`plesk://host/extensions/query/capabilities` joins that state with the checked-in
profiles. An installed but unknown extension is visible with
`execution_policy=discovery-only`. It cannot be called until a reviewed profile is
added.

## Operation profile

Each profile declares:

- extension and operation identifiers;
- `query` or `command` effect;
- risk class;
- transport;
- accepted and required argument names;
- optional delegation to another stable URI Process.

Inputs are scalar values or lists. The connector creates the XML tree itself. Raw XML,
arbitrary REST paths, shell fragments and private panel URLs are not profile inputs.

## Mutation lifecycle

`extension/command/call` always returns a deterministic dry-run first. Apply requires:

1. the same operation and arguments producing the same `plan_hash`;
2. a live global mutation switch or short-lived mutate lease;
3. `PLESK_EXTENSION_APPLY=1`;
4. a signed grant bound to target, actor, intent pack, plan and artifact hash;
5. a grant risk class equal to the operation profile;
6. a previously unused grant JTI;
7. the extension still being installed and active immediately before execution.

## SSL It!

SSL It! is discovered as an extension, but certificate work is delegated to
`plesk://host/site/command/ssl-ensure`. That process already implements strict TLS
probing, certificate assignment, the reviewed SSL It! flow and administrator REST CLI
fallback. The generic extension command does not replay private browser endpoints.

## Adding another extension

1. Read it from the live capability catalog.
2. Verify the operation against the vendor/Plesk documentation and the target Plesk
   version.
3. Add the smallest argument allowlist to `extension_profiles.json`.
4. Prefer official XML or REST; delegate complex domains to a dedicated URI Process.
5. Add response-redaction, dry-run, denial and success tests.
6. Only then expose the operation to an AQL contract or process pack.

This model supports changing installed modules without converting module discovery into
arbitrary administrator code execution.
