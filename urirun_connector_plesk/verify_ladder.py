"""DNS/TLS/HTTPS + content fingerprint verify ladder (PR8 / ADR-004).

Upload OK + public verify FAIL → ``applied_unverified`` ≠ plan ``completed``.

The ladder is injectable for unit tests (no live docs.subactor.com required).
Origin checks use Host header / resolve IP (``curl --resolve`` style) so
preflight can run against Plesk before public DNS cutover (PR9).

Recommended staging hostname: ``docs-stage.subactor.com`` (optional infra;
not required to exist for these library/capability tests).
"""
from __future__ import annotations

import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

RELEASE_MARKER_PATH = "/__subactor_release.json"
CACHE_CONTROL_NO_STORE = "no-store"

# Structured failure codes (orchestrator → applied_unverified / rollback / ticket).
DNS_MISMATCH = "dns_mismatch"
DNS_LOOKUP_FAILED = "dns_lookup_failed"
TLS_SAN_MISMATCH = "tls_san_mismatch"
TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
HTTPS_STATUS_UNEXPECTED = "https_status_unexpected"
FINGERPRINT_MISMATCH = "fingerprint_mismatch"
FINGERPRINT_MISSING = "fingerprint_missing"
FINGERPRINT_STALE = "fingerprint_stale"
ORIGIN_UNREACHABLE = "origin_unreachable"
RELEASE_FILES_MISMATCH = "release_files_mismatch"

_APPLIED_UNVERIFIED_CODES = frozenset(
    {
        DNS_MISMATCH,
        DNS_LOOKUP_FAILED,
        TLS_SAN_MISMATCH,
        TLS_HANDSHAKE_FAILED,
        HTTPS_STATUS_UNEXPECTED,
        FINGERPRINT_MISMATCH,
        FINGERPRINT_MISSING,
        FINGERPRINT_STALE,
        ORIGIN_UNREACHABLE,
        RELEASE_FILES_MISMATCH,
    }
)

DnsResolver = Callable[[str], list[str]]
HttpFetcher = Callable[..., dict[str, Any]]
TlsInspector = Callable[[str, int, str], dict[str, Any]]


@dataclass
class VerifyExpectation:
    """Expected public/origin release fingerprint (from upload meta)."""

    release_id: str = ""
    artifact_sha256: str = ""
    source_commit: str = ""
    pack_version: str = ""
    # DNS desired targets (A/AAAA/CNAME values). Empty → skip DNS step.
    dns_targets: list[str] = field(default_factory=list)
    # Hostname that must appear in TLS SAN.
    tls_hostname: str = ""


def is_applied_unverified(code: str | None) -> bool:
    return bool(code) and code in _APPLIED_UNVERIFIED_CODES


def normalize_fingerprint(meta: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize release marker fields (ADR-004 + PR7 aliases)."""
    data = dict(meta or {})
    artifact = (
        data.get("artifact_sha256")
        or data.get("content_sha256")
        or data.get("plan_hash")
        or ""
    )
    commit = data.get("source_commit") or data.get("git_commit") or ""
    built = data.get("built_at") or data.get("created_at") or ""
    return {
        "release_id": str(data.get("release_id") or ""),
        "artifact_sha256": str(artifact or ""),
        "source_commit": str(commit or ""),
        "built_at": str(built or ""),
        "pack_version": str(data.get("pack_version") or ""),
        "cache_control": str(data.get("cache_control") or CACHE_CONTROL_NO_STORE),
    }


def compare_fingerprints(
    expected: VerifyExpectation | dict[str, Any],
    observed: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare expected vs observed ``__subactor_release.json`` fingerprint."""
    if isinstance(expected, VerifyExpectation):
        exp = {
            "release_id": expected.release_id,
            "artifact_sha256": expected.artifact_sha256,
            "source_commit": expected.source_commit,
            "pack_version": expected.pack_version,
        }
    else:
        exp = normalize_fingerprint(expected)

    obs = normalize_fingerprint(observed)
    if not obs.get("release_id") and not obs.get("artifact_sha256"):
        return {
            "ok": False,
            "error": FINGERPRINT_MISSING,
            "expected": exp,
            "observed": obs,
        }

    mismatches: list[str] = []
    for key in ("release_id", "artifact_sha256", "source_commit", "pack_version"):
        want = str(exp.get(key) or "")
        got = str(obs.get(key) or "")
        if want and got and want != got:
            mismatches.append(key)
        elif want and not got:
            mismatches.append(key)

    if mismatches:
        # Stale content often shows as wrong release_id / artifact with HTTP 200.
        code = FINGERPRINT_STALE if "release_id" in mismatches or "artifact_sha256" in mismatches else FINGERPRINT_MISMATCH
        return {
            "ok": False,
            "error": code,
            "mismatches": mismatches,
            "expected": exp,
            "observed": obs,
        }
    return {"ok": True, "expected": exp, "observed": obs}


def default_dns_resolver(hostname: str) -> list[str]:
    """Resolve A/AAAA via getaddrinfo (public recursive path)."""
    results: list[str] = []
    try:
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
            except socket.gaierror:
                continue
            for info in infos:
                addr = info[4][0]
                if addr not in results:
                    results.append(addr)
    except OSError:
        return []
    return results


def check_dns(
    hostname: str,
    *,
    expected_targets: list[str],
    public_resolver: DnsResolver | None = None,
    authoritative_resolver: DnsResolver | None = None,
) -> dict[str, Any]:
    """Compare desired DNS targets against public (+ optional authoritative) answers."""
    if not expected_targets:
        return {"ok": True, "skipped": True, "reason": "no_expected_targets"}

    public = public_resolver or default_dns_resolver
    auth = authoritative_resolver or public

    try:
        public_answers = list(public(hostname) or [])
    except Exception as exc:  # noqa: BLE001 — surface as structured failure
        return {
            "ok": False,
            "error": DNS_LOOKUP_FAILED,
            "hostname": hostname,
            "detail": str(exc),
            "layer": "public",
        }
    try:
        auth_answers = list(auth(hostname) or [])
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": DNS_LOOKUP_FAILED,
            "hostname": hostname,
            "detail": str(exc),
            "layer": "authoritative",
        }

    expected_norm = {t.strip().rstrip(".").lower() for t in expected_targets if t}
    public_norm = {a.strip().rstrip(".").lower() for a in public_answers}
    auth_norm = {a.strip().rstrip(".").lower() for a in auth_answers}

    public_hit = bool(expected_norm & public_norm)
    auth_hit = bool(expected_norm & auth_norm)
    ok = public_hit and auth_hit
    return {
        "ok": ok,
        "error": None if ok else DNS_MISMATCH,
        "hostname": hostname,
        "expected": sorted(expected_norm),
        "public": sorted(public_norm),
        "authoritative": sorted(auth_norm),
        "public_match": public_hit,
        "authoritative_match": auth_hit,
    }


def _sans_from_cert(cert: dict[str, Any] | None) -> list[str]:
    if not cert:
        return []
    names: list[str] = []
    subject = cert.get("subject") or ()
    for rdn in subject:
        for key, value in rdn:
            if key == "commonName" and value:
                names.append(str(value))
    for typ, value in cert.get("subjectAltName") or ():
        if typ.lower() in {"dns", "ip address"} and value:
            names.append(str(value))
    return names


def hostname_matches_san(hostname: str, sans: list[str]) -> bool:
    host = hostname.strip().rstrip(".").lower()
    for san in sans:
        pattern = san.strip().rstrip(".").lower()
        if pattern.startswith("*."):
            # Wildcard: *.example.com matches a.example.com, not example.com.
            suffix = pattern[1:]  # .example.com
            if host.endswith(suffix) and host.count(".") == pattern.count("."):
                return True
        elif host == pattern:
            return True
    return False


def default_tls_inspector(hostname: str, port: int, server_hostname: str) -> dict[str, Any]:
    """TLS handshake and return peer cert SAN list (stdlib)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
            cert = ssock.getpeercert()
            sans = _sans_from_cert(cert)
            return {
                "ok": True,
                "sans": sans,
                "server_hostname": server_hostname,
                "peer_address": hostname,
                "port": port,
            }


def check_tls_san(
    *,
    connect_host: str,
    hostname: str,
    port: int = 443,
    inspector: TlsInspector | None = None,
) -> dict[str, Any]:
    """Verify TLS certificate SAN covers ``hostname`` (may differ from connect_host)."""
    inspect = inspector or default_tls_inspector
    try:
        peer = inspect(connect_host, port, hostname)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": TLS_HANDSHAKE_FAILED,
            "hostname": hostname,
            "connect_host": connect_host,
            "detail": str(exc),
        }
    sans = list(peer.get("sans") or [])
    ok = hostname_matches_san(hostname, sans)
    return {
        "ok": ok,
        "error": None if ok else TLS_SAN_MISMATCH,
        "hostname": hostname,
        "connect_host": connect_host,
        "sans": sans,
        "peer": peer,
    }


def default_http_fetcher(
    url: str,
    *,
    host_header: str = "",
    resolve_ip: str = "",
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Fetch URL; optional Host header + connect-to IP (``curl --resolve`` style)."""
    headers = {"Accept": "application/json, text/plain, */*"}
    if host_header:
        headers["Host"] = host_header

    # When resolve_ip is set, open a connection to that IP while keeping URL host
    # for SNI / Host. Implemented via custom opener host rewrite for http(s).
    target_url = url
    if resolve_ip:
        # Rewrite netloc host → IP for TCP connect; keep Host header for vhost.
        m = re.match(r"^(https?)://([^/:]+)(:\d+)?(/.*)?$", url)
        if m:
            scheme, _host, port, path = m.group(1), m.group(2), m.group(3) or "", m.group(4) or "/"
            target_url = f"{scheme}://{resolve_ip}{port}{path}"
            if not host_header:
                headers["Host"] = _host

    req = Request(target_url, headers=headers, method="GET")
    # For IP-literal HTTPS, disable hostname check on the IP; caller verifies SAN separately.
    ctx = None
    if target_url.startswith("https://") and resolve_ip:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310 — ops verify helper
            body = resp.read()
            status = getattr(resp, "status", None) or resp.getcode()
            cache = resp.headers.get("Cache-Control") if hasattr(resp, "headers") else None
            return {
                "ok": True,
                "status": int(status),
                "body": body,
                "cache_control": cache,
                "url": url,
                "resolved_to": resolve_ip or None,
            }
    except HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        return {
            "ok": False,
            "status": int(exc.code),
            "body": body,
            "error": HTTPS_STATUS_UNEXPECTED,
            "url": url,
            "resolved_to": resolve_ip or None,
        }
    except (URLError, OSError, TimeoutError, ValueError) as exc:
        return {
            "ok": False,
            "status": None,
            "body": b"",
            "error": ORIGIN_UNREACHABLE,
            "detail": str(exc),
            "url": url,
            "resolved_to": resolve_ip or None,
        }


def check_https_status(fetch_result: dict[str, Any], *, expect_status: int = 200) -> dict[str, Any]:
    status = fetch_result.get("status")
    ok = fetch_result.get("ok") and status == expect_status
    return {
        "ok": bool(ok),
        "error": None if ok else (fetch_result.get("error") or HTTPS_STATUS_UNEXPECTED),
        "status": status,
        "expect_status": expect_status,
    }


def parse_release_marker(body: bytes | str | None) -> dict[str, Any] | None:
    if body is None:
        return None
    try:
        raw = body if isinstance(body, str) else body.decode("utf-8")
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def check_fingerprint_response(
    fetch_result: dict[str, Any],
    expected: VerifyExpectation | dict[str, Any],
) -> dict[str, Any]:
    status_check = check_https_status(fetch_result, expect_status=200)
    if not status_check["ok"]:
        return {**status_check, "step": "https"}
    marker = parse_release_marker(fetch_result.get("body"))
    compared = compare_fingerprints(expected, marker)
    cache = fetch_result.get("cache_control")
    return {
        **compared,
        "https_status": 200,
        "cache_control": cache,
        "cache_control_ok": (not cache) or ("no-store" in str(cache).lower()) or ("no-cache" in str(cache).lower()),
        "step": "fingerprint",
    }


def marker_url(hostname: str, *, path: str = RELEASE_MARKER_PATH, scheme: str = "https") -> str:
    host = hostname.strip().rstrip(".")
    p = path if path.startswith("/") else f"/{path}"
    return f"{scheme}://{host}{p}"


def run_publish_verify_ladder(
    *,
    hostname: str,
    expected: VerifyExpectation | dict[str, Any],
    origin_ip: str = "",
    check_dns_step: bool = True,
    check_tls_step: bool = True,
    check_origin: bool = True,
    check_public: bool = True,
    release_files_ok: bool | None = None,
    public_resolver: DnsResolver | None = None,
    authoritative_resolver: DnsResolver | None = None,
    http_fetcher: HttpFetcher | None = None,
    tls_inspector: TlsInspector | None = None,
    expect_https_status: int = 200,
) -> dict[str, Any]:
    """Run ADR-004 verify ladder; failures yield ``status=applied_unverified``.

    Order:
      1. release files (caller-supplied gate)
      2. origin verify (Host / --resolve) — no public DNS required
      3. DNS authoritative + public
      4. TLS SAN
      5. HTTPS status + fingerprint via ``/__subactor_release.json``
    """
    if isinstance(expected, dict):
        exp = VerifyExpectation(
            release_id=str(expected.get("release_id") or ""),
            artifact_sha256=str(
                expected.get("artifact_sha256")
                or expected.get("content_sha256")
                or ""
            ),
            source_commit=str(expected.get("source_commit") or expected.get("git_commit") or ""),
            pack_version=str(expected.get("pack_version") or ""),
            dns_targets=list(expected.get("dns_targets") or []),
            tls_hostname=str(expected.get("tls_hostname") or hostname),
        )
    else:
        exp = expected
        if not exp.tls_hostname:
            exp.tls_hostname = hostname

    steps: dict[str, Any] = {}
    fetch = http_fetcher or default_http_fetcher

    # 1. Release files (path/hash already verified by caller / release-verify).
    if release_files_ok is False:
        return _fail_ladder(
            RELEASE_FILES_MISMATCH,
            steps={
                "release_files": {"ok": False, "error": RELEASE_FILES_MISMATCH},
            },
            hostname=hostname,
            expected=exp,
        )
    steps["release_files"] = {
        "ok": True if release_files_ok is not False else False,
        "skipped": release_files_ok is None,
    }

    # 2. Origin verify without public DNS.
    if check_origin:
        if not origin_ip:
            steps["origin"] = {"ok": True, "skipped": True, "reason": "no_origin_ip"}
        else:
            origin_fetch = fetch(
                marker_url(hostname),
                host_header=hostname,
                resolve_ip=origin_ip,
            )
            origin_fp = check_fingerprint_response(origin_fetch, exp)
            steps["origin"] = origin_fp
            if not origin_fp.get("ok"):
                return _fail_ladder(
                    str(origin_fp.get("error") or ORIGIN_UNREACHABLE),
                    steps=steps,
                    hostname=hostname,
                    expected=exp,
                    origin_verified=False,
                )

    # 3. DNS (skip when no targets — common pre-cutover / staging).
    if check_dns_step and exp.dns_targets:
        dns = check_dns(
            hostname,
            expected_targets=exp.dns_targets,
            public_resolver=public_resolver,
            authoritative_resolver=authoritative_resolver,
        )
        steps["dns"] = dns
        if not dns.get("ok"):
            return _fail_ladder(
                str(dns.get("error") or DNS_MISMATCH),
                steps=steps,
                hostname=hostname,
                expected=exp,
                origin_verified=bool((steps.get("origin") or {}).get("ok")),
            )
    else:
        steps["dns"] = {"ok": True, "skipped": True, "reason": "dns_check_disabled_or_no_targets"}

    # 4. TLS SAN (connect via origin_ip when provided).
    if check_tls_step:
        connect_host = origin_ip or hostname
        tls = check_tls_san(
            connect_host=connect_host,
            hostname=exp.tls_hostname or hostname,
            inspector=tls_inspector,
        )
        steps["tls"] = tls
        if not tls.get("ok"):
            return _fail_ladder(
                str(tls.get("error") or TLS_SAN_MISMATCH),
                steps=steps,
                hostname=hostname,
                expected=exp,
                origin_verified=bool((steps.get("origin") or {}).get("ok")),
                dns_verified=bool((steps.get("dns") or {}).get("ok")),
            )
    else:
        steps["tls"] = {"ok": True, "skipped": True}

    # 5. Public HTTPS + fingerprint (optional; skip when still on Pages / pre-cutover).
    if check_public:
        public_fetch = fetch(marker_url(hostname), host_header=hostname)
        status = check_https_status(public_fetch, expect_status=expect_https_status)
        steps["https"] = status
        if not status.get("ok"):
            return _fail_ladder(
                str(status.get("error") or HTTPS_STATUS_UNEXPECTED),
                steps=steps,
                hostname=hostname,
                expected=exp,
                origin_verified=bool((steps.get("origin") or {}).get("ok")),
                dns_verified=bool((steps.get("dns") or {}).get("ok")),
                tls_verified=bool((steps.get("tls") or {}).get("ok")),
            )
        fp = check_fingerprint_response(public_fetch, exp)
        steps["fingerprint"] = fp
        if not fp.get("ok"):
            return _fail_ladder(
                str(fp.get("error") or FINGERPRINT_MISMATCH),
                steps=steps,
                hostname=hostname,
                expected=exp,
                origin_verified=bool((steps.get("origin") or {}).get("ok")),
                dns_verified=bool((steps.get("dns") or {}).get("ok")),
                tls_verified=bool((steps.get("tls") or {}).get("ok")),
                https_ok=True,
            )
    else:
        steps["https"] = {"ok": True, "skipped": True}
        steps["fingerprint"] = {"ok": True, "skipped": True, "reason": "public_verify_disabled"}

    return {
        "ok": True,
        "status": "publicly_verified" if check_public else "origin_verified",
        "hostname": hostname,
        "dns_target_verified": bool((steps.get("dns") or {}).get("ok")),
        "tls_verified": bool((steps.get("tls") or {}).get("ok")),
        "content_verified": bool(
            (steps.get("fingerprint") or {}).get("ok")
            or (steps.get("origin") or {}).get("ok")
        ),
        "origin_verified": bool((steps.get("origin") or {}).get("ok")),
        "steps": steps,
        "expected": normalize_fingerprint(
            {
                "release_id": exp.release_id,
                "artifact_sha256": exp.artifact_sha256,
                "source_commit": exp.source_commit,
                "pack_version": exp.pack_version,
            }
        ),
    }


def _fail_ladder(
    error: str,
    *,
    steps: dict[str, Any],
    hostname: str,
    expected: VerifyExpectation,
    origin_verified: bool = False,
    dns_verified: bool = False,
    tls_verified: bool = False,
    https_ok: bool = False,
) -> dict[str, Any]:
    status = "applied_unverified" if is_applied_unverified(error) else "failed"
    return {
        "ok": False,
        "status": status,
        "error": error,
        "hostname": hostname,
        "dns_target_verified": dns_verified,
        "tls_verified": tls_verified,
        "content_verified": False,
        "origin_verified": origin_verified,
        "https_ok": https_ok,
        "steps": steps,
        "expected": normalize_fingerprint(
            {
                "release_id": expected.release_id,
                "artifact_sha256": expected.artifact_sha256,
                "source_commit": expected.source_commit,
                "pack_version": expected.pack_version,
            }
        ),
        "note": "upload/activate may have succeeded; ADR-004 DoD not met — rollback or ticket",
    }


def curl_resolve_hint(hostname: str, origin_ip: str, *, port: int = 443) -> str:
    """Document-friendly ``curl --resolve`` for origin preflight."""
    host = hostname.strip().rstrip(".")
    return (
        f"curl -fsS --resolve {host}:{port}:{origin_ip} "
        f"https://{host}{RELEASE_MARKER_PATH}"
    )
