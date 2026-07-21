"""Safe Plesk nginx reverse-proxy planning and root-SSH application helpers."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


_FQDN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
BEGIN_MARKER = "# BEGIN SUBACTOR MANAGED REVERSE PROXY"
END_MARKER = "# END SUBACTOR MANAGED REVERSE PROXY"


def normalize_hostname(value: str) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if not _FQDN.fullmatch(host) or "." not in host or ".." in host:
        raise RuntimeError("plesk_reverse_proxy_hostname_invalid")
    return host


def normalize_upstream(value: str, *, hostname: str) -> str:
    try:
        parsed = urllib.parse.urlparse(str(value or "").strip())
    except ValueError as error:
        raise RuntimeError("plesk_reverse_proxy_upstream_invalid") from error
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("plesk_reverse_proxy_upstream_https_required")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise RuntimeError("plesk_reverse_proxy_upstream_origin_required")
    upstream_host = parsed.hostname.lower().rstrip(".")
    if upstream_host == hostname:
        raise RuntimeError("plesk_reverse_proxy_upstream_loop")
    port = f":{parsed.port}" if parsed.port and parsed.port != 443 else ""
    return f"https://{upstream_host}{port}"


def assert_public_upstream(upstream: str, *, resolver=socket.getaddrinfo) -> list[str]:
    host = urllib.parse.urlparse(upstream).hostname or ""
    try:
        addresses = sorted({row[4][0] for row in resolver(host, 443, type=socket.SOCK_STREAM)})
    except OSError as error:
        raise RuntimeError("plesk_reverse_proxy_upstream_dns_failed") from error
    if not addresses:
        raise RuntimeError("plesk_reverse_proxy_upstream_dns_failed")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise RuntimeError("plesk_reverse_proxy_upstream_not_public")
    return addresses


def probe_upstream(upstream: str, *, path: str = "/", timeout: float = 10) -> dict[str, Any]:
    probe_path = str(path or "/")
    if not probe_path.startswith("/") or "\n" in probe_path or "\r" in probe_path:
        raise RuntimeError("plesk_reverse_proxy_probe_path_invalid")
    url = upstream.rstrip("/") + probe_path
    request = urllib.request.Request(url, method="GET", headers={"user-agent": "urirun-connector-plesk/reverse-proxy-preflight"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
    except urllib.error.HTTPError as error:
        status = int(error.code)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RuntimeError("plesk_reverse_proxy_upstream_unreachable") from error
    if status < 200 or status >= 500:
        raise RuntimeError("plesk_reverse_proxy_upstream_unhealthy")
    return {"url": url, "status": status, "reachable": True, "authentication_challenge": status in {401, 403}}


def managed_directives(hostname: str, upstream: str) -> str:
    upstream_host = urllib.parse.urlparse(upstream).hostname or ""
    return "\n".join([
        BEGIN_MARKER,
        "location / {",
        f"    proxy_pass {upstream};",
        "    proxy_http_version 1.1;",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Forwarded-Host $host;",
        "    proxy_set_header X-Forwarded-Proto $scheme;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_ssl_server_name on;",
        f"    proxy_ssl_name {upstream_host};",
        "    proxy_ssl_verify on;",
        "}",
        END_MARKER,
        "",
    ])


def merge_managed_directives(existing: str, managed: str) -> str:
    text = str(existing or "")
    start = text.find(BEGIN_MARKER)
    end = text.find(END_MARKER)
    if (start >= 0) != (end >= 0) or (start >= 0 and end < start):
        raise RuntimeError("plesk_reverse_proxy_managed_block_corrupt")
    if start >= 0:
        end += len(END_MARKER)
        suffix = text[end:].lstrip("\r\n")
        prefix = text[:start].rstrip()
        return "\n\n".join(part for part in (prefix, managed.rstrip(), suffix.rstrip()) if part) + "\n"
    prefix = text.rstrip()
    return (prefix + "\n\n" if prefix else "") + managed


def build_plan(hostname: str, upstream: str, *, authentication_required: bool) -> dict[str, Any]:
    directives = managed_directives(hostname, upstream)
    body = {
        "schema": "urirun.plesk-reverse-proxy-plan/v1",
        "hostname": hostname,
        "upstream": upstream,
        "authentication_required": bool(authentication_required),
        "transport": "plesk-root-ssh-cli",
        "directives_sha256": hashlib.sha256(directives.encode()).hexdigest(),
        "risk_class": "boundary",
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**body, "plan_hash": digest, "artifact_sha256": digest, "directives": directives}
