"""SSL / certificate ensure helpers for Plesk (customer XML + panel session).

Strategies (first success wins after probe):
1. TLS SAN already covers hostname → ok (idempotent)
2. Assign existing repository cert by name (XML site/set)
3. Panel SMB self-signed / uploaded PEM with SAN (session login)
4. Panel SSL It! Let's Encrypt install (multipart FormData)
5. REST CLI extension call (requires admin/runtime API key)

LE via XML extension returns 1013 (ApiRpc not implemented) on this panel.
Customer REST /api/v2/cli/* is 403. Prefer panel SSL It when LE is requested.
"""
from __future__ import annotations

import datetime as _dt
import http.cookiejar
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable

from .apply_grant import autonomy_mutations_enabled
from .verify_ladder import check_tls_san, hostname_matches_san

PANEL_ACTION_LE = (
    "Plesk → Websites & Domains → docs host → SSL/TLS Certificates (SSL It!) → "
    "Get it free (Let's Encrypt). Uncheck Wildcard and Mail SANs before install "
    "(ACME rejects mail.* together with *.)."
)

XmlAgent = Callable[[str, str, str, str], str]
VaultLease = Callable[[str, str, str, str], str]


def ssl_apply_permitted(*, apply: bool) -> tuple[bool, str | None]:
    """Fail-closed mutate gate for ssl-ensure (env only; no grant required)."""
    if not apply:
        return False, None
    if not autonomy_mutations_enabled():
        return False, "apply_denied_autonomy_mutations"
    if os.environ.get("PLESK_SSL_APPLY", "").strip() != "1":
        return False, "apply_denied_plesk_ssl_apply"
    return True, None


def origin_tls_probe(
    *,
    connect_host: str,
    hostname: str,
    port: int = 443,
) -> dict[str, Any]:
    """Read peer cert SAN/CN without trusting the chain (origin may be self-signed)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with __import__("socket").create_connection((connect_host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": "tls_handshake_failed",
            "hostname": hostname,
            "connect_host": connect_host,
            "detail": str(exc)[:200],
        }
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(der, default_backend())
        sans: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(n) for n in ext.value.get_values_for_type(x509.DNSName)]
        except Exception:  # noqa: BLE001
            sans = []
        cn = None
        for attr in cert.subject:
            if attr.oid.dotted_string == "2.5.4.3":
                cn = attr.value
                break
        if not sans and cn:
            sans = [str(cn)]
        issuer = cert.issuer.rfc4514_string()
        covers = hostname_matches_san(hostname, sans) or (
            cn is not None and str(cn).lower() == hostname.lower()
        )
        return {
            "ok": covers,
            "hostname": hostname,
            "connect_host": connect_host,
            "sans": sans,
            "cn": cn,
            "issuer": issuer[:200],
            "error": None if covers else "tls_san_mismatch",
        }
    except Exception as exc:  # noqa: BLE001
        # Fallback: stdlib verified path (works for public LE chains)
        return check_tls_san(connect_host=connect_host, hostname=hostname, port=port) | {
            "detail": f"cryptography_parse_failed:{exc}"[:120],
        }


def xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def xml_ok(raw: str) -> bool:
    return "<status>ok</status>" in raw and "<status>error</status>" not in raw


def resolve_site_id(
    *,
    base_url: str,
    username: str,
    password: str,
    hostname: str,
    xml_agent: XmlAgent,
) -> int | None:
    packet = f"""<?xml version="1.0" encoding="UTF-8"?>
<packet>
  <site>
    <get><filter><name>{xml_escape(hostname)}</name></filter></get>
  </site>
</packet>"""
    raw = xml_agent(base_url, username, password, packet)
    if not xml_ok(raw):
        # subdomain alias
        packet = f"""<?xml version="1.0" encoding="UTF-8"?>
<packet>
  <subdomain>
    <get><filter><name>{xml_escape(hostname)}</name></filter></get>
  </subdomain>
</packet>"""
        raw = xml_agent(base_url, username, password, packet)
    m = re.search(r"<id>(\d+)</id>", raw)
    return int(m.group(1)) if m and xml_ok(raw) else None


def assign_certificate(
    *,
    base_url: str,
    username: str,
    password: str,
    site_id: int,
    certificate_name: str,
    xml_agent: XmlAgent,
) -> dict[str, Any]:
    name = certificate_name.strip()
    packet = f"""<?xml version="1.0" encoding="UTF-8"?>
<packet>
  <site>
    <set>
      <filter><id>{int(site_id)}</id></filter>
      <values>
        <hosting>
          <vrt_hst>
            <property><name>certificate_name</name><value>{xml_escape(name)}</value></property>
            <property><name>ssl</name><value>true</value></property>
          </vrt_hst>
        </hosting>
      </values>
    </set>
  </site>
</packet>"""
    raw = xml_agent(base_url, username, password, packet)
    if xml_ok(raw):
        return {"ok": True, "strategy": "assign", "certificate_name": name, "site_id": site_id}
    err = re.search(r"<errtext>([^<]*)</errtext>", raw)
    return {
        "ok": False,
        "strategy": "assign",
        "error": "plesk_ssl_assign_failed",
        "detail": (err.group(1) if err else raw[:200])[:300],
        "certificate_name": name,
        "site_id": site_id,
    }


def _panel_opener(ctx: ssl.SSLContext | None) -> tuple[Any, http.cookiejar.CookieJar]:
    jar = http.cookiejar.CookieJar()
    handlers: list[Any] = [urllib.request.HTTPCookieProcessor(jar)]
    if ctx is not None:
        handlers.insert(0, urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers), jar


def panel_login(
    *,
    base_url: str,
    username: str,
    password: str,
    tls_verify: bool = False,
) -> Any:
    """Customer panel session via login_up.php3 (returns opener with cookies)."""
    origin = base_url.rstrip("/")
    ctx = None if tls_verify else ssl._create_unverified_context()
    opener, _jar = _panel_opener(ctx)
    qs = urllib.parse.urlencode(
        {
            "login_name": username,
            "passwd": password,
            "success_redirect_url": "/smb/web/view",
            "failure_redirect_url": "/login_up.php",
        }
    )
    req = urllib.request.Request(
        f"{origin}/login_up.php3?{qs}",
        headers={"User-Agent": "urirun-connector-plesk/ssl-ensure"},
    )
    with opener.open(req, timeout=30) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        final = resp.geturl()
    if "login" in final.lower() and "smb" not in final.lower():
        raise RuntimeError("plesk_panel_login_failed")
    if "Incorrect" in body and "smb/web" not in final:
        raise RuntimeError("plesk_panel_login_failed")
    return opener


def _forgery_token(html: str) -> str:
    m = re.search(
        r'content=["\']([^"\']+)["\'][^>]*name=["\']forgery_protection_token["\']',
        html,
        re.I,
    ) or re.search(
        r'name=["\']forgery_protection_token["\'][^>]*content=["\']([^"\']+)',
        html,
        re.I,
    ) or re.search(
        r'name=["\']forgery_protection_token["\'][^>]*value=["\']([^"\']+)',
        html,
        re.I,
    ) or re.search(
        r'value=["\']([^"\']+)["\'][^>]*name=["\']forgery_protection_token["\']',
        html,
        re.I,
    )
    if not m:
        raise RuntimeError("plesk_panel_csrf_missing")
    return m.group(1)


def _multipart(fields: dict[str, str]) -> tuple[bytes, str]:
    boundary = "----UrirunPlesk" + uuid.uuid4().hex[:16]
    parts: list[str] = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode("utf-8"), boundary


def panel_create_self_signed(
    *,
    opener: Any,
    base_url: str,
    site_id: int,
    hostname: str,
    cert_name: str,
    email: str = "agent@subactor.com",
) -> dict[str, Any]:
    origin = base_url.rstrip("/")
    add_url = f"{origin}/smb/ssl-certificate/add/id/{int(site_id)}"
    with opener.open(add_url, timeout=30) as resp:
        html = resp.read().decode("utf-8", errors="replace")
    token = _forgery_token(html)
    fields = {
        "name": cert_name,
        "type": "selfSigned",
        "settings[bits]": "2048",
        "settings[country]": "PL",
        "settings[state]": "NA",
        "settings[city]": "NA",
        "settings[companyName]": "subactor",
        "settings[companyUnitName]": "docs",
        "settings[domainName]": hostname,
        "settings[email]": email,
        "settings[selfSigned]": "",
        "hidden": "",
        "forgery_protection_token": token,
    }
    body, boundary = _multipart(fields)
    req = urllib.request.Request(
        add_url,
        data=body,
        method="POST",
        headers={
            "User-Agent": "urirun-connector-plesk/ssl-ensure",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
            "Referer": add_url,
        },
    )
    with opener.open(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    try:
        payload = json.loads(raw) if raw else {}
    except ValueError:
        payload = {"raw": raw[:200]}
    ok = payload.get("status") == "success"
    return {
        "ok": ok,
        "strategy": "panel_self_signed",
        "certificate_name": cert_name,
        "site_id": site_id,
        "error": None if ok else "plesk_ssl_panel_self_signed_failed",
        "detail": None if ok else str(payload)[:300],
        # Plesk self-signed often sets CN only (no SAN extension).
        "san_note": "panel_self_signed_may_lack_san_extension",
    }


def panel_upload_pem(
    *,
    opener: Any,
    base_url: str,
    site_id: int,
    cert_name: str,
    cert_pem: str,
    key_pem: str,
) -> dict[str, Any]:
    """Upload PEM text (sendText) — preferred when SAN extension is required."""
    origin = base_url.rstrip("/")
    add_url = f"{origin}/smb/ssl-certificate/add/id/{int(site_id)}"
    with opener.open(add_url, timeout=30) as resp:
        html = resp.read().decode("utf-8", errors="replace")
    token = _forgery_token(html)
    fields = {
        "name": cert_name,
        "type": "sendText",
        "uploadText[privateKeyText]": key_pem,
        "uploadText[certificateText]": cert_pem,
        "uploadText[caCertificateText]": "",
        "uploadText[sendText]": "",
        "hidden": "",
        "forgery_protection_token": token,
    }
    body, boundary = _multipart(fields)
    req = urllib.request.Request(
        add_url,
        data=body,
        method="POST",
        headers={
            "User-Agent": "urirun-connector-plesk/ssl-ensure",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
            "Referer": add_url,
        },
    )
    with opener.open(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    try:
        payload = json.loads(raw) if raw else {}
    except ValueError:
        payload = {"raw": raw[:200]}
    ok = payload.get("status") == "success"
    return {
        "ok": ok,
        "strategy": "panel_upload_pem",
        "certificate_name": cert_name,
        "site_id": site_id,
        "error": None if ok else "plesk_ssl_panel_upload_failed",
        "detail": None if ok else str(payload)[:300],
    }


def generate_self_signed_pem(hostname: str, days: int = 90) -> tuple[str, str]:
    """Return (cert_pem, key_pem) with DNS SAN for hostname."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "subactor"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


def panel_sslit_letsencrypt(
    *,
    opener: Any,
    base_url: str,
    site_id: int,
    hostname: str,
) -> dict[str, Any]:
    """Issue LE via SSL It! panel install FormData (validateDomain only)."""
    origin = base_url.rstrip("/")
    page_url = f"{origin}/modules/sslit/index.php/index/certificate/id/{int(site_id)}"
    with opener.open(page_url, timeout=30) as resp:
        html = resp.read().decode("utf-8", errors="replace")
    token = _forgery_token(html)
    # Omit false flags — PHP treats non-empty "false" as truthy and then ACME
    # requests wildcard+mail together (malformed order).
    fields = {
        "validateDomain": "1",
        "id": str(int(site_id)),
        "vendorId": "letsencrypt.letsencrypt",
        "productId": "base",
        "forgery_protection_token": token,
    }
    body, boundary = _multipart(fields)
    req = urllib.request.Request(
        f"{origin}/modules/sslit/index.php/index/install/",
        data=body,
        method="POST",
        headers={
            "User-Agent": "urirun-connector-plesk/ssl-ensure",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
            "Referer": page_url,
            "forgery_protection_token": token,
            "X-XSRF-TOKEN": token,
        },
    )
    try:
        with opener.open(req, timeout=180) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace")
    try:
        payload = json.loads(raw) if raw else {}
    except ValueError:
        payload = {"raw": raw[:300]}
    msg = ""
    for item in payload.get("actionMessages") or []:
        if isinstance(item, dict):
            msg += " " + str(item.get("message") or "")
    text = re.sub(r"<[^>]+>", " ", msg)
    text = re.sub(r"\s+", " ", text).strip()
    ok = payload.get("status") == "success" and "Could not" not in text
    error = None if ok else "plesk_ssl_letsencrypt_failed"
    if "redundant with a wildcard" in text:
        error = "plesk_ssl_le_san_conflict"
    return {
        "ok": ok,
        "strategy": "panel_sslit_le",
        "site_id": site_id,
        "hostname": hostname,
        "error": error,
        "detail": text[:500] if text else str(payload)[:300],
        "panel_action": None if ok else PANEL_ACTION_LE,
    }


def rest_cli_letsencrypt(
    *,
    base_url: str,
    api_key: str,
    hostname: str,
    email: str,
    request_json: Callable[..., tuple[int, dict[str, Any]]],
) -> dict[str, Any]:
    origin = base_url.rstrip("/")
    status, data = request_json(
        f"{origin}/api/v2/cli/extension/call",
        method="POST",
        headers={"X-API-Key": api_key, "accept": "application/json", "content-type": "application/json"},
        body={
            "params": [
                "--exec",
                "letsencrypt",
                "cli.php",
                "-d",
                hostname,
                "-m",
                email,
            ]
        },
        timeout=180,
    )
    ok = status in {200, 201} and int(data.get("code") or 0) == 0
    return {
        "ok": ok,
        "strategy": "rest_cli_le",
        "http_status": status,
        "error": None if ok else "plesk_ssl_rest_cli_le_failed",
        "detail": str(data.get("stderr") or data.get("message") or data)[:400],
        "panel_action": None if ok else PANEL_ACTION_LE,
    }
