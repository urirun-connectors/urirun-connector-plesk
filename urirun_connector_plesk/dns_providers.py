"""Provider-aware DNS helpers used by the Plesk connector facade.

The Plesk connector remains the single URI entry point, but mutations are sent to
the provider that is authoritative for the zone.  Provider credentials never
cross this module's public result boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import urllib.parse
import urllib.request
from typing import Any


_CLOUDFLARE_ORIGIN = "https://api.cloudflare.com"
_CLOUDFLARE_API = f"{_CLOUDFLARE_ORIGIN}/client/v4"
_ZONE_ID = re.compile(r"^[a-f0-9]{32}$", re.I)
_RECORD_ID = re.compile(r"^[a-f0-9]{32}$", re.I)
_RESOLVERS = (
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/resolve"),
)


def _json_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: Any = None,
    timeout: float = 10,
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "accept": "application/json",
            **({"content-type": "application/json"} if data is not None else {}),
            **(headers or {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except Exception as error:  # errors must not include headers/token in the receipt
        if hasattr(error, "code"):
            try:
                raw = error.read().decode("utf-8", errors="replace")
                return int(error.code), json.loads(raw) if raw else {}
            except (AttributeError, ValueError):
                return int(error.code), {}
        raise RuntimeError("dns_provider_transport_failed") from error


def _doh_records(name: str, record_type: str, endpoint: str) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"name": name, "type": record_type})
    status, payload = _json_request(
        f"{endpoint}?{query}", headers={"accept": "application/dns-json"}, timeout=8,
    )
    if status != 200:
        raise RuntimeError("dns_resolver_http_failed")
    dns_status = int(payload.get("Status", -1))
    if dns_status == 3:
        raise RuntimeError("dns_name_not_found")
    if dns_status != 0:
        raise RuntimeError("dns_resolver_response_failed")
    type_number = {"A": 1, "NS": 2, "CNAME": 5, "AAAA": 28}[record_type]
    return sorted(({
        "value": str(row.get("data") or "").strip().rstrip(".").lower(),
        "ttl": max(0, int(row.get("TTL") or 0)),
    } for row in payload.get("Answer") or []
        if int(row.get("type") or 0) == type_number and row.get("data")), key=lambda row: row["value"])


def _doh_nameservers(zone: str, endpoint: str) -> list[str]:
    return sorted({row["value"] for row in _doh_records(zone, "NS", endpoint)})


def _provider_from_nameservers(nameservers: list[str]) -> str:
    if nameservers and all(item.endswith(".ns.cloudflare.com") for item in nameservers):
        return "cloudflare"
    suffixes = [
        item.strip().rstrip(".").lower()
        for item in os.environ.get("PLESK_AUTHORITATIVE_NS_SUFFIXES", "").split(",")
        if item.strip()
    ]
    if suffixes and nameservers and all(any(ns == suffix or ns.endswith(f".{suffix}") for suffix in suffixes) for ns in nameservers):
        return "plesk"
    return "external"


def resolve_dns_authority(zone: str) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    for resolver, endpoint in _RESOLVERS:
        try:
            nameservers = _doh_nameservers(zone, endpoint)
            observations.append({"resolver": resolver, "ok": bool(nameservers), "nameservers": nameservers})
        except RuntimeError:
            observations.append({"resolver": resolver, "ok": False, "nameservers": []})
    successful = [row for row in observations if row["ok"]]
    sets = {tuple(row["nameservers"]) for row in successful}
    consistent = len(successful) == len(_RESOLVERS) and len(sets) == 1
    nameservers = list(next(iter(sets))) if len(sets) == 1 else []
    return {
        "zone": zone,
        "provider": _provider_from_nameservers(nameservers) if consistent else "inconsistent",
        "nameservers": nameservers,
        "consistent": consistent,
        "observations": observations,
    }


def resolve_dns_propagation(host: str, record_type: str, expected_value: str = "") -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    for resolver, endpoint in _RESOLVERS:
        try:
            records = _doh_records(host, record_type, endpoint)
            observations.append({"resolver": resolver, "ok": True, "records": records, "error": None})
        except RuntimeError as error:
            observations.append({"resolver": resolver, "ok": False, "records": [], "error": str(error)})
    if record_type in {"A", "AAAA"}:
        try:
            system_records = _system_records(host, record_type)
            observations.append({"resolver": "runtime-system", "ok": True, "records": system_records, "error": None})
        except RuntimeError as error:
            observations.append({"resolver": "runtime-system", "ok": False, "records": [], "error": str(error)})
    successful = [row for row in observations if row["ok"]]
    value_sets = {tuple(record["value"] for record in row["records"]) for row in successful}
    consensus = len(successful) == len(observations) and len(value_sets) == 1
    expected = expected_value.rstrip(".").lower()
    propagated = consensus and bool(expected) and all(
        [record["value"] for record in row["records"]] == [expected] for row in successful
    )
    ttls = [record["ttl"] for row in successful for record in row["records"] if record["ttl"] > 0]
    return {
        "host": host,
        "record_type": record_type,
        "expected_value": expected or None,
        "consensus": consensus,
        "propagated": propagated,
        "ttl_min": min(ttls) if ttls else None,
        "ttl_max": max(ttls) if ttls else None,
        "observations": observations,
    }


def tls_dns_preflight(
    hostname: str,
    expected_origin: str = "",
    *,
    resolver: Any = None,
) -> dict[str, Any]:
    """Prove public address readiness before any certificate mutation.

    This is deliberately independent from the direct-origin TLS probe. ACME
    validates the public hostname, so a successful socket connection to an
    explicit ``origin_ip`` is not evidence that public DNS exists.
    """
    query = resolver or resolve_dns_propagation
    host = str(hostname or "").strip().rstrip(".").lower()
    expected = str(expected_origin or "").strip().lower()
    observations: list[dict[str, Any]] = []
    addresses: set[str] = set()
    for record_type in ("A", "AAAA"):
        result = query(host, record_type, expected if record_type == "A" else "")
        for row in result.get("observations") or []:
            normalized = {
                "resolver": str(row.get("resolver") or "unknown"),
                "record_type": record_type,
                "ok": bool(row.get("ok")),
                "error": str(row.get("error") or "") or None,
                "records": [
                    {"value": str(record.get("value") or "").lower(), "ttl": int(record.get("ttl") or 0)}
                    for record in row.get("records") or []
                    if record.get("value")
                ],
            }
            observations.append(normalized)
            addresses.update(record["value"] for record in normalized["records"])

    ordered = sorted(addresses)
    public = [row for row in observations if row["resolver"] in {"cloudflare", "google"}]
    public_resolvers = {row["resolver"] for row in public}
    absence_proven = public_resolvers == {"cloudflare", "google"} and all(
        (row["ok"] and not row["records"]) or row["error"] == "dns_name_not_found"
        for row in public
    )
    origin_matches = not expected or expected in addresses
    if ordered and origin_matches:
        cause = None
        ready = True
    elif ordered:
        cause = "dns_origin_mismatch"
        ready = False
    elif absence_proven:
        cause = "dns_name_missing"
        ready = False
    else:
        cause = "dns_observation_inconclusive"
        ready = False
    return {
        "schema": "urirun.plesk-tls-dns-preflight/v1",
        "hostname": host,
        "ready": ready,
        "root_cause": cause,
        "addresses": ordered,
        "expected_origin": expected or None,
        "origin_matches": origin_matches if ordered else False,
        "blocks": [] if ready else ["acme_domain_validation", "tls_certificate_issuance"],
        "next_action": None if ready else {
            "uri": "plesk://host/dns/query/propagation",
            "payload": {"host": host, "record_type": "A", "expected_value": expected},
            "then_capability": "dns.record.reconcile",
        },
        "observations": observations,
    }


def _system_records(host: str, record_type: str) -> list[dict[str, Any]]:
    family = socket.AF_INET if record_type == "A" else socket.AF_INET6
    try:
        rows = socket.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise RuntimeError("dns_system_resolver_failed") from error
    return [{"value": value, "ttl": 0} for value in sorted({row[4][0].lower() for row in rows})]


def _cf_call(
    token: str,
    path: str,
    *,
    method: str = "GET",
    body: Any = None,
) -> dict[str, Any]:
    status, payload = _json_request(
        f"{_CLOUDFLARE_API}{path}",
        method=method,
        headers={"authorization": f"Bearer {token}"},
        body=body,
    )
    if status < 200 or status >= 300 or payload.get("success") is not True:
        raise RuntimeError("cloudflare_dns_api_failed")
    return payload


def cloudflare_records(zone_id: str, zone: str, host: str, token: str) -> list[dict[str, Any]]:
    if not _ZONE_ID.fullmatch(zone_id):
        raise RuntimeError("cloudflare_zone_id_invalid")
    zone_payload = _cf_call(token, f"/zones/{zone_id}")
    zone_data = zone_payload.get("result") or {}
    if str(zone_data.get("name") or "").rstrip(".").lower() != zone:
        raise RuntimeError("cloudflare_zone_mismatch")
    query = urllib.parse.urlencode({"name": host, "per_page": "100"})
    payload = _cf_call(token, f"/zones/{zone_id}/dns_records?{query}")
    rows = []
    for raw in payload.get("result") or []:
        record_id = str(raw.get("id") or "")
        record_type = str(raw.get("type") or "").upper()
        if not _RECORD_ID.fullmatch(record_id) or record_type not in {"A", "AAAA", "CNAME"}:
            continue
        if str(raw.get("name") or "").rstrip(".").lower() != host:
            continue
        rows.append({
            "id": record_id,
            "host": host,
            "type": record_type,
            "value": str(raw.get("content") or "").rstrip("."),
            "ttl": int(raw.get("ttl") or 1),
            "proxied": bool(raw.get("proxied", False)),
        })
    return sorted(rows, key=lambda row: (row["type"], row["id"]))


def cloudflare_plan(
    zone: str,
    host: str,
    record_type: str,
    value: str,
    records: list[dict[str, Any]],
    *,
    ttl: int = 1,
    proxied: bool = False,
) -> dict[str, Any]:
    exact = [
        row for row in records
        if row["type"] == record_type
        and row["value"].rstrip(".").lower() == value.lower()
        and row["ttl"] == ttl
        and row["proxied"] is proxied
    ]
    keep = exact[:1]
    delete = [row for row in records if row not in keep]
    create = not keep
    body = {
        "schema": "urirun.provider-dns-reconcile-plan/v1",
        "provider": "cloudflare",
        "zone": zone,
        "host": host,
        "record_type": record_type,
        "value": value,
        "ttl": ttl,
        "proxied": proxied,
        "delete_record_ids": sorted(row["id"] for row in delete),
        "create_record": create,
        "risk_class": "boundary",
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**body, "changed": bool(delete or create), "plan_hash": digest, "artifact_sha256": digest}


def apply_cloudflare_plan(zone_id: str, token: str, plan: dict[str, Any]) -> None:
    body = {
        "deletes": [{"id": item} for item in plan["delete_record_ids"]],
        "posts": ([{
            "name": plan["host"],
            "type": plan["record_type"],
            "content": plan["value"],
            "ttl": plan["ttl"],
            "proxied": plan["proxied"],
        }] if plan["create_record"] else []),
    }
    _cf_call(token, f"/zones/{zone_id}/dns_records/batch", method="POST", body=body)


CLOUDFLARE_CREDENTIAL_ORIGIN = _CLOUDFLARE_ORIGIN
