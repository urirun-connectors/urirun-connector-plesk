"""Safe discovery and policy for dynamically installed Plesk extensions."""
from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from importlib.resources import files
from typing import Any


PROFILE_SCHEMA = "urirun.plesk-extension-profiles/v1"
CATALOG_SCHEMA = "urirun.plesk-extension-catalog/v1"
PLAN_SCHEMA = "urirun.plesk-extension-operation-plan/v1"
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MAX_ARGUMENTS = 32
_MAX_VALUE_LENGTH = 2048


def load_extension_profiles() -> dict[str, Any]:
    raw = files(__package__).joinpath("extension_profiles.json").read_text(encoding="utf-8")
    document = json.loads(raw)
    if document.get("schema") != PROFILE_SCHEMA or not isinstance(document.get("extensions"), dict):
        raise RuntimeError("plesk_extension_profiles_invalid")
    return document


def extension_inventory_packet(extension_id: str = "") -> str:
    root = ET.Element("packet")
    get = ET.SubElement(ET.SubElement(root, "extension"), "get")
    if extension_id:
        if not _IDENTIFIER.fullmatch(extension_id):
            raise RuntimeError("plesk_extension_id_invalid")
        filter_node = ET.SubElement(get, "filter")
        ET.SubElement(filter_node, "id").text = extension_id
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def parse_extension_inventory(raw: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise RuntimeError("plesk_extension_inventory_invalid") from error
    result: list[dict[str, Any]] = []
    for node in root.findall(".//extension/get/result"):
        if (node.findtext("status") or "").strip() != "ok":
            continue
        details = node.find("details")
        if details is None:
            continue
        extension_id = (details.findtext("id") or "").strip()
        if not _IDENTIFIER.fullmatch(extension_id):
            continue
        release_text = (details.findtext("release") or "").strip()
        try:
            release = int(release_text) if release_text else None
        except ValueError:
            release = None
        result.append({
            "id": extension_id,
            "name": (details.findtext("name") or extension_id).strip()[:160],
            "version": (details.findtext("version") or "").strip()[:80] or None,
            "release": release,
            "active": (details.findtext("active") or "").strip().lower() in {"1", "true", "yes"},
        })
    return sorted(result, key=lambda item: item["id"])


def _operation_spec(extension_id: str, operation: str, effect: str) -> dict[str, Any]:
    if not _IDENTIFIER.fullmatch(extension_id) or not _IDENTIFIER.fullmatch(operation):
        raise RuntimeError("plesk_extension_operation_invalid")
    profiles = load_extension_profiles()["extensions"]
    spec = profiles.get(extension_id, {}).get("operations", {}).get(operation)
    if not isinstance(spec, dict):
        raise RuntimeError("plesk_extension_operation_not_profiled")
    if spec.get("effect") != effect:
        raise RuntimeError("plesk_extension_operation_effect_mismatch")
    return spec


def extension_capability_catalog(installed: list[dict[str, Any]]) -> dict[str, Any]:
    profiles = load_extension_profiles()["extensions"]
    rows = []
    for item in installed:
        profile = profiles.get(item["id"])
        operations = []
        if profile:
            for operation, spec in sorted(profile.get("operations", {}).items()):
                operations.append({"id": operation, **spec})
        rows.append({
            **item,
            "profiled": profile is not None,
            "operations": operations,
            "execution_policy": "profiled-only" if profile else "discovery-only",
        })
    return {
        "schema": CATALOG_SCHEMA,
        "extensions": rows,
        "installed": len(rows),
        "profiled": sum(1 for row in rows if row["profiled"]),
        "unknown": [row["id"] for row in rows if not row["profiled"]],
    }


def _validated_arguments(spec: dict[str, Any], arguments: Any) -> dict[str, list[str]]:
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict) or len(arguments) > _MAX_ARGUMENTS:
        raise RuntimeError("plesk_extension_arguments_invalid")
    allowed = set(spec.get("arguments") or [])
    required = set(spec.get("required") or [])
    if not required.issubset(arguments) or not set(arguments).issubset(allowed):
        raise RuntimeError("plesk_extension_arguments_not_allowed")
    normalized: dict[str, list[str]] = {}
    for key, value in arguments.items():
        if not _IDENTIFIER.fullmatch(str(key)):
            raise RuntimeError("plesk_extension_argument_name_invalid")
        values = value if isinstance(value, list) else [value]
        if not values or len(values) > 32:
            raise RuntimeError("plesk_extension_argument_value_invalid")
        output = []
        for item in values:
            if isinstance(item, bool):
                text = "true" if item else "false"
            elif isinstance(item, (str, int, float)) and not isinstance(item, complex):
                text = str(item)
            else:
                raise RuntimeError("plesk_extension_argument_value_invalid")
            if len(text) > _MAX_VALUE_LENGTH or any(ord(char) < 32 and char not in "\t\n\r" for char in text):
                raise RuntimeError("plesk_extension_argument_value_invalid")
            output.append(text)
        normalized[str(key)] = output
    return normalized


def extension_call_packet(extension_id: str, operation: str, arguments: Any, *, effect: str) -> tuple[str, dict[str, Any]]:
    spec = _operation_spec(extension_id, operation, effect)
    if spec.get("transport") != "xml-extension" or spec.get("callable") is not True:
        raise RuntimeError("plesk_extension_operation_delegated")
    normalized = _validated_arguments(spec, arguments)
    root = ET.Element("packet")
    call = ET.SubElement(ET.SubElement(root, "extension"), "call")
    extension_node = ET.SubElement(call, extension_id)
    operation_node = ET.SubElement(extension_node, operation)
    for key, values in normalized.items():
        for value in values:
            ET.SubElement(operation_node, key).text = value
    return ET.tostring(root, encoding="unicode", xml_declaration=True), spec


def _safe_tree(node: ET.Element, *, depth: int = 0) -> Any:
    if depth > 8:
        return "[TRUNCATED]"
    children = list(node)
    if not children:
        value = (node.text or "").strip()[:_MAX_VALUE_LENGTH]
        lowered = node.tag.lower()
        if any(marker in lowered for marker in ("password", "secret", "token", "key", "authorization")):
            return "[REDACTED]"
        return value
    result: dict[str, Any] = {}
    for child in children[:128]:
        value = _safe_tree(child, depth=depth + 1)
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(value)
        else:
            result[child.tag] = value
    return result


def parse_extension_call(raw: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise RuntimeError("plesk_extension_response_invalid") from error
    result = root.find(".//extension/call/result")
    if result is None:
        raise RuntimeError("plesk_extension_response_invalid")
    status = (result.findtext("status") or "").strip()
    if status != "ok":
        code = (result.findtext("errcode") or "unknown").strip()
        raise RuntimeError(f"plesk_extension_call_failed:{code}")
    return _safe_tree(result)


def extension_operation_plan(extension_id: str, operation: str, arguments: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    spec = _operation_spec(extension_id, operation, "command")
    normalized = _validated_arguments(spec, arguments)
    payload = {
        "schema": PLAN_SCHEMA,
        "extension_id": extension_id,
        "operation": operation,
        "arguments": normalized,
        "transport": spec.get("transport"),
        "risk_class": spec.get("risk_class"),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    plan_hash = hashlib.sha256(encoded).hexdigest()
    return {**payload, "plan_hash": plan_hash, "artifact_sha256": plan_hash}, spec
