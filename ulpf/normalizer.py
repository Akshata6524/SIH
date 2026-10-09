"""Normalize extracted device fields into the ULPF unified event shape."""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ulpf.quality import compute_quality


_PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp"}
_TIMESTAMP_PATTERNS = (
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
    re.compile(r"\b\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),
)
_IP_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Fa-f0-9:]*:[A-Fa-f0-9:]+)(?![A-Fa-f0-9:.])"
)
_KEY_VALUE_PATTERN = re.compile(
    r"""(?<!\S)(?P<key>[A-Za-z0-9_.-]+)=(?:"(?P<double>(?:\\.|[^"\\])*)"|'(?P<single>(?:\\.|[^'\\])*)'|(?P<bare>[^\s]*))"""
)


def _assign_path(target: dict[str, Any], path: str, value: Any) -> None:
    """Assign a value into a nested dictionary using a dot-separated path."""
    path_parts = path.split(".")
    if not all(path_parts):
        raise ValueError(f"Invalid mapping destination: {path!r}")
    current = target
    for part in path_parts[:-1]:
        child = current.get(part)
        if child is None:
            child = {}
            current[part] = child
        if not isinstance(child, dict):
            raise ValueError(f"Conflicting mapping destination: {path!r}")
        current = child
    current[path_parts[-1]] = value


def _timestamp_fields(
    extracted: Mapping[str, Any], timestamp_config: Mapping[str, Any]
) -> tuple[list[str], Any]:
    fields = timestamp_config.get("fields", [])
    if isinstance(fields, str):
        fields = [fields]
    if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
        raise ValueError("Timestamp 'fields' must be a string or a list of strings")

    values = [extracted[field] for field in fields if field in extracted]
    if not values:
        return fields, None
    if len(values) == 1:
        return fields, values[0]
    separator = str(timestamp_config.get("separator", " "))
    return fields, separator.join(str(value) for value in values)


def _to_utc_iso(value: Any, timestamp_config: Mapping[str, Any]) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        timestamp_format = timestamp_config.get("format")
        try:
            if timestamp_format is not None:
                if not isinstance(timestamp_format, str):
                    raise ValueError("Timestamp 'format' must be a string")
                parsed = datetime.strptime(text, timestamp_format)
            else:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None

    if parsed.tzinfo is None:
        timezone_name = timestamp_config.get("tz", "UTC")
        if not isinstance(timezone_name, str):
            raise ValueError("Timestamp 'tz' must be a timezone name")
        if timezone_name.upper() in {"UTC", "Z", "GMT", "ETC/UTC"}:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            try:
                parsed = parsed.replace(tzinfo=ZoneInfo(timezone_name))
            except ZoneInfoNotFoundError as error:
                raise ValueError(f"Unknown timestamp timezone: {timezone_name}") from error
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _mapped_value(
    source_field: str, value: Any, value_maps: Mapping[str, Any]
) -> Any:
    field_maps = value_maps.get(source_field)
    if not isinstance(field_maps, Mapping):
        return value
    try:
        if value in field_maps:
            return field_maps[value]
    except TypeError:
        return value
    string_value = str(value)
    if string_value in field_maps:
        return field_maps[string_value]
    lowered_maps = {str(key).lower(): mapped for key, mapped in field_maps.items()}
    return lowered_maps.get(string_value.lower(), value)


def normalize(
    extracted: dict[str, Any],
    config: dict[str, Any],
    raw_event_id: str,
    sha256: str,
    device_ip: str | None = None,
) -> dict[str, Any]:
    """Build a traceable unified event while retaining unmapped source fields."""
    mapping = config.get("mapping", {})
    if not isinstance(mapping, Mapping):
        raise ValueError("Config 'mapping' must be a mapping")
    value_maps = config.get("value_maps", {})
    if not isinstance(value_maps, Mapping):
        raise ValueError("Config 'value_maps' must be a mapping")
    timestamp_config = config.get("timestamp", {})
    if not isinstance(timestamp_config, Mapping):
        raise ValueError("Config 'timestamp' must be a mapping")

    event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "raw_event_id": raw_event_id,
        "raw_sha256": sha256,
        "timestamp": None,
        "ingest_time": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "source": {
            "vendor": config.get("vendor", "unknown"),
            "product": config.get("product", "unknown"),
            "format": config.get("format", "unknown"),
            "device_ip": device_ip,
        },
        "category": config.get("category", "other"),
        "action": "unknown",
        "severity": 0,
        "src": {"ip": None, "port": None},
        "dst": {"ip": None, "port": None},
        "protocol": None,
        "user": None,
        "rule": {"id": None, "name": None},
        "bytes": {"in": None, "out": None},
        "vendor_extras": {},
        "parse_status": "failed",
        "parse_score": 0.0,
        "schema_version": "1.0",
    }

    timestamp_fields, timestamp_value = _timestamp_fields(extracted, timestamp_config)
    timestamp = _to_utc_iso(timestamp_value, timestamp_config)
    if timestamp is not None:
        event["timestamp"] = timestamp
    elif timestamp_value is not None:
        event["vendor_extras"].update(
            {field: extracted[field] for field in timestamp_fields if field in extracted}
        )

    mapped_source_fields: set[str] = set()
    for source_field, destination in mapping.items():
        if not isinstance(source_field, str) or not isinstance(destination, str):
            raise ValueError("Field mappings must be string source and destination paths")
        if source_field not in extracted:
            continue

        mapped_source_fields.add(source_field)
        value = _mapped_value(source_field, extracted[source_field], value_maps)
        if destination in {"src.port", "dst.port", "bytes.in", "bytes.out", "severity"}:
            cast_value = _safe_int(value)
            if cast_value is None:
                event["vendor_extras"][source_field] = extracted[source_field]
                continue
            value = cast_value
        elif destination == "protocol":
            value = _PROTOCOLS.get(str(value).lower(), value)
        _assign_path(event, destination, value)

    for source_field, value in extracted.items():
        if source_field not in mapped_source_fields and source_field not in timestamp_fields:
            event["vendor_extras"][source_field] = value

    parse_score, parse_status = compute_quality(extracted, event)
    event["parse_score"] = parse_score
    event["parse_status"] = parse_status
    return event


def _extract_key_values(text: str) -> dict[str, str]:
    """Extract key/value pairs from text for generic events."""
    values: dict[str, str] = {}
    for match in _KEY_VALUE_PATTERN.finditer(text):
        value = match.group("double")
        if value is None:
            value = match.group("single")
        if value is None:
            value = match.group("bare")
        values[match.group("key")] = re.sub(r"""\\(["'\\])""", r"\1", value)
    return values


def normalize_generic(
    extracted: dict[str, Any], raw_event_id: str, sha256: str
) -> dict[str, Any]:
    """Create a generic event and retain all extracted fields and detected values."""
    text = " ".join(f"{key}={value}" for key, value in extracted.items())
    vendor_extras = dict(extracted)
    vendor_extras.update(_extract_key_values(text))

    timestamp_value: str | None = None
    for pattern in _TIMESTAMP_PATTERNS:
        match = pattern.search(text)
        if match:
            timestamp_value = match.group(0)
            break

    timestamp = None
    if timestamp_value:
        timestamp_config: dict[str, Any] = {"tz": "UTC"}
        if "/" in timestamp_value:
            timestamp_config["format"] = "%Y/%m/%d %H:%M:%S"
        timestamp = _to_utc_iso(timestamp_value, timestamp_config)

    ips: list[str] = []
    for match in _IP_PATTERN.finditer(text):
        candidate = match.group(0)
        try:
            parsed_ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in ips:
            ips.append(str(parsed_ip))

    event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "raw_event_id": raw_event_id,
        "raw_sha256": sha256,
        "timestamp": timestamp,
        "ingest_time": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "source": {
            "vendor": "unknown",
            "product": "unknown",
            "format": "unknown",
            "device_ip": None,
        },
        "category": "other",
        "action": "unknown",
        "severity": 0,
        "src": {"ip": ips[0] if ips else None, "port": None},
        "dst": {"ip": ips[1] if len(ips) > 1 else None, "port": None},
        "protocol": None,
        "user": None,
        "rule": {"id": None, "name": None},
        "bytes": {"in": None, "out": None},
        "vendor_extras": vendor_extras,
        "parse_status": "failed",
        "parse_score": 0.0,
        "schema_version": "1.0",
    }
    parse_score, parse_status = compute_quality(extracted, event)
    event["parse_score"] = parse_score
    event["parse_status"] = parse_status
    return event