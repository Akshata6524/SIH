"""Generate parser configurations from representative perimeter-device logs."""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import yaml

from ulpf import detector, parser_engine


def _normalize_name(name: str) -> str:
    return re.sub(r"[_\-.@]", "", name).lower()


_SYNONYMS: dict[str, tuple[str, ...]] = {
    "src.ip": (
        "srcip", "src", "source_ip", "src_ip", "client_ip", "clientip",
        "src_endpoint.ip", "srcaddr", "source", "src_address",
    ),
    "dst.ip": (
        "dstip", "dst", "dest_ip", "destination_ip", "dst_ip", "dest_endpoint.ip",
        "server_ip", "serverip", "dest", "destination", "dstaddr", "dest_address",
    ),
    "src.port": ("srcport", "sport", "src_port", "source_port", "client_port"),
    "dst.port": ("dstport", "dport", "dst_port", "dest_port", "destination_port", "server_port"),
    "protocol": ("proto", "protocol", "ip_protocol"),
    "action": ("action", "disposition", "outcome", "verdict", "result"),
    "rule.id": ("policyid", "rule_id", "signature_id", "sid"),
    "rule.name": ("policyname", "rule", "rule_name", "signature", "alert"),
    "user": ("user", "username", "usr", "account"),
    "bytes.in": ("rcvdbyte", "bytes_in", "bytes_received", "rbytes"),
    "bytes.out": ("sentbyte", "bytes_out", "bytes_sent", "sbytes"),
    "severity": ("severity", "level", "priority", "sev"),
}
_NORMALIZED_SYNONYMS = {
    _normalize_name(alias): destination
    for destination, aliases in _SYNONYMS.items()
    for alias in aliases
}
_TIMESTAMP_NAMES = {
    "timestamp",
    "datetime",
    "eventtime",
    "timegenerated",
    "eventtimestamp",
    "date",
    "time",
    "ts",
    "@timestamp",
}
_ACTION_VALUES = {
    "deny": "block",
    "denied": "block",
    "blocked": "block",
    "drop": "block",
    "reject": "block",
    "accept": "allow",
    "allow": "allow",
    "allowed": "allow",
    "permit": "allow",
    "pass": "allow",
    "close": "allow",
    "alert": "alert",
    "detected": "alert",
}
_DATETIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d",
    "%m/%d/%Y %H:%M:%S",
    "%b %d %Y %H:%M:%S",
)


def _flatten_json(value: Any, prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, nested in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(_flatten_json(nested, path))
    elif prefix:
        flattened[prefix] = value
    return flattened


def _syslog_fields(lines: list[str]) -> list[dict[str, Any]]:
    return [parser_engine.parse(line, {"format": "syslog-kv"}) for line in lines]


def _json_fields(lines: list[str]) -> list[dict[str, Any]]:
    return [_flatten_json(json.loads(line)) for line in lines]


def _looks_like_header(row: list[str]) -> bool:
    if not row or len(set(row)) != len(row):
        return False
    labels = sum(
        bool(value.strip())
        and not re.search(r"\d", value)
        and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_. -]*", value.strip()))
        for value in row
    )
    return labels >= max(1, (len(row) + 1) // 2)


def _csv_fields(lines: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    rows = [next(csv.reader(io.StringIO(line))) for line in lines]
    header: list[str] | None = None
    if rows and _looks_like_header(rows[0]):
        header = [value.strip() for value in rows[0]]
        data_rows = rows[1:]
    else:
        data_rows = rows
    width = max((len(row) for row in data_rows), default=len(header or []))
    columns = header or [f"col{index}" for index in range(1, width + 1)]
    fields = [
        {column: value for column, value in zip(columns, row)}
        for row in data_rows
    ]
    if not fields and header is not None:
        fields = [{column: "" for column in columns}]
    return fields, columns


def _extract_fields(lines: list[str], format_name: str) -> tuple[list[dict[str, Any]], list[str] | None]:
    if format_name == "syslog-kv":
        return _syslog_fields(lines), None
    if format_name == "json":
        return _json_fields(lines), None
    if format_name == "csv":
        fields, columns = _csv_fields(lines)
        return fields, columns
    if format_name == "cef":
        return [parser_engine.parse(line, {"format": "cef"}) for line in lines], None
    return [{} for _ in lines], None


def _guess_timestamp(
    fields_by_line: list[dict[str, Any]],
) -> dict[str, Any] | None:
    field_names = list(dict.fromkeys(key for fields in fields_by_line for key in fields))
    normalized: dict[str, list[str]] = {}
    for field in field_names:
        normalized.setdefault(_normalize_name(field), []).append(field)

    selected: list[str] = []
    for candidate in ("timestamp", "datetime", "eventtimestamp", "eventtime", "ts"):
        if candidate in normalized:
            selected = normalized[candidate]
            break
    if not selected and "date" in normalized and "time" in normalized:
        selected = normalized["date"] + normalized["time"]
    if not selected and "date" in normalized:
        selected = normalized["date"]

    if not selected:
        return None
    separator = " "
    timestamp_samples: list[str] = []
    for fields in fields_by_line:
        values: list[Any] = []
        for normalized_name in (
            ("date", "time") if "date" in normalized and "time" in normalized
            and all(_normalize_name(field) in {"date", "time"} for field in selected)
            else ()
        ):
            field_value = next(
                (
                    fields[field]
                    for field in selected
                    if _normalize_name(field) == normalized_name
                    and fields.get(field) not in (None, "")
                ),
                None,
            )
            if field_value is not None:
                values.append(field_value)
        if not values:
            values = [
                fields[field]
                for field in selected
                if fields.get(field) not in (None, "")
            ][:1]
        if values:
            timestamp_samples.append(separator.join(str(value) for value in values))
    for timestamp_format in _DATETIME_FORMATS:
        try:
            if timestamp_samples:
                for value in timestamp_samples:
                    datetime.strptime(value, timestamp_format)
                return {"fields": selected, "format": timestamp_format, "tz": "UTC"}
        except ValueError:
            continue
    return None


def _guess_detect(
    lines: list[str],
    format_name: str,
    fields_by_line: list[dict[str, Any]],
) -> dict[str, str]:
    if format_name == "cef":
        return {"contains": "CEF:"}
    if format_name in {"syslog-kv", "json"} and fields_by_line:
        common_fields = set(fields_by_line[0])
        for fields in fields_by_line[1:]:
            common_fields.intersection_update(fields)
        unmapped_fields = [
            field
            for field in common_fields
            if _normalize_name(field) not in _NORMALIZED_SYNONYMS
            and _normalize_name(field) not in _TIMESTAMP_NAMES
        ]
        candidates = unmapped_fields or list(common_fields)
        if candidates:
            candidates.sort(
                key=lambda field: (
                    not any(
                        marker in _normalize_name(field)
                        for marker in ("vendor", "device", "product", "model", "manufacturer")
                    ),
                    -len(field),
                    field.lower(),
                )
            )
            selected = candidates[:2]
            if format_name == "syslog-kv":
                lookaheads = [rf"(?=.*(?:^|\s){re.escape(field)}=)" for field in selected]
            else:
                json_keys = dict.fromkeys(field.split(".", 1)[0] for field in selected)
                lookaheads = [rf'(?=.*"{re.escape(field)}"\s*:)' for field in json_keys]
            return {"regex": "^" + "".join(lookaheads)}
    if format_name == "csv":
        columns = len(next(csv.reader(io.StringIO(lines[0]))))
        return {"regex": rf"^[^,\r\n]*(?:,[^,\r\n]*){{{max(0, columns - 1)}}}$"}
    return {"regex": r".+"}


def generate_config(
    sample_lines: list[str], name: str, vendor: str, product: str
) -> dict[str, Any]:
    """Infer a parser config from log samples without modifying the workspace."""
    if not sample_lines or not all(isinstance(line, str) and line.strip() for line in sample_lines):
        raise ValueError("Provide at least one non-empty string sample line")

    formats = Counter(detector.detect_format(line) for line in sample_lines)
    format_name = formats.most_common(1)[0][0]
    fields_by_line, columns = _extract_fields(sample_lines, format_name)
    field_names = list(dict.fromkeys(key for fields in fields_by_line for key in fields))

    mapping: dict[str, str] = {}
    for field in field_names:
        destination = _NORMALIZED_SYNONYMS.get(_normalize_name(field))
        if destination is not None:
            mapping[field] = destination

    config: dict[str, Any] = {
        "name": name,
        "vendor": vendor,
        "product": product,
        "format": format_name,
        "detect": _guess_detect(sample_lines, format_name, fields_by_line),
        "mapping": mapping,
    }
    if columns is not None:
        config["columns"] = columns

    if "action" in mapping.values():
        action_field = next(key for key, value in mapping.items() if value == "action")
        action_values = {
            str(fields[action_field]).strip().lower()
            for fields in fields_by_line
            if fields.get(action_field) not in (None, "")
        }
        action_maps = {
            value: _ACTION_VALUES[value]
            for value in sorted(action_values)
            if value in _ACTION_VALUES
        }
        if action_maps:
            config["value_maps"] = {action_field: action_maps}

    field_names_normalized = {_normalize_name(field) for field in field_names}
    if any(
        "signature" in field or "alert" in field or field == "sid"
        for field in field_names_normalized
    ):
        category = "threat_detection"
    elif any(
        "url" in field or field == "uri" or "httpmethod" in field
        for field in field_names_normalized
    ):
        category = "web_activity"
    else:
        category = "network_activity"
    config["category"] = category

    timestamp_config = _guess_timestamp(fields_by_line)
    if timestamp_config is not None:
        config["timestamp"] = timestamp_config

    return config


def confidence_report(
    sample_lines: list[str], config: Mapping[str, Any]
) -> dict[str, Any]:
    """Count fields mapped by a generated config and fields left unmapped."""
    format_name = config.get("format")
    if isinstance(format_name, str):
        fields_by_line, _ = _extract_fields(sample_lines, format_name)
    else:
        fields_by_line = []
    field_names = sorted({key for fields in fields_by_line for key in fields})
    mapping = config.get("mapping", {})
    timestamp = config.get("timestamp", {})
    timestamp_fields = timestamp.get("fields", []) if isinstance(timestamp, Mapping) else []
    if isinstance(timestamp_fields, str):
        timestamp_fields = [timestamp_fields]
    mapped_names = set(mapping) if isinstance(mapping, Mapping) else set()
    mapped_names.update(timestamp_fields)
    mapped_fields = sorted(key for key in field_names if key in mapped_names)
    unmapped_fields = sorted(set(field_names) - set(mapped_fields))
    return {
        "auto_mapped": len(mapped_fields),
        "left_unmapped": len(unmapped_fields),
        "mapped_fields": mapped_fields,
        "unmapped_fields": unmapped_fields,
    }


def save_config(config: Mapping[str, Any], directory: str | Path = "configs") -> Path:
    """Write a generated config as YAML and return its destination path."""
    name = config.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError("Config name may contain only letters, numbers, underscores, and hyphens")
    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=True)
    config_path = destination / f"{name}.yaml"
    with config_path.open("w", encoding="utf-8", newline="\n") as config_file:
        yaml.safe_dump(dict(config), config_file, sort_keys=False, allow_unicode=True)
    return config_path