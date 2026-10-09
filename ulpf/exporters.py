"""Export unified events to CEF, OCSF, JSONL, and Parquet formats."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ulpf import vault


def _epoch_milliseconds(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return int(timestamp.timestamp() * 1000)


def _get_path(event: Mapping[str, Any], *path: str) -> Any:
    value: Any = event
    for part in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _cef_header(value: Any) -> str:
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _cef_extension(value: Any) -> str:
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    return text.replace("\\", "\\\\").replace("=", "\\=")


def to_cef(event: dict[str, Any]) -> str:
    """Convert a unified event to one CEF record without raw line breaks."""
    source = event.get("source", {})
    rule = event.get("rule", {})
    source = source if isinstance(source, Mapping) else {}
    rule = rule if isinstance(rule, Mapping) else {}

    category = event.get("category") or "other"
    action = event.get("action") or "unknown"
    try:
        severity = max(0, min(5, int(event.get("severity", 0)))) * 2
    except (TypeError, ValueError, OverflowError):
        severity = 0

    header = (
        "CEF:0"
        f"|{_cef_header(source.get('vendor') or 'unknown')}"
        f"|{_cef_header(source.get('product') or 'unknown')}"
        "|1.0"
        f"|{_cef_header(rule.get('id') if rule.get('id') is not None else '0')}"
        f"|{_cef_header(f'{category} {action}')}"
        f"|{severity}"
    )

    fields = (
        ("src", _get_path(event, "src", "ip")),
        ("dst", _get_path(event, "dst", "ip")),
        ("spt", _get_path(event, "src", "port")),
        ("dpt", _get_path(event, "dst", "port")),
        ("proto", event.get("protocol")),
        ("act", event.get("action")),
        ("suser", event.get("user")),
        ("in", _get_path(event, "bytes", "in")),
        ("out", _get_path(event, "bytes", "out")),
        ("rt", _epoch_milliseconds(event.get("timestamp"))),
        ("externalId", event.get("event_id")),
        ("cs1Label", "rawEventId"),
        ("cs1", event.get("raw_event_id")),
        ("cs2Label", "rawSha256"),
        ("cs2", event.get("raw_sha256")),
    )
    extension = [
        f"{key}={_cef_extension(value)}"
        for key, value in fields
        if value is not None
    ]
    line = header + "|" + " ".join(extension)
    return line.replace("\r", "\\r").replace("\n", "\\n")


def to_ocsf(event: dict[str, Any]) -> dict[str, Any]:
    """Convert a unified event to OCSF Network Activity (class 4001)."""
    source = event.get("source", {})
    source = source if isinstance(source, Mapping) else {}
    action = event.get("action")
    action_id = 1 if action == "allow" else 2 if action in {"block", "drop"} else 0

    result: dict[str, Any] = {
        "class_uid": 4001,
        "category_uid": 4,
        "class_name": "Network Activity",
        "activity_id": 6,
        "action_id": action_id,
        "metadata": {"version": "1.1.0"},
    }
    if event.get("severity") is not None:
        result["severity_id"] = event["severity"]
    event_time = _epoch_milliseconds(event.get("timestamp"))
    if event_time is not None:
        result["time"] = event_time
    if event.get("parse_status") is not None:
        result["status"] = event["parse_status"]

    source_endpoint = {
        key: _get_path(event, "src", field)
        for key, field in (("ip", "ip"), ("port", "port"))
        if _get_path(event, "src", field) is not None
    }
    if source_endpoint:
        result["src_endpoint"] = source_endpoint
    destination_endpoint = {
        key: _get_path(event, "dst", field)
        for key, field in (("ip", "ip"), ("port", "port"))
        if _get_path(event, "dst", field) is not None
    }
    if destination_endpoint:
        result["dst_endpoint"] = destination_endpoint

    if event.get("protocol") is not None:
        result["connection_info"] = {"protocol_name": event["protocol"]}
    traffic = {
        key: _get_path(event, "bytes", source_key)
        for key, source_key in (("bytes_in", "in"), ("bytes_out", "out"))
        if _get_path(event, "bytes", source_key) is not None
    }
    if traffic:
        result["traffic"] = traffic
    if event.get("user") is not None:
        result["user"] = {"name": event["user"]}

    product: dict[str, Any] = {}
    if source.get("vendor") is not None:
        product["vendor_name"] = source["vendor"]
    if source.get("product") is not None:
        product["name"] = source["product"]
    if product:
        result["metadata"]["product"] = product
    if event.get("event_id") is not None:
        result["metadata"]["uid"] = event["event_id"]
    if event.get("vendor_extras") is not None:
        result["unmapped"] = event["vendor_extras"]

    raw_event_id = event.get("raw_event_id")
    if raw_event_id is not None:
        raw_record = vault.get_raw(str(raw_event_id))
        if raw_record is not None:
            result["raw_data"] = raw_record["raw_text"]
    return result


def to_jsonl(events: list[dict[str, Any]], path: str) -> int:
    """Write events as UTF-8 JSON Lines, creating parent folders as needed."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as output_file:
        for event in events:
            output_file.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    return len(events)


def _flatten_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten nested fields into underscore-separated columns."""
    flattened: dict[str, Any] = {}

    def visit(value: Any, prefix: str) -> None:
        if isinstance(value, Mapping):
            if not value:
                flattened[prefix] = "{}"
            else:
                for key, nested_value in value.items():
                    name = f"{prefix}_{key}" if prefix else str(key)
                    visit(nested_value, name)
        elif isinstance(value, (list, tuple)):
            flattened[prefix] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            flattened[prefix] = value

    for key, value in event.items():
        if key == "vendor_extras":
            flattened[key] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            visit(value, key)
    return flattened


def to_parquet(events: list[dict[str, Any]], path: str) -> int:
    """Write flattened events to Parquet using pandas and the PyArrow engine."""
    try:
        import pandas as pd
    except ImportError as error:
        raise ImportError(
            "Parquet export requires pandas and PyArrow; install PyArrow with "
            "'python -m pip install pyarrow'."
        ) from error

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    frame = pd.DataFrame([_flatten_event(event) for event in events])
    try:
        frame.to_parquet(destination, engine="pyarrow", index=False)
    except ImportError as error:
        raise ImportError(
            "Parquet export requires PyArrow; install it with "
            "'python -m pip install pyarrow'."
        ) from error
    return len(events)


def export_events(events: list[dict[str, Any]], fmt: str) -> str | list[Any]:
    """Dispatch event conversion for the CEF, OCSF, or JSON format."""
    normalized_format = fmt.lower()
    if normalized_format == "cef":
        return "\n".join(to_cef(event) for event in events)
    if normalized_format == "ocsf":
        return [to_ocsf(event) for event in events]
    if normalized_format == "json":
        return events
    raise ValueError(f"Unsupported export format: {fmt}")
