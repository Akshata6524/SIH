"""Load source parser configurations and extract fields from log records."""

from __future__ import annotations

import csv
from functools import lru_cache
import io
import json
import re
from pathlib import Path
from typing import Any, Mapping

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "configs"
FORTIGATE_SAMPLE = PROJECT_ROOT / "sample_logs" / "fortigate.log"


def load_configs(config_dir: str | Path = CONFIG_DIR) -> list[dict[str, Any]]:
    """Load YAML source configurations from a directory in filename order."""
    directory = Path(config_dir)
    if not directory.is_dir():
        raise FileNotFoundError(f"Config directory does not exist: {directory}")

    configs: list[dict[str, Any]] = []
    for path in sorted(
        (item for item in directory.iterdir() if item.suffix.lower() in {".yaml", ".yml"}),
        key=lambda item: item.name.lower(),
    ):
        with path.open("r", encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file)
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError(f"Expected a YAML mapping in {path}")
        configs.append(config)
    return configs


def parse(raw_text: str, config: Mapping[str, Any]) -> dict[str, Any]:
    """Extract source fields from one log record using its YAML configuration."""
    format_name = config.get("format")
    if not isinstance(format_name, str):
        raise ValueError("Parser config must include a string 'format'")

    normalized_format = format_name.lower()
    if normalized_format == "syslog-kv":
        return _parse_syslog_kv(raw_text)
    if normalized_format == "csv":
        return _parse_csv(raw_text, config)
    if normalized_format == "json":
        return _parse_json(raw_text)
    if normalized_format == "regex":
        return _parse_regex(raw_text, config)
    if normalized_format == "cef":
        return _parse_cef(raw_text)
    raise ValueError(f"Unsupported log format: {format_name}")


_KV_PATTERN = re.compile(
    r"""(?<!\S)(?P<key>[A-Za-z0-9_.-]+)=(?:"(?P<double>(?:\\.|[^"\\])*)"|'(?P<single>(?:\\.|[^'\\])*)'|(?P<bare>[^\s]*))"""
)


@lru_cache(maxsize=256)
def _compiled_regex(pattern: str) -> re.Pattern[str]:
    """Compile each configured parser expression once per process."""
    return re.compile(pattern)


def _parse_syslog_kv(raw_text: str) -> dict[str, str]:
    """Extract whitespace-delimited key/value pairs, including quoted values."""
    fields: dict[str, str] = {}
    for match in _KV_PATTERN.finditer(raw_text):
        value = match.group("double")
        if value is None:
            value = match.group("single")
        if value is None:
            value = match.group("bare")
        fields[match.group("key")] = re.sub(r"""\\(["'\\])""", r"\1", value)
    return fields


def _parse_csv(raw_text: str, config: Mapping[str, Any]) -> dict[str, str]:
    """Parse one CSV record using its configured column names."""
    csv_options = config.get("csv", {})
    if not isinstance(csv_options, Mapping):
        raise ValueError("The 'csv' parser options must be a mapping")
    columns = config.get("columns", csv_options.get("columns"))
    if not isinstance(columns, list) or not all(isinstance(column, str) for column in columns):
        raise ValueError("CSV parser config must include a list of string 'columns'")
    if not columns:
        raise ValueError("CSV parser config must include at least one column")

    delimiter = config.get("delimiter", csv_options.get("delimiter", ","))
    if not isinstance(delimiter, str) or len(delimiter) != 1:
        raise ValueError("CSV delimiter must be a single character")

    reader = csv.reader(io.StringIO(raw_text, newline=""), delimiter=delimiter)
    rows = list(reader)
    if len(rows) > 1:
        raise ValueError("Expected exactly one CSV record")
    if not rows:
        return {}

    row = rows[0]
    fields = {column: value for column, value in zip(columns, row)}
    for index, value in enumerate(row[len(columns):], start=1):
        fields[f"_extra_{index}"] = value
    return fields


def _parse_json(raw_text: str) -> dict[str, Any]:
    """Parse JSON and flatten nested object paths into dot-separated keys."""
    document = json.loads(raw_text)
    if not isinstance(document, dict):
        raise ValueError("JSON log record must have an object at its root")

    fields: dict[str, Any] = {}

    def flatten(value: Any, prefix: str) -> None:
        if isinstance(value, dict) and value:
            for key, nested_value in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                flatten(nested_value, path)
        elif isinstance(value, dict):
            fields[prefix] = "{}"
        elif isinstance(value, (list, tuple)):
            fields[prefix] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            fields[prefix] = value

    flatten(document, "")
    return fields


def _parse_regex(raw_text: str, config: Mapping[str, Any]) -> dict[str, str]:
    """Return named capture groups matched by the configured regular expression."""
    pattern = config.get("pattern")
    regex_options = config.get("regex")
    if pattern is None:
        if isinstance(regex_options, Mapping):
            pattern = regex_options.get("pattern")
        else:
            pattern = regex_options
    if not isinstance(pattern, str):
        raise ValueError("Regex parser config must include a string 'pattern'")

    match = _compiled_regex(pattern).search(raw_text)
    if match is None:
        return {}
    return {name: value for name, value in match.groupdict().items() if value is not None}


def _parse_cef(raw_text: str) -> dict[str, str]:
    """Extract the standard CEF header and key/value extension fields."""
    marker = raw_text.find("CEF:")
    if marker == -1:
        raise ValueError("CEF record does not contain a 'CEF:' header")
    cef_text = raw_text[marker + len("CEF:"):]

    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in cef_text:
        if character == "|" and not escaped and len(parts) < 7:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
    parts.append("".join(current))
    if len(parts) < 7:
        raise ValueError("CEF record is missing required header fields")

    header_names = (
        "cef_version",
        "device_vendor",
        "device_product",
        "device_version",
        "signature_id",
        "name",
        "severity",
    )
    fields = {
        name: value.replace(r"\|", "|").replace(r"\=", "=").replace(r"\\", "\\")
        for name, value in zip(header_names, parts[:7])
    }

    if len(parts) == 8:
        extension = parts[7]
        keys = list(re.finditer(r"(?:^|\s)([A-Za-z][A-Za-z0-9_.-]*)=", extension))
        for index, key_match in enumerate(keys):
            value_start = key_match.end()
            value_end = keys[index + 1].start() if index + 1 < len(keys) else len(extension)
            value = extension[value_start:value_end].strip()
            fields[key_match.group(1)] = (
                value.replace(r"\|", "|").replace(r"\=", "=").replace(r"\\", "\\")
            )
    return fields


if __name__ == "__main__":
    fortigate_config = next(
        (config for config in load_configs() if config.get("name") == "fortigate"),
        None,
    )
    if fortigate_config is None:
        raise SystemExit("No FortiGate parser config found in configs/")

    sample = FORTIGATE_SAMPLE.read_text(encoding="utf-8").rstrip("\r\n")
    extracted = parse(sample, fortigate_config)
    assert extracted.get("srcip") == "10.0.0.1"
    assert extracted.get("action") == "accept"
    print(json.dumps(extracted, indent=2, ensure_ascii=False))