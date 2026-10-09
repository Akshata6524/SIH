"""Guess log formats and match records to configured sources."""

from __future__ import annotations

import csv
from functools import lru_cache
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Mapping, Sequence


_KEY_VALUE_PATTERN = re.compile(r"(?:^|\s)[A-Za-z_][A-Za-z0-9_.-]*=")


@lru_cache(maxsize=256)
def _compiled_regex(pattern: str) -> re.Pattern[str]:
    """Compile each configured source-detection expression once per process."""
    return re.compile(pattern)


def detect_format(line: str) -> str:
    """Guess a log record's format, returning ``plain`` when none is recognized."""
    stripped = line.strip()
    if not stripped:
        return "plain"

    if "CEF:" in stripped:
        return "cef"

    try:
        json.loads(stripped)
    except json.JSONDecodeError:
        pass
    else:
        return "json"

    try:
        ET.fromstring(stripped)
    except ET.ParseError:
        pass
    else:
        return "xml"

    if _KEY_VALUE_PATTERN.search(stripped):
        return "syslog-kv"

    try:
        rows = list(csv.reader(io.StringIO(stripped, newline="")))
    except csv.Error:
        rows = []
    if len(rows) == 1 and len(rows[0]) > 1:
        return "csv"

    return "plain"


def identify_source(
    line: str, configs: Sequence[Mapping[str, Any]]
) -> Mapping[str, Any] | None:
    """Return the first config whose ``detect`` contains or regex rule matches."""
    for config in configs:
        detect = config.get("detect")
        if detect is None:
            continue
        if not isinstance(detect, Mapping):
            raise ValueError(f"Detect rule for {config.get('name', '<unnamed>')} must be a mapping")

        contains = detect.get("contains")
        regex = detect.get("regex")
        if contains is None and regex is None:
            continue
        if contains is not None and not isinstance(contains, str):
            raise ValueError(
                f"'contains' detect rule for {config.get('name', '<unnamed>')} must be a string"
            )
        if regex is not None and not isinstance(regex, str):
            raise ValueError(
                f"'regex' detect rule for {config.get('name', '<unnamed>')} must be a string"
            )

        matches = True
        if contains is not None:
            matches = contains in line
        if regex is not None:
            try:
                matches = matches and _compiled_regex(regex).search(line) is not None
            except re.error as error:
                raise ValueError(
                    f"Invalid regex detect rule for {config.get('name', '<unnamed>')}: {error}"
                ) from error
        if matches:
            return config

    return None