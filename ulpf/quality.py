"""Quality scoring for normalized events."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def compute_quality(
    extracted: dict[str, Any], event: dict[str, Any]
) -> tuple[float, str]:
    """Return mapped-field ratio and its success, partial, or failed status."""
    total_fields = len(extracted)
    if total_fields == 0:
        return 0.0, "failed"

    vendor_extras = event.get("vendor_extras", {})
    if not isinstance(vendor_extras, Mapping):
        vendor_extras = {}
    mapped_fields = sum(1 for field in extracted if field not in vendor_extras)
    score = min(1.0, mapped_fields / total_fields)
    if score >= 0.8:
        status = "success"
    elif score >= 0.4:
        status = "partial"
    else:
        status = "failed"
    return score, status