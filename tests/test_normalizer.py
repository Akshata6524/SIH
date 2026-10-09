"""Tests for normalized unified events and parse quality."""

from ulpf.normalizer import normalize, normalize_generic
from ulpf.quality import compute_quality


FORTIGATE_CONFIG = {
    "name": "fortigate",
    "vendor": "Fortinet",
    "product": "FortiGate",
    "format": "syslog-kv",
    "mapping": {
        "srcip": "src.ip",
        "srcport": "src.port",
        "dstip": "dst.ip",
        "dstport": "dst.port",
        "proto": "protocol",
        "action": "action",
        "policyid": "rule.id",
        "sentbyte": "bytes.out",
        "rcvdbyte": "bytes.in",
    },
    "value_maps": {"action": {"deny": "block", "accept": "allow"}},
    "category": "network_activity",
    "timestamp": {
        "fields": ["date", "time"],
        "format": "%Y-%m-%d %H:%M:%S",
        "tz": "UTC",
    },
}


def test_normalize_fortigate_event():
    extracted = {
        "date": "2026-10-04",
        "time": "16:30:00",
        "devname": "FGT-01",
        "srcip": "192.0.2.10",
        "srcport": "52000",
        "dstip": "203.0.113.20",
        "dstport": "53",
        "proto": "17",
        "action": "deny",
        "policyid": "42",
        "sentbyte": "120",
        "rcvdbyte": "80",
    }

    event = normalize(extracted, FORTIGATE_CONFIG, "raw-id", "raw-hash", "192.0.2.1")

    assert event["action"] == "block"
    assert event["protocol"] == "udp"
    assert event["timestamp"] == "2026-10-04T16:30:00Z"
    assert event["source"]["device_ip"] == "192.0.2.1"
    assert event["vendor_extras"]["devname"] == "FGT-01"
    assert event["src"]["port"] == 52000
    assert event["dst"]["port"] == 53
    assert event["bytes"] == {"in": 80, "out": 120}
    assert event["raw_event_id"] == "raw-id"
    assert event["raw_sha256"] == "raw-hash"


def test_invalid_cast_values_are_preserved_as_extras():
    event = normalize(
        {"srcport": "not-a-port"},
        {"mapping": {"srcport": "src.port"}},
        "raw-id",
        "raw-hash",
    )

    assert event["src"]["port"] is None
    assert event["vendor_extras"]["srcport"] == "not-a-port"


def test_normalize_generic_extracts_timestamp_ips_and_pairs():
    event = normalize_generic(
        {"raw": "2026-10-04T10:00:00Z src=192.0.2.2 dst=198.51.100.4 action=deny"},
        "raw-id",
        "raw-hash",
    )

    assert event["timestamp"] == "2026-10-04T10:00:00Z"
    assert event["src"]["ip"] == "192.0.2.2"
    assert event["dst"]["ip"] == "198.51.100.4"
    assert event["vendor_extras"]["action"] == "deny"
    assert event["vendor_extras"]["raw"].startswith("2026-10-04T10:00:00Z")
    assert event["source"]["vendor"] == "unknown"


def test_compute_quality_thresholds_and_empty_input():
    assert compute_quality({"a": 1, "b": 2}, {"vendor_extras": {}}) == (1.0, "success")
    assert compute_quality(
        {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5},
        {"vendor_extras": {"e": 5, "d": 4, "c": 3}},
    ) == (0.4, "partial")
    assert compute_quality({"a": 1, "b": 2, "c": 3}, {"vendor_extras": {"a": 1, "b": 2}}) == (
        1 / 3,
        "failed",
    )
    assert compute_quality({}, {"vendor_extras": {}}) == (0.0, "failed")
