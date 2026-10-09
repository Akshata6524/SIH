"""Tests for CEF, OCSF, JSONL, and Parquet exporters."""

import json

import pandas as pd
from fastapi.testclient import TestClient

from ulpf import exporters, ingest, vault


def _fortigate_event(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "DB_PATH", tmp_path / "raw.sqlite3")
    raw_text = (
        "date=2026-10-04 time=10:15:00 devname=FW1 srcip=10.1.1.5 "
        "srcport=51234 dstip=8.8.8.8 dstport=53 proto=17 action=deny policyid=12"
    )
    raw_event_id, sha256 = vault.save_raw(raw_text, "192.0.2.1")
    return {
        "event_id": "event-1",
        "raw_event_id": raw_event_id,
        "raw_sha256": sha256,
        "timestamp": "2026-10-04T10:15:00Z",
        "source": {
            "vendor": "Fortinet",
            "product": "FortiGate",
            "format": "syslog-kv",
            "device_ip": "192.0.2.1",
        },
        "category": "network_activity",
        "action": "block",
        "severity": 3,
        "src": {"ip": "10.1.1.5", "port": 51234},
        "dst": {"ip": "8.8.8.8", "port": 53},
        "protocol": "udp",
        "user": "ravi",
        "rule": {"id": "12", "name": None},
        "bytes": {"in": 80, "out": 120},
        "vendor_extras": {"devname": "FW1"},
        "parse_status": "success",
        "parse_score": 0.9,
        "schema_version": "1.0",
    }


def test_to_cef_contains_event_fields_and_no_newline(tmp_path, monkeypatch):
    event = _fortigate_event(tmp_path, monkeypatch)

    cef = exporters.to_cef(event)

    assert cef.startswith("CEF:0|Fortinet|FortiGate")
    assert "src=10.1.1.5" in cef
    assert "dst=8.8.8.8" in cef
    assert "\n" not in cef
    assert "\r" not in cef


def test_to_cef_escapes_header_and_extension_delimiters(tmp_path, monkeypatch):
    event = _fortigate_event(tmp_path, monkeypatch)
    event["source"]["vendor"] = "Acme|Vendor\\"
    event["user"] = "alice=admin|team\\one"

    cef = exporters.to_cef(event)

    assert r"Acme\|Vendor\\" in cef
    assert r"suser=alice\=admin|team\\one" in cef


def test_to_ocsf_maps_network_activity_and_includes_raw_data(tmp_path, monkeypatch):
    event = _fortigate_event(tmp_path, monkeypatch)

    ocsf = exporters.to_ocsf(event)

    assert ocsf["class_uid"] == 4001
    assert ocsf["action_id"] == 2
    assert ocsf["src_endpoint"]["ip"] == "10.1.1.5"
    assert "devname" in ocsf["unmapped"]
    assert ocsf["raw_data"] == vault.get_raw(event["raw_event_id"])["raw_text"]


def test_to_parquet_round_trips_flattened_rows(tmp_path, monkeypatch):
    first_event = _fortigate_event(tmp_path, monkeypatch)
    second_event = {**first_event, "event_id": "event-2"}
    destination = tmp_path / "exports" / "events.parquet"

    count = exporters.to_parquet([first_event, second_event], str(destination))
    restored = pd.read_parquet(destination, engine="pyarrow")

    assert count == 2
    assert len(restored) == 2
    assert restored.loc[0, "src_ip"] == "10.1.1.5"
    assert json.loads(restored.loc[0, "vendor_extras"])["devname"] == "FW1"


def test_to_jsonl_and_dispatcher(tmp_path, monkeypatch):
    event = _fortigate_event(tmp_path, monkeypatch)
    destination = tmp_path / "nested" / "events.jsonl"

    assert exporters.to_jsonl([event], str(destination)) == 1
    assert json.loads(destination.read_text(encoding="utf-8")) == event
    assert exporters.export_events([event], "json") == [event]
    assert isinstance(exporters.export_events([event], "cef"), str)
    assert exporters.export_events([event], "ocsf")[0]["class_uid"] == 4001


def test_export_endpoints_return_requested_formats(tmp_path, monkeypatch):
    event = _fortigate_event(tmp_path, monkeypatch)
    monkeypatch.setattr(ingest, "EVENTS_JSONL_PATH", tmp_path / "events.jsonl")
    monkeypatch.setattr(ingest, "PROJECT_ROOT", tmp_path)
    ingest._store_event(event)

    with TestClient(ingest.app) as client:
        cef_response = client.get("/export", params={"format": "cef", "limit": 1})
        assert cef_response.status_code == 200
        assert cef_response.headers["content-type"].startswith("text/plain")
        assert cef_response.text.startswith("CEF:0|Fortinet|FortiGate")

        ocsf_response = client.get("/export", params={"format": "ocsf", "limit": 1})
        assert ocsf_response.status_code == 200
        assert ocsf_response.json()[0]["class_uid"] == 4001

        single_response = client.get(
            f"/export/{event['event_id']}", params={"format": "ocsf"}
        )
        assert single_response.status_code == 200
        assert single_response.json()["metadata"]["uid"] == event["event_id"]

        parquet_response = client.get("/export", params={"format": "parquet", "limit": 1})
        assert parquet_response.status_code == 200
        assert len(pd.read_parquet(tmp_path / "data" / "export.parquet")) == 1
