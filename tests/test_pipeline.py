"""API integration tests for the end-to-end ingestion pipeline."""

import hashlib
import json

from fastapi.testclient import TestClient

from ulpf import ingest, vault


def test_ingest_event_and_verify_raw_text(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "DB_PATH", tmp_path / "vault.sqlite3")
    monkeypatch.setattr(ingest, "EVENTS_JSONL_PATH", tmp_path / "events.jsonl")
    sample_line = (
        'date=2026-10-04 time=16:30:00 devname="FGT-01" '
        "srcip=192.0.2.10 srcport=52000 dstip=203.0.113.20 "
        "dstport=53 proto=17 action=deny policyid=42 sentbyte=120 rcvdbyte=80"
    )

    with TestClient(ingest.app) as client:
        health_response = client.get("/health")
        assert health_response.status_code == 200
        assert health_response.json()["status"] == "ok"
        assert health_response.json()["configs_loaded"] >= 5
        root_response = client.get("/", follow_redirects=False)
        assert root_response.status_code == 307
        assert root_response.headers["location"] == "/docs"

        response = client.post("/ingest", json=sample_line)

        assert response.status_code == 200
        event = response.json()
        assert event["action"] == "block"
        assert event["protocol"] == "udp"
        assert event["vendor_extras"]["devname"] == "FGT-01"

        events_response = client.get("/events")
        assert events_response.status_code == 200
        assert event["event_id"] in {
            stored_event["event_id"] for stored_event in events_response.json()
        }

        raw_response = client.get(f"/raw/{event['raw_event_id']}")
        assert raw_response.status_code == 200
        assert raw_response.json() == {
            "raw_event_id": event["raw_event_id"],
            "raw_text": sample_line,
            "raw_sha256": hashlib.sha256(sample_line.encode("utf-8")).hexdigest(),
            "verified": True,
        }

        assert ingest.EVENTS_JSONL_PATH.read_text(encoding="utf-8").count("\n") == 1
        assert json.loads(ingest.EVENTS_JSONL_PATH.read_text(encoding="utf-8"))["event_id"] == (
            event["event_id"]
        )
