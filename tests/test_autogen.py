"""Tests for generated source configs and immediate ingestion."""

from fastapi.testclient import TestClient

from ulpf import autogen, ingest, vault


SAMPLES = [
    "device=AcmeFW date=2026-10-04 time=10:00:00 srcip=192.0.2.10 dstip=203.0.113.10 proto=17 action=deny policyid=10",
    "device=AcmeFW date=2026-10-04 time=10:01:00 srcip=192.0.2.11 dstip=203.0.113.11 proto=6 action=accept policyid=11",
    "device=AcmeFW date=2026-10-04 time=10:02:00 srcip=192.0.2.12 dstip=203.0.113.12 proto=17 action=blocked policyid=12",
    "device=AcmeFW date=2026-10-04 time=10:03:00 srcip=192.0.2.13 dstip=203.0.113.13 proto=6 action=allow policyid=13",
    "device=AcmeFW date=2026-10-04 time=10:04:00 srcip=192.0.2.14 dstip=203.0.113.14 proto=17 action=reject policyid=14",
]


def test_autogen_saves_config_and_ingests_new_device_line(tmp_path, monkeypatch):
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    monkeypatch.setattr(ingest, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(vault, "DB_PATH", tmp_path / "raw.sqlite3")
    monkeypatch.setattr(ingest, "EVENTS_JSONL_PATH", tmp_path / "events.jsonl")
    monkeypatch.setattr(ingest, "CONFIGS", [])

    new_line = (
        "device=AcmeFW date=2026-10-04 time=10:05:00 srcip=192.0.2.15 "
        "dstip=203.0.113.15 proto=17 action=deny policyid=15"
    )
    with TestClient(ingest.app) as client:
        generated = client.post(
            "/autogen",
            json={
                "samples": SAMPLES,
                "name": "acmefw",
                "vendor": "Acme",
                "product": "AcmeFW",
                "save": True,
            },
        )
        assert generated.status_code == 200, generated.text

        response = generated.json()
        config = response["config"]
        assert config["mapping"]["srcip"] == "src.ip"
        assert config["mapping"]["dstip"] == "dst.ip"
        assert config["mapping"]["proto"] == "protocol"
        assert config["mapping"]["action"] == "action"
        assert config["mapping"]["policyid"] == "rule.id"
        assert response["confidence"]["auto_mapped"] >= 5
        assert (config_dir / "acmefw.yaml").is_file()

        event_response = client.post("/ingest", json=[new_line])
        assert event_response.status_code == 200, event_response.text
        event = event_response.json()[0]
        assert event["source"]["vendor"] == "Acme"
        assert event["action"] == "block"
        assert event["protocol"] == "udp"
        assert event["parse_status"] == "success"


def test_autogen_maps_requested_synonyms_and_timestamp_aliases():
    samples = [
        "TS=2026-10-03T10:20:01Z device=AcmeFW client_ip=192.0.2.1 "
        "client_port=40001 server_ip=203.0.113.1 server_port=443 verdict=denied",
        "ts=2026-10-03T10:21:01Z device=AcmeFW client_ip=192.0.2.2 "
        "client_port=40002 server_ip=203.0.113.2 server_port=80 verdict=allowed",
    ]

    config = autogen.generate_config(samples, "acmefw", "Acme", "AcmeFW")

    assert config["timestamp"]["fields"] == ["TS", "ts"]
    assert config["timestamp"]["format"] == "%Y-%m-%dT%H:%M:%S%z"
    assert config["mapping"]["client_ip"] == "src.ip"
    assert config["mapping"]["client_port"] == "src.port"
    assert config["mapping"]["server_ip"] == "dst.ip"
    assert config["mapping"]["server_port"] == "dst.port"
    assert config["mapping"]["verdict"] == "action"
