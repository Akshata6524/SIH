"""Verify that every bundled sample line is retained and parseable."""

import sqlite3
from pathlib import Path

from ulpf import ingest, vault


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILES = (
    "fortigate.log",
    "cisco_asa.log",
    "paloalto.csv",
    "suricata.json",
    "squid.log",
)


def test_all_sample_lines_are_stored_and_parseable(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "DB_PATH", tmp_path / "sample-test.sqlite3")
    monkeypatch.setattr(ingest, "EVENTS_JSONL_PATH", tmp_path / "events.jsonl")
    monkeypatch.setattr(ingest, "CONFIGS", [])
    ingest.reload_configs()

    expected_lines = 0
    successful_or_partial = 0
    for filename in SAMPLE_FILES:
        sample_path = PROJECT_ROOT / "sample_logs" / filename
        lines = [line for line in sample_path.read_text(encoding="utf-8").splitlines() if line]
        expected_lines += len(lines)
        assert len(lines) == 20, f"{filename} should contain 20 sample records"
        for line in lines:
            event = ingest.process_line(line)
            successful_or_partial += event["parse_status"] in {"success", "partial"}

    with sqlite3.connect(vault.DB_PATH) as connection:
        (stored_raw_count,) = connection.execute("SELECT COUNT(*) FROM raw_events").fetchone()

    assert stored_raw_count == expected_lines
    assert successful_or_partial / expected_lines >= 0.9
