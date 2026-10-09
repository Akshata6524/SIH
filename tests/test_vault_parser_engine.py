"""Focused tests for raw-vault persistence and parser format support."""

import hashlib

import pytest

from ulpf import vault
from ulpf.parser_engine import load_configs, parse


def test_raw_vault_preserves_exact_text_and_digest(tmp_path, monkeypatch):
    raw_text = ' key="value with spaces"\r\n'
    monkeypatch.setattr(vault, "DB_PATH", tmp_path / "raw.sqlite3")

    raw_event_id, digest = vault.save_raw(raw_text, "192.0.2.1")
    stored = vault.get_raw(raw_event_id)

    assert stored is not None
    assert digest == hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    assert stored["raw_event_id"] == raw_event_id
    assert stored["raw_sha256"] == digest
    assert stored["source_ip"] == "192.0.2.1"
    assert stored["raw_text"] == raw_text


def test_get_raw_returns_none_for_unknown_id(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "DB_PATH", tmp_path / "raw.sqlite3")

    assert vault.get_raw("missing") is None


def test_load_configs_reads_yaml_files(tmp_path):
    (tmp_path / "example.yaml").write_text("name: example\nformat: json\n", encoding="utf-8")

    assert load_configs(tmp_path) == [{"name": "example", "format": "json"}]


@pytest.mark.parametrize(
    ("config", "raw_text", "expected"),
    [
        (
            {"format": "syslog-kv"},
            'srcip=192.0.2.1 message="blocked by policy"',
            {"srcip": "192.0.2.1", "message": "blocked by policy"},
        ),
        (
            {"format": "csv", "columns": ["srcip", "dstport"]},
            "192.0.2.1,443",
            {"srcip": "192.0.2.1", "dstport": "443"},
        ),
        (
            {"format": "json"},
            '{"src_endpoint":{"ip":"192.0.2.1"},"allowed":false}',
            {"src_endpoint.ip": "192.0.2.1", "allowed": False},
        ),
        (
            {"format": "regex", "pattern": r"src=(?P<srcip>\S+)"},
            "event src=192.0.2.1",
            {"srcip": "192.0.2.1"},
        ),
        (
            {"format": "cef"},
            r"CEF:0|Vendor|Product|1|42|Denied|5|src=192.0.2.1 dst=198.51.100.2",
            {
                "cef_version": "0",
                "device_vendor": "Vendor",
                "device_product": "Product",
                "device_version": "1",
                "signature_id": "42",
                "name": "Denied",
                "severity": "5",
                "src": "192.0.2.1",
                "dst": "198.51.100.2",
            },
        ),
    ],
)
def test_parse_supported_formats(config, raw_text, expected):
    assert parse(raw_text, config) == expected
