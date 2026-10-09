"""Tests for log format and source detection."""

import pytest

from ulpf.detector import detect_format, identify_source


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('{"event":"blocked","src":{"ip":"192.0.2.1"}}', "json"),
        ("CEF:0|Vendor|Product|1|42|Denied|5|src=192.0.2.1", "cef"),
        ("<event><action>blocked</action></event>", "xml"),
        ("srcip=192.0.2.1 action=deny", "syslog-kv"),
        ("192.0.2.1,203.0.113.1,443", "csv"),
        ("An unstructured perimeter device message", "plain"),
        ("  ", "plain"),
    ],
)
def test_detect_format(line, expected):
    assert detect_format(line) == expected


def test_identify_source_matches_contains_rule():
    config = {"name": "fortigate", "detect": {"contains": "devname="}}

    assert identify_source('devname="FGT-01" action=accept', [config]) is config


def test_identify_source_matches_regex_rule():
    config = {"name": "suricata", "detect": {"regex": r"\[\*\*\]"}}

    assert identify_source("[**] [1:2:3] alert", [config]) is config


def test_identify_source_returns_none_when_no_rule_matches():
    configs = [
        {"name": "fortigate", "detect": {"contains": "devname="}},
        {"name": "suricata", "detect": {"regex": r"\[\*\*\]"}},
    ]

    assert identify_source("plain message", configs) is None


def test_identify_source_returns_first_matching_config():
    first = {"name": "first", "detect": {"contains": "event"}}
    second = {"name": "second", "detect": {"contains": "event"}}

    assert identify_source("event", [first, second]) is first


def test_identify_source_requires_valid_regex():
    with pytest.raises(ValueError, match="Invalid regex"):
        identify_source("line", [{"name": "bad", "detect": {"regex": "("}}])
