"""
test_summarize.py
Unit tests for triage/summarize.py host grouping and narrative correlation.
"""

from enrich import enrich_detections
from summarize import _group_by_host, generate_executive_summary


def test_generate_executive_summary_empty():
    summary = generate_executive_summary([])
    assert "No alerts were triggered" in summary


def test_generate_executive_summary_full_chain(sample_raw_detections):
    enriched = enrich_detections(sample_raw_detections)
    summary = generate_executive_summary(enriched)

    assert "3 alert(s) triggered across 3 MITRE ATT&CK technique(s)" in summary
    assert "2 alert(s) rated Critical severity" in summary
    assert "36 failed SSH login attempts were observed from 72.255.58.137 against ip-172-31-13-183" in summary
    assert "followed by a successful login as 'ubuntu'" in summary
    assert "execution of 'wget' targeting http://example.com/malware.sh" in summary
    assert "priority incident" in summary


def test_group_by_host(sample_raw_detections):
    enriched = enrich_detections(sample_raw_detections)
    groups = _group_by_host(enriched)

    assert len(groups) == 1
    assert "ip-172-31-13-183" in groups
    assert len(groups["ip-172-31-13-183"]) == 3


def test_multi_host_summary():
    alerts = [
        {
            "technique_id": "T1110",
            "technique_name": "SSH Brute Force",
            "score": 50,
            "severity": "Medium",
            "summary": "15 failed SSH attempts",
            "raw_event": {"host": "host-alpha", "src_ip": "10.0.0.1", "failed_attempts": "15"},
        },
        {
            "technique_id": "T1059",
            "technique_name": "Scripting Execution",
            "score": 75,
            "severity": "High",
            "summary": "Executed curl",
            "raw_event": {"host": "host-beta", "command": "curl", "arg1": "http://evil.com"},
        },
    ]

    summary = generate_executive_summary(alerts)
    assert "2 alert(s) triggered across 2 MITRE ATT&CK technique(s)" in summary
    assert "15 failed SSH login attempts were observed from 10.0.0.1 against host-alpha" in summary
    assert "Execution of 'curl' targeting http://evil.com" in summary
    assert "was observed on host-beta" in summary
