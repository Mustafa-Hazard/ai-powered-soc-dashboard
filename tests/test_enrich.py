"""
test_enrich.py
Unit tests for triage/enrich.py scoring rules, labels, and event summaries.
"""

from enrich import (
    enrich_detections,
    label_for_score,
    score_t1059,
    score_t1078,
    score_t1110,
    summarize_event,
)


def test_score_t1110():
    # 5 attempts -> 20 + 5*2 = 30
    assert score_t1110({"failed_attempts": "5"}) == 30
    # 36 attempts -> 20 + 36*2 = 92
    assert score_t1110({"failed_attempts": 36}) == 92
    # 50 attempts -> 20 + 100 = 120 -> capped at 100
    assert score_t1110({"failed_attempts": "50"}) == 100
    # Missing / malformed / negative inputs fallback gracefully
    assert score_t1110({}) == 20
    assert score_t1110({"failed_attempts": "invalid"}) == 20
    assert score_t1110({"failed_attempts": -5}) == 20


def test_score_t1078():
    # 5 prior failed -> 60 + 5 = 65
    assert score_t1078({"prior_failed_attempts": "5"}) == 65
    # 35 prior failed -> 60 + 35 = 95
    assert score_t1078({"prior_failed_attempts": 35}) == 95
    # 50 prior failed -> 60 + 50 = 110 -> capped at 100
    assert score_t1078({"prior_failed_attempts": 50}) == 100
    # Missing / malformed inputs fallback gracefully
    assert score_t1078({}) == 60
    assert score_t1078({"prior_failed_attempts": "bad"}) == 60


def test_score_t1059():
    assert score_t1059({"command": "wget"}) == 75
    assert score_t1059({}) == 75


def test_label_for_score():
    assert label_for_score(100) == "Critical"
    assert label_for_score(85) == "Critical"
    assert label_for_score(84) == "High"
    assert label_for_score(60) == "High"
    assert label_for_score(59) == "Medium"
    assert label_for_score(35) == "Medium"
    assert label_for_score(34) == "Low"
    assert label_for_score(0) == "Low"


def test_summarize_event():
    t1110_summary = summarize_event("T1110", "Brute Force", {"failed_attempts": "10", "src_ip": "1.2.3.4", "user": "admin"})
    assert "10 failed SSH login attempts" in t1110_summary
    assert "1.2.3.4" in t1110_summary
    assert "'admin'" in t1110_summary

    t1078_summary = summarize_event("T1078", "Valid Accounts", {"user": "root", "src_ip": "1.2.3.4", "prior_failed_attempts": "8"})
    assert "Successful login as 'root'" in t1078_summary

    t1059_summary = summarize_event("T1059", "Interpreter", {"command": "curl", "arg1": "http://test.com", "host": "web01"})
    assert "Executed 'curl' targeting http://test.com on web01" in t1059_summary


def test_enrich_detections(sample_raw_detections):
    enriched = enrich_detections(sample_raw_detections)
    assert len(enriched) == 3

    # Check sorting: scores should be in descending order (T1078: 95, T1110: 92, T1059: 75)
    scores = [a["score"] for a in enriched]
    assert scores == sorted(scores, reverse=True)

    top_alert = enriched[0]
    assert top_alert["technique_id"] == "T1078"
    assert top_alert["score"] == 95
    assert top_alert["severity"] == "Critical"
