"""
test_state.py
Unit tests for triage/state.py persistent state tracking and deduplication using _time.
"""

import os

from state import AlertStateManager, compute_alert_hash


def test_compute_alert_hash_uses_event_time():
    event1 = {
        "_time": "2026-07-27T10:00:00Z",
        "_indextime": "1722074400",
        "host": "srv1",
        "src_ip": "1.2.3.4",
        "user": "ubuntu",
    }
    # Same event time, different index time
    event2 = {
        "_time": "2026-07-27T10:00:00Z",
        "_indextime": "1722075500",
        "host": "srv1",
        "src_ip": "1.2.3.4",
        "user": "ubuntu",
    }

    hash1 = compute_alert_hash("T1110", event1)
    hash2 = compute_alert_hash("T1110", event2)

    # Hashes should be identical because hash generation relies on _time (event time), not _indextime
    assert hash1 == hash2

    # Different event time -> different hash
    event3 = dict(event1, _time="2026-07-27T10:05:00Z")
    assert compute_alert_hash("T1110", event3) != hash1


def test_alert_state_manager_lifecycle(tmp_path):
    state_file = str(tmp_path / "test_state.json")
    mgr = AlertStateManager(state_file=state_file)

    assert not mgr.is_seen("hash1")
    mgr.mark_seen("hash1")
    assert mgr.is_seen("hash1")
    mgr.save()

    assert os.path.exists(state_file)

    # Reload from disk
    mgr2 = AlertStateManager(state_file=state_file)
    assert mgr2.is_seen("hash1")
    assert not mgr2.is_seen("hash2")

    # Reset
    mgr2.reset()
    assert not mgr2.is_seen("hash1")
    assert not os.path.exists(state_file)


def test_filter_new_alerts(tmp_path, sample_raw_detections):
    state_file = str(tmp_path / "test_state.json")
    mgr = AlertStateManager(state_file=state_file)

    # First run: all 3 events are new
    filtered1 = mgr.filter_new_alerts(sample_raw_detections)
    total_events1 = sum(len(d["events"]) for d in filtered1.values())
    assert total_events1 == 3

    # Second run with same raw detections: all 3 events are duplicates -> 0 new events
    filtered2 = mgr.filter_new_alerts(sample_raw_detections)
    total_events2 = sum(len(d["events"]) for d in filtered2.values())
    assert total_events2 == 0
