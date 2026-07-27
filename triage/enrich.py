"""
enrich.py
Phase 5 - SOC Dashboard Python Triage Layer

Takes raw detection events (from fetch_alerts.py) and enriches them with:
    - a severity score (0-100)
    - a severity label (Low / Medium / High / Critical)
    - a human-readable summary line

Scoring logic is intentionally simple and rule-based rather than a black box:
each technique has its own transparent scoring function so the reasoning is
auditable, which is essential for a SOC triage engine.
"""

import logging
from collections.abc import Callable
from typing import Any

from config import (
    SCORE_CRITICAL_THRESHOLD,
    SCORE_HIGH_THRESHOLD,
    SCORE_MEDIUM_THRESHOLD,
    T1059_FIXED_SCORE,
    T1078_BASE_SCORE,
    T1078_MAX_SCORE,
    T1078_PER_PRIOR_FAIL_SCORE,
    T1110_BASE_SCORE,
    T1110_MAX_SCORE,
    T1110_PER_ATTEMPT_SCORE,
)

logger = logging.getLogger("soc_triage.enrich")


def score_t1110(event: dict[str, Any]) -> int:
    """
    Brute force severity scales with failed attempt volume.

    A handful of failures is low-severity noise; dozens+ is a real attack.
    Formula: min(100, 20 + (failed_attempts * 2))
    """
    try:
        attempts = int(event.get("failed_attempts", 0))
    except (TypeError, ValueError):
        attempts = 0

    attempts = max(attempts, 0)

    score = min(T1110_MAX_SCORE, T1110_BASE_SCORE + (attempts * T1110_PER_ATTEMPT_SCORE))
    return score


def score_t1078(event: dict[str, Any]) -> int:
    """
    A successful login after failed attempts indicates a likely account compromise.

    Starts with a high base severity (60) and scales up with prior failure volume.
    Formula: min(100, 60 + prior_failed_attempts)
    """
    try:
        prior_failed = int(event.get("prior_failed_attempts", 0))
    except (TypeError, ValueError):
        prior_failed = 0

    prior_failed = max(prior_failed, 0)

    score = min(T1078_MAX_SCORE, T1078_BASE_SCORE + (prior_failed * T1078_PER_PRIOR_FAIL_SCORE))
    return score


def score_t1059(event: dict[str, Any]) -> int:
    """
    Command execution (wget/curl) post-login.

    In this lab context, command utility downloads post-compromise are inherently
    suspicious regardless of frequency, yielding a fixed high score (75).
    """
    return T1059_FIXED_SCORE


SCORERS: dict[str, Callable[[dict[str, Any]], int]] = {
    "T1110": score_t1110,
    "T1078": score_t1078,
    "T1059": score_t1059,
}


def label_for_score(score: int) -> str:
    """Maps a numeric score (0-100) to a human severity label."""
    if score >= SCORE_CRITICAL_THRESHOLD:
        return "Critical"
    if score >= SCORE_HIGH_THRESHOLD:
        return "High"
    if score >= SCORE_MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def summarize_event(technique_id: str, technique_name: str, event: dict[str, Any]) -> str:
    """
    Produces a one-line human-readable summary for an event, tailored per
    technique so the output reads like an analyst description.
    """
    if technique_id == "T1110":
        attempts = event.get("failed_attempts", "?")
        src_ip = event.get("src_ip", "unknown IP")
        user = event.get("user", "unknown")
        return f"{attempts} failed SSH login attempts from {src_ip} targeting user '{user}'"

    if technique_id == "T1078":
        user = event.get("user", "unknown")
        src_ip = event.get("src_ip", "unknown IP")
        prior_failed = event.get("prior_failed_attempts", "?")
        return f"Successful login as '{user}' from {src_ip} after {prior_failed} failed attempts"

    if technique_id == "T1059":
        command = event.get("command", "unknown")
        arg1 = event.get("arg1", "unknown target")
        host = event.get("host", "host")
        return f"Executed '{command}' targeting {arg1} on {host}"

    return f"{technique_name}: {event}"


def enrich_detections(raw_results: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Takes the dictionary returned by fetch_alerts.fetch_all_detections() and
    flattens it into a single sorted, scored list of triage-ready alerts.

    Returns alerts ordered by score descending (highest severity first).
    """
    enriched: list[dict[str, Any]] = []

    for technique_id, data in raw_results.items():
        technique_name = data.get("name", technique_id)
        scorer = SCORERS.get(technique_id)

        events = data.get("events", [])
        for event in events:
            score = scorer(event) if scorer else 0
            enriched.append({
                "technique_id": technique_id,
                "technique_name": technique_name,
                "score": score,
                "severity": label_for_score(score),
                "summary": summarize_event(technique_id, technique_name, event),
                "raw_event": event,
            })

    enriched.sort(key=lambda alert: alert["score"], reverse=True)
    logger.debug("Enriched and scored %d alert(s)", len(enriched))
    return enriched
