"""
enrich.py
Phase 5 - SOC Dashboard Python Triage Layer

Takes raw detection events (from fetch_alerts.py) and enriches them with:
    - a severity score (0-100)
    - a severity label (Low / Medium / High / Critical)
    - a human-readable summary line

Scoring logic is intentionally simple and rule-based rather than a black box -
each technique has its own transparent scoring function so the reasoning is
auditable, which matters for a SOC tool.
"""

from typing import Any


def score_t1110(event: dict[str, Any]) -> int:
    """
    Brute force severity scales with failed attempt volume.
    A handful of failures is low-severity noise; dozens+ is a real attack.
    """
    try:
        attempts = int(event.get("failed_attempts", 0))
    except (TypeError, ValueError):
        attempts = 0

    # 5 attempts (our alert threshold) -> ~30, scaling up, capped at 100
    score = min(100, 20 + (attempts * 2))
    return score


def score_t1078(event: dict[str, Any]) -> int:
    """
    A successful login after failed attempts means the attacker likely got in -
    this starts high severity by default and climbs with prior failure count.
    """
    try:
        prior_failed = int(event.get("prior_failed_attempts", 0))
    except (TypeError, ValueError):
        prior_failed = 0

    # Base severity of 60 (a real successful compromise), scaling toward 100
    score = min(100, 60 + prior_failed)
    return score


def score_t1059(event: dict[str, Any]) -> int:
    """
    Any wget/curl execution post-login is inherently suspicious in this lab
    context (no legitimate reason for it in this scenario) - fixed high score.
    """
    return 75


SCORERS = {
    "T1110": score_t1110,
    "T1078": score_t1078,
    "T1059": score_t1059,
}


def label_for_score(score: int) -> str:
    """Maps a numeric score to a human severity label."""
    if score >= 85:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def summarize_event(technique_id: str, technique_name: str, event: dict[str, Any]) -> str:
    """
    Produces a one-line human-readable summary for an event, tailored per
    technique so the output reads like an analyst wrote it, not a data dump.
    """
    if technique_id == "T1110":
        return (
            f"{event.get('failed_attempts', '?')} failed SSH login attempts "
            f"from {event.get('src_ip', 'unknown IP')} targeting user "
            f"'{event.get('user', 'unknown')}'"
        )
    if technique_id == "T1078":
        return (
            f"Successful login as '{event.get('user', 'unknown')}' from "
            f"{event.get('src_ip', 'unknown IP')} after "
            f"{event.get('prior_failed_attempts', '?')} failed attempts"
        )
    if technique_id == "T1059":
        return (
            f"Executed '{event.get('command', 'unknown')}' targeting "
            f"{event.get('arg1', 'unknown target')} on {event.get('host', 'host')}"
        )
    return f"{technique_name}: {event}"


def enrich_detections(raw_results: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Takes the dict returned by fetch_alerts.fetch_all_detections() and
    flattens it into a single sorted, scored list of triage-ready alerts.
    """
    enriched = []

    for technique_id, data in raw_results.items():
        technique_name = data.get("name", technique_id)
        scorer = SCORERS.get(technique_id)

        for event in data.get("events", []):
            score = scorer(event) if scorer else 0
            enriched.append({
                "technique_id": technique_id,
                "technique_name": technique_name,
                "score": score,
                "severity": label_for_score(score),
                "summary": summarize_event(technique_id, technique_name, event),
                "raw_event": event,
            })

    # Highest severity first - this is what an analyst wants to see at the top
    enriched.sort(key=lambda alert: alert["score"], reverse=True)
    return enriched
