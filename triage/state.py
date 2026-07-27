"""
state.py
Phase 5 - SOC Dashboard Python Triage Layer

Provides persistent alert state tracking and deduplication across triage runs.

Deduplication hashing design decision:
We explicitly use '_time' (the raw event timestamp from Splunk) rather than
'_indextime' (Splunk ingestion timestamp) when computing event hashes.
'_time' is intrinsic to the observed security event on the target system,
ensuring consistent fingerprinting regardless of index re-processing or log
re-ingestion.
"""

import hashlib
import json
import logging
import os
from typing import Any

logger = logging.getLogger("soc_triage.state")


def compute_alert_hash(technique_id: str, raw_event: dict[str, Any]) -> str:
    """
    Computes a deterministic MD5 hash for a raw event to uniquely identify it.

    Uses technique_id and event fields including '_time' (event time) rather
    than '_indextime' to ensure repeatable deduplication.
    """
    # Event timestamp - fallback to empty string if missing
    event_time = str(raw_event.get("_time", ""))
    host = str(raw_event.get("host", ""))
    src_ip = str(raw_event.get("src_ip", ""))
    user = str(raw_event.get("user", ""))
    command = str(raw_event.get("command", ""))
    arg1 = str(raw_event.get("arg1", ""))
    failed_attempts = str(raw_event.get("failed_attempts", ""))

    payload = (
        f"{technique_id}:{event_time}:{host}:{src_ip}:{user}:"
        f"{command}:{arg1}:{failed_attempts}"
    )
    return hashlib.md5(payload.encode("utf-8")).hexdigest()


class AlertStateManager:
    """
    Manages persistent state of seen alert hashes to prevent duplicate reporting
    in repeated or scheduled (--watch) runs.
    """

    def __init__(self, state_file: str = "state.json"):
        self.state_file = state_file
        self.seen_hashes: set[str] = set()
        self.load()

    def load(self) -> None:
        """Loads seen alert hashes from the JSON state file if it exists."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.seen_hashes = set(data.get("seen_hashes", []))
                logger.debug("Loaded %d seen alert hashes from %s", len(self.seen_hashes), self.state_file)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Could not read state file %s: %e. Starting with empty state.", self.state_file, e)
                self.seen_hashes = set()
        else:
            self.seen_hashes = set()

    def save(self) -> None:
        """Persists seen alert hashes to the JSON state file."""
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump({"seen_hashes": sorted(self.seen_hashes)}, f, indent=2)
            logger.debug("Saved %d seen alert hashes to %s", len(self.seen_hashes), self.state_file)
        except OSError as e:
            logger.error("Failed to save state file %s: %s", self.state_file, e)

    def is_seen(self, alert_hash: str) -> bool:
        """Checks whether an alert hash has been previously recorded."""
        return alert_hash in self.seen_hashes

    def mark_seen(self, alert_hash: str) -> None:
        """Marks an alert hash as seen."""
        self.seen_hashes.add(alert_hash)

    def reset(self) -> None:
        """Clears all seen alert hashes and removes the state file if present."""
        self.seen_hashes.clear()
        if os.path.exists(self.state_file):
            try:
                os.remove(self.state_file)
                logger.info("Reset alert state file %s", self.state_file)
            except OSError as e:
                logger.error("Failed to remove state file %s: %s", self.state_file, e)

    def filter_new_alerts(self, raw_results: dict[str, Any]) -> dict[str, Any]:
        """
        Takes raw results from fetch_all_detections() and returns a new dict
        containing only previously unseen events, updating state with newly seen events.
        """
        filtered_results: dict[str, Any] = {}
        new_count = 0
        skipped_count = 0

        for technique_id, data in raw_results.items():
            name = data.get("name", technique_id)
            events = data.get("events", [])
            new_events = []

            for ev in events:
                h = compute_alert_hash(technique_id, ev)
                if not self.is_seen(h):
                    self.mark_seen(h)
                    new_events.append(ev)
                    new_count += 1
                else:
                    skipped_count += 1

            filtered_results[technique_id] = {
                "name": name,
                "events": new_events,
            }
            if "error" in data:
                filtered_results[technique_id]["error"] = data["error"]

        if new_count > 0:
            self.save()

        logger.info("Deduplication filter: %d new event(s), %d duplicate event(s) skipped", new_count, skipped_count)
        return filtered_results
