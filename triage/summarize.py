"""
summarize.py
Phase 5 - SOC Dashboard Python Triage Layer

Generates a plain-English executive summary from the enriched alert list.

This engine is rule-based and auditable. It correlates alerts sharing the same
victim host into a cohesive attack narrative (e.g. brute force -> successful login
-> post-exploitation command execution), presenting a multi-stage incident story.
"""

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger("soc_triage.summarize")


def _group_by_host(alerts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """
    Groups alerts by the victim host they occurred on.

    Host is used as the correlation key because it is present across all technique
    queries, allowing login attempts and subsequent shell commands to be joined.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        raw = alert.get("raw_event", {})
        host_key = raw.get("host", "unknown-host")
        grouped[host_key].append(alert)
    return grouped


def _attacker_ip_for_group(group: list[dict[str, Any]]) -> str:
    """Extracts the attacker's source IP from the first event in the group containing one."""
    for alert in group:
        raw = alert.get("raw_event", {})
        src_ip = raw.get("src_ip")
        if src_ip:
            return str(src_ip)
    return "an unidentified source"


def _narrative_for_group(host: str, group: list[dict[str, Any]]) -> str:
    """
    Builds a one-paragraph narrative for a group of alerts sharing a victim host.

    Orders narrative events by attack lifecycle (T1110 brute force -> T1078 valid
    accounts -> T1059 command execution) rather than raw severity score.
    """
    by_technique: dict[str, dict[str, Any]] = {
        alert["technique_id"]: alert for alert in group if "technique_id" in alert
    }
    chain_order = ["T1110", "T1078", "T1059"]
    present = [t for t in chain_order if t in by_technique]

    if not present:
        return ""

    attacker_ip = _attacker_ip_for_group(group)
    parts: list[str] = []
    top_score = max((alert.get("score", 0) for alert in group), default=0)

    if "T1110" in present:
        ev = by_technique["T1110"].get("raw_event", {})
        attempts = ev.get("failed_attempts", "?")
        parts.append(
            f"{attempts} failed SSH login attempts were observed from {attacker_ip} against {host}"
        )

    if "T1078" in present:
        ev = by_technique["T1078"].get("raw_event", {})
        user = ev.get("user", "unknown")
        prior_failed = ev.get("prior_failed_attempts", "?")
        if parts:
            parts.append(
                f"followed by a successful login as '{user}', indicating the brute force succeeded"
            )
        else:
            parts.append(
                f"A successful login as '{user}' was observed on {host} from {attacker_ip} "
                f"after {prior_failed} failed attempts"
            )

    if "T1059" in present:
        ev = by_technique["T1059"].get("raw_event", {})
        cmd = ev.get("command", "unknown")
        arg1 = ev.get("arg1", "an external target")
        command_phrase = (
            f"execution of '{cmd}' targeting {arg1} - consistent with post-exploitation payload retrieval"
        )
        if parts:
            parts.append(f"and was followed by {command_phrase}")
        else:
            parts.append(f"{command_phrase.capitalize()} was observed on {host}")

    narrative = ", ".join(parts) + "."
    narrative = narrative[0].upper() + narrative[1:]

    if len(present) >= 2 and top_score >= 85:
        narrative += (
            f" This sequence indicates a likely successful compromise of {host} originating "
            f"from {attacker_ip}, and should be treated as a priority incident."
        )

    return narrative


def generate_executive_summary(alerts: list[dict[str, Any]]) -> str:
    """
    Produces executive summary text: high-level metrics headline followed by
    narrative paragraphs grouped per victim host.
    """
    if not alerts:
        return "No alerts were triggered in this run. No action needed."

    critical = sum(1 for a in alerts if a.get("severity") == "Critical")
    high = sum(1 for a in alerts if a.get("severity") == "High")
    unique_techniques = len({a.get("technique_id") for a in alerts if "technique_id" in a})

    headline = (
        f"{len(alerts)} alert(s) triggered across {unique_techniques} MITRE ATT&CK technique(s). "
    )
    if critical:
        headline += f"{critical} alert(s) rated Critical severity. "
    if high:
        headline += f"{high} alert(s) rated High severity. "

    groups = _group_by_host(alerts)
    narratives: list[str] = []
    for host, group in groups.items():
        text = _narrative_for_group(host, group)
        if text:
            narratives.append(text)

    if not narratives:
        return headline.strip()

    return headline.strip() + "\n\n" + "\n\n".join(narratives)
