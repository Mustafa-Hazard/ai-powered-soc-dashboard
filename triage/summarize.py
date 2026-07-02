"""
summarize.py
Phase 5 - SOC Dashboard Python Triage Layer

Generates a plain-English executive summary from the enriched alert list.

This is intentionally rule-based rather than an LLM call - it's fully
deterministic and auditable, and correlates alerts that share a victim host
into a single attack narrative (e.g. brute force -> successful login ->
post-exploitation command execution), which is what an analyst actually
wants to read first.
"""

from typing import Any
from collections import defaultdict


def _group_by_host(alerts: list[dict[str, Any]]) -> dict[str, list[dict]]:
    """
    Groups alerts by the victim host they occurred on. Host is used as the
    correlation key (rather than src_ip) because it's the one field every
    technique's query reliably tags - src_ip identifies the attacker, which
    is only present on login-related events, not on-host execution events.
    Using host means a brute force, the login it led to, and any commands
    run afterward all correlate into a single narrative.
    """
    grouped = defaultdict(list)
    for alert in alerts:
        raw = alert["raw_event"]
        key = raw.get("host", "unknown")
        grouped[key].append(alert)
    return grouped


def _attacker_ip_for_group(group: list[dict[str, Any]]) -> str:
    """Pulls the attacker's src_ip from whichever event in the group has one."""
    for alert in group:
        src_ip = alert["raw_event"].get("src_ip")
        if src_ip:
            return src_ip
    return "an unidentified source"


def _narrative_for_group(host: str, group: list[dict[str, Any]]) -> str:
    """
    Builds a one-paragraph narrative for a group of alerts sharing the same
    victim host, ordered by the logical attack chain (brute force -> valid
    account -> execution) rather than by score.
    """
    by_technique = {alert["technique_id"]: alert for alert in group}
    chain_order = ["T1110", "T1078", "T1059"]
    present = [t for t in chain_order if t in by_technique]

    if not present:
        return ""

    attacker_ip = _attacker_ip_for_group(group)
    parts = []
    top_score = max(alert["score"] for alert in group)

    if "T1110" in present:
        ev = by_technique["T1110"]["raw_event"]
        parts.append(
            f"{ev.get('failed_attempts', '?')} failed SSH login attempts "
            f"were observed from {attacker_ip} against {host}"
        )

    if "T1078" in present:
        ev = by_technique["T1078"]["raw_event"]
        if parts:
            parts.append(
                f"followed by a successful login as '{ev.get('user', 'unknown')}', "
                f"indicating the brute force succeeded"
            )
        else:
            parts.append(
                f"A successful login as '{ev.get('user', 'unknown')}' was observed "
                f"on {host} from {attacker_ip} after "
                f"{ev.get('prior_failed_attempts', '?')} failed attempts"
            )

    if "T1059" in present:
        ev = by_technique["T1059"]["raw_event"]
        command_phrase = (
            f"execution of '{ev.get('command', 'unknown')}' targeting "
            f"{ev.get('arg1', 'an external target')} - consistent with "
            f"post-exploitation payload retrieval"
        )
        if parts:
            parts.append(f"and was followed by {command_phrase}")
        else:
            parts.append(f"{command_phrase.capitalize()} was observed on {host}")

    narrative = ", ".join(parts) + "."
    narrative = narrative[0].upper() + narrative[1:]

    if len(present) >= 2 and top_score >= 85:
        narrative += (
            f" This sequence indicates a likely successful compromise of {host} "
            f"originating from {attacker_ip}, and should be treated as a priority incident."
        )

    return narrative


def generate_executive_summary(alerts: list[dict[str, Any]]) -> str:
    """
    Produces the full executive summary text: an overall headline plus one
    narrative paragraph per correlated host group.
    """
    if not alerts:
        return "No alerts were triggered in this run. No action needed."

    critical = sum(1 for a in alerts if a["severity"] == "Critical")
    high = sum(1 for a in alerts if a["severity"] == "High")

    headline = (
        f"{len(alerts)} alert(s) triggered across "
        f"{len({a['technique_id'] for a in alerts})} MITRE ATT&CK technique(s). "
    )
    if critical:
        headline += f"{critical} alert(s) rated Critical severity. "
    if high:
        headline += f"{high} alert(s) rated High severity. "

    groups = _group_by_host(alerts)
    narratives = []
    for host, group in groups.items():
        text = _narrative_for_group(host, group)
        if text:
            narratives.append(text)

    if not narratives:
        return headline.strip()

    return headline.strip() + "\n\n" + "\n\n".join(narratives)
