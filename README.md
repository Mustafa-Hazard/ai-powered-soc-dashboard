# AI-Powered SOC Dashboard

A hands-on SIEM + threat detection lab connecting GRC/compliance knowledge with practical
security engineering. Built to demonstrate real Tier-1 SOC analyst skills, mapped to
MITRE ATT&CK, with a Python automation/triage layer.

## Status: 🚧 In Progress

## Why This Project

Most portfolio projects either show compliance knowledge (ISO 27001, NIST, PDPL) *or*
software engineering skills, rarely both. This project ties them together: detections
are mapped not just to MITRE ATT&CK techniques, but also back to the compliance
requirements they support (e.g. "this detection supports ISO 27001 A.8.16 logging
requirements").

## Architecture

```
Log Sources (EC2 victim server)
        │
        ▼
Universal Forwarder
        │
        ▼
Splunk (local VM)  ──── Detection Rules (MITRE-mapped)
        │
        ▼
Python Triage Layer ──── Enrich → Score → Summarize (LLM)
```

**Layer 1 — Log Sources:** AWS EC2 instance (Ubuntu) generating real SSH/auth logs.

**Layer 2 — SIEM:** Splunk, running locally in a VirtualBox VM, collecting logs via
Universal Forwarder from the EC2 instance.

**Layer 3 — Detection Rules:** Correlation searches inside Splunk, each explicitly
mapped to a MITRE ATT&CK technique ID.

**Layer 4 — Python Automation:** Pulls alerts via Splunk REST API, enriches
(threat intel lookups, false-positive filtering), scores severity, and optionally
summarizes in plain English via an LLM call.

## MITRE ATT&CK Techniques Covered

| ID | Technique | Category |
|---|---|---|
| T1110 | Brute Force | Credential Access |
| T1078 | Valid Accounts (suspicious login patterns) | Defense Evasion / Persistence |
| T1059 | Command and Scripting Interpreter | Execution |

## Build Log

Detailed, step-by-step documentation of each phase lives in [`/docs`](./docs):

- [Phase 0 — AWS Account Setup](./docs/phase-0-aws-setup.md)
- [Phase 1 — Environment Setup](./docs/phase-1-environment.md)

## Tech Stack

- **Cloud:** AWS (EC2, IAM)
- **SIEM:** Splunk
- **Automation:** Python
- **Simulated attacks:** Hydra, scripted patterns
- **Version control:** Git/GitHub

## Compliance Mapping

A differentiator of this project: select detections are tied back to real compliance
controls (ISO 27001, NIST) to demonstrate the GRC ↔ technical security bridge.

## Author

**Mustafa Muhammad Iqbal**
