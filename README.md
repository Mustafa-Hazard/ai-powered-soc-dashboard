# AI-Powered SOC Dashboard

A hands-on SIEM + threat detection lab connecting GRC/compliance knowledge with practical
security engineering. Built to demonstrate real Tier-1 SOC analyst skills, mapped to
MITRE ATT&CK, with a Python automation/triage layer.

**Portfolio:** [mustafa-cyberhub.vercel.app](https://mustafa-cyberhub.vercel.app/)

## Status: ✅ Core pipeline complete (Phases 0–5) · Phase 6 documentation polish in progress

## Why This Project

Most portfolio projects either show compliance knowledge (ISO 27001, NIST, PDPL) *or*
software engineering skills, rarely both. This project ties them together: detections
are mapped not just to MITRE ATT&CK techniques, but also back to the compliance
requirements they support — see [`docs/compliance-mapping.md`](./docs/compliance-mapping.md).

## Architecture

![Architecture diagram](./docs/assets/architecture-diagram.svg)

```
[EC2 victim-server]  --auth.log / audit.log-->  [Splunk Universal Forwarder]
        │                                              │
        │                                  sends to localhost:9997
        │
        ▼
[Reverse SSH tunnel: initiated FROM the Splunk VM, target = EC2 public IP]
        │
        ▼
[Splunk Enterprise VM in VirtualBox] -- listens on 9997 --> indexes into Splunk
        │
        ▼
   Detection Rules (MITRE-mapped, scheduled alerts)
        │
        ▼
   Python Triage Layer ──── Fetch (REST API) → Enrich/Score → Summarize → Report
        │
        ▼
   Dockerized, CI-linted, runs on demand or continuously (--watch)
```

**Layer 1 — Log Sources:** AWS EC2 instance (Ubuntu 24.04) generating real SSH/auth
logs (`auth.log`) and command-execution audit logs (`auditd` → `audit.log`).

**Layer 2 — SIEM:** Splunk Enterprise, running locally in a VirtualBox VM, collecting
logs via Universal Forwarder from the EC2 instance. Since the home network isn't
reachable from the public internet, log delivery is bridged using a **reverse SSH
tunnel** initiated from the Splunk VM outward to the EC2 host.

**Layer 3 — Detection Rules:** Correlation searches (SPL) inside Splunk, each mapped to
a MITRE ATT&CK technique ID and saved as a scheduled alert.

**Layer 4 — Python Automation:** Pulls alerts via the Splunk REST API, scores severity
with transparent rule-based logic, and generates a plain-English executive summary that
correlates related alerts (e.g. brute force → successful login → payload download) into
a single incident narrative. Runs on demand or continuously via `--watch`, and ships as
a Docker image, validated by CI on every push.

## MITRE ATT&CK Techniques Covered

| ID | Technique | Category | Status |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | ✅ Done |
| T1078 | Valid Accounts (suspicious login patterns) | Defense Evasion / Persistence | ✅ Done |
| T1059 | Command and Scripting Interpreter | Execution | ✅ Done |

Each technique's SPL query and detection logic is documented in
[`docs/phase-4-detection-engineering.md`](./docs/phase-4-detection-engineering.md).

## Compliance Mapping

Each detection is explicitly tied to real controls in ISO 27001:2022 and NIST SP 800-53
Rev 5 — not just technically justified, but compliance-justified. Full mapping and
rationale (including honest scope notes on partial control coverage) in
[`docs/compliance-mapping.md`](./docs/compliance-mapping.md).

| Technique | ISO 27001:2022 | NIST 800-53 Rev 5 |
|---|---|---|
| T1110 | A.8.5 Secure authentication | AC-7 Unsuccessful Logon Attempts |
| T1078 | A.8.2 Privileged access rights | AC-2 Account Management |
| T1059 | A.8.16 Monitoring activities | AU-6 Audit Record Review, Analysis, and Reporting |

## Build Log

Detailed, step-by-step documentation of each phase lives in [`/docs`](./docs):

- [Phase 0 — AWS Account Setup](./docs/phase-0-aws-setup.md)
- [Phase 1 — Environment Setup](./docs/phase-1-environment.md)
- [Phase 2 — Splunk Enterprise + Universal Forwarder + Reverse Tunnel](./docs/phase-2-splunk-setup.md)
- [Phase 3 — Hydra Brute-Force Simulation](./docs/phase-3-hydra-simulation.md)
- [Phase 4 — Detection Engineering](./docs/phase-4-detection-engineering.md)
- [Phase 5 — Python Triage Layer](./docs/phase-5-python-triage.md)
- [Compliance Mapping](./docs/compliance-mapping.md)

## Tech Stack

- **Cloud:** AWS (EC2, IAM)
- **SIEM:** Splunk Enterprise + Universal Forwarder
- **Host auditing:** auditd (execve tracking)
- **Automation:** Python (`requests`, `python-dotenv`)
- **Containerization:** Docker
- **CI:** GitHub Actions (lint + Docker build validation)
- **Simulated attacks:** Hydra
- **Version control:** Git/GitHub

## Python Triage Layer

Located in [`/triage`](./triage). Fetches all three detections from Splunk via REST
API, scores each event with transparent, auditable rule-based logic (not a black box),
and produces a ranked triage report with an executive summary that correlates related
alerts into a single incident narrative.

```bash
cd triage
pip install -r requirements.txt
cp .env.example .env   # fill in your Splunk credentials
python main.py              # run once
python main.py --watch      # run continuously (default every 5 min)
```

Or via Docker:

```bash
docker build -t soc-triage .
docker run --env-file .env soc-triage
```

## What's Working

- End-to-end log pipeline: EC2 `auth.log`/`audit.log` → Universal Forwarder → reverse
  SSH tunnel → Splunk Enterprise, confirmed searchable in the Splunk web UI
- Simulated SSH brute-force attack (Hydra) and post-login command execution, both fully
  captured in Splunk
- Three MITRE-mapped detection rules (T1110, T1078, T1059), each saved and scheduled
  as a Splunk alert
- Python triage layer: fetch → enrich/score → correlate → summarize → report, runnable
  on demand, continuously, or in Docker
- CI pipeline linting the triage layer and validating the Docker build on every push
- Detections explicitly mapped to verified ISO 27001:2022 and NIST SP 800-53 Rev 5
  controls

## Known Limitations (By Design — Lab Scope)

This is a home lab, not a production deployment, and intentionally so:

- Credentials are managed via `.env` files, not a secrets manager
- SSH password authentication remains enabled on the victim server for repeatable
  attack simulation, rather than reverted to key-only auth
- No AWS Elastic IP allocated — the EC2 public IP changes on every restart
- Single point of failure throughout (one Splunk VM, no HA, no log retention policy)
- CI validates code quality and Docker build integrity only; it can't reach the local
  Splunk VM to run true integration tests

None of these block the project's goal — demonstrating the full detection engineering
and automation pipeline end-to-end — but they'd be the first things addressed before
any real-world deployment.

## Author

**Mustafa Muhammad Iqbal**
Portfolio: [mustafa-cyberhub.vercel.app](https://mustafa-cyberhub.vercel.app/)
