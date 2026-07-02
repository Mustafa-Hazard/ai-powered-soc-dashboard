# AI-Powered SOC Dashboard

A hands-on SIEM + threat detection lab connecting GRC/compliance knowledge with practical
security engineering. Built to demonstrate real Tier-1 SOC analyst skills, mapped to
MITRE ATT&CK, with a Python automation/triage layer.

## Status: 🚧 In Progress (Phase 4 of 6)

## Why This Project

Most portfolio projects either show compliance knowledge (ISO 27001, NIST, PDPL) *or*
software engineering skills, rarely both. This project ties them together: detections
are mapped not just to MITRE ATT&CK techniques, but also back to the compliance
requirements they support (e.g. "this detection supports ISO 27001 A.8.16 logging
requirements").

## Architecture

```
[EC2 victim-server]  --auth.log-->  [Splunk Universal Forwarder]
        │                                      │
        │                          sends to localhost:9997
        │                                      │
        │                    (this "localhost" is on the EC2 box)
        │
        ▼
[Reverse SSH tunnel: initiated FROM the Splunk VM, target = EC2 public IP]
   ssh -i ~/aws-keys/victim-server-key.pem -R 9997:localhost:9997 ubuntu@<EC2_IP> -N
        │
        ▼
[Splunk Enterprise VM in VirtualBox] -- listens on 9997 --> indexes into Splunk
        │
        ▼
   Detection Rules (MITRE-mapped) ──── Web UI: http://<splunk-vm-ip>:8000
        │
        ▼
   Python Triage Layer ──── Enrich → Score → Summarize (LLM)   [not yet built]
```

**Layer 1 — Log Sources:** AWS EC2 instance (Ubuntu 24.04) generating real SSH/auth logs.

**Layer 2 — SIEM:** Splunk Enterprise, running locally in a VirtualBox VM, collecting logs
via Universal Forwarder from the EC2 instance. Since the home network isn't reachable from
the public internet, log delivery is bridged using a **reverse SSH tunnel** initiated from
the Splunk VM outward to the EC2 host — rather than exposing the home network directly.

**Layer 3 — Detection Rules:** Correlation searches (SPL) inside Splunk, each explicitly
mapped to a MITRE ATT&CK technique ID and saved as a scheduled alert.

**Layer 4 — Python Automation:** Will pull alerts via Splunk REST API, enrich
(threat intel lookups, false-positive filtering), score severity, and optionally
summarize in plain English via an LLM call. *(Planned — not yet implemented.)*

## MITRE ATT&CK Techniques Covered

| ID | Technique | Category | Status |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | ✅ Done |
| T1078 | Valid Accounts (suspicious login patterns) | Defense Evasion / Persistence | ⏳ Planned |
| T1059 | Command and Scripting Interpreter | Execution | ⏳ Planned |

### T1110 — Detection Detail

Simulated a real SSH brute-force attack against the EC2 victim server using Hydra,
captured end-to-end in Splunk, and built a correlation search + alert:

```spl
index=* host="ip-172-31-13-183" "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count as failed_attempts by src_ip, user
| where failed_attempts >= 3
```

Saved as alert **"T1110 - SSH Brute Force Detected"**, scheduled to run every 5 minutes,
triggering on any result. The `>= 3` threshold reflects the volume produced by an
early-stopping test attack; a larger-scale/no-early-stop run is planned to validate a more
realistic production threshold.

## Build Log

Detailed, step-by-step documentation of each phase lives in [`/docs`](./docs):

- [Phase 0 — AWS Account Setup](./docs/phase-0-aws-setup.md)
- [Phase 1 — Environment Setup](./docs/phase-1-environment.md)
- Phase 2 — Splunk Enterprise + Universal Forwarder + Reverse Tunnel *(doc pending)*
- Phase 3 — Hydra Brute-Force Simulation *(doc pending)*
- Phase 4 — Detection Engineering (T1110 complete; T1078/T1059 planned) *(doc pending)*
- Phase 5 — Python Triage Layer *(not started)*
- Phase 6 — Full Documentation & Compliance Mapping *(not started)*

## Tech Stack

- **Cloud:** AWS (EC2, IAM)
- **SIEM:** Splunk Enterprise + Universal Forwarder
- **Automation:** Python (planned — Phase 5)
- **Simulated attacks:** Hydra
- **Version control:** Git/GitHub

## What's Working

- End-to-end log pipeline: EC2 `auth.log` → Universal Forwarder → reverse SSH tunnel →
  Splunk Enterprise, confirmed searchable in the Splunk web UI
- Simulated SSH brute-force attack, fully captured in Splunk
- First MITRE-mapped detection rule (T1110) built, saved, and scheduled as an alert

## What's Next

- Confirm the T1110 alert's 5-minute cron schedule saved correctly
- Run a larger-scale Hydra attack to validate/re-tune the detection threshold
- Build detection rules for T1078 (suspicious valid account logins) and T1059
  (command/scripting execution)
- Build the Python triage layer (Splunk REST API → enrich → score → summarize)
- Backfill Phase 2–4 documentation in `/docs`
- Write up compliance mapping (ISO 27001, NIST) tying detections to specific controls

## Compliance Mapping

A differentiator of this project: select detections are tied back to real compliance
controls (ISO 27001, NIST) to demonstrate the GRC ↔ technical security bridge.
*(Detailed mapping write-up planned for Phase 6.)*

## Author

**Mustafa Muhammad Iqbal**
