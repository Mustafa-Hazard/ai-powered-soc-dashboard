# Compliance Mapping

A core differentiator of this project: each detection isn't just a technical rule, it's
tied back to real, verifiable compliance controls from ISO 27001:2022 and NIST SP 800-53
Rev 5. This reflects how detections are actually justified in a GRC-aware SOC — a
detection exists not just because it's technically interesting, but because it evidences
a specific control being operated.

Control references below were verified against current ISO 27001:2022 Annex A and NIST
SP 800-53 Rev 5 documentation as of this write-up.

---

## T1110 — Brute Force

| Framework | Control | Title |
|---|---|---|
| ISO 27001:2022 | **A.8.5** | Secure authentication |
| NIST SP 800-53 Rev 5 | **AC-7** | Unsuccessful Logon Attempts |

**Why it maps:** A.8.5 requires organizations to implement secure authentication
procedures that prevent unauthorized access, and NIST's AC-7 specifically requires
systems to enforce a limit on consecutive invalid logon attempts and take automatic
action when that limit is exceeded. The T1110 detection directly evidences this: it
counts failed SSH attempts per source IP/user and alerts once a defined threshold
(currently 5+) is crossed — the same logic AC-7 asks a system to implement at a
technical level. This detection is the closest 1:1 match of the three: it's
essentially monitoring for violations of exactly what these controls require.

---

## T1078 — Valid Accounts (Suspicious Login Patterns)

| Framework | Control | Title |
|---|---|---|
| ISO 27001:2022 | **A.8.2** | Privileged access rights |
| NIST SP 800-53 Rev 5 | **AC-2** | Account Management |

**Why it maps:** A.8.2 and AC-2 both govern how account access is granted, reviewed,
and monitored — including detecting atypical account usage (NIST AC-2(12), "Account
Monitoring for Atypical Usage," speaks to this directly). The T1078 detection flags a
successful login immediately following a burst of failed attempts from the same
source, which is a textbook example of atypical account usage that these controls
expect an organization to notice.

**Honest scope note:** this detection *monitors for* a suspicious account access
pattern; it does not itself implement account provisioning, privilege review, or
access revocation, which are the fuller requirements of A.8.2/AC-2. It's best
described as supporting the monitoring component of these controls, not satisfying
them end-to-end.

---

## T1059 — Command and Scripting Interpreter

| Framework | Control | Title |
|---|---|---|
| ISO 27001:2022 | **A.8.16** | Monitoring activities |
| NIST SP 800-53 Rev 5 | **AU-6** | Audit Record Review, Analysis, and Reporting |

**Why it maps:** A.8.16 requires networks, systems, and applications to be monitored
for anomalous behavior, with appropriate action taken to evaluate potential security
incidents — and explicitly calls out correlating events across systems as part of
effective monitoring. AU-6 requires organizations to review and analyze audit records
for indications of inappropriate or unusual activity. The T1059 detection, built on
`auditd` execve tracking, does exactly this: it reviews command-execution audit
records and flags specific commands (`wget`, `curl`) associated with post-exploitation
payload retrieval. This is the strongest match for the "monitoring/audit review"
half of both frameworks.

---

## The Detection Chain as a Whole

NIST's own documentation for AC-7 explicitly lists AU-6 as a related control — the
idea being that a failed-logon control is only effective if audit logs are actually
reviewed. This project's three detections mirror that relationship directly: T1110
detects the attempt, T1078 detects the consequence (a successful compromise), and
T1059 detects what happened next (post-exploitation activity) — and the Python triage
layer's executive summary (see [Phase 5 docs](./phase-5-python-triage.md)) explicitly
correlates all three into one incident narrative. In compliance terms, this
demonstrates AC-7 and AU-6 operating together as intended, rather than as isolated
technical rules.

---

## Sources

- ISO/IEC 27001:2022, Annex A (A.8.2, A.8.5, A.8.16)
- NIST SP 800-53 Revision 5, Access Control (AC) and Audit and Accountability (AU)
  families
