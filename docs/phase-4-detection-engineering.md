# Phase 4 — Detection Engineering

## Goal

Build MITRE ATT&CK-mapped detection rules in Splunk against the log data captured in
Phases 2–3, starting with the SSH brute-force attack from Phase 3.

## Status

| ID | Technique | Status |
|---|---|---|
| T1110 | Brute Force | ✅ Complete |
| T1078 | Valid Accounts (suspicious login patterns) | ⏳ Planned |
| T1059 | Command and Scripting Interpreter | ⏳ Planned |

---

## T1110 — SSH Brute Force Detection

### Detection Logic

```spl
index=* host="ip-172-31-13-183" "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count as failed_attempts by src_ip, user
| where failed_attempts >= 3
```

**How it works:**
1. Filters `auth.log` events to failed SSH login attempts on the victim host
2. Extracts the attempted username and source IP via regex, handling both valid and
   invalid usernames (`invalid user` prefix is optional in the log line)
3. Aggregates failed attempts per source IP / username pair
4. Flags any pair with 3 or more failed attempts

### Threshold Rationale

The `>= 3` threshold was set based on the actual attack data available: the Phase 3
Hydra run stopped after finding the correct password, generating only 3 failed
attempts before success. A real-world brute-force attempt is typically far noisier
(tens to thousands of attempts). This threshold is intentionally conservative for now
and flagged for re-tuning once a larger-scale attack run is available.

### Saved Alert

- **Name:** T1110 - SSH Brute Force Detected
- **Description:** Detects 3+ failed SSH login attempts from the same source IP —
  MITRE T1110
- **Trigger condition:** Number of results > 0
- **Action:** Add to Triggered Alerts
- **Schedule:** Cron `*/5 * * * *` (every 5 minutes) — changed from the default hourly
  schedule to support faster detection turnaround
- **Verification status:** Schedule change needs to be reconfirmed at the start of the
  next session (edit was in progress when the prior session ended)

### Result

Successfully triggered against the Phase 3 Hydra attack data, correctly identifying
the source IP (`72.255.58.137`) and targeted username (`ubuntu`) with 3 failed
attempts before the successful login.

---

## T1078 — Valid Accounts (Planned)

Not yet built. Intent: detect suspicious *successful* logins that don't fit an
established pattern — e.g. logins from previously unseen source IPs, logins outside
expected time windows, or successful logins immediately following a string of failed
attempts from the same source (tying back into the T1110 data).

## T1059 — Command and Scripting Interpreter (Planned)

Not yet built. Intent: detect suspicious command execution patterns post-login (e.g.
via shell history or auditd logs, which would need to be added as an additional log
source beyond `auth.log`).

## Next Steps

1. Confirm the T1110 alert's cron schedule saved correctly
2. Run a larger-scale Hydra attack (bigger wordlist / no early stop) to get realistic
   failed-attempt volume, then re-tune the `>= 3` threshold if warranted
3. Design and build T1078 and T1059 detections
4. Carry all three techniques forward into the Phase 5 Python triage layer
