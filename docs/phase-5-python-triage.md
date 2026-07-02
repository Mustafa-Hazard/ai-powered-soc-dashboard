# Phase 5 — Python Triage Layer

## Goal

Automate what a Tier-1 SOC analyst does manually: pull triggered detections, assess
their severity, connect related alerts into a single incident story, and produce a
ranked report — without needing to log into the Splunk UI at all.

## Architecture

```
fetch_alerts.py  ──►  enrich.py  ──►  summarize.py  ──►  main.py (report)
  (Splunk REST API)    (scoring)      (narrative)         (orchestrator)
```

Each stage is a separate module rather than one script, so the logic stays testable
and each piece has a single responsibility:

- **`fetch_alerts.py`** — authenticates to Splunk's REST API and runs each of the
  three MITRE-mapped detection queries (T1110, T1078, T1059), returning raw matching
  events per technique
- **`enrich.py`** — scores every event 0–100 using transparent, technique-specific
  rules (not a black-box model) and assigns a severity label (Low/Medium/High/Critical)
- **`summarize.py`** — correlates alerts that share a victim host into a single
  attack narrative, ordered by logical attack chain (brute force → valid account →
  execution), rather than presenting three disconnected events
- **`main.py`** — orchestrates all three stages and prints the final report; also
  supports `--watch` mode for continuous monitoring

## Connecting to Splunk's REST API

Splunk's management API runs on port **8089** (separate from the web UI's 8000).
Authentication uses the same `admin`/password credentials as the web UI, passed as
HTTP basic auth.

Searches are run in **oneshot** mode via `POST /services/search/jobs`, which returns
results synchronously — no need to poll a job ID and wait, which keeps the script
simple for this use case (each search finishes in well under a second against this
lab's data volume).

```python
response = requests.post(
    f"{BASE_URL}/services/search/jobs",
    auth=(SPLUNK_USER, SPLUNK_PASS),
    data={"search": query, "output_mode": "json", "exec_mode": "oneshot"},
    verify=False,  # self-signed cert, lab environment only
)
```

## Scoring Logic

Each technique has its own scoring function, deliberately simple and explainable:

- **T1110 (Brute Force):** `min(100, 20 + attempts * 2)` — scales with failed-attempt
  volume, capped at 100
- **T1078 (Valid Accounts):** `min(100, 60 + prior_failed_attempts)` — starts at a high
  base (a successful login after failures is inherently serious) and climbs further
- **T1059 (Command Execution):** fixed score of 75 — any `wget`/`curl` execution in
  this lab context is inherently suspicious regardless of volume

This rule-based approach was a deliberate choice over an opaque ML model: a SOC
tool's severity reasoning should be auditable by an analyst, not a black box.

## Correlation & Narrative Summarization

The most interesting piece: rather than listing three unrelated alerts, `summarize.py`
groups alerts by the **victim host** (the one field reliably present across all three
detection queries — `src_ip` identifies the attacker but only appears on
login-related events, not on-host execution events) and builds a single narrative
paragraph per group, e.g.:

> 36 failed SSH login attempts were observed from 72.255.58.137 against
> ip-172-31-13-183, followed by a successful login as 'ubuntu', indicating the brute
> force succeeded, and was followed by execution of 'wget' targeting
> http://example.com — consistent with post-exploitation payload retrieval. This
> sequence indicates a likely successful compromise of ip-172-31-13-183 originating
> from 72.255.58.137, and should be treated as a priority incident.

This required adding an explicit `| eval host="..."` to the T1110 and T1078 SPL
queries in `fetch_alerts.py`, since neither originally carried a `host` field in its
output — without a shared key, the correlation logic couldn't tell that all three
alerts were part of the same incident.

## Running the Triage Layer

```bash
cd triage
pip install -r requirements.txt
cp .env.example .env   # fill in real Splunk credentials — never commit .env
python main.py              # run once
python main.py --watch      # run continuously, default every 300s
python main.py --watch --interval 60   # custom interval
```

## Docker

Packaged as a container so the triage layer can run independently of the local Python
environment:

```bash
docker build -t soc-triage .
docker run --env-file .env soc-triage
```

Credentials are injected at runtime via `--env-file`, never baked into the image.
Verified to produce identical output to running natively.

## Continuous Integration

`.github/workflows/ci.yml` runs on every push touching `triage/`:

1. Installs dependencies and lints with `flake8`
2. Builds the Docker image and confirms it succeeds

CI intentionally does **not** attempt to run the triage layer against live Splunk
data — GitHub's runners can't reach the home-network Splunk VM, and that's the
correct scope for this CI: it validates code quality and build integrity, not live
behavior. True integration testing happens locally against the real environment.

## Environment Variables

Credentials were deliberately kept out of source: `fetch_alerts.py` reads
`SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USER`, and `SPLUNK_PASS` from the environment
(loaded via `python-dotenv` from a local `.env` file, gitignored). `.env.example`
documents the required variables without real values.

## Sample Output

```
EXECUTIVE SUMMARY
----------------------------------------------------------------------
3 alert(s) triggered across 3 MITRE ATT&CK technique(s). 2 alert(s) rated
Critical severity. 1 alert(s) rated High severity.

36 failed SSH login attempts were observed from 72.255.58.137 against
ip-172-31-13-183, followed by a successful login as 'ubuntu', indicating
the brute force succeeded, and was followed by execution of 'wget'
targeting http://example.com - consistent with post-exploitation payload
retrieval. This sequence indicates a likely successful compromise of
ip-172-31-13-183 originating from 72.255.58.137, and should be treated
as a priority incident.

----------------------------------------------------------------------
ALERT DETAIL (3 alert(s), ranked by severity)
----------------------------------------------------------------------

[CRIT] [ 95] T1078 - Successful Login Following Failed Attempts
        Successful login as 'ubuntu' from 72.255.58.137 after 35 failed attempts

[CRIT] [ 92] T1110 - SSH Brute Force Detected
        36 failed SSH login attempts from 72.255.58.137 targeting user 'ubuntu'

[HIGH] [ 75] T1059 - Suspicious Download Utility Execution
        Executed 'wget' targeting http://example.com on ip-172-31-13-183

----------------------------------------------------------------------
Summary: 2 Critical, 1 High severity alert(s)
======================================================================
```

## What's Not Included (By Design, For Now)

- **LLM-based summarization:** the README originally scoped this as a stretch goal.
  The current summarizer is fully rule-based and deterministic instead — a
  conscious choice to keep the tool auditable and dependency-free, though a real
  LLM call (e.g. via the Anthropic API) remains a natural future extension if richer
  natural-language variation is wanted.
- **Persistent alert state / deduplication:** each run re-fetches and re-reports all
  matching events; there's no tracking of "already seen" alerts across runs yet.
- **Real-time/streaming ingestion:** `--watch` mode polls on an interval rather than
  subscribing to a live event stream.

## Outcome

A working, containerized, CI-validated Python layer that turns three raw Splunk
detections into a single prioritized, human-readable incident report — closing the
loop described in the project's original architecture diagram (Layer 4: Enrich →
Score → Summarize).
