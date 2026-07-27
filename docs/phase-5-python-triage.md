# Phase 5 — Python Triage Layer

## Goal

Automate what a Tier-1 SOC analyst does manually: pull triggered detections, assess
their severity, connect related alerts into a single incident story, and produce a
ranked report — without needing to log into the Splunk UI at all.

## Architecture

```
fetch_alerts.py  ──►  enrich.py  ──►  summarize.py  ──►  main.py (report)
  (Splunk REST API)    (scoring)      (narrative)         (orchestrator)
       ▲                                                     │
       │                                                     ▼
   config.py                                             state.py
(SplunkConfig & secrets)                             (alert state & dedup)
```

Each stage is a separate module rather than one script, so the logic stays testable
and each piece has a single responsibility:

- **`config.py`** — centralized configuration management (`SplunkConfig`), credential
  redaction (`SPLUNK_PASS` masked in string representations), scoring constants, and structured logging.
- **`state.py`** — persistent alert state manager (`AlertStateManager`) that deduplicates
  previously reported alerts across runs by computing an MD5 hash of event fields using `_time`
  (event timestamp).
- **`fetch_alerts.py`** — authenticates to Splunk's REST API and runs each of the
  three MITRE-mapped detection queries (T1110, T1078, T1059), returning raw matching
  events per technique. Custom exceptions (`SplunkAPIError`, `SplunkConnectionError`) handle API failures.
- **`enrich.py`** — scores every event 0–100 using transparent, technique-specific
  rules (not a black-box model) and assigns a severity label (Low/Medium/High/Critical).
- **`summarize.py`** — correlates alerts that share a victim host into a single
  attack narrative, ordered by logical attack chain (brute force → valid account →
  execution), rather than presenting three disconnected events.
- **`main.py`** — orchestrates all stages and prints the final report; supports `--watch` mode
  for continuous monitoring, `--debug` for verbose logs, and `--no-dedup`/`--reset-state` for state control.

## Connecting to Splunk's REST API

Splunk's management API runs on port **8089** (separate from the web UI's 8000).
Authentication uses the same `admin`/password credentials as the web UI, passed as
HTTP basic auth.

SSL Certificate Verification defaults to `verify_ssl = True`. For lab setups using
self-signed SSL certificates, `SPLUNK_VERIFY_SSL=false` can be explicitly set in `.env`.

Searches are run in **oneshot** mode via `POST /services/search/jobs`, which returns
results synchronously — no need to poll a job ID and wait, keeping execution fast and predictable.

```python
response = requests.post(
    f"{config.base_url()}/services/search/jobs",
    auth=(config.user, config.password),
    data={"search": query, "output_mode": "json", "exec_mode": "oneshot"},
    verify=config.verify_ssl,
    timeout=config.timeout,
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

## Persistent State & Alert Deduplication

To prevent alert fatigue and duplicate reports during periodic or `--watch` runs, `state.py` maintains a `state.json` cache.
Alert hashes are calculated using `_time` (event occurrence timestamp) rather than `_indextime` (Splunk ingestion time):

```python
def compute_alert_hash(technique_id: str, raw_event: dict) -> str:
    payload = f"{technique_id}:{raw_event.get('_time')}:{raw_event.get('host')}:{raw_event.get('src_ip')}:{raw_event.get('user')}"
    return hashlib.md5(payload.encode("utf-8")).hexdigest()
```

This guarantees idempotent hashing regardless of indexer re-runs or log re-ingestion.

## Running the Triage Layer

```bash
cd triage
pip install -r requirements.txt
cp .env.example .env   # fill in real Splunk credentials — never commit .env

python main.py              # run once with deduplication
python main.py --no-dedup    # ignore deduplication state
python main.py --reset-state # clear deduplication state cache
python main.py --watch      # run continuously, default every 300s
python main.py --watch --interval 60   # custom interval
python main.py --debug      # enable verbose debug logging
```

## Unit Testing

A comprehensive test suite in `tests/` covers all modules using `pytest`:

```bash
pytest tests/ -v
mypy triage
ruff check triage tests
```

- **`test_enrich.py`**: Tests scoring calculations, threshold caps, severity labels, and edge cases.
- **`test_summarize.py`**: Tests host grouping, single and multi-stage attack narratives, and multi-host scenarios.
- **`test_fetch_alerts.py`**: Mocks Splunk API calls for HTTP errors, timeouts, connection failures, and invalid JSON responses.
- **`test_state.py`**: Tests `_time` timestamp hashing, persistent state load/save/reset operations, and deduplication filtering.
- **`test_main.py`**: Tests CLI argument parsing (`--watch`, `--reset-state`, `--no-dedup`, `--debug`) and orchestration.

## Docker

Packaged as an unprivileged, multi-stage Docker container:

```bash
docker build -t soc-triage triage/
docker run --env-file triage/.env soc-triage
```

Credentials are injected at runtime via `--env-file`, never baked into the image. The image runs as non-root user `appuser` (uid 10001).

## Continuous Integration

`.github/workflows/ci.yml` runs on every push/PR:

1. Lints code formatting with `ruff`
2. Validates type hints with `mypy`
3. Audits dependencies for security vulnerabilities with `pip-audit`
4. Executes unit test suite with `pytest`
5. Validates multi-stage Docker container build

CI intentionally does **not** attempt to run the triage layer against live Splunk
data — GitHub's runners can't reach the home-network Splunk VM, and that's the
correct scope for this CI: it validates code quality, type safety, test coverage, and build integrity.

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

## Outcome

A robust, type-safe, containerized, stateful, and thoroughly tested Python layer that turns raw Splunk detections into a prioritized, human-readable incident report.
