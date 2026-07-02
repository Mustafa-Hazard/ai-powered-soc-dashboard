"""
fetch_alerts.py
Phase 5 - SOC Dashboard Python Triage Layer

Connects to the Splunk REST API and runs each MITRE-mapped detection search,
returning the raw matching events for downstream enrichment/scoring.

Requires environment variables (see .env.example):
    SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USER, SPLUNK_PASS
"""

import os
import sys
import requests
import urllib3
from dotenv import load_dotenv

# Load variables from a local .env file if present (does nothing if it's absent,
# e.g. in CI or when real env vars are set another way)
load_dotenv()

# Splunk self-signed cert -> suppress the warning (lab environment only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.environ.get("SPLUNK_HOST")
SPLUNK_PORT = os.environ.get("SPLUNK_PORT", "8089")
SPLUNK_USER = os.environ.get("SPLUNK_USER")
SPLUNK_PASS = os.environ.get("SPLUNK_PASS")

if not all([SPLUNK_HOST, SPLUNK_USER, SPLUNK_PASS]):
    sys.exit(
        "Missing Splunk connection details. Set SPLUNK_HOST, SPLUNK_USER, "
        "and SPLUNK_PASS as environment variables (see .env.example)."
    )

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

# Each detection's search query, tagged with its MITRE technique ID
DETECTIONS = {
    "T1110": {
        "name": "SSH Brute Force Detected",
        "query": '''search index=* host="ip-172-31-13-183" "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\\S+) from (?<src_ip>\\S+)"
| stats count as failed_attempts by src_ip, user
| where failed_attempts >= 5
| eval host="ip-172-31-13-183"''',
    },
    "T1078": {
        "name": "Successful Login Following Failed Attempts",
        "query": '''search index=* host="ip-172-31-13-183" ("Failed password" OR "Accepted password")
| rex field=_raw "Failed password for (invalid user )?(?<user>\\S+) from (?<src_ip>\\S+)"
| rex field=_raw "Accepted password for (?<user>\\S+) from (?<src_ip>\\S+)"
| eval status=if(match(_raw,"Failed password"),"failed","accepted")
| sort 0 src_ip _time
| streamstats count(eval(status="failed")) as prior_failed_attempts by src_ip
| where status="accepted" AND prior_failed_attempts>=5
| eval host="ip-172-31-13-183"
| table _time src_ip user prior_failed_attempts status host''',
    },
    "T1059": {
        "name": "Suspicious Download Utility Execution",
        "query": '''search index=* host="ip-172-31-13-183" sourcetype="linux_audit" type=EXECVE
| rex field=_raw "a0=\\"(?<command>[^\\"]+)\\""
| search command IN ("wget", "curl")
| rex field=_raw "a1=\\"(?<arg1>[^\\"]+)\\""
| table _time host command arg1
| sort -_time''',
    },
}


def run_search(query: str) -> list[dict]:
    """
    Runs a one-shot Splunk search via the REST API and returns results as a
    list of dicts. Uses search mode 'oneshot' so results come back
    synchronously, no polling needed.
    """
    endpoint = f"{BASE_URL}/services/search/jobs"
    params = {
        "search": query,
        "output_mode": "json",
        "exec_mode": "oneshot",
    }

    response = requests.post(
        endpoint,
        auth=(SPLUNK_USER, SPLUNK_PASS),
        data=params,
        verify=False,
        timeout=30,
    )
    response.raise_for_status()

    data = response.json()
    return data.get("results", [])


def fetch_all_detections() -> dict:
    """
    Runs every detection query and returns a dict keyed by MITRE ID,
    each containing the technique name and its matching raw events.
    """
    all_results = {}

    for technique_id, detection in DETECTIONS.items():
        print(f"[*] Running {technique_id} - {detection['name']}...")
        try:
            results = run_search(detection["query"])
            all_results[technique_id] = {
                "name": detection["name"],
                "events": results,
            }
            print(f"    -> {len(results)} matching event(s)")
        except requests.exceptions.RequestException as e:
            print(f"    -> ERROR: {e}")
            all_results[technique_id] = {
                "name": detection["name"],
                "events": [],
                "error": str(e),
            }

    return all_results


if __name__ == "__main__":
    results = fetch_all_detections()

    print("\n" + "=" * 60)
    print("RAW FETCH RESULTS")
    print("=" * 60)
    for technique_id, data in results.items():
        print(f"\n{technique_id} - {data['name']}")
        if not data["events"]:
            print("  No matching events.")
        for event in data["events"]:
            print(f"  {event}")