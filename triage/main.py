"""
main.py
Phase 5 - SOC Dashboard Python Triage Layer

Entry point: fetches all detections from Splunk, enriches/scores them,
generates an executive summary, and prints a triage report ranked by
severity.

Usage:
    python main.py                  Run once and exit
    python main.py --watch          Run continuously (default every 300s)
    python main.py --watch --interval 60   Run continuously every 60s
"""

import argparse
import time
from datetime import datetime

from fetch_alerts import fetch_all_detections
from enrich import enrich_detections
from summarize import generate_executive_summary

SEVERITY_ICON = {
    "Critical": "[CRIT]",
    "High": "[HIGH]",
    "Medium": "[MED] ",
    "Low": "[LOW] ",
}


def print_report(alerts: list[dict]) -> None:
    print("\n" + "=" * 70)
    print("SOC TRIAGE REPORT")
    print("=" * 70)

    if not alerts:
        print("\nNo alerts triggered. All clear.")
        return

    print("\nEXECUTIVE SUMMARY")
    print("-" * 70)
    print(generate_executive_summary(alerts))

    print("\n" + "-" * 70)
    print(f"ALERT DETAIL ({len(alerts)} alert(s), ranked by severity)")
    print("-" * 70 + "\n")

    for alert in alerts:
        icon = SEVERITY_ICON.get(alert["severity"], "[----]")
        print(
            f"{icon} [{alert['score']:>3}] {alert['technique_id']} - "
            f"{alert['technique_name']}"
        )
        print(f"        {alert['summary']}")
        print()

    critical_count = sum(1 for a in alerts if a["severity"] == "Critical")
    high_count = sum(1 for a in alerts if a["severity"] == "High")
    print("-" * 70)
    print(f"Summary: {critical_count} Critical, {high_count} High severity alert(s)")
    print("=" * 70)


def run_once() -> None:
    print(f"[{datetime.now().isoformat(timespec='seconds')}] Fetching detections from Splunk...\n")
    raw_results = fetch_all_detections()

    print("\nEnriching and scoring events...")
    alerts = enrich_detections(raw_results)

    print_report(alerts)


def run_watch(interval: int) -> None:
    print(f"Starting watch mode - running every {interval} second(s). Press Ctrl+C to stop.\n")
    try:
        while True:
            run_once()
            print(f"\nSleeping for {interval} second(s)...\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC Dashboard Python Triage Layer")
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Run continuously on a schedule instead of once.",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Seconds between runs in --watch mode (default: 300).",
    )
    args = parser.parse_args()

    if args.watch:
        run_watch(args.interval)
    else:
        run_once()


if __name__ == "__main__":
    main()