"""
main.py
Phase 5 - SOC Dashboard Python Triage Layer

Entry point: fetches all detections from Splunk, enriches/scores them,
generates an executive summary, and prints a triage report ranked by
severity. Supports continuous watch mode and stateful alert deduplication.

Usage:
    python main.py                     Run once and exit (with deduplication)
    python main.py --no-dedup          Run once, ignoring deduplication state
    python main.py --reset-state       Clear deduplication state file and exit
    python main.py --watch             Run continuously (default every 300s)
    python main.py --watch --interval 60   Run continuously every 60s
    python main.py --debug             Enable verbose debug logging
"""

import argparse
import logging
import sys
import time
from datetime import UTC, datetime
from typing import Any

from config import DEFAULT_STATE_FILE, SplunkConfig, setup_logging
from enrich import enrich_detections
from fetch_alerts import fetch_all_detections
from state import AlertStateManager
from summarize import generate_executive_summary
from web import app, application, handler

__all__ = [
    "app",
    "application",
    "handler",
    "main",
    "print_report",
    "run_once",
    "run_watch",
]

logger = logging.getLogger("soc_triage.main")

SEVERITY_ICON = {
    "Critical": "[CRIT]",
    "High": "[HIGH]",
    "Medium": "[MED] ",
    "Low": "[LOW] ",
}


def print_report(alerts: list[dict[str, Any]]) -> None:
    """Formats and prints the human-readable SOC triage report to stdout."""
    print("\n" + "=" * 70)
    print("SOC TRIAGE REPORT")
    print("=" * 70)

    if not alerts:
        print("\nNo new alerts triggered. All clear.")
        return

    print("\nEXECUTIVE SUMMARY")
    print("-" * 70)
    print(generate_executive_summary(alerts))

    print("\n" + "-" * 70)
    print(f"ALERT DETAIL ({len(alerts)} alert(s), ranked by severity)")
    print("-" * 70 + "\n")

    for alert in alerts:
        icon = SEVERITY_ICON.get(alert.get("severity", ""), "[----]")
        score = alert.get("score", 0)
        tech_id = alert.get("technique_id", "UNKNOWN")
        tech_name = alert.get("technique_name", "Unknown Technique")
        summary = alert.get("summary", "")

        print(f"{icon} [{score:>3}] {tech_id} - {tech_name}")
        print(f"        {summary}")
        print()

    critical_count = sum(1 for a in alerts if a.get("severity") == "Critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "High")
    print("-" * 70)
    print(f"Summary: {critical_count} Critical, {high_count} High severity alert(s)")
    print("=" * 70)


def run_once(
    config: SplunkConfig | None = None,
    state_manager: AlertStateManager | None = None,
    use_dedup: bool = True,
) -> list[dict[str, Any]]:
    """Runs a single pass of the triage pipeline."""
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")
    logger.info("[%s] Fetching detections from Splunk...", timestamp)

    raw_results = fetch_all_detections(config=config)

    if use_dedup and state_manager is not None:
        logger.debug("Applying alert deduplication filter...")
        raw_results = state_manager.filter_new_alerts(raw_results)

    logger.debug("Enriching and scoring events...")
    alerts = enrich_detections(raw_results)

    print_report(alerts)
    return alerts


def run_watch(
    interval: int,
    config: SplunkConfig | None = None,
    state_manager: AlertStateManager | None = None,
    use_dedup: bool = True,
) -> None:
    """Runs the triage pipeline continuously at fixed time intervals."""
    logger.info("Starting watch mode - running every %d second(s). Press Ctrl+C to stop.\n", interval)
    try:
        while True:
            run_once(config=config, state_manager=state_manager, use_dedup=use_dedup)
            logger.info("Sleeping for %d second(s)...", interval)
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Watch mode stopped by user.")


def main(argv: list[str] | None = None) -> None:
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
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable persistent alert state deduplication.",
    )
    parser.add_argument(
        "--reset-state",
        action="store_true",
        help="Clear saved deduplication state and exit.",
    )
    parser.add_argument(
        "--state-file",
        type=str,
        default=DEFAULT_STATE_FILE,
        help=f"Path to JSON alert state file (default: {DEFAULT_STATE_FILE}).",
    )

    args = parser.parse_args(argv)

    setup_logging(debug=args.debug)

    state_manager = AlertStateManager(state_file=args.state_file)

    if args.reset_state:
        state_manager.reset()
        logger.info("State cleared successfully.")
        sys.exit(0)

    config = SplunkConfig.from_env()
    use_dedup = not args.no_dedup

    if args.watch:
        run_watch(
            interval=args.interval,
            config=config,
            state_manager=state_manager,
            use_dedup=use_dedup,
        )
    else:
        run_once(config=config, state_manager=state_manager, use_dedup=use_dedup)


if __name__ == "__main__":
    main()
