"""
fetch_alerts.py
Phase 5 - SOC Dashboard Python Triage Layer

Connects to the Splunk REST API and runs each MITRE-mapped detection search,
returning the raw matching events for downstream enrichment/scoring.

Configuration is loaded via config.py (environment variables or SplunkConfig object).
"""

import logging
from typing import Any

import requests
import urllib3
from config import DETECTIONS, SplunkConfig

# Suppress urllib3 SSL warnings when verify_ssl is explicitly False (lab use)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("soc_triage.fetch")


class SplunkAPIError(Exception):
    """Raised when Splunk API returns an HTTP error or malformed payload."""


class SplunkConnectionError(Exception):
    """Raised when Splunk API is unreachable due to network error or timeout."""


def run_search(query: str, config: SplunkConfig | None = None) -> list[dict[str, Any]]:
    """
    Runs a one-shot Splunk search query via the REST API synchronously.

    Args:
        query: The SPL search query to execute.
        config: SplunkConfig instance (defaults to SplunkConfig.from_env()).

    Returns:
        List of matching event dictionary objects.

    Raises:
        SplunkConnectionError: On network connection errors or timeouts.
        SplunkAPIError: On HTTP error status codes or invalid JSON responses.
    """
    if config is None:
        config = SplunkConfig.from_env()

    if not config.host:
        raise SplunkAPIError(
            "Missing Splunk host. Set SPLUNK_HOST as an environment variable (see .env.example)."
        )

    endpoint = f"{config.base_url()}/services/search/jobs"
    params = {
        "search": query,
        "output_mode": "json",
        "exec_mode": "oneshot",
    }

    logger.debug("Executing search query against %s (verify_ssl=%s)", endpoint, config.verify_ssl)

    try:
        response = requests.post(
            endpoint,
            auth=(config.user, config.password),
            data=params,
            verify=config.verify_ssl,
            timeout=config.timeout,
        )
        response.raise_for_status()
    except requests.exceptions.Timeout as e:
        logger.error("Splunk API request timed out after %d seconds: %s", config.timeout, e)
        raise SplunkConnectionError(f"Connection to Splunk at {config.host} timed out.") from e
    except requests.exceptions.ConnectionError as e:
        logger.error("Failed to connect to Splunk host %s: %s", config.host, e)
        raise SplunkConnectionError(f"Could not connect to Splunk at {config.host}:{config.port}.") from e
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else "Unknown"
        logger.error("Splunk API returned HTTP %s: %s", status_code, e)
        raise SplunkAPIError(f"Splunk API HTTP Error {status_code}: {e}") from e
    except requests.exceptions.RequestException as e:
        logger.error("Unexpected Splunk API request failure: %s", e)
        raise SplunkAPIError(f"Splunk request failed: {e}") from e

    try:
        data = response.json()
    except ValueError as e:
        logger.error("Failed to parse JSON response from Splunk API: %s", e)
        raise SplunkAPIError("Invalid JSON response received from Splunk API.") from e

    if not isinstance(data, dict):
        raise SplunkAPIError("Unexpected JSON root structure from Splunk API (expected dict).")

    results = data.get("results", [])
    if not isinstance(results, list):
        raise SplunkAPIError("Unexpected 'results' structure from Splunk API (expected list).")

    return results


def fetch_all_detections(config: SplunkConfig | None = None) -> dict[str, Any]:
    """
    Runs every defined detection query and returns a dict keyed by MITRE technique ID,
    each containing the technique name and matching raw events or error message.

    Args:
        config: SplunkConfig instance (defaults to SplunkConfig.from_env()).

    Returns:
        Dict structure: {technique_id: {"name": str, "events": list, ["error": str]}}
    """
    if config is None:
        config = SplunkConfig.from_env()

    all_results: dict[str, Any] = {}

    for technique_id, detection in DETECTIONS.items():
        name = detection["name"]
        query = detection["query"]
        logger.info("Running detection search %s - %s...", technique_id, name)

        try:
            results = run_search(query, config=config)
            all_results[technique_id] = {
                "name": name,
                "events": results,
            }
            logger.info(" -> %s returned %d matching event(s)", technique_id, len(results))
        except (SplunkAPIError, SplunkConnectionError) as e:
            logger.warning(" -> Error executing search %s (%s): %s", technique_id, name, e)
            all_results[technique_id] = {
                "name": name,
                "events": [],
                "error": str(e),
            }

    return all_results


if __name__ == "__main__":
    from config import setup_logging
    setup_logging(debug=True)
    logger.info("Running standalone Splunk detection fetch...")
    res = fetch_all_detections()
    for tech_id, d in res.items():
        print(f"\n{tech_id} - {d['name']}: {len(d['events'])} events")
        if "error" in d:
            print(f"  Error: {d['error']}")
