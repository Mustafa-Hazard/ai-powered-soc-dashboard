"""
config.py
Phase 5 - SOC Dashboard Python Triage Layer

Centralized configuration module for Splunk connection parameters, scoring
thresholds, severity labels, logging setup, and detection search queries.
"""

import logging
import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Load variables from .env if present
load_dotenv()


@dataclass(frozen=True)
class SplunkConfig:
    """
    Splunk REST API connection configuration.

    Redacts credentials in __repr__ and __str__ so secrets are never leaked into
    log outputs or stack traces even at DEBUG level.
    """
    host: str
    port: int = 8089
    user: str = "admin"
    password: str = field(repr=False, default="")
    verify_ssl: bool = True
    timeout: int = 30

    @classmethod
    def from_env(cls) -> "SplunkConfig":
        host = os.environ.get("SPLUNK_HOST", "")
        port_str = os.environ.get("SPLUNK_PORT", "8089")
        user = os.environ.get("SPLUNK_USER", "admin")
        password = os.environ.get("SPLUNK_PASS", "")
        verify_ssl_str = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower()

        try:
            port = int(port_str)
        except ValueError:
            port = 8089

        verify_ssl = verify_ssl_str not in ("false", "0", "no", "off")

        return cls(
            host=host,
            port=port,
            user=user,
            password=password,
            verify_ssl=verify_ssl,
        )

    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    def __repr__(self) -> str:
        return (
            f"SplunkConfig(host={self.host!r}, port={self.port!r}, "
            f"user={self.user!r}, password='[REDACTED]', "
            f"verify_ssl={self.verify_ssl!r}, timeout={self.timeout!r})"
        )


# --- Severity Thresholds ---
SCORE_CRITICAL_THRESHOLD = 85
SCORE_HIGH_THRESHOLD = 60
SCORE_MEDIUM_THRESHOLD = 35

# --- Scoring Logic Parameters ---
# T1110 (Brute Force)
T1110_BASE_SCORE = 20
T1110_PER_ATTEMPT_SCORE = 2
T1110_MAX_SCORE = 100

# T1078 (Valid Accounts)
T1078_BASE_SCORE = 60
T1078_PER_PRIOR_FAIL_SCORE = 1
T1078_MAX_SCORE = 100

# T1059 (Command Execution)
T1059_FIXED_SCORE = 75

# --- Detection Queries ---
DETECTIONS: dict[str, dict[str, str]] = {
    "T1110": {
        "name": "SSH Brute Force Detected",
        "query": (
            'search index=* host="ip-172-31-13-183" "Failed password"\n'
            '| rex field=_raw "Failed password for (invalid user )?(?<user>\\S+) from (?<src_ip>\\S+)"\n'
            '| stats count as failed_attempts by src_ip, user\n'
            '| where failed_attempts >= 5\n'
            '| eval host="ip-172-31-13-183"'
        ),
    },
    "T1078": {
        "name": "Successful Login Following Failed Attempts",
        "query": (
            'search index=* host="ip-172-31-13-183"\n'
            '("Failed password" OR "Accepted password")\n'
            '| rex field=_raw "Failed password for (invalid user )?(?<user>\\S+) from (?<src_ip>\\S+)"\n'
            '| rex field=_raw "Accepted password for (?<user>\\S+) from (?<src_ip>\\S+)"\n'
            '| eval status=if(match(_raw,"Failed password"),"failed","accepted")\n'
            '| sort 0 src_ip _time\n'
            '| streamstats count(eval(status="failed")) as prior_failed_attempts by src_ip\n'
            '| where status="accepted" AND prior_failed_attempts>=5\n'
            '| eval host="ip-172-31-13-183"\n'
            '| table _time src_ip user prior_failed_attempts status host'
        ),
    },
    "T1059": {
        "name": "Suspicious Download Utility Execution",
        "query": (
            'search index=* host="ip-172-31-13-183" sourcetype="linux_audit" type=EXECVE\n'
            '| rex field=_raw "a0=\\"(?<command>[^\\"]+)\\""\n'
            '| search command IN ("wget", "curl")\n'
            '| rex field=_raw "a1=\\"(?<arg1>[^\\"]+)\\""\n'
            '| table _time host command arg1\n'
            '| sort -_time'
        ),
    },
}

# Default alert state storage file
DEFAULT_STATE_FILE = "state.json"


def setup_logging(debug: bool = False) -> logging.Logger:
    """Configures structured logging for the triage application."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger("soc_triage")
