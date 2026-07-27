"""
test_config.py
Unit tests for triage/config.py credential redaction and SplunkConfig properties.
"""

import os
from unittest.mock import patch

from config import SplunkConfig


def test_splunk_config_secret_redaction():
    cfg = SplunkConfig(
        host="splunk.local",
        user="admin",
        password="SuperSecretPassword123!",
        verify_ssl=True,
    )

    repr_str = repr(cfg)
    assert "[REDACTED]" in repr_str
    assert "SuperSecretPassword123!" not in repr_str
    assert "admin" in repr_str
    assert "splunk.local" in repr_str


def test_splunk_config_defaults():
    cfg = SplunkConfig(host="10.0.0.1")
    assert cfg.port == 8089
    assert cfg.user == "admin"
    assert cfg.verify_ssl is True
    assert cfg.base_url() == "https://10.0.0.1:8089"


@patch.dict(os.environ, {
    "SPLUNK_HOST": "splunk.example.com",
    "SPLUNK_PORT": "9089",
    "SPLUNK_USER": "soc_user",
    "SPLUNK_PASS": "mysecret",
    "SPLUNK_VERIFY_SSL": "false",
})
def test_splunk_config_from_env():
    cfg = SplunkConfig.from_env()
    assert cfg.host == "splunk.example.com"
    assert cfg.port == 9089
    assert cfg.user == "soc_user"
    assert cfg.password == "mysecret"
    assert cfg.verify_ssl is False
    assert "[REDACTED]" in repr(cfg)
