"""
test_fetch_alerts.py
Unit tests for triage/fetch_alerts.py mocking Splunk REST API calls.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests
from config import SplunkConfig
from fetch_alerts import (
    SplunkAPIError,
    SplunkConnectionError,
    fetch_all_detections,
    run_search,
)


@pytest.fixture
def mock_config():
    return SplunkConfig(
        host="127.0.0.1",
        port=8089,
        user="admin",
        password="secretpassword",
        verify_ssl=False,
    )


@patch("requests.post")
def test_run_search_success(mock_post, mock_config):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": [{"host": "test-host", "src_ip": "1.1.1.1"}]
    }
    mock_post.return_value = mock_response

    results = run_search("search index=*", config=mock_config)
    assert len(results) == 1
    assert results[0]["host"] == "test-host"
    mock_post.assert_called_once()


def test_run_search_missing_host():
    empty_config = SplunkConfig(host="")
    with pytest.raises(SplunkAPIError, match="Missing Splunk host"):
        run_search("search index=*", config=empty_config)


@patch("requests.post")
def test_run_search_timeout(mock_post, mock_config):
    mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")
    with pytest.raises(SplunkConnectionError, match="timed out"):
        run_search("search index=*", config=mock_config)


@patch("requests.post")
def test_run_search_connection_error(mock_post, mock_config):
    mock_post.side_effect = requests.exceptions.ConnectionError("Refused")
    with pytest.raises(SplunkConnectionError, match="Could not connect"):
        run_search("search index=*", config=mock_config)


@patch("requests.post")
def test_run_search_http_error(mock_post, mock_config):
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Unauthorized", response=mock_response)
    mock_post.return_value = mock_response

    with pytest.raises(SplunkAPIError, match="HTTP Error 401"):
        run_search("search index=*", config=mock_config)


@patch("requests.post")
def test_run_search_invalid_json(mock_post, mock_config):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_post.return_value = mock_response

    with pytest.raises(SplunkAPIError, match="Invalid JSON response"):
        run_search("search index=*", config=mock_config)


@patch("fetch_alerts.run_search")
def test_fetch_all_detections(mock_run_search, mock_config):
    mock_run_search.return_value = [{"event": "data"}]

    results = fetch_all_detections(config=mock_config)

    assert "T1110" in results
    assert "T1078" in results
    assert "T1059" in results
    assert len(results["T1110"]["events"]) == 1
    assert mock_run_search.call_count == 3
