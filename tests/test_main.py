"""
test_main.py
Unit tests for triage/main.py CLI argument parsing and execution orchestration.
"""

from unittest.mock import MagicMock, patch

import pytest

from main import main, run_once


@patch("main.fetch_all_detections")
@patch("main.enrich_detections")
@patch("main.print_report")
def test_run_once_with_dedup(mock_print, mock_enrich, mock_fetch, sample_raw_detections):
    mock_fetch.return_value = sample_raw_detections
    mock_enrich.return_value = [{"score": 90, "severity": "Critical"}]

    mock_state_mgr = MagicMock()
    mock_state_mgr.filter_new_alerts.return_value = sample_raw_detections

    alerts = run_once(state_manager=mock_state_mgr, use_dedup=True)

    mock_fetch.assert_called_once()
    mock_state_mgr.filter_new_alerts.assert_called_once_with(sample_raw_detections)
    mock_enrich.assert_called_once()
    mock_print.assert_called_once()
    assert len(alerts) == 1


@patch("main.fetch_all_detections")
@patch("main.enrich_detections")
@patch("main.print_report")
def test_run_once_no_dedup(mock_print, mock_enrich, mock_fetch, sample_raw_detections):
    mock_fetch.return_value = sample_raw_detections
    mock_enrich.return_value = []

    mock_state_mgr = MagicMock()

    alerts = run_once(state_manager=mock_state_mgr, use_dedup=False)

    mock_fetch.assert_called_once()
    mock_state_mgr.filter_new_alerts.assert_not_called()
    assert alerts == []


@patch("main.AlertStateManager")
def test_main_reset_state(mock_state_cls):
    mock_mgr = MagicMock()
    mock_state_cls.return_value = mock_mgr

    with pytest.raises(SystemExit) as exc_info:
        main(["--reset-state"])

    assert exc_info.value.code == 0
    mock_mgr.reset.assert_called_once()


@patch("main.run_watch")
@patch("main.AlertStateManager")
def test_main_watch_mode(mock_state_cls, mock_run_watch):
    main(["--watch", "--interval", "60", "--no-dedup"])
    mock_run_watch.assert_called_once()
    _, kwargs = mock_run_watch.call_args
    assert kwargs["interval"] == 60
    assert kwargs["use_dedup"] is False


@patch("main.run_once")
@patch("main.AlertStateManager")
def test_main_single_run(mock_state_cls, mock_run_once):
    main(["--debug"])
    mock_run_once.assert_called_once()
