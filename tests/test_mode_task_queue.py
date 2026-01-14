from typing import Dict, List
from unittest.mock import MagicMock, patch
import shlex

import pytest

from check_pve import CheckPVE, CheckState, CheckThreshold


def test_arguments(pve_instance: CheckPVE) -> None:
    cli_args = "-e endpoint -u user -p password -m task-queue"

    args = pve_instance.parse_args(shlex.split(cli_args))
    assert args.mode == "task-queue"

    args = pve_instance.parse_args(shlex.split(cli_args + " -n node1"))
    assert args.mode == "task-queue" and args.node == "node1"

    args = pve_instance.parse_args(shlex.split(cli_args + " -w running:5 -c running:10"))
    assert args.mode == "task-queue"


@pytest.mark.parametrize(
    "mock_response, node_filter, expected_state, expected_message_part",
    [
        (
            # No running tasks, no failed tasks
            [
                {"node": "node1", "type": "qmrestore", "status": "OK", "starttime": 1700000000},
                {"node": "node2", "type": "backup", "status": "OK", "starttime": 1700000001},
            ],
            None,
            CheckState.OK,
            "Cluster: 0 tasks running",
        ),
        (
            # Some running tasks
            [
                {"node": "node1", "type": "qmrestore", "starttime": 1700000000},
                {"node": "node1", "type": "backup", "starttime": 1700000001},
                {"node": "node2", "type": "qmigrate", "status": "OK", "starttime": 1700000002},
            ],
            None,
            CheckState.OK,
            "Cluster: 2 tasks running (1 backup, 1 qmrestore)",
        ),
        (
            # Failed tasks present
            [
                {"node": "node1", "type": "backup", "status": "ERROR", "starttime": 1700000000},
                {"node": "node1", "type": "qmrestore", "status": "OK", "starttime": 1700000001},
            ],
            None,
            CheckState.WARNING,
            "1 tasks failed",
        ),
        (
            # Running tasks on specific node
            [
                {"node": "node1", "type": "backup", "starttime": 1700000000},
                {"node": "node2", "type": "qmrestore", "starttime": 1700000001},
                {"node": "node1", "type": "qmigrate", "status": "OK", "starttime": 1700000002},
            ],
            "node1",
            CheckState.OK,
            "Node 'node1': 1 tasks running (1 backup)",
        ),
        (
            # Multiple task types
            [
                {"node": "node1", "type": "backup", "starttime": 1700000000},
                {"node": "node1", "type": "backup", "starttime": 1700000001},
                {"node": "node1", "type": "qmrestore", "starttime": 1700000002},
                {"node": "node1", "type": "qmigrate", "starttime": 1700000003},
            ],
            None,
            CheckState.OK,
            "4 tasks running (2 backup, 1 qmigrate, 1 qmrestore)",
        ),
    ],
    ids=["no tasks", "running tasks", "failed tasks", "specific node", "multiple task types"],
)
@patch.object(CheckPVE, "request")
def test_check_task_queue(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
    mock_response: List[Dict],
    node_filter: str,
    expected_state: CheckState,
    expected_message_part: str,
) -> None:
    """Test check_task_queue with various scenarios."""
    mock_request.return_value = mock_response

    pve_instance.options.node = node_filter
    pve_instance.options.threshold_warning = {}
    pve_instance.options.threshold_critical = {}
    pve_instance.check_task_queue()

    assert expected_message_part in pve_instance.check_message
    assert pve_instance.check_result == expected_state


@patch.object(CheckPVE, "request")
def test_check_task_queue_with_thresholds(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
) -> None:
    """Test check_task_queue with warning and critical thresholds."""
    # 6 running tasks
    mock_response = [
        {"node": "node1", "type": "backup", "starttime": 1700000000},
        {"node": "node1", "type": "backup", "starttime": 1700000001},
        {"node": "node1", "type": "backup", "starttime": 1700000002},
        {"node": "node1", "type": "qmrestore", "starttime": 1700000003},
        {"node": "node1", "type": "qmrestore", "starttime": 1700000004},
        {"node": "node1", "type": "qmigrate", "starttime": 1700000005},
    ]
    mock_request.return_value = mock_response

    # Test warning threshold
    pve_instance.options.node = None
    pve_instance.options.threshold_warning = {"running": CheckThreshold(5)}
    pve_instance.options.threshold_critical = {}
    pve_instance.check_task_queue()

    assert pve_instance.check_result == CheckState.WARNING
    assert "6 tasks running" in pve_instance.check_message

    # Test critical threshold
    pve_instance.options.threshold_warning = {}
    pve_instance.options.threshold_critical = {"running": CheckThreshold(5)}
    pve_instance.check_task_queue()

    assert pve_instance.check_result == CheckState.CRITICAL
    assert "6 tasks running" in pve_instance.check_message


@patch.object(CheckPVE, "request")
def test_check_task_queue_empty_response(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
) -> None:
    """Test check_task_queue with empty API response."""
    mock_request.return_value = None

    pve_instance.options.node = None
    pve_instance.check_task_queue()

    assert "Could not fetch task queue data from API" in pve_instance.check_message
    assert pve_instance.check_result == CheckState.UNKNOWN
