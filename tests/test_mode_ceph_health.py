"""Tests for Ceph health status and summary output."""

import shlex
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from check_pve import CheckPVE, CheckState


def test_arguments(pve_instance: CheckPVE) -> None:
    """Accept the Ceph health check mode."""
    cli_args = "-e endpoint -u user -p password -m ceph-health"

    args = pve_instance.parse_args(shlex.split(cli_args))

    assert args.mode == "ceph-health"


@pytest.mark.parametrize(
    "status, expected_state, expected_message",
    [
        ("HEALTH_OK", CheckState.OK, "Ceph Cluster is healthy"),
        ("HEALTH_WARN", CheckState.WARNING, "Ceph Cluster is in warning state"),
        ("HEALTH_CRIT", CheckState.CRITICAL, "Ceph Cluster is in critical state"),
        ("unexpected", CheckState.UNKNOWN, "Ceph Cluster is in unknown state"),
    ],
)
@pytest.mark.parametrize("checks", [None, {}, {"OSDMAP_FLAGS": {"summary": {}}}])
@patch.object(CheckPVE, "request")
def test_check_ceph_health_without_messages(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
    status: str,
    expected_state: CheckState,
    expected_message: str,
    checks: Optional[dict],
) -> None:
    """Preserve the status line when no summaries are available."""
    health = {"status": status}
    if checks is not None:
        health["checks"] = checks
    mock_request.return_value = {"health": health}

    pve_instance.check_ceph_health()

    assert pve_instance.check_result == expected_state
    assert pve_instance.check_message == expected_message


@pytest.mark.parametrize(
    "status, expected_state, expected_message",
    [
        ("HEALTH_OK", CheckState.OK, "Ceph Cluster is healthy"),
        ("HEALTH_WARN", CheckState.WARNING, "Ceph Cluster is in warning state"),
        ("HEALTH_CRIT", CheckState.CRITICAL, "Ceph Cluster is in critical state"),
    ],
)
@patch.object(CheckPVE, "request")
def test_check_ceph_health_with_messages(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
    status: str,
    expected_state: CheckState,
    expected_message: str,
) -> None:
    """Include each available summary on its own line without changing severity."""
    mock_request.return_value = {
        "health": {
            "status": status,
            "checks": {
                "OSDMAP_FLAGS": {
                    "summary": {"message": "nobackfill,norebalance,norecover flag(s) set"},
                },
                "POOL_SCRUB_FLAGS": {
                    "summary": {
                        "message": "Some pool(s) have the noscrub, nodeep-scrub flag(s) set"
                    },
                },
                "MISSING_SUMMARY": {},
                "EMPTY_SUMMARY": {"summary": {"message": ""}},
            },
        }
    }

    pve_instance.check_ceph_health()

    assert pve_instance.check_result == expected_state
    assert pve_instance.check_message == (
        expected_message + "\n"
        "- nobackfill,norebalance,norecover flag(s) set\n"
        "- Some pool(s) have the noscrub, nodeep-scrub flag(s) set"
    )


@pytest.mark.parametrize("mock_response", [{}, {"health": {}}, {"health": {"checks": {}}}])
@patch.object(CheckPVE, "request")
def test_check_ceph_health_missing_status(
    mock_request: MagicMock, pve_instance: CheckPVE, mock_response: dict
) -> None:
    """Keep the existing unknown result when the API omits health status."""
    mock_request.return_value = mock_response

    pve_instance.check_ceph_health()

    assert pve_instance.check_result == CheckState.UNKNOWN
    assert pve_instance.check_message == (
        "Could not fetch Ceph status from API. "
        "Check the output of 'pvesh get cluster/ceph' on your node"
    )
