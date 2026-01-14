from unittest.mock import MagicMock, patch

import pytest
import shlex

from check_pve import CheckPVE, CheckState


def test_arguments(pve_instance: CheckPVE) -> None:
    cli_args = "-e endpoint -u user -p password -m cluster"

    args = pve_instance.parse_args(shlex.split(cli_args))
    assert args.mode == "cluster"


@pytest.mark.parametrize(
    "mock_response, expected_state",
    [
        ([{"type": "cluster", "quorate": 1, "name": "pve-cluster"}], CheckState.OK),
        ([{"type": "cluster", "quorate": 0, "name": "pve-cluster"}], CheckState.CRITICAL),
        ([], CheckState.UNKNOWN),
    ],
    ids=["healthy cluster", "no quorum", "no cluster config"],
)
@patch.object(CheckPVE, "request")
def test_check_cluster_status(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
    mock_response: list,
    expected_state: CheckState,
) -> None:
    """Test check_cluster_status with different paths."""
    mock_request.return_value = mock_response

    pve_instance.check_cluster_status()

    if expected_state == CheckState.OK:
        expected_message = f"Cluster '{mock_response[0]['name']}' is healthy'"
    elif expected_state == CheckState.CRITICAL:
        expected_message = "Cluster is unhealthy - no quorum"
    else:
        expected_message = "No cluster configuration found"

    assert expected_message in pve_instance.check_message
    assert pve_instance.check_result == expected_state
