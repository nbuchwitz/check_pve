from typing import Dict, List
from unittest.mock import MagicMock, patch
import shlex
import pytest
from check_pve import CheckPVE, CheckState

CLI_ARGS = "-e endpoint -u user -p password -m memory"


def test_arguments(pve_instance: CheckPVE) -> None:
    """Test CLI argument parsing for check_memory."""
    args = pve_instance.parse_args(shlex.split(CLI_ARGS + " -n pve"))
    assert args.mode == "memory" and args.node == "pve"

    args = pve_instance.parse_args(shlex.split(CLI_ARGS + " --node pve"))
    assert args.mode == "memory" and args.node == "pve"

    with pytest.raises(SystemExit):
        # missing node name
        args = pve_instance.parse_args(shlex.split(CLI_ARGS))


@pytest.mark.parametrize(
    "mock_response, expected_value, expected_state, expected_perfdata",
    [
        (
            {"memory": {"used": 4 * 1024 * 1024 * 1024, "total": 8 * 1024 * 1024 * 1024}},
            50.0,
            CheckState.OK,
            ["usage=50.0%;;;0;", "used=4096.0MiB;;;0;8192.0"],
        ),
    ],
    ids=[
        "simple usage",
    ],
)
@patch.object(CheckPVE, "request")
def test_check_memory(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
    mock_response: Dict[str, Dict[str, int]],
    expected_state: CheckState,
    expected_value: float,
    expected_perfdata: List[str],
) -> None:
    """Test check_memory, including perfdata."""
    mock_request.return_value = mock_response

    pve_instance.options = MagicMock()
    pve_instance.options = pve_instance.parse_args(shlex.split(CLI_ARGS + " -n pve"))
    pve_instance.check_memory()

    assert f"Memory usage is {expected_value:.1f} %" in pve_instance.check_message
    assert pve_instance.check_result == expected_state
    assert expected_perfdata == pve_instance.perfdata
