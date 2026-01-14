from typing import Dict, Optional
from unittest.mock import MagicMock, patch
import shlex

import pytest

from check_pve import CheckPVE, CheckState


def test_arguments(pve_instance: CheckPVE) -> None:
    cli_args = "-e endpoint -u user -p password -m version"

    args = pve_instance.parse_args(shlex.split(cli_args))
    assert args.mode == "version"

    args = pve_instance.parse_args(shlex.split(cli_args + " -V 123"))
    assert args.mode == "version" and args.min_version == "123"

    args = pve_instance.parse_args(shlex.split(cli_args + " --min-version 123"))
    assert args.mode == "version" and args.min_version == "123"

    with pytest.raises(SystemExit):
        args = pve_instance.parse_args(shlex.split(cli_args + " --V"))

    with pytest.raises(SystemExit):
        args = pve_instance.parse_args(shlex.split(cli_args + " --min-version"))


@pytest.mark.parametrize(
    "mock_response, min_version, expected_state",
    [
        ({"version": "7.1-2", "repoid": "enterprise"}, None, CheckState.OK),
        ({"version": "6.0-1", "repoid": "no-subscription"}, "7.0", CheckState.CRITICAL),
        ({}, None, CheckState.UNKNOWN),
    ],
    ids=["version ok", "version too low", "empty response"],
)
@patch.object(CheckPVE, "request")
def test_check_version(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
    mock_response: Dict[str, str],
    min_version: Optional[str],
    expected_state: CheckState,
) -> None:
    """Test check_version with different paths, including empty response."""
    mock_request.return_value = mock_response

    pve_instance.options.min_version = min_version
    pve_instance.check_version()

    if expected_state == CheckState.OK:
        expected_message = (
            f"Your PVE instance version '{mock_response['version']}' "
            f"({mock_response['repoid']}) is up to date"
        )
    elif expected_state == CheckState.CRITICAL:
        expected_message = (
            f"Current PVE version '{mock_response['version']}' ({mock_response['repoid']}) "
            f"is lower than the min. required version '{min_version}'"
        )
    else:
        expected_message = "Unable to determine PVE version"

    assert expected_message in pve_instance.check_message
    assert pve_instance.check_result == expected_state
