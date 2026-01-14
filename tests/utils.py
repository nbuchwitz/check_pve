from unittest.mock import MagicMock, patch

from check_pve import CheckPVE, CheckState


def run_check_test(
    check_function: str,
    pve_instance: CheckPVE,
    mock_request: MagicMock,
    mock_response: dict,
    expected_state: CheckState,
    expected_message: str,
) -> None:
    """Test given check function with mock reponse."""
    mock_request.return_value = mock_response
    pve_instance.options = MagicMock()
    pve_instance.options.api_endpoint = "mock-endpoint"
    pve_instance.options.api_port = 8006
    pve_instance.options.api_user = "mock-user"
    pve_instance.options.api_password = "mock-password"

    # Dynamically call the check function
    getattr(pve_instance, check_function)()

    assert expected_message in pve_instance.check_message
    assert pve_instance.check_result == expected_state
