from unittest.mock import MagicMock, patch
import pytest
from check_pve import CheckPVE, CheckState


@pytest.fixture
def pve_instance() -> CheckPVE:
    """Fixture to create a CheckPVE instance without triggering the constructor."""
    with patch.object(CheckPVE, "__init__", lambda x: None):
        instance = CheckPVE()
        instance.options = MagicMock()
        instance.perfdata = []
        instance.check_result = CheckState.UNKNOWN
        instance.check_message = ""
        instance.output = MagicMock()

        # Private attributes created in the real constructor
        instance._CheckPVE__headers = {}
        instance._CheckPVE__cookies = {}
        instance.options.api_insecure = False

        return instance
