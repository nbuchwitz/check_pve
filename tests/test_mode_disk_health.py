from typing import Dict, List
from unittest.mock import patch

import pytest

from check_pve import CheckPVE, CheckState


@pytest.fixture
def disk_check(pve_instance: CheckPVE) -> CheckPVE:
    """Configure a disk-health check with the normal initial check state."""
    pve_instance.options = pve_instance.parse_args(
        ["-e", "endpoint", "-u", "user", "-p", "password", "-m", "disk-health", "-n", "pve"]
    )
    pve_instance.check_result = CheckState.OK
    return pve_instance


@pytest.mark.parametrize(
    "ignored, excluded",
    [
        pytest.param([], False, id="no-exclusions"),
        pytest.param(["sdb"], True, id="device"),
        pytest.param([" SDB "], True, id="normalized-device"),
        pytest.param(["AbC123"], True, id="serial"),
        pytest.param([" abc123 "], True, id="normalized-serial"),
        pytest.param(["unrelated", "ABC123"], True, id="repeated-option"),
        pytest.param(["abc12"], False, id="serial-prefix-does-not-match"),
        pytest.param(["sd"], False, id="device-prefix-does-not-match"),
    ],
)
@pytest.mark.parametrize("health", ["FAILED", "UNKNOWN"])
def test_ignore_disks(
    disk_check: CheckPVE, ignored: List[str], excluded: bool, health: str
) -> None:
    """Exclusions suppress both health warnings and wearout metrics."""
    disk_check.options = disk_check.parse_args(
        ["-e", "endpoint", "-u", "user", "-p", "password", "-m", "disk-health", "-n", "pve"]
        + [arg for value in ignored for arg in ("--ignore-disk", value)]
    )
    disk = {"devpath": "/dev/sdb", "serial": "AbC123", "health": health, "wearout": 90}

    with patch.object(CheckPVE, "request", return_value=[disk]):
        disk_check.check_disks()

    if excluded:
        assert disk_check.check_result == CheckState.OK
        assert disk_check.check_message == "All disks are healthy"
        assert disk_check.perfdata == []
    else:
        assert disk_check.check_result == CheckState.WARNING
        assert "/dev/sdb with serial 'AbC123'" in disk_check.check_message
        assert disk_check.perfdata == ["wearout_sdb=90%;;;0;"]


@pytest.mark.parametrize(
    "serial_fields",
    [
        pytest.param({}, id="missing"),
        pytest.param({"serial": None}, id="null"),
        pytest.param({"serial": ""}, id="empty"),
    ],
)
@pytest.mark.parametrize("health", ["FAILED", "UNKNOWN"])
def test_missing_serial(disk_check: CheckPVE, serial_fields: Dict, health: str) -> None:
    """Disks without serials remain reportable even with an empty exclusion."""
    disk_check.options.ignore_disks = [""]
    disk = {"devpath": "/dev/sdb", "health": health, "wearout": "N/A", **serial_fields}

    with patch.object(CheckPVE, "request", return_value=[disk]):
        disk_check.check_disks()

    assert disk_check.check_result == CheckState.WARNING
    assert "/dev/sdb with serial ''" in disk_check.check_message
    assert disk_check.perfdata == []


def test_exclusion_keeps_other_disks_checked(disk_check: CheckPVE) -> None:
    """Serial exclusions follow renamed devices without hiding other failures."""
    disk_check.options.ignore_disks = ["ABC123"]
    disks = [
        {"devpath": "/dev/sdc", "serial": "AbC123", "health": "FAILED", "wearout": 90},
        {"devpath": "/dev/sdb", "serial": "OTHER", "health": "FAILED", "wearout": 80},
    ]

    with patch.object(CheckPVE, "request", return_value=disks):
        disk_check.check_disks()

    assert disk_check.check_result == CheckState.WARNING
    assert disk_check.check_message == (
        "1 of 2 disks failed the health test:\n- /dev/sdb with serial 'OTHER'\n"
    )
    assert disk_check.perfdata == ["wearout_sdb=80%;;;0;"]
