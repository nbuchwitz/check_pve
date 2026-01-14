from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch
import shlex

import pytest

from check_pve import CheckPVE, CheckState


def test_arguments(pve_instance: CheckPVE) -> None:
    cli_args = "-e endpoint -u user -p password -m network-status -n node1"

    args = pve_instance.parse_args(shlex.split(cli_args))
    assert args.mode == "network-status"
    assert args.node == "node1"

    args = pve_instance.parse_args(shlex.split(cli_args + " --name bond0"))
    assert args.mode == "network-status" and args.name == "bond0"

    args = pve_instance.parse_args(shlex.split(cli_args + " --ignore-interface vmbr1"))
    assert args.mode == "network-status" and args.ignore_interfaces == ["vmbr1"]

    args = pve_instance.parse_args(
        shlex.split(cli_args + " --ignore-interface vmbr1 --ignore-interface bond1")
    )
    assert args.mode == "network-status" and args.ignore_interfaces == ["vmbr1", "bond1"]


@pytest.mark.parametrize(
    "mock_response, interface_name, expected_state, expected_message",
    [
        (
            # All interfaces healthy
            [
                {
                    "iface": "bond0",
                    "type": "bond",
                    "active": 1,
                    "slaves": "ens1 ens2",
                    "bond_mode": "balance-rr",
                },
                {"iface": "ens1", "type": "eth", "active": 1},
                {"iface": "ens2", "type": "eth", "active": 1},
                {"iface": "vmbr0", "type": "bridge", "active": 1},
            ],
            None,
            CheckState.OK,
            "All network interfaces on node 'test-node' are healthy",
        ),
        (
            # Bond degraded - one member down
            [
                {
                    "iface": "bond0",
                    "type": "bond",
                    "active": 1,
                    "slaves": "ens1 ens2",
                    "bond_mode": "802.3ad",
                },
                {"iface": "ens1", "type": "eth", "active": 1, "slave": 1},
                {"iface": "ens2", "type": "eth", "active": 0, "slave": 1},
                {"iface": "vmbr0", "type": "bridge", "active": 1},
            ],
            None,
            CheckState.WARNING,
            "Bond 'bond0' degraded: 1/2 members active (mode: 802.3ad)",
        ),
        (
            # Bond completely down
            [
                {
                    "iface": "bond0",
                    "type": "bond",
                    "active": 0,
                    "slaves": "ens1 ens2",
                    "bond_mode": "active-backup",
                },
                {"iface": "ens1", "type": "eth", "active": 0},
                {"iface": "ens2", "type": "eth", "active": 0},
            ],
            None,
            CheckState.CRITICAL,
            "Interface 'bond0' is down",
        ),
        (
            # Bridge down
            [
                {"iface": "vmbr0", "type": "bridge", "active": 0, "slave": 0},
                {"iface": "ens1", "type": "eth", "active": 1},
            ],
            None,
            CheckState.CRITICAL,
            "Interface 'vmbr0' is down",
        ),
        (
            # Specific interface check - healthy
            [
                {
                    "iface": "bond0",
                    "type": "bond",
                    "active": 1,
                    "slaves": "ens1 ens2",
                    "bond_mode": "balance-rr",
                },
                {"iface": "ens1", "type": "eth", "active": 1},
                {"iface": "ens2", "type": "eth", "active": 1},
            ],
            "bond0",
            CheckState.OK,
            "Network interface 'bond0' is healthy",
        ),
        (
            # Specific interface check - degraded bond
            [
                {
                    "iface": "bond0",
                    "type": "bond",
                    "active": 1,
                    "slaves": "ens1 ens2",
                    "bond_mode": "802.3ad",
                },
                {"iface": "ens1", "type": "eth", "active": 1},
                {"iface": "ens2", "type": "eth", "active": 0},
            ],
            "bond0",
            CheckState.WARNING,
            "Bond 'bond0' degraded: 1/2 members active (mode: 802.3ad)",
        ),
        (
            # Interface not found
            [
                {"iface": "bond0", "type": "bond", "active": 1, "slaves": "ens1 ens2"},
                {"iface": "ens1", "type": "eth", "active": 1},
            ],
            "bond1",
            CheckState.UNKNOWN,
            "Network interface 'bond1' not found on node 'test-node'",
        ),
    ],
    ids=[
        "all healthy",
        "bond degraded",
        "bond down",
        "bridge down",
        "specific interface healthy",
        "specific interface degraded",
        "interface not found",
    ],
)
@patch.object(CheckPVE, "request")
def test_check_network_status(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
    mock_response: List[Dict],
    interface_name: Optional[str],
    expected_state: CheckState,
    expected_message: str,
) -> None:
    """Test check_network_status with various scenarios."""
    mock_request.return_value = mock_response

    pve_instance.options.node = "test-node"
    pve_instance.options.name = interface_name
    pve_instance.check_network_status(interface_name)

    assert expected_message in pve_instance.check_message
    assert pve_instance.check_result == expected_state


@patch.object(CheckPVE, "request")
def test_check_network_status_with_ignore(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
) -> None:
    """Test check_network_status with --ignore-interface option."""
    mock_response = [
        {
            "iface": "bond0",
            "type": "bond",
            "active": 1,
            "slaves": "ens1 ens2",
            "bond_mode": "802.3ad",
        },
        {"iface": "ens1", "type": "eth", "active": 1, "slave": 1},
        {"iface": "ens2", "type": "eth", "active": 0, "slave": 1},
        {"iface": "vmbr0", "type": "bridge", "active": 0},
    ]
    mock_request.return_value = mock_response

    pve_instance.options.node = "test-node"
    pve_instance.options.name = None
    pve_instance.options.ignore_interfaces = ["bond0", "vmbr0"]
    pve_instance.check_network_status(None)

    # With both bond0 (degraded) and vmbr0 (down) ignored, all should be healthy
    assert "All network interfaces on node 'test-node' are healthy" in pve_instance.check_message
    assert pve_instance.check_result == CheckState.OK


@patch.object(CheckPVE, "request")
def test_check_network_status_bond_with_primary(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
) -> None:
    """Test check_network_status with bond primary information."""
    # Active-backup bond with primary set, primary is inactive
    mock_response = [
        {
            "iface": "bond0",
            "type": "bond",
            "active": 1,
            "slaves": "ens1 ens2",
            "bond_mode": "active-backup",
            "bond-primary": "ens1",
        },
        {"iface": "ens1", "type": "eth", "active": 0, "slave": 1},
        {"iface": "ens2", "type": "eth", "active": 1, "slave": 1},
    ]
    mock_request.return_value = mock_response

    pve_instance.options.node = "test-node"
    pve_instance.options.name = None
    pve_instance.options.ignore_interfaces = []
    pve_instance.check_network_status(None)

    assert "primary: ens1 (inactive)" in pve_instance.check_message
    assert pve_instance.check_result == CheckState.WARNING


@patch.object(CheckPVE, "request")
def test_check_network_status_bond_primary_active(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
) -> None:
    """Test check_network_status with bond when primary is active but bond degraded."""
    # Active-backup bond with primary set, primary is active but secondary is down
    mock_response = [
        {
            "iface": "bond0",
            "type": "bond",
            "active": 1,
            "slaves": "ens1 ens2",
            "bond_mode": "active-backup",
            "bond-primary": "ens1",
        },
        {"iface": "ens1", "type": "eth", "active": 1, "slave": 1},
        {"iface": "ens2", "type": "eth", "active": 0, "slave": 1},
    ]
    mock_request.return_value = mock_response

    pve_instance.options.node = "test-node"
    pve_instance.options.name = None
    pve_instance.options.ignore_interfaces = []
    pve_instance.check_network_status(None)

    assert "primary: ens1 (active)" in pve_instance.check_message
    assert pve_instance.check_result == CheckState.WARNING
