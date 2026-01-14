from typing import Dict, List
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
import shlex

import pytest

from check_pve import CheckPVE, CheckState, CheckThreshold


def test_arguments(pve_instance: CheckPVE) -> None:
    cli_args = "-e endpoint -u user -p password -m certificate"

    args = pve_instance.parse_args(shlex.split(cli_args))
    assert args.mode == "certificate"

    args = pve_instance.parse_args(shlex.split(cli_args + " -n node1"))
    assert args.mode == "certificate" and args.node == "node1"

    args = pve_instance.parse_args(shlex.split(cli_args + " -w 30 -c 7"))
    assert args.mode == "certificate"


@pytest.mark.parametrize(
    "cluster_resources, cert_data, node_filter, warning_days, critical_days, expected_state, expected_message_part",
    [
        (
            # All certificates valid (90 days left)
            [{"type": "node", "node": "node1"}],
            {
                "node1": [
                    {
                        "filename": "pve-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=90)).timestamp(),
                    }
                ]
            },
            None,
            30,
            7,
            CheckState.OK,
            "All certificates on 1 node(s) are valid",
        ),
        (
            # Certificate expiring soon - warning (20 days left)
            [{"type": "node", "node": "node1"}],
            {
                "node1": [
                    {
                        "filename": "pve-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=20)).timestamp(),
                    }
                ]
            },
            None,
            30,
            7,
            CheckState.WARNING,
            "expiring soon",
        ),
        (
            # Certificate expiring soon - critical (5 days left)
            [{"type": "node", "node": "node1"}],
            {
                "node1": [
                    {
                        "filename": "pve-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=5)).timestamp(),
                    }
                ]
            },
            None,
            30,
            7,
            CheckState.CRITICAL,
            "expiring soon",
        ),
        (
            # Certificate expired (-1 days)
            [{"type": "node", "node": "node1"}],
            {
                "node1": [
                    {
                        "filename": "pve-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=-1)).timestamp(),
                    }
                ]
            },
            None,
            30,
            7,
            CheckState.CRITICAL,
            "certificate(s) expired",
        ),
        (
            # Multiple nodes, one with expiring cert
            [{"type": "node", "node": "node1"}, {"type": "node", "node": "node2"}],
            {
                "node1": [
                    {
                        "filename": "pve-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=90)).timestamp(),
                    }
                ],
                "node2": [
                    {
                        "filename": "pve-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=5)).timestamp(),
                    }
                ],
            },
            None,
            30,
            7,
            CheckState.CRITICAL,
            "node2/pve-ssl.pem expires in",
        ),
        (
            # Specific node check - valid
            [{"type": "node", "node": "node1"}, {"type": "node", "node": "node2"}],
            {
                "node1": [
                    {
                        "filename": "pve-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=90)).timestamp(),
                    }
                ],
                "node2": [
                    {
                        "filename": "pve-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=5)).timestamp(),
                    }
                ],
            },
            "node1",
            30,
            7,
            CheckState.OK,
            "Certificate on node 'node1' is valid",
        ),
        (
            # Multiple certificates - pveproxy-ssl.pem preferred over pve-ssl.pem
            [{"type": "node", "node": "node1"}],
            {
                "node1": [
                    {
                        "filename": "pveproxy-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=5)).timestamp(),
                    },
                    {
                        "filename": "pve-ssl.pem",
                        "notafter": (datetime.now(timezone.utc) + timedelta(days=90)).timestamp(),
                    },
                ]
            },
            None,
            30,
            7,
            CheckState.CRITICAL,
            "node1/pveproxy-ssl.pem expires in",
        ),
    ],
    ids=[
        "all valid",
        "warning threshold",
        "critical threshold",
        "expired",
        "multi-node with expiring",
        "specific node valid",
        "pveproxy-ssl.pem preferred",
    ],
)
@patch.object(CheckPVE, "request")
def test_check_certificate(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
    cluster_resources: List[Dict],
    cert_data: Dict,
    node_filter: str,
    warning_days: int,
    critical_days: int,
    expected_state: CheckState,
    expected_message_part: str,
) -> None:
    """Test check_certificate with various scenarios."""

    def request_side_effect(url):
        if "cluster/resources" in url:
            return cluster_resources
        # Extract node name from URL
        for node_name in cert_data:
            if f"nodes/{node_name}/certificates" in url:
                return cert_data[node_name]
        return []

    mock_request.side_effect = request_side_effect

    pve_instance.options.node = node_filter
    pve_instance.options.threshold_warning = {None: CheckThreshold(warning_days)}
    pve_instance.options.threshold_critical = {None: CheckThreshold(critical_days)}
    pve_instance.check_certificate()

    assert expected_message_part in pve_instance.check_message
    assert pve_instance.check_result == expected_state


@patch.object(CheckPVE, "request")
def test_check_certificate_default_thresholds(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
) -> None:
    """Test check_certificate with default thresholds (30/7 days)."""
    cluster_resources = [{"type": "node", "node": "node1"}]
    # Certificate expires in 20 days - should trigger warning with default 30-day threshold
    cert_data = [
        {
            "filename": "pve-ssl.pem",
            "notafter": (datetime.now(timezone.utc) + timedelta(days=20)).timestamp(),
        }
    ]

    def request_side_effect(url):
        if "cluster/resources" in url:
            return cluster_resources
        elif "nodes/node1/certificates" in url:
            return cert_data
        return []

    mock_request.side_effect = request_side_effect

    pve_instance.options.node = None
    pve_instance.options.threshold_warning = {}
    pve_instance.options.threshold_critical = {}
    pve_instance.check_certificate()

    assert pve_instance.check_result == CheckState.WARNING
    assert "expiring soon" in pve_instance.check_message


@patch.object(CheckPVE, "request")
def test_check_certificate_node_not_found(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
) -> None:
    """Test check_certificate when specified node is not found."""
    cluster_resources = [{"type": "node", "node": "node1"}]

    mock_request.return_value = cluster_resources

    pve_instance.options.node = "node2"
    pve_instance.options.threshold_warning = {}
    pve_instance.options.threshold_critical = {}
    pve_instance.check_certificate()

    assert "Node 'node2' not found" in pve_instance.check_message
    assert pve_instance.check_result == CheckState.UNKNOWN


@patch.object(CheckPVE, "request")
def test_check_certificate_empty_response(
    mock_request: MagicMock,
    pve_instance: CheckPVE,
) -> None:
    """Test check_certificate with empty API response."""
    mock_request.return_value = None

    pve_instance.options.node = None
    pve_instance.options.threshold_warning = {}
    pve_instance.options.threshold_critical = {}
    pve_instance.check_certificate()

    assert "Could not fetch cluster resources from API" in pve_instance.check_message
    assert pve_instance.check_result == CheckState.UNKNOWN
