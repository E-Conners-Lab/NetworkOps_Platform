"""
Unit tests for EVE-NG API client.

Tests use mocked responses - no actual EVE-NG server required.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import responses
import json

from core.eve_ng_client import (
    EVEClient,
    EVEClientError,
    EVEAuthError,
    EVEConnectionError,
    EVELabError,
    get_client,
    is_eve_ng_available,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def client():
    """Create EVE-NG client with test credentials."""
    return EVEClient(
        host="203.0.113.201",
        username="admin",
        password="eve",
        lab_path="/Test Lab.unl",
    )


@pytest.fixture
def mock_responses():
    """Enable responses mock for HTTP requests."""
    with responses.RequestsMock() as rsps:
        yield rsps


# =============================================================================
# Lab Path Encoding Tests
# =============================================================================


class TestLabPathEncoding:
    """Tests for lab path encoding."""

    def test_encode_simple_path(self, client):
        """Simple path without spaces."""
        assert client._encode_lab_path("/mylab.unl") == "mylab.unl"

    def test_encode_path_with_spaces(self, client):
        """Path with spaces should be URL-encoded."""
        assert client._encode_lab_path("/NetworkOps Lab.unl") == "NetworkOps%20Lab.unl"

    def test_encode_nested_path(self, client):
        """Nested path preserves slashes."""
        assert client._encode_lab_path("/folder/subfolder/lab.unl") == "folder/subfolder/lab.unl"

    def test_encode_nested_path_with_spaces(self, client):
        """Nested path with spaces."""
        result = client._encode_lab_path("/My Labs/Test Lab.unl")
        assert result == "My%20Labs/Test%20Lab.unl"

    def test_encode_path_without_leading_slash(self, client):
        """Path without leading slash."""
        assert client._encode_lab_path("mylab.unl") == "mylab.unl"

    def test_encode_special_characters(self, client):
        """Path with special characters."""
        result = client._encode_lab_path("/Lab (v1).unl")
        assert "%28" in result  # (
        assert "%29" in result  # )


# =============================================================================
# Authentication Tests
# =============================================================================


class TestAuthentication:
    """Tests for login/logout operations."""

    def test_login_success(self, client, mock_responses):
        """Successful login sets authenticated flag."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200, "status": "success", "message": "Logged in"},
            status=200,
        )

        result = client.login()

        assert result is True
        assert client.authenticated is True

    def test_login_invalid_credentials(self, client, mock_responses):
        """Invalid credentials raise EVEAuthError."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 401, "status": "fail", "message": "Invalid username or password"},
            status=401,
        )

        with pytest.raises(EVEAuthError) as exc_info:
            client.login()

        assert "Invalid credentials" in str(exc_info.value) or "Authentication required" in str(exc_info.value)
        assert client.authenticated is False

    def test_login_connection_error(self, client, mock_responses):
        """Connection error raises EVEConnectionError."""
        from requests.exceptions import ConnectionError as RequestsConnectionError

        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            body=RequestsConnectionError("Connection refused"),
        )

        with pytest.raises(EVEConnectionError):
            client.login()

    def test_logout_success(self, client, mock_responses):
        """Successful logout clears authenticated flag."""
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/auth/logout",
            json={"code": 200, "status": "success"},
            status=200,
        )
        client.authenticated = True

        result = client.logout()

        assert result is True
        assert client.authenticated is False


# =============================================================================
# Image Listing Tests
# =============================================================================


class TestImageListing:
    """Tests for image/template listing."""

    def test_get_images_all_types(self, client, mock_responses):
        """Get all available images."""
        # Mock auth
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        # Mock templates endpoint (returns dict of name -> description)
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/list/templates/",
            json={
                "code": 200,
                "data": {
                    "vios": "Cisco IOSv",
                    "veos": "Arista vEOS",
                    "c8000v": "Cisco C8000V",
                    "missing_image": "Not installed.missing",  # Should be filtered out
                },
            },
            status=200,
        )

        client.login()
        images = client.get_images()

        # Should have 3 images (missing_image filtered out)
        assert len(images) == 3
        assert any(i["name"] == "vios" for i in images)
        assert any(i["name"] == "veos" for i in images)
        assert any(i["name"] == "c8000v" for i in images)
        # Verify missing images are filtered out
        assert not any(i["name"] == "missing_image" for i in images)

    def test_get_images_filtered_type(self, client, mock_responses):
        """Get images filtered by keyword."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/list/templates/",
            json={
                "code": 200,
                "data": {
                    "vios": "Cisco IOSv",
                    "c8000v": "Cisco C8000V",
                    "veos": "Arista vEOS",
                },
            },
            status=200,
        )

        client.login()
        # Filter by "cisco" - should match vios and c8000v (in name or description)
        images = client.get_images(image_type="cisco")

        assert len(images) == 2
        assert any(i["name"] == "vios" for i in images)
        assert any(i["name"] == "c8000v" for i in images)
        assert not any(i["name"] == "veos" for i in images)

    def test_get_image_by_name(self, client, mock_responses):
        """Get specific image by name."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/list/templates/",
            json={
                "code": 200,
                "data": {
                    "vios": "Cisco IOSv",
                    "veos": "Arista vEOS",
                },
            },
            status=200,
        )

        client.login()
        image = client.get_image("vios")

        assert image is not None
        assert image["name"] == "vios"
        assert image["description"] == "Cisco IOSv"

    def test_get_image_not_found(self, client, mock_responses):
        """Get non-existent image returns None."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/list/templates/",
            json={
                "code": 200,
                "data": {
                    "vios": "Cisco IOSv",
                },
            },
            status=200,
        )

        client.login()
        image = client.get_image("nonexistent")

        assert image is None


# =============================================================================
# Lab Validation Tests
# =============================================================================


class TestLabValidation:
    """Tests for lab validation."""

    def test_validate_lab_exists(self, client, mock_responses):
        """Validate existing lab returns True."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl",
            json={"code": 200, "data": {"name": "Test Lab"}},
            status=200,
        )

        client.login()
        result = client.validate_lab("/Test Lab.unl")

        assert result is True

    def test_validate_lab_not_found(self, client, mock_responses):
        """Validate non-existent lab raises EVELabError."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Missing%20Lab.unl",
            json={"code": 404, "message": "Lab not found"},
            status=404,
        )

        client.login()
        with pytest.raises(EVELabError) as exc_info:
            client.validate_lab("/Missing Lab.unl")

        assert "not found" in str(exc_info.value).lower()


# =============================================================================
# Node Listing Tests
# =============================================================================


class TestNodeListing:
    """Tests for node listing."""

    def test_get_nodes(self, client, mock_responses):
        """Get nodes in a lab."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes",
            json={
                "code": 200,
                "data": {
                    "1": {"name": "R1", "template": "vios", "status": 2, "cpu": 1, "ram": 512},
                    "2": {"name": "R2", "template": "vios", "status": 0, "cpu": 1, "ram": 512},
                },
            },
            status=200,
        )

        client.login()
        nodes = client.get_nodes("/Test Lab.unl")

        assert len(nodes) == 2
        assert nodes[0]["name"] == "R1"
        assert nodes[0]["id"] == 1
        assert nodes[1]["name"] == "R2"
        assert nodes[1]["id"] == 2

    def test_get_node_interfaces(self, client, mock_responses):
        """Get interfaces for a node."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/1/interfaces",
            json={
                "code": 200,
                "data": {
                    "ethernet": {
                        "0": {"name": "e0", "network_id": 1},
                        "1": {"name": "e1", "network_id": 2},
                    },
                    "serial": {},
                },
            },
            status=200,
        )

        client.login()
        interfaces = client.get_node_interfaces(1, "/Test Lab.unl")

        assert len(interfaces) == 2
        assert interfaces[0]["name"] == "e0"
        assert interfaces[0]["network_id"] == 1


# =============================================================================
# Network Management Tests
# =============================================================================


class TestNetworkManagement:
    """Tests for network operations."""

    def test_get_networks(self, client, mock_responses):
        """Get networks in a lab."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/networks",
            json={
                "code": 200,
                "data": {
                    "1": {"name": "pnet1", "type": "pnet1"},
                    "2": {"name": "Internal", "type": "bridge"},
                },
            },
            status=200,
        )

        client.login()
        networks = client.get_networks("/Test Lab.unl")

        assert len(networks) == 2
        assert any(n["name"] == "pnet1" for n in networks)

    def test_get_mgmt_network_found(self, client, mock_responses):
        """Find management network by name."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/networks",
            json={
                "code": 200,
                "data": {
                    "1": {"name": "pnet1", "type": "pnet1", "visibility": 1},
                },
            },
            status=200,
        )

        client.login()
        mgmt_net = client.get_or_validate_mgmt_network("/Test Lab.unl")

        assert mgmt_net is not None
        assert mgmt_net["name"] == "pnet1"

    def test_get_mgmt_network_not_found(self, client, mock_responses):
        """Return None when management network not found."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/networks",
            json={
                "code": 200,
                "data": {
                    "1": {"name": "Internal", "type": "bridge"},
                },
            },
            status=200,
        )

        client.login()
        mgmt_net = client.get_or_validate_mgmt_network("/Test Lab.unl")

        assert mgmt_net is None


# =============================================================================
# Context Manager Tests
# =============================================================================


class TestContextManager:
    """Tests for context manager protocol."""

    def test_context_manager_login_logout(self, mock_responses):
        """Context manager logs in and out."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/auth/logout",
            json={"code": 200},
            status=200,
        )

        with EVEClient(host="203.0.113.201") as client:
            assert client.authenticated is True

        assert client.authenticated is False


# =============================================================================
# Utility Function Tests
# =============================================================================


class TestUtilityFunctions:
    """Tests for module-level utility functions."""

    @patch("core.eve_ng_client.EVEClient")
    def test_is_eve_ng_available_true(self, mock_client_class):
        """is_eve_ng_available returns True when server is reachable."""
        mock_instance = Mock()
        mock_instance.is_connected.return_value = True
        mock_client_class.return_value = mock_instance

        with patch.dict("os.environ", {"EVE_NG_HOST": "203.0.113.201"}):
            result = is_eve_ng_available()

        assert result is True

    @patch("core.eve_ng_client.EVEClient")
    def test_is_eve_ng_available_no_host(self, mock_client_class):
        """is_eve_ng_available returns False when host not set."""
        with patch.dict("os.environ", {"EVE_NG_HOST": ""}, clear=True):
            result = is_eve_ng_available()

        assert result is False


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_api_error_parsing(self, client, mock_responses):
        """API errors are properly parsed."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl",
            json={"code": 500, "message": "Internal server error"},
            status=500,
        )

        client.login()
        with pytest.raises(EVEClientError) as exc_info:
            client.validate_lab()

        assert "Internal server error" in str(exc_info.value) or "API error" in str(exc_info.value)

    def test_timeout_handling(self, client, mock_responses):
        """Timeouts are properly handled."""
        from requests.exceptions import Timeout

        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            body=Timeout("Connection timed out"),
        )

        with pytest.raises(EVEConnectionError) as exc_info:
            client.login()

        assert "timed out" in str(exc_info.value).lower()


# =============================================================================
# Correlation ID Tests
# =============================================================================


class TestCorrelationIds:
    """Tests for correlation ID logging."""

    def test_login_with_correlation_id(self, client, mock_responses, caplog):
        """Correlation ID appears in log messages."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )

        import logging
        caplog.set_level(logging.INFO)

        client.login(correlation_id="corr-12345")

        # Check that correlation ID appears in logs
        assert any("corr-12345" in record.message for record in caplog.records)


# =============================================================================
# Phase 5: Node Write Operations Tests
# =============================================================================


class TestCreateNode:
    """Tests for node creation."""

    def test_create_node_success(self, client, mock_responses):
        """Create node returns node info with ID."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes",
            json={"code": 201, "data": {"id": 10}},
            status=201,
        )

        client.login()
        result = client.create_node(
            name="R8",
            template="vios",
            cpu=2,
            ram=2048,
            ethernet=4,
        )

        assert result["id"] == 10
        assert result["name"] == "R8"
        assert result["template"] == "vios"

    def test_create_node_api_error(self, client, mock_responses):
        """Create node raises EVELabError on failure."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes",
            json={"code": 400, "message": "Template not found"},
            status=400,
        )

        client.login()
        with pytest.raises(EVELabError) as exc_info:
            client.create_node(name="R8", template="invalid_template")

        assert "failed to create" in str(exc_info.value).lower()


class TestDeleteNode:
    """Tests for node deletion."""

    def test_delete_node_success(self, client, mock_responses):
        """Delete node returns True on success."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.DELETE,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10",
            json={"code": 200, "message": "Node deleted"},
            status=200,
        )

        client.login()
        result = client.delete_node(node_id=10)

        assert result is True

    def test_delete_node_not_found_succeeds(self, client, mock_responses):
        """Delete non-existent node returns True (idempotent)."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.DELETE,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/99",
            json={"code": 404, "message": "Node not found"},
            status=404,
        )

        client.login()
        result = client.delete_node(node_id=99)

        assert result is True  # Still succeeds - node is already gone


class TestConnectToNetwork:
    """Tests for interface-to-network connections."""

    def test_connect_to_network_success(self, client, mock_responses):
        """Connect interface to network returns True."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.PUT,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/interfaces",
            json={"code": 200},
            status=200,
        )

        client.login()
        result = client.connect_to_network(
            node_id=10,
            interface_id=3,
            network_id=1,
        )

        assert result is True

    def test_connect_to_network_failure(self, client, mock_responses):
        """Connect interface raises EVELabError on failure."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.PUT,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/interfaces",
            json={"code": 400, "message": "Network not found"},
            status=400,
        )

        client.login()
        with pytest.raises(EVELabError):
            client.connect_to_network(node_id=10, interface_id=3, network_id=99)


class TestStartStopNode:
    """Tests for starting and stopping nodes."""

    def test_start_node_success(self, client, mock_responses):
        """Start node returns True on success."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/start",
            json={"code": 200, "message": "Node started"},
            status=200,
        )

        client.login()
        result = client.start_node(node_id=10)

        assert result is True

    def test_stop_node_success(self, client, mock_responses):
        """Stop node returns True on success."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/stop",
            json={"code": 200, "message": "Node stopped"},
            status=200,
        )

        client.login()
        result = client.stop_node(node_id=10)

        assert result is True


class TestWaitForBoot:
    """Tests for boot wait functionality."""

    @patch("socket.socket")
    def test_wait_for_boot_immediate_success(self, mock_socket_class, client):
        """Node immediately reachable returns True."""
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        result = client.wait_for_boot(
            node_ip="10.255.255.48",
            timeout=30,
            retry_interval=1,
        )

        assert result is True

    @patch("time.sleep")
    @patch("socket.socket")
    def test_wait_for_boot_timeout(self, mock_socket_class, mock_sleep, client):
        """Node unreachable raises EVELabError after timeout."""
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 1  # Connection refused
        mock_socket_class.return_value = mock_sock

        with pytest.raises(EVELabError) as exc_info:
            client.wait_for_boot(
                node_ip="10.255.255.99",
                timeout=2,  # Short timeout for test
                retry_interval=1,
            )

        assert "not reachable" in str(exc_info.value).lower()


class TestGetNodeByName:
    """Tests for finding nodes by name."""

    def test_get_node_by_name_found(self, client, mock_responses):
        """Find existing node by name."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes",
            json={
                "code": 200,
                "data": {
                    "1": {"name": "R1", "template": "vios"},
                    "2": {"name": "R2", "template": "vios"},
                },
            },
            status=200,
        )

        client.login()
        node = client.get_node_by_name("R2")

        assert node is not None
        assert node["name"] == "R2"
        assert node["id"] == 2

    def test_get_node_by_name_not_found(self, client, mock_responses):
        """Return None when node not found."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes",
            json={"code": 200, "data": {}},
            status=200,
        )

        client.login()
        node = client.get_node_by_name("NonExistent")

        assert node is None


class TestProvisionNode:
    """Tests for the full provisioning workflow."""

    def test_provision_node_success(self, client, mock_responses):
        """Full provisioning workflow succeeds."""
        # Auth
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        # Get networks (for mgmt network check)
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/networks",
            json={
                "code": 200,
                "data": {"1": {"name": "pnet1", "type": "pnet1", "id": 1}},
            },
            status=200,
        )
        # Create node
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes",
            json={"code": 201, "data": {"id": 10}},
            status=201,
        )
        # Connect interface
        mock_responses.add(
            responses.PUT,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/interfaces",
            json={"code": 200},
            status=200,
        )
        # Start node
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/start",
            json={"code": 200},
            status=200,
        )

        client.login()
        with patch.object(client, "wait_for_boot", return_value=True):
            with patch.object(client, "apply_ztp_config", return_value=True):
                result = client.provision_node(
                    name="R8",
                    template="vios",
                    mgmt_ip="10.255.255.48/24",
                )

        assert result["status"] == "success"
        assert result["node_id"] == 10
        assert result["name"] == "R8"

    def test_provision_node_no_mgmt_network(self, client, mock_responses):
        """Provisioning fails if management network missing."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/networks",
            json={"code": 200, "data": {}},  # No networks
            status=200,
        )

        client.login()
        with pytest.raises(EVELabError) as exc_info:
            client.provision_node(
                name="R8",
                template="vios",
                mgmt_ip="10.255.255.48/24",
            )

        assert "not found" in str(exc_info.value).lower()

    def test_provision_node_rollback_on_start_failure(self, client, mock_responses):
        """Provisioning rolls back on start failure."""
        # Auth
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        # Get networks
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/networks",
            json={
                "code": 200,
                "data": {"1": {"name": "pnet1", "type": "pnet1", "id": 1}},
            },
            status=200,
        )
        # Create node
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes",
            json={"code": 201, "data": {"id": 10}},
            status=201,
        )
        # Connect interface
        mock_responses.add(
            responses.PUT,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/interfaces",
            json={"code": 200},
            status=200,
        )
        # Start fails
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/start",
            json={"code": 500, "message": "Insufficient resources"},
            status=500,
        )
        # Stop (during rollback, may fail)
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/stop",
            json={"code": 200},
            status=200,
        )
        # Delete (rollback)
        mock_responses.add(
            responses.DELETE,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10",
            json={"code": 200},
            status=200,
        )

        client.login()
        with pytest.raises(EVELabError):
            client.provision_node(
                name="R8",
                template="vios",
                mgmt_ip="10.255.255.48/24",
                wait_for_boot=False,  # Skip boot wait for test
            )

        # Verify DELETE was called (rollback)
        delete_calls = [c for c in mock_responses.calls if c.request.method == "DELETE"]
        assert len(delete_calls) == 1


class TestDeprovisionNode:
    """Tests for node deprovisioning."""

    def test_deprovision_by_id(self, client, mock_responses):
        """Deprovision node by ID."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/stop",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.DELETE,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10",
            json={"code": 200},
            status=200,
        )

        client.login()
        result = client.deprovision_node(node_id=10)

        assert result is True

    def test_deprovision_by_name(self, client, mock_responses):
        """Deprovision node by name (finds ID first)."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes",
            json={
                "code": 200,
                "data": {"10": {"name": "R8", "template": "vios"}},
            },
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10/stop",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.DELETE,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes/10",
            json={"code": 200},
            status=200,
        )

        client.login()
        result = client.deprovision_node(name="R8")

        assert result is True

    def test_deprovision_not_found_succeeds(self, client, mock_responses):
        """Deprovision non-existent node returns True (idempotent)."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )
        mock_responses.add(
            responses.GET,
            "https://203.0.113.201/api/labs/Test%20Lab.unl/nodes",
            json={"code": 200, "data": {}},
            status=200,
        )

        client.login()
        result = client.deprovision_node(name="NonExistent")

        assert result is True

    def test_deprovision_requires_id_or_name(self, client, mock_responses):
        """Deprovision raises error if neither ID nor name provided."""
        mock_responses.add(
            responses.POST,
            "https://203.0.113.201/api/auth/login",
            json={"code": 200},
            status=200,
        )

        client.login()
        with pytest.raises(EVELabError) as exc_info:
            client.deprovision_node()  # No node_id or name

        assert "node_id or name required" in str(exc_info.value).lower()
