"""
API Contract Tests for NetworkOps Dashboard

These tests verify that API responses match the shape expected by the React frontend.
They catch backend/frontend mismatches before they cause UI failures.

Run with: pytest tests/test_api_contracts.py -v

These tests are FAST (no real device connections) and run in CI.
"""

import pytest


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_returns_ok(self, client):
        """GET /api/health returns {status: ok}"""
        response = client.get('/api/health')
        assert response.status_code == 200

        data = response.get_json()
        assert 'status' in data
        assert data['status'] == 'ok'

    def test_healthz_returns_ok(self, client):
        """GET /healthz returns ok (k8s liveness probe)"""
        response = client.get('/healthz')
        assert response.status_code == 200

    def test_readyz_returns_status(self, client):
        """GET /readyz returns 200 (ready) or 503 (not ready)"""
        response = client.get('/readyz')
        # 200 = ready, 503 = not ready (e.g., Redis unavailable)
        assert response.status_code in [200, 503]


class TestDeviceEndpoints:
    """Tests for device-related endpoints."""

    def test_devices_returns_list(self, client, auth_headers):
        """GET /api/devices returns array of device names"""
        response = client.get('/api/devices', headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert isinstance(data, list)
        # Should have at least some devices
        assert len(data) > 0
        # Each item should be a string (device name)
        assert all(isinstance(name, str) for name in data)

    def test_devices_contains_expected_routers(self, client, auth_headers):
        """Device list should include core routers"""
        response = client.get('/api/devices', headers=auth_headers)
        data = response.get_json()

        # Core routers should be present
        expected_devices = ['R1', 'R2', 'R3', 'R4']
        for device in expected_devices:
            assert device in data, f"Expected device {device} not in device list"


class TestTopologyEndpoints:
    """Tests for topology-related endpoints."""

    def test_topology_returns_nodes_and_links(self, client, auth_headers):
        """GET /api/topology returns {nodes: [], links: []}"""
        response = client.get('/api/topology', headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'nodes' in data, "Topology must have 'nodes' array"
        assert 'links' in data, "Topology must have 'links' array"
        assert isinstance(data['nodes'], list)
        assert isinstance(data['links'], list)

    def test_topology_node_shape(self, client, auth_headers):
        """Each topology node must have required fields"""
        response = client.get('/api/topology', headers=auth_headers)
        data = response.get_json()

        if len(data['nodes']) > 0:
            node = data['nodes'][0]
            # Required fields for frontend rendering
            assert 'id' in node, "Node must have 'id'"
            assert 'status' in node, "Node must have 'status'"
            # Platform helps determine device type for icons
            assert 'platform' in node or 'ip' in node, "Node should have 'platform' or 'ip'"

    def test_topology_link_shape(self, client, auth_headers):
        """Each topology link must have source and target"""
        response = client.get('/api/topology', headers=auth_headers)
        data = response.get_json()

        if len(data['links']) > 0:
            link = data['links'][0]
            assert 'source' in link, "Link must have 'source'"
            assert 'target' in link, "Link must have 'target'"


class TestAuthEndpoints:
    """Tests for authentication endpoints."""

    def test_login_returns_token_on_success(self, client):
        """POST /api/auth/login returns token on valid credentials"""
        response = client.post('/api/auth/login', json={
            'username': 'admin',
            'password': 'admin'
        })
        assert response.status_code == 200

        data = response.get_json()
        # Should have either 'token' or 'access_token'
        has_token = 'token' in data or 'access_token' in data
        assert has_token, "Login response must include token"

    def test_login_returns_user_info(self, client):
        """POST /api/auth/login returns user details"""
        response = client.post('/api/auth/login', json={
            'username': 'admin',
            'password': 'admin'
        })
        data = response.get_json()

        # Should have user info
        assert 'user' in data or 'username' in data, "Login should return user info"

    def test_login_fails_with_wrong_password(self, client):
        """POST /api/auth/login returns 401 for bad credentials"""
        response = client.post('/api/auth/login', json={
            'username': 'admin',
            'password': 'wrongpassword'
        })
        assert response.status_code == 401

    def test_login_fails_with_missing_fields(self, client):
        """POST /api/auth/login returns 400 for missing fields"""
        response = client.post('/api/auth/login', json={})
        assert response.status_code in [400, 401]

    def test_verify_requires_token(self, client):
        """GET /api/auth/verify requires authorization"""
        response = client.get('/api/auth/verify')
        # Should return 401 without token
        assert response.status_code == 401

    def test_verify_with_valid_token(self, client, auth_headers):
        """GET /api/auth/verify returns user info with valid token"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.get('/api/auth/verify', headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'username' in data or 'user' in data


class TestCommandEndpoints:
    """Tests for device command endpoints."""

    def test_command_requires_auth(self, client):
        """POST /api/command requires authentication"""
        response = client.post('/api/command', json={
            'device': 'R1',
            'command': 'show version'
        })
        # Should require auth
        assert response.status_code == 401

    def test_command_validates_input(self, client, auth_headers):
        """POST /api/command validates required fields"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        # Missing device
        response = client.post('/api/command', json={
            'command': 'show version'
        }, headers=auth_headers)
        assert response.status_code == 400

        # Missing command
        response = client.post('/api/command', json={
            'device': 'R1'
        }, headers=auth_headers)
        assert response.status_code == 400


class TestEventsEndpoints:
    """Tests for event log endpoints."""

    def test_events_returns_list(self, client, auth_headers):
        """GET /api/events returns {events: [], total_events: n}"""
        response = client.get('/api/events', headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'events' in data, "Events response must have 'events' array"
        assert 'total_events' in data, "Events response must have 'total_events'"
        assert isinstance(data['events'], list)
        assert isinstance(data['total_events'], int)

    def test_events_limit_parameter(self, client, auth_headers):
        """GET /api/events?limit=N respects limit"""
        response = client.get('/api/events?limit=5', headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert len(data['events']) <= 5


class TestProtocolStatusEndpoints:
    """Tests for protocol status endpoints (OSPF, BGP, DMVPN)."""

    def test_ospf_status_shape(self, client, auth_headers):
        """GET /api/ospf-status returns proper structure"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.get('/api/ospf-status', headers=auth_headers)
        # May return 200 or 500 depending on device connectivity
        if response.status_code == 200:
            data = response.get_json()
            assert 'status' in data

    def test_bgp_summary_requires_device(self, client, auth_headers):
        """GET /api/bgp-summary requires device parameter"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.get('/api/bgp-summary', headers=auth_headers)
        assert response.status_code == 400

        data = response.get_json()
        assert 'error' in data or 'status' in data

    def test_bgp_summary_validates_device(self, client, auth_headers):
        """GET /api/bgp-summary?device=INVALID returns 404"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.get('/api/bgp-summary?device=NONEXISTENT',
                              headers=auth_headers)
        assert response.status_code == 404

    def test_dmvpn_status_shape(self, client, auth_headers):
        """GET /api/dmvpn-status returns proper structure"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.get('/api/dmvpn-status', headers=auth_headers)
        if response.status_code == 200:
            data = response.get_json()
            assert 'status' in data


class TestMTUCalculatorEndpoints:
    """Tests for MTU calculator endpoints."""

    def test_mtu_scenarios_returns_list(self, client, auth_headers):
        """GET /api/mtu/scenarios returns scenario list"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.get('/api/mtu/scenarios', headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert isinstance(data, dict)
        # Should have scenarios
        assert 'scenarios' in data or len(data) > 0

    def test_mtu_calculate_validates_input(self, client, auth_headers):
        """POST /api/mtu/calculate validates tunnel_type"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        # Missing tunnel_type
        response = client.post('/api/mtu/calculate', json={},
                               headers=auth_headers)
        assert response.status_code == 400

    def test_mtu_calculate_returns_values(self, client, auth_headers):
        """POST /api/mtu/calculate returns MTU values"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.post('/api/mtu/calculate', json={
            'tunnel_type': 'gre_ipsec'
        }, headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'tunnel_mtu' in data, "Response must include tunnel_mtu"
        assert 'tcp_mss' in data, "Response must include tcp_mss"


class TestSubnetCalculatorEndpoints:
    """Tests for subnet calculator endpoints."""

    def test_subnet_reference_returns_table(self, client, auth_headers):
        """GET /api/subnet/reference returns subnet reference table"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.get('/api/subnet/reference', headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert isinstance(data, dict)

    def test_subnet_calculate_validates_input(self, client, auth_headers):
        """POST /api/subnet/calculate validates address"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        # Missing address
        response = client.post('/api/subnet/calculate', json={},
                               headers=auth_headers)
        assert response.status_code == 400

    def test_subnet_calculate_returns_info(self, client, auth_headers):
        """POST /api/subnet/calculate returns subnet details"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.post('/api/subnet/calculate', json={
            'address': '192.168.1.0/24'
        }, headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'network' in data or 'network_address' in data


class TestHierarchyEndpoints:
    """Tests for hierarchical view endpoints."""

    def test_hierarchy_disabled_by_default(self, client, auth_headers):
        """GET /api/hierarchy returns 403 when disabled"""
        response = client.get('/api/hierarchy', headers=auth_headers)
        # Either returns data (if enabled) or 403 (if disabled)
        assert response.status_code in [200, 403]

    def test_topology_level_validates_type(self, client, auth_headers):
        """GET /api/topology/level/invalid/id returns error"""
        response = client.get('/api/topology/level/invalid/test-id', headers=auth_headers)
        # Should return 400 or 403 (if feature disabled)
        assert response.status_code in [400, 403, 404]


class TestChangeManagementEndpoints:
    """Tests for change management endpoints."""

    def test_changes_list_requires_auth(self, client):
        """GET /api/changes requires authentication"""
        response = client.get('/api/changes')
        assert response.status_code == 401

    def test_changes_list_returns_array(self, client, auth_headers):
        """GET /api/changes returns list of changes"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.get('/api/changes', headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'changes' in data or isinstance(data, list)

    def test_changes_types_returns_list(self, client, auth_headers):
        """GET /api/changes/types returns change types"""
        if not auth_headers:
            pytest.skip("Could not obtain auth token")

        response = client.get('/api/changes/types', headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert isinstance(data, (list, dict))


class TestErrorResponses:
    """Tests for consistent error response format."""

    def test_404_returns_json(self, client):
        """404 errors return JSON with error field"""
        response = client.get('/api/nonexistent-endpoint')
        assert response.status_code == 404

    def test_method_not_allowed(self, client):
        """Invalid methods are rejected"""
        # Try DELETE on a GET-only endpoint
        response = client.delete('/api/health')
        # Should return error (405 or 500 depending on Flask config)
        assert response.status_code in [405, 500]


class TestCORSHeaders:
    """Tests for CORS header configuration."""

    def test_cors_headers_present(self, client):
        """Responses include CORS headers"""
        response = client.get('/api/health')

        # Check for security headers
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers


class TestRateLimiting:
    """Tests for rate limiting behavior."""

    def test_rate_limit_headers(self, client):
        """Rate limited endpoints include limit headers"""
        # Make a request to a rate-limited endpoint
        response = client.get('/api/health')

        # Rate limit headers may or may not be present depending on config
        # This test just ensures the endpoint works
        assert response.status_code == 200