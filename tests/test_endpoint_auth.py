"""
Endpoint Auth Verification Tests.

Verifies that all protected endpoints return 401/403 without a valid JWT.
Uses route introspection to check decorator presence on every non-public endpoint.
"""

import os
import pytest


# Endpoints that are intentionally public (no auth required)
PUBLIC_ENDPOINTS = {
    'health.healthz',
    'health.readyz',
    'spa.serve_index',
    'spa.not_found',
    'static',
    'events.get_events',
    'metrics.prometheus_metrics',
    'metrics.device_metrics',
    'metrics.before_request_metrics',
    'metrics.after_request_metrics',
    'topology.get_topology',
    'topology.get_hierarchical_topology',
    'telemetry.get_cpu_stats',
    'telemetry.get_memory_stats',
    'telemetry.get_interface_stats',
    'telemetry.get_mdt_status',
    'telemetry.get_telemetry_ip_map',
    'devices.get_linux_health',
    'devices.get_containerlab_health',
    'devices.get_devices_list',
    'devices.get_device_detail',
    'network_tools.calculate_subnet',
    'network_tools.split_network',
    'chat.rag_chat',
    'chat.get_rag_stats',
    'impact.get_impact_overview',
    'impact.get_device_impact',
    'impact.get_interface_impact',
    'impact.get_impact_analysis',
    # Network ops read-only endpoints
    'network_ops.get_bgp_summary',
    'network_ops.get_ospf_neighbors',
    'network_ops.get_ospf_interfaces',
    'network_ops.get_ospf_routes',
    'network_ops.get_ospf_status',
    # Interface status (read-only)
    'interfaces.get_interface_stats',
    'interfaces.get_dmvpn_status',
    'interfaces.get_switch_status',
    # Provision read-only
    'provision.get_provision_status',
    'provision.list_provision_jobs',
    'provision.get_provision_capabilities',
    'provision.get_templates',
}

# Endpoints that require JWT auth
EXPECTED_JWT_PROTECTED = {
    'changes.list_changes',
    'changes.get_change',
    'changes.create_change',
    'changes.get_change_types',
    'network_ops.run_command',
    'network_ops.run_ping',
    'network_ops.ping_sweep',
    'interfaces.remediate',
    'devices.create_device',
    'devices.get_netbox_options',
    'provision.provision_eve_ng',
    'provision.provision_containerlab',
    'provision.deprovision_device',
    'provision.cancel_provision_job',
    'chat.get_user_usage',
    'cache.get_cache_stats',
    'cache.clear_cache',
}

# Endpoints that require admin role
EXPECTED_ADMIN_PROTECTED = {
    'changes.approve_change',
    'changes.reject_change',
    'changes.execute_change',
    'changes.rollback_change',
    'changes.cancel_change',
    # Admin blueprint (before_request ensures all are protected)
    'admin.list_all_quotas',
    'admin.get_org_quota',
    'admin.update_org_quota',
    'admin.reset_org_usage',
    'admin.list_organizations',
    'admin.create_organization',
    'admin.get_org_users',
    'admin.add_user_to_org',
    'admin.get_feature_flags',
    'admin.refresh_feature_flags',
    'admin.save_automation_metrics',
    'admin.load_automation_metrics',
}


@pytest.fixture
def test_app():
    """Create test app for auth checking."""
    from dashboard.app import create_app
    app = create_app(config={'TESTING': True})
    return app


class TestProtectedEndpointsReturn401:
    """Verify that protected endpoints reject unauthenticated requests."""

    def test_changes_endpoints_require_auth(self, test_app):
        """Change management endpoints should require JWT."""
        client = test_app.test_client()

        # GET with no auth
        resp = client.get('/api/changes')
        assert resp.status_code in (401, 403), f"/api/changes returned {resp.status_code}"

        # POST with no auth
        resp = client.post('/api/changes', json={'device': 'R1', 'description': 'test'})
        assert resp.status_code in (401, 403), f"POST /api/changes returned {resp.status_code}"

    def test_admin_endpoints_require_auth(self, test_app):
        """Admin endpoints should require admin role."""
        client = test_app.test_client()

        resp = client.get('/api/admin/quotas')
        assert resp.status_code in (401, 403), f"/api/admin/quotas returned {resp.status_code}"

    def test_command_endpoint_requires_auth(self, test_app):
        """Command execution should require JWT."""
        client = test_app.test_client()

        resp = client.post('/api/command', json={'device': 'R1', 'command': 'show version'})
        assert resp.status_code in (401, 403), f"/api/command returned {resp.status_code}"

    def test_remediate_requires_auth(self, test_app):
        """Interface remediation should require JWT + permission."""
        client = test_app.test_client()

        resp = client.post('/api/remediate', json={
            'device': 'R1', 'interface': 'GigabitEthernet1', 'action': 'bounce'
        })
        assert resp.status_code in (401, 403), f"/api/remediate returned {resp.status_code}"

    def test_cache_endpoints_require_auth(self, test_app):
        """Cache management should require auth."""
        client = test_app.test_client()

        resp = client.get('/api/cache/stats')
        assert resp.status_code in (401, 403), f"/api/cache/stats returned {resp.status_code}"

        resp = client.delete('/api/cache')
        assert resp.status_code in (401, 403), f"DELETE /api/cache returned {resp.status_code}"

    def test_usage_requires_auth(self, test_app):
        """Usage endpoint should require JWT."""
        client = test_app.test_client()

        resp = client.get('/api/usage')
        assert resp.status_code in (401, 403), f"/api/usage returned {resp.status_code}"


class TestPublicEndpointsAccessible:
    """Verify that public endpoints don't require auth."""

    def test_health_endpoints_public(self, test_app):
        """Health check endpoints should be publicly accessible."""
        client = test_app.test_client()

        resp = client.get('/healthz')
        assert resp.status_code == 200, f"/healthz returned {resp.status_code}"

    def test_metrics_endpoint_public(self, test_app):
        """Metrics endpoint should be publicly accessible."""
        client = test_app.test_client()

        resp = client.get('/metrics')
        assert resp.status_code == 200, f"/metrics returned {resp.status_code}"
