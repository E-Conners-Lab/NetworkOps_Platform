"""
Tests for critical security fixes:
1. Shell injection in containerlab send_config / run_command
2. Path traversal in config rollback/list/compare
3. Command injection via interface name parameter
4. Arbitrary filesystem read via /api/ingest
5. Auth enforcement on previously-open endpoints

All tests mock subprocess and file I/O -- no live devices or filesystem access needed.
"""

import json
import os
import re
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

import pytest


# ---------------------------------------------------------------------------
# Critical 1: Shell injection in containerlab commands
# ---------------------------------------------------------------------------

class TestContainerlabShellInjection:
    """Verify that shell metacharacters in commands/config are rejected."""

    def test_run_command_rejects_shell_injection_semicolon(self):
        """run_command should reject commands with shell metacharacters."""
        from core.containerlab import run_command

        # Simulate device lookup returning a containerlab device
        mock_devices = {
            "edge1": {
                "container": "clab-datacenter-edge1",
                "device_type": "containerlab_frr",
                "host": "172.20.20.3",
            }
        }
        with patch("core.containerlab._get_devices", return_value=mock_devices):
            result = run_command("edge1", 'show ip route"; rm -rf /')
            assert "error" in result.lower() or "blocked" in result.lower()

    def test_run_command_rejects_backtick_injection(self):
        from core.containerlab import run_command

        mock_devices = {
            "edge1": {
                "container": "clab-datacenter-edge1",
                "device_type": "containerlab_frr",
                "host": "172.20.20.3",
            }
        }
        with patch("core.containerlab._get_devices", return_value=mock_devices):
            result = run_command("edge1", "show `whoami`")
            assert "error" in result.lower() or "blocked" in result.lower()

    def test_run_command_rejects_dollar_paren(self):
        from core.containerlab import run_command

        mock_devices = {
            "edge1": {
                "container": "clab-datacenter-edge1",
                "device_type": "containerlab_frr",
                "host": "172.20.20.3",
            }
        }
        with patch("core.containerlab._get_devices", return_value=mock_devices):
            result = run_command("edge1", "show $(cat /etc/passwd)")
            assert "error" in result.lower() or "blocked" in result.lower()

    def test_run_command_rejects_pipe(self):
        from core.containerlab import run_command

        mock_devices = {
            "edge1": {
                "container": "clab-datacenter-edge1",
                "device_type": "containerlab_frr",
                "host": "172.20.20.3",
            }
        }
        with patch("core.containerlab._get_devices", return_value=mock_devices):
            result = run_command("edge1", "show ip route | cat /etc/shadow")
            assert "error" in result.lower() or "blocked" in result.lower()

    def test_run_command_allows_safe_show_command(self):
        """Legitimate show commands should still work."""
        from core.containerlab import run_command

        mock_devices = {
            "edge1": {
                "container": "clab-datacenter-edge1",
                "device_type": "containerlab_frr",
                "host": "172.20.20.3",
            }
        }
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "192.168.1.0/24 via 10.0.0.1"
        mock_result.stderr = ""

        with patch("core.containerlab._get_devices", return_value=mock_devices), \
             patch("subprocess.run", return_value=mock_result):
            result = run_command("edge1", "show ip route")
            assert "192.168.1.0" in result

    def test_send_config_rejects_shell_injection(self):
        """send_config containerlab path should reject shell metacharacters."""
        import asyncio
        from mcp_tools.device import send_config

        mock_devices = {
            "edge1": {
                "container": "clab-datacenter-edge1",
                "device_type": "containerlab_frr",
                "host": "172.20.20.3",
            }
        }
        with patch("mcp_tools.device.DEVICES", mock_devices), \
             patch("mcp_tools.device.is_containerlab_device", return_value=True):
            result = asyncio.run(send_config("edge1", 'interface eth0"; rm -rf /'))
            parsed = json.loads(result)
            assert "error" in parsed
            assert "blocked" in parsed["error"].lower() or "shell" in parsed["error"].lower()

    def test_send_config_rejects_newline_escape(self):
        """Newline in config should not allow command escape."""
        import asyncio
        from mcp_tools.device import send_config

        mock_devices = {
            "edge1": {
                "container": "clab-datacenter-edge1",
                "device_type": "containerlab_frr",
                "host": "172.20.20.3",
            }
        }
        with patch("mcp_tools.device.DEVICES", mock_devices), \
             patch("mcp_tools.device.is_containerlab_device", return_value=True):
            result = asyncio.run(send_config("edge1", 'interface eth0\n"; cat /etc/passwd'))
            parsed = json.loads(result)
            assert "error" in parsed

    def test_send_config_allows_safe_config(self):
        """Legitimate config commands should still work."""
        import asyncio
        from mcp_tools.device import send_config

        mock_devices = {
            "edge1": {
                "container": "clab-datacenter-edge1",
                "device_type": "containerlab_frr",
                "host": "172.20.20.3",
            }
        }
        mock_result = MagicMock()
        mock_result.stdout = "Configuration applied"
        mock_result.stderr = ""

        with patch("mcp_tools.device.DEVICES", mock_devices), \
             patch("mcp_tools.device.is_containerlab_device", return_value=True), \
             patch("subprocess.run", return_value=mock_result):
            result = asyncio.run(send_config("edge1", "interface eth0\nip address 10.0.0.1/24"))
            # Should not contain "error" about blocked chars
            # (the actual subprocess is mocked, so it returns the mock result)
            assert "Configuration applied" in result or "error" not in result.lower()

    def test_run_command_rejects_double_quote_escape(self):
        """Double quotes used to break out of the vtysh -c argument."""
        from core.containerlab import run_command

        mock_devices = {
            "edge1": {
                "container": "clab-datacenter-edge1",
                "device_type": "containerlab_frr",
                "host": "172.20.20.3",
            }
        }
        with patch("core.containerlab._get_devices", return_value=mock_devices):
            result = run_command("edge1", 'show ip route" && cat /etc/passwd && echo "')
            assert "error" in result.lower() or "blocked" in result.lower()


# ---------------------------------------------------------------------------
# Critical 2: Path traversal in config backup/rollback/compare
# ---------------------------------------------------------------------------

class TestPathTraversal:
    """Verify that path traversal attempts are blocked."""

    def test_rollback_rejects_absolute_path(self):
        """rollback_config should reject absolute paths outside backup dir."""
        import asyncio
        from mcp_tools.config import rollback_config

        with patch("mcp_tools.config.DEVICES", {"R1": {"device_type": "cisco_xe"}}), \
             patch("mcp_tools.config.is_cisco_device", return_value=True):
            result = asyncio.run(rollback_config("R1", backup_file="/etc/passwd"))
            parsed = json.loads(result)
            assert "error" in parsed
            assert "outside" in parsed["error"].lower() or "traversal" in parsed["error"].lower()

    def test_rollback_rejects_dot_dot_traversal(self):
        """rollback_config should reject ../../../etc/passwd."""
        import asyncio
        from mcp_tools.config import rollback_config

        with patch("mcp_tools.config.DEVICES", {"R1": {"device_type": "cisco_xe"}}), \
             patch("mcp_tools.config.is_cisco_device", return_value=True):
            result = asyncio.run(
                rollback_config("R1", backup_file="../../../etc/passwd")
            )
            parsed = json.loads(result)
            assert "error" in parsed
            assert "outside" in parsed["error"].lower() or "traversal" in parsed["error"].lower()

    def test_rollback_rejects_jwt_secret_read(self):
        """rollback_config should not allow reading dashboard/auth/config.py."""
        import asyncio
        from mcp_tools.config import rollback_config

        with patch("mcp_tools.config.DEVICES", {"R1": {"device_type": "cisco_xe"}}), \
             patch("mcp_tools.config.is_cisco_device", return_value=True):
            result = asyncio.run(
                rollback_config(
                    "R1",
                    backup_file="../../dashboard/auth/config.py"
                )
            )
            parsed = json.loads(result)
            assert "error" in parsed

    def test_list_backups_rejects_traversal(self):
        """list_backups should reject device names with path traversal."""
        import asyncio
        from mcp_tools.config import list_backups

        result = asyncio.run(list_backups("../../etc"))
        parsed = json.loads(result)
        # Should either error or return empty, not list /etc contents
        if "error" in parsed:
            assert "traversal" in parsed["error"].lower() or "invalid" in parsed["error"].lower()
        else:
            # If no error, backups list should be empty (not listing /etc)
            assert parsed.get("total_backups", 0) == 0

    def test_compare_configs_rejects_file_traversal(self):
        """compare_configs should reject file paths outside backup dir."""
        import asyncio
        from mcp_tools.config import compare_configs

        result = asyncio.run(
            compare_configs(
                device1=None,
                file1="/etc/passwd",
                file2="/etc/shadow"
            )
        )
        parsed = json.loads(result)
        assert "error" in parsed

    def test_rollback_allows_valid_backup(self):
        """Legitimate backup file within the backup directory should work."""
        import asyncio
        from mcp_tools.config import rollback_config

        # Create a temp backup dir structure
        backup_dir = Path(__file__).parent.parent / "data" / "config_backups" / "R1"
        backup_dir.mkdir(parents=True, exist_ok=True)
        test_backup = backup_dir / "R1_test_20260101_120000.cfg"
        test_backup.write_text("hostname R1\ninterface Gi1\n ip address 10.0.0.1 255.255.255.0")

        try:
            with patch("mcp_tools.config.DEVICES", {"R1": {"device_type": "cisco_xe"}}), \
                 patch("mcp_tools.config.is_cisco_device", return_value=True):
                # Use backup_label to find the test file
                result = asyncio.run(rollback_config("R1", backup_label="test_20260101"))
                parsed = json.loads(result)
                # Should be a valid preview (dry_run=True by default), not a path error
                assert parsed.get("status") in ("preview", "no_changes", "error")
                # If error, it should be about device connection, not path traversal
                if "error" in parsed:
                    assert "outside" not in parsed.get("error", "").lower()
        finally:
            test_backup.unlink(missing_ok=True)

    def test_backup_label_glob_injection(self):
        """backup_label with glob chars should not escape the backup dir."""
        import asyncio
        from mcp_tools.config import rollback_config

        with patch("mcp_tools.config.DEVICES", {"R1": {"device_type": "cisco_xe"}}), \
             patch("mcp_tools.config.is_cisco_device", return_value=True):
            result = asyncio.run(
                rollback_config("R1", backup_label="../../*")
            )
            parsed = json.loads(result)
            # Should not find files outside the device backup dir
            assert "error" in parsed


# ---------------------------------------------------------------------------
# Critical 3: Command injection via interface name in interfaces.py
# ---------------------------------------------------------------------------

class TestInterfaceNameInjection:
    """Verify interface name validation blocks shell metacharacters.

    The regex pattern used in interfaces.py:
        ^[A-Za-z][A-Za-z0-9/._-]{0,63}$
    We test the regex directly to avoid import chain issues
    (dashboard.routes.__init__ pulls in auth which needs sys.path setup).
    """

    # Copy of the regex from dashboard/routes/interfaces.py line 20
    INTERFACE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9/._-]{0,63}$')

    def test_rejects_semicolon(self):
        """Interface names with ';' should be rejected."""
        assert not self.INTERFACE_RE.match('GigabitEthernet0/0; cat /etc/passwd')

    def test_rejects_backtick(self):
        """Interface names with backticks should be rejected."""
        assert not self.INTERFACE_RE.match('Gi0/0`whoami`')

    def test_rejects_pipe(self):
        """Interface names with '|' should be rejected."""
        assert not self.INTERFACE_RE.match('Gi0/0 | cat /etc/shadow')

    def test_rejects_dollar(self):
        """Interface names with '$()' should be rejected."""
        assert not self.INTERFACE_RE.match('Gi0/0$(rm -rf /)')

    def test_rejects_ampersand(self):
        """Interface names with '&&' should be rejected."""
        assert not self.INTERFACE_RE.match('Gi0/0 && whoami')

    def test_rejects_empty(self):
        """Empty interface names should be rejected."""
        assert not self.INTERFACE_RE.match('')

    def test_rejects_starting_with_digit(self):
        """Interface names starting with a digit should be rejected."""
        assert not self.INTERFACE_RE.match('0Gi0/0')

    def test_accepts_cisco_names(self):
        """Legitimate Cisco interface names should pass validation."""
        valid = [
            'GigabitEthernet0/0/0',
            'Loopback0',
            'Tunnel100',
            'Vlan10',
            'Port-channel1',
            'eth0',
            'eth1.100',
            'Gi0/0/0',
        ]
        for name in valid:
            assert self.INTERFACE_RE.match(name), f"Should accept: {name}"

    def test_endpoint_rejects_injection_via_api(self, client, auth_headers):
        """GET /api/interface/<device>/<intf> rejects malicious names."""
        # Use a name without '/' since Flask <interface> param doesn't match '/'
        response = client.get(
            '/api/interface/R1/Gi0;whoami',
            headers=auth_headers
        )
        # Should return 400 (validation error), not execute the command
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Critical 4: Arbitrary filesystem read via /api/ingest
# ---------------------------------------------------------------------------

class TestIngestPathTraversal:
    """Verify /api/ingest restricts paths to project directory."""

    def test_ingest_requires_admin_auth(self, client):
        """POST /api/ingest without auth returns 401."""
        response = client.post('/api/ingest', json={
            'path': '/tmp/test.txt'
        })
        assert response.status_code == 401

    def test_ingest_rejects_absolute_path_outside_project(self, client, auth_headers):
        """POST /api/ingest with /etc/passwd path returns 400."""
        response = client.post('/api/ingest', json={
            'path': '/etc/passwd'
        }, headers=auth_headers)
        # Either 400 (validation) or 403 (admin required)
        assert response.status_code in [400, 403]

    def test_ingest_rejects_traversal(self, client, auth_headers):
        """POST /api/ingest with ../../ traversal returns 400."""
        response = client.post('/api/ingest', json={
            'path': '../../../../etc/shadow'
        }, headers=auth_headers)
        assert response.status_code in [400, 403]


# ---------------------------------------------------------------------------
# Critical 5: Auth enforcement on previously-open endpoints
# ---------------------------------------------------------------------------

class TestAuthEnforcement:
    """Verify that previously-open endpoints now require JWT auth."""

    @pytest.mark.parametrize("endpoint", [
        '/api/devices',
        '/api/topology',
        '/api/events',
        '/api/hierarchy',
        '/api/mtu/scenarios',
        '/api/subnet/reference',
    ])
    def test_read_endpoints_require_auth(self, client, endpoint):
        """GET endpoints that were previously open now return 401 without token."""
        response = client.get(endpoint)
        assert response.status_code == 401, (
            f"{endpoint} should require auth but returned {response.status_code}"
        )

    @pytest.mark.parametrize("endpoint", [
        '/api/mtu/calculate',
        '/api/subnet/calculate',
        '/api/subnet/split',
        '/api/subnet/convert',
    ])
    def test_post_endpoints_require_auth(self, client, endpoint):
        """POST endpoints that were previously open now return 401 without token."""
        response = client.post(endpoint, json={})
        assert response.status_code == 401, (
            f"{endpoint} should require auth but returned {response.status_code}"
        )

    def test_health_endpoints_remain_open(self, client):
        """Health probes should NOT require auth (k8s compatibility)."""
        for endpoint in ['/api/health', '/healthz', '/readyz']:
            response = client.get(endpoint)
            assert response.status_code in [200, 503], (
                f"{endpoint} should be open but returned {response.status_code}"
            )
