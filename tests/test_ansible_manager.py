"""
Tests for Ansible Manager - Playbook execution and inventory management.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from core.ansible_manager import (
    AnsibleManager, PlaybookResult, PlaybookInfo,
    get_ansible, run_playbook,
)


class TestPlaybookResult:
    """Tests for PlaybookResult dataclass"""

    def test_successful_result(self):
        """Create successful playbook result"""
        result = PlaybookResult(
            playbook="health_check",
            success=True,
            ok=10,
            changed=2,
            failed=0,
            skipped=1,
            unreachable=0,
            hosts={"R1": {"ok": 5, "changed": 1}, "R2": {"ok": 5, "changed": 1}},
            elapsed_time=15.5,
        )

        assert result.success is True
        assert result.ok == 10
        assert result.changed == 2
        assert result.total_hosts == 2
        assert result.failed_hosts() == []
        assert set(result.successful_hosts()) == {"R1", "R2"}

    def test_failed_result(self):
        """Create failed playbook result"""
        result = PlaybookResult(
            playbook="deploy_changes",
            success=False,
            ok=5,
            changed=0,
            failed=2,
            hosts={
                "R1": {"ok": 5, "failed": 0},
                "R2": {"ok": 0, "failed": 2, "unreachable": False},
            },
            elapsed_time=30.0,
        )

        assert result.success is False
        assert result.failed == 2
        assert "R2" in result.failed_hosts()

    def test_unreachable_hosts(self):
        """Handle unreachable hosts"""
        result = PlaybookResult(
            playbook="backup_configs",
            success=False,
            ok=3,
            failed=0,
            unreachable=1,
            hosts={
                "R1": {"ok": 3, "failed": 0, "unreachable": False},
                "R2": {"ok": 0, "failed": 0, "unreachable": True},
            },
            elapsed_time=10.0,
        )

        assert result.success is False
        assert result.unreachable == 1
        assert "R2" in result.failed_hosts()

    def test_to_dict(self):
        """Convert result to dictionary"""
        result = PlaybookResult(
            playbook="test",
            success=True,
            ok=5,
            changed=2,
            failed=0,
            skipped=1,
            unreachable=0,
            hosts={"R1": {"ok": 5}},
            elapsed_time=5.123,
        )

        d = result.to_dict()

        assert d["playbook"] == "test"
        assert d["success"] is True
        assert d["summary"]["ok"] == 5
        assert d["summary"]["changed"] == 2
        assert d["elapsed_time"] == 5.12  # Rounded


class TestPlaybookInfo:
    """Tests for PlaybookInfo dataclass"""

    def test_basic_info(self):
        """Create basic playbook info"""
        info = PlaybookInfo(
            name="health_check",
            path="/path/to/health_check.yml",
            description="Check device health",
            hosts="cisco_routers",
        )

        assert info.name == "health_check"
        assert info.hosts == "cisco_routers"
        assert info.tags == []

    def test_to_dict(self):
        """Convert info to dictionary"""
        info = PlaybookInfo(
            name="backup_configs",
            path="/path/to/backup_configs.yml",
            description="Backup device configurations",
            hosts="all",
            tags=["backup", "maintenance"],
        )

        d = info.to_dict()

        assert d["name"] == "backup_configs"
        assert d["description"] == "Backup device configurations"
        assert "backup" in d["tags"]


class TestAnsibleManager:
    """Tests for AnsibleManager class"""

    def test_list_playbooks(self):
        """Should list available playbooks"""
        manager = AnsibleManager()
        playbooks = manager.list_playbooks()

        # Should find existing playbooks
        assert len(playbooks) >= 4  # health_check, backup_configs, etc.

        # Check playbook names
        playbook_names = [p.name for p in playbooks]
        assert "health_check" in playbook_names
        assert "backup_configs" in playbook_names

    def test_playbook_info_parsing(self):
        """Should parse playbook metadata"""
        manager = AnsibleManager()
        playbooks = manager.list_playbooks()

        health_check = next(
            (p for p in playbooks if p.name == "health_check"),
            None
        )

        assert health_check is not None
        assert "Health check" in health_check.description or "health" in health_check.description.lower()

    def test_get_inventory(self):
        """Should get inventory information"""
        manager = AnsibleManager()
        inventory = manager.get_inventory()

        # Should have structure with hosts
        assert "_meta" in inventory or "all" in inventory

    def test_get_inventory_specific_host(self):
        """Should get specific host info"""
        manager = AnsibleManager()
        host_info = manager.get_inventory(host="R1")

        # Should return host vars or error if not found
        assert isinstance(host_info, dict)

    def test_get_summary(self):
        """Should return summary information"""
        manager = AnsibleManager()
        summary = manager.get_summary()

        assert "ansible_available" in summary
        assert "ansible_enabled" in summary
        assert "playbooks" in summary
        assert "inventory" in summary

    def test_ansible_dir_configuration(self):
        """Should use correct ansible directory"""
        manager = AnsibleManager()

        assert manager.ansible_dir.exists()
        assert manager.playbooks_dir.exists()
        assert manager.inventory_file.exists()


class TestAnsibleManagerWithMocks:
    """Tests that require mocking external connections"""

    @patch('core.ansible_manager.is_enabled')
    def test_run_playbook_disabled(self, mock_enabled):
        """Should return error when Ansible disabled"""
        mock_enabled.return_value = False
        manager = AnsibleManager()

        result = manager.run_playbook("health_check")

        assert result.success is False
        assert "disabled" in result.stderr.lower()

    @patch('core.ansible_manager.is_enabled')
    @patch('subprocess.run')
    def test_run_playbook_success(self, mock_run, mock_enabled):
        """Should parse successful playbook output"""
        mock_enabled.return_value = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"stats": {"R1": {"ok": 5, "changed": 1, "failures": 0, "skipped": 0}}}',
            stderr="",
        )
        manager = AnsibleManager()

        result = manager.run_playbook("health_check")

        assert result.success is True
        assert result.ok == 5
        assert result.changed == 1

    @patch('core.ansible_manager.is_enabled')
    @patch('subprocess.run')
    def test_run_playbook_with_limit(self, mock_run, mock_enabled):
        """Should pass limit to ansible-playbook"""
        mock_enabled.return_value = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"stats": {}}',
            stderr="",
        )
        manager = AnsibleManager()

        manager.run_playbook("health_check", limit="R1,R2")

        # Check --limit was passed
        call_args = mock_run.call_args[0][0]
        assert "--limit" in call_args
        assert "R1,R2" in call_args

    @patch('core.ansible_manager.is_enabled')
    @patch('subprocess.run')
    def test_run_playbook_check_mode(self, mock_run, mock_enabled):
        """Should pass --check flag in check mode"""
        mock_enabled.return_value = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"stats": {}}',
            stderr="",
        )
        manager = AnsibleManager()

        manager.run_playbook("deploy_changes", check_mode=True)

        # Check --check was passed
        call_args = mock_run.call_args[0][0]
        assert "--check" in call_args

    @patch('core.ansible_manager.is_enabled')
    @patch('subprocess.run')
    def test_run_playbook_extra_vars(self, mock_run, mock_enabled):
        """Should pass extra vars as JSON"""
        mock_enabled.return_value = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"stats": {}}',
            stderr="",
        )
        manager = AnsibleManager()

        manager.run_playbook(
            "deploy_changes",
            extra_vars={"commands": ["logging host 198.51.100.1"]}
        )

        # Check --extra-vars was passed
        call_args = mock_run.call_args[0][0]
        assert "--extra-vars" in call_args

    @patch('core.ansible_manager.is_enabled')
    @patch('subprocess.run')
    def test_run_playbook_timeout(self, mock_run, mock_enabled):
        """Should handle timeout"""
        import subprocess
        mock_enabled.return_value = True
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ansible-playbook", timeout=300)
        manager = AnsibleManager()
        manager._ansible_available = True  # Mock ansible availability

        result = manager.run_playbook("health_check", timeout=300)

        assert result.success is False
        assert "timed out" in result.stderr.lower()

    @patch('core.ansible_manager.is_enabled')
    def test_run_playbook_not_found(self, mock_enabled):
        """Should handle missing playbook"""
        mock_enabled.return_value = True
        manager = AnsibleManager()

        result = manager.run_playbook("nonexistent_playbook")

        assert result.success is False
        assert "not found" in result.stderr.lower()


class TestAnsibleAdhoc:
    """Tests for ad-hoc command execution"""

    @patch('core.ansible_manager.is_enabled')
    @patch('subprocess.run')
    def test_adhoc_command(self, mock_run, mock_enabled):
        """Should run ad-hoc command"""
        mock_enabled.return_value = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="R1 | SUCCESS",
            stderr="",
        )
        manager = AnsibleManager()

        result = manager.run_adhoc(
            hosts="cisco_routers",
            module="cisco.ios.ios_command",
            args="commands='show clock'",
        )

        assert result.success is True
        assert "SUCCESS" in result.stdout

    @patch('core.ansible_manager.is_enabled')
    def test_adhoc_disabled(self, mock_enabled):
        """Should return error when disabled"""
        mock_enabled.return_value = False
        manager = AnsibleManager()

        result = manager.run_adhoc(
            hosts="all",
            module="ping",
        )

        assert result.success is False
        assert "disabled" in result.stderr.lower()


class TestConvenienceFunctions:
    """Tests for module-level convenience functions"""

    def test_get_ansible_singleton(self):
        """Should return same instance"""
        manager1 = get_ansible()
        manager2 = get_ansible()

        assert manager1 is manager2
        assert isinstance(manager1, AnsibleManager)

    @patch('core.ansible_manager.is_enabled')
    def test_run_playbook_function(self, mock_enabled):
        """run_playbook should work as convenience function"""
        mock_enabled.return_value = False

        result = run_playbook("health_check")

        assert isinstance(result, PlaybookResult)
        assert result.success is False  # Disabled


class TestInventoryGeneration:
    """Tests for inventory generation"""

    def test_generate_inventory(self):
        """Should generate inventory from config/devices.py"""
        manager = AnsibleManager()
        inventory = manager.generate_inventory()

        assert "all" in inventory
        assert "children" in inventory["all"]

        # Should have device groups
        children = inventory["all"]["children"]
        assert "cisco_routers" in children or "cisco_switches" in children


class TestTextOutputParsing:
    """Tests for parsing text output when JSON fails"""

    def test_parse_text_output(self):
        """Should parse PLAY RECAP text output"""
        manager = AnsibleManager()

        text_output = """
PLAY RECAP *********************************************************************
R1                         : ok=5    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
R2                         : ok=5    changed=0    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
R3                         : ok=0    changed=0    unreachable=1    failed=0    skipped=0    rescued=0    ignored=0
"""

        hosts, stats = manager._parse_text_output(text_output)

        assert "R1" in hosts
        assert "R2" in hosts
        assert "R3" in hosts
        assert hosts["R1"]["ok"] == 5
        assert hosts["R1"]["changed"] == 1
        assert stats["unreachable"] == 1


class TestAnsibleAvailability:
    """Tests for Ansible availability detection"""

    def test_ansible_available_property(self):
        """Should detect Ansible availability"""
        manager = AnsibleManager()

        # Just check it doesn't crash
        available = manager.ansible_available
        assert isinstance(available, bool)

    def test_ansible_available_cached(self):
        """Should cache availability check"""
        manager = AnsibleManager()

        # First call
        result1 = manager.ansible_available
        # Second call (should use cache)
        result2 = manager.ansible_available

        assert result1 == result2
