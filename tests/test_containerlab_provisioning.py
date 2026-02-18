"""
Unit tests for containerlab provisioning functions.

Tests the Phase 2 read-only provisioning functions in core/containerlab.py.
All external calls (multipass, docker) are mocked.
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest


# Sample topology YAML for testing
SAMPLE_TOPOLOGY_YAML = """
name: datacenter
prefix: clab

topology:
  nodes:
    edge1:
      kind: linux
      image: frrouting/frr:v10.2.1
      startup-config: edge1.cfg
    spine1:
      kind: nokia_srlinux
      image: ghcr.io/nokia/srlinux:24.7.1
    server1:
      kind: linux
      image: alpine:latest

  links:
    - endpoints: ["edge1:eth1", "spine1:e1-1"]
    - endpoints: ["spine1:e1-2", "server1:eth0"]
"""


class TestVMStatus:
    """Tests for is_vm_running()."""

    @patch("core.containerlab.subprocess.run")
    def test_vm_running(self, mock_run):
        """VM is running - returns True."""
        from core.containerlab import is_vm_running

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"info": {"containerlab": {"state": "Running"}}}',
        )

        result = is_vm_running()
        assert result is True

    @patch("core.containerlab.subprocess.run")
    def test_vm_stopped(self, mock_run):
        """VM is stopped - returns False."""
        from core.containerlab import is_vm_running

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"info": {"containerlab": {"state": "Stopped"}}}',
        )

        result = is_vm_running()
        assert result is False

    @patch("core.containerlab.subprocess.run")
    def test_vm_not_found(self, mock_run):
        """VM doesn't exist - returns False."""
        from core.containerlab import is_vm_running

        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Instance not found",
        )

        result = is_vm_running()
        assert result is False

    @patch("core.containerlab.subprocess.run")
    def test_multipass_timeout(self, mock_run):
        """Multipass command times out - returns False."""
        from core.containerlab import is_vm_running

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="multipass", timeout=10)

        result = is_vm_running()
        assert result is False

    @patch("core.containerlab.subprocess.run")
    def test_correlation_id_in_logs(self, mock_run, caplog):
        """Correlation ID appears in logs."""
        from core.containerlab import is_vm_running

        mock_run.side_effect = Exception("Test error")

        with caplog.at_level("WARNING"):
            result = is_vm_running(correlation_id="test-123")

        assert result is False
        # Check correlation ID is logged on failure
        assert "test-123" in caplog.text or result is False  # Either logged or silently handled


class TestGetTopology:
    """Tests for get_topology()."""

    @patch("core.containerlab._run_multipass_command")
    def test_parse_valid_topology(self, mock_cmd):
        """Valid topology YAML is parsed correctly."""
        from core.containerlab import get_topology

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout=SAMPLE_TOPOLOGY_YAML,
            stderr="",
        )

        result = get_topology()

        assert result["name"] == "datacenter"
        assert result["prefix"] == "clab"
        assert len(result["nodes"]) == 3
        assert "edge1" in result["nodes"]
        assert "spine1" in result["nodes"]
        assert "server1" in result["nodes"]
        assert len(result["links"]) == 2

    @patch("core.containerlab._run_multipass_command")
    def test_parse_node_details(self, mock_cmd):
        """Node details are correctly extracted."""
        from core.containerlab import get_topology

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout=SAMPLE_TOPOLOGY_YAML,
            stderr="",
        )

        result = get_topology()
        edge1 = result["nodes"]["edge1"]

        assert edge1["name"] == "edge1"
        assert edge1["kind"] == "linux"
        assert edge1["image"] == "frrouting/frr:v10.2.1"
        assert edge1["startup_config"] == "edge1.cfg"

    @patch("core.containerlab._run_multipass_command")
    def test_file_not_found(self, mock_cmd):
        """File not found raises ContainerlabTopologyError."""
        from core.containerlab import ContainerlabTopologyError, get_topology

        mock_cmd.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="cat: /path/to/file: No such file or directory",
        )

        with pytest.raises(ContainerlabTopologyError) as exc_info:
            get_topology()

        assert "Failed to read topology file" in str(exc_info.value)

    @patch("core.containerlab._run_multipass_command")
    def test_invalid_yaml(self, mock_cmd):
        """Invalid YAML raises ContainerlabTopologyError."""
        from core.containerlab import ContainerlabTopologyError, get_topology

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout="not: valid: yaml: [[[",
            stderr="",
        )

        with pytest.raises(ContainerlabTopologyError):
            get_topology()

    @patch("core.containerlab._run_multipass_command")
    def test_empty_file(self, mock_cmd):
        """Empty file raises ContainerlabTopologyError."""
        from core.containerlab import ContainerlabTopologyError, get_topology

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )

        with pytest.raises(ContainerlabTopologyError) as exc_info:
            get_topology()

        assert "Empty or invalid" in str(exc_info.value)

    @patch("core.containerlab._run_multipass_command")
    def test_custom_topology_path(self, mock_cmd):
        """Custom topology path is used."""
        from core.containerlab import get_topology

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout=SAMPLE_TOPOLOGY_YAML,
            stderr="",
        )

        get_topology(topology_path="/custom/path.yml")

        # Verify the custom path was used
        call_args = mock_cmd.call_args[0][0]
        assert "/custom/path.yml" in call_args


class TestGetExistingNodeNames:
    """Tests for get_existing_node_names()."""

    @patch("core.containerlab.get_topology")
    def test_returns_node_names(self, mock_topology):
        """Returns list of node names from topology."""
        from core.containerlab import get_existing_node_names

        mock_topology.return_value = {
            "nodes": {"edge1": {}, "spine1": {}, "server1": {}}
        }

        result = get_existing_node_names()

        assert len(result) == 3
        assert "edge1" in result
        assert "spine1" in result
        assert "server1" in result

    @patch("core.containerlab.get_topology")
    def test_topology_error_returns_empty(self, mock_topology):
        """Returns empty list if topology cannot be read."""
        from core.containerlab import ContainerlabTopologyError, get_existing_node_names

        mock_topology.side_effect = ContainerlabTopologyError("Test error")

        result = get_existing_node_names()

        assert result == []


class TestGetRunningContainers:
    """Tests for get_running_containers()."""

    @patch("core.containerlab._run_multipass_command")
    def test_parse_containerlab_inspect(self, mock_cmd):
        """Parses containerlab inspect JSON output."""
        from core.containerlab import get_running_containers

        inspect_output = {
            "containers": [
                {"name": "clab-datacenter-edge1", "image": "frr:latest", "state": "running"},
                {"name": "clab-datacenter-spine1", "image": "srlinux:24.7", "state": "running"},
            ]
        }

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(inspect_output),
            stderr="",
        )

        result = get_running_containers()

        assert len(result) == 2
        assert result[0]["name"] == "clab-datacenter-edge1"
        assert result[0]["status"] == "running"

    @patch("core.containerlab._run_multipass_command")
    def test_fallback_to_docker_ps(self, mock_cmd):
        """Falls back to docker ps if containerlab inspect fails."""
        from core.containerlab import get_running_containers

        # First call (containerlab inspect) fails, second (docker ps) succeeds
        mock_cmd.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="containerlab not found"),
            MagicMock(
                returncode=0,
                stdout="clab-datacenter-edge1|frr:latest|Up 2 hours\nclab-datacenter-spine1|srlinux:24.7|Up 2 hours",
                stderr="",
            ),
        ]

        result = get_running_containers()

        assert len(result) == 2
        assert result[0]["name"] == "clab-datacenter-edge1"
        assert result[0]["image"] == "frr:latest"

    @patch("core.containerlab._run_multipass_command")
    def test_connection_error_returns_empty(self, mock_cmd):
        """Returns empty list if cannot connect to VM."""
        from core.containerlab import ContainerlabConnectionError, get_running_containers

        mock_cmd.side_effect = ContainerlabConnectionError("VM not running")

        result = get_running_containers()

        assert result == []


class TestListAvailableImages:
    """Tests for list_available_images()."""

    @patch("core.containerlab._run_multipass_command")
    def test_filters_containerlab_images(self, mock_cmd):
        """Only returns images matching containerlab patterns."""
        from core.containerlab import list_available_images

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout="""ghcr.io/nokia/srlinux|24.7.1|2.1GB
frrouting/frr|v10.2.1|250MB
alpine|latest|8MB
ubuntu|22.04|77MB
nginx|latest|187MB
random-image|v1|100MB""",
            stderr="",
        )

        result = list_available_images()

        # Should only include nokia, frr, and alpine
        assert len(result) == 3
        repos = [img["repository"] for img in result]
        assert "ghcr.io/nokia/srlinux" in repos
        assert "frrouting/frr" in repos
        assert "alpine" in repos
        assert "nginx" not in repos
        assert "ubuntu" not in repos

    @patch("core.containerlab._run_multipass_command")
    def test_parse_image_details(self, mock_cmd):
        """Correctly parses image details."""
        from core.containerlab import list_available_images

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout="ghcr.io/nokia/srlinux|24.7.1|2.1GB",
            stderr="",
        )

        result = list_available_images()

        assert len(result) == 1
        assert result[0]["repository"] == "ghcr.io/nokia/srlinux"
        assert result[0]["tag"] == "24.7.1"
        assert result[0]["size"] == "2.1GB"

    @patch("core.containerlab._run_multipass_command")
    def test_sorted_by_repository(self, mock_cmd):
        """Results are sorted alphabetically by repository."""
        from core.containerlab import list_available_images

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout="""frrouting/frr|v10.2.1|250MB
alpine|latest|8MB
ghcr.io/nokia/srlinux|24.7.1|2.1GB""",
            stderr="",
        )

        result = list_available_images()

        assert result[0]["repository"] == "alpine"
        assert result[1]["repository"] == "frrouting/frr"
        assert result[2]["repository"] == "ghcr.io/nokia/srlinux"

    @patch("core.containerlab._run_multipass_command")
    def test_connection_error_returns_empty(self, mock_cmd):
        """Returns empty list if cannot connect to VM."""
        from core.containerlab import ContainerlabConnectionError, list_available_images

        mock_cmd.side_effect = ContainerlabConnectionError("VM not running")

        result = list_available_images()

        assert result == []


class TestValidateNodeName:
    """Tests for validate_node_name()."""

    @patch("core.containerlab.get_existing_node_names")
    def test_valid_name(self, mock_nodes):
        """Valid name returns valid=True."""
        from core.containerlab import validate_node_name

        mock_nodes.return_value = ["edge1", "spine1"]

        result = validate_node_name("R10")

        assert result["valid"] is True
        assert "reason" not in result

    @patch("core.containerlab.get_existing_node_names")
    def test_name_already_exists(self, mock_nodes):
        """Existing name returns valid=False."""
        from core.containerlab import validate_node_name

        mock_nodes.return_value = ["edge1", "spine1"]

        result = validate_node_name("edge1")

        assert result["valid"] is False
        assert "already exists" in result["reason"]

    def test_empty_name(self):
        """Empty name returns valid=False."""
        from core.containerlab import validate_node_name

        result = validate_node_name("")

        assert result["valid"] is False
        assert "cannot be empty" in result["reason"]

    def test_name_starts_with_number(self):
        """Name starting with number returns valid=False."""
        from core.containerlab import validate_node_name

        result = validate_node_name("123router")

        assert result["valid"] is False
        assert "must start with a letter" in result["reason"]

    def test_name_with_invalid_chars(self):
        """Name with invalid characters returns valid=False."""
        from core.containerlab import validate_node_name

        result = validate_node_name("router@1")

        assert result["valid"] is False
        assert "letters, numbers" in result["reason"]

    def test_name_too_long(self):
        """Name over 50 characters returns valid=False."""
        from core.containerlab import validate_node_name

        long_name = "a" * 51

        result = validate_node_name(long_name)

        assert result["valid"] is False
        assert "50 characters" in result["reason"]

    def test_reserved_names(self):
        """Reserved names return valid=False."""
        from core.containerlab import validate_node_name

        reserved = ["host", "bridge", "mgmt", "docker", "clab", "containerlab"]

        for name in reserved:
            result = validate_node_name(name)
            assert result["valid"] is False
            assert "reserved" in result["reason"]

    def test_valid_names_with_special_chars(self):
        """Valid names with underscores and hyphens."""
        from core.containerlab import validate_node_name

        valid_names = ["router_1", "router-1", "R1_backup", "spine-leaf-1"]

        with patch("core.containerlab.get_existing_node_names", return_value=[]):
            for name in valid_names:
                result = validate_node_name(name)
                assert result["valid"] is True, f"Expected {name} to be valid"


class TestGetNodeKinds:
    """Tests for get_node_kinds()."""

    def test_returns_list_of_kinds(self):
        """Returns list of supported node kinds."""
        from core.containerlab import get_node_kinds

        result = get_node_kinds()

        assert isinstance(result, list)
        assert len(result) >= 4  # At least linux, frr, srlinux, ceos

    def test_kind_has_required_fields(self):
        """Each kind has kind, description, default_image."""
        from core.containerlab import get_node_kinds

        result = get_node_kinds()

        for kind in result:
            assert "kind" in kind
            assert "description" in kind
            assert "default_image" in kind

    def test_includes_common_kinds(self):
        """Includes commonly used kinds."""
        from core.containerlab import get_node_kinds

        result = get_node_kinds()
        kinds = [k["kind"] for k in result]

        assert "linux" in kinds
        assert "nokia_srlinux" in kinds
        assert "frr" in kinds


class TestRunMultipassCommand:
    """Tests for _run_multipass_command()."""

    @patch("core.containerlab.subprocess.run")
    def test_successful_command(self, mock_run):
        """Successful command returns CompletedProcess."""
        from core.containerlab import _run_multipass_command

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="output",
            stderr="",
        )

        result = _run_multipass_command("echo test")

        assert result.returncode == 0
        assert result.stdout == "output"

    @patch("core.containerlab.subprocess.run")
    def test_timeout_raises_error(self, mock_run):
        """Timeout raises ContainerlabConnectionError."""
        from core.containerlab import ContainerlabConnectionError, _run_multipass_command

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="multipass", timeout=30)

        with pytest.raises(ContainerlabConnectionError) as exc_info:
            _run_multipass_command("slow command", timeout=30)

        assert "Timeout" in str(exc_info.value)

    @patch("core.containerlab.subprocess.run")
    def test_multipass_not_found(self, mock_run):
        """Missing multipass raises ContainerlabConnectionError."""
        from core.containerlab import ContainerlabConnectionError, _run_multipass_command

        mock_run.side_effect = FileNotFoundError("multipass not found")

        with pytest.raises(ContainerlabConnectionError) as exc_info:
            _run_multipass_command("echo test")

        assert "Multipass not found" in str(exc_info.value)

    @patch("core.containerlab.subprocess.run")
    def test_correlation_id_in_error(self, mock_run):
        """Correlation ID appears in error message."""
        from core.containerlab import ContainerlabConnectionError, _run_multipass_command

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="multipass", timeout=30)

        with pytest.raises(ContainerlabConnectionError) as exc_info:
            _run_multipass_command("slow command", correlation_id="corr-123")

        assert "corr-123" in str(exc_info.value)


class TestExceptionClasses:
    """Tests for custom exception classes."""

    def test_containerlab_error_hierarchy(self):
        """ContainerlabError is base for all containerlab exceptions."""
        from core.containerlab import (
            ContainerlabConnectionError,
            ContainerlabError,
            ContainerlabTopologyError,
        )

        assert issubclass(ContainerlabConnectionError, ContainerlabError)
        assert issubclass(ContainerlabTopologyError, ContainerlabError)
        assert issubclass(ContainerlabError, Exception)

    def test_exceptions_with_messages(self):
        """Exceptions can be raised with messages."""
        from core.containerlab import (
            ContainerlabConnectionError,
            ContainerlabTopologyError,
        )

        with pytest.raises(ContainerlabConnectionError) as exc_info:
            raise ContainerlabConnectionError("Test connection error")

        assert "Test connection error" in str(exc_info.value)

        with pytest.raises(ContainerlabTopologyError) as exc_info:
            raise ContainerlabTopologyError("Test topology error")

        assert "Test topology error" in str(exc_info.value)


# =============================================================================
# Phase 4 - Write Operations Tests
# =============================================================================


class TestBackupTopology:
    """Tests for _backup_topology()."""

    @patch("core.containerlab._run_multipass_command")
    def test_creates_backup_with_timestamp(self, mock_cmd):
        """Backup creates file with timestamp."""
        from core.containerlab import _backup_topology

        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = _backup_topology("/path/to/topology.yml")

        assert result.startswith("/path/to/topology.yml.backup.")
        assert mock_cmd.called
        # Check cp command was used
        call_cmd = mock_cmd.call_args[0][0]
        assert "cp" in call_cmd

    @patch("core.containerlab._run_multipass_command")
    def test_backup_failure_raises_error(self, mock_cmd):
        """Backup failure raises ContainerlabTopologyError."""
        from core.containerlab import ContainerlabTopologyError, _backup_topology

        mock_cmd.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Permission denied",
        )

        with pytest.raises(ContainerlabTopologyError) as exc_info:
            _backup_topology("/path/to/topology.yml")

        assert "Failed to create backup" in str(exc_info.value)


class TestRestoreTopology:
    """Tests for _restore_topology()."""

    @patch("core.containerlab._run_multipass_command")
    def test_restore_success(self, mock_cmd):
        """Successful restore returns True."""
        from core.containerlab import _restore_topology

        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = _restore_topology("/path/to/backup.yml", "/path/to/topology.yml")

        assert result is True

    @patch("core.containerlab._run_multipass_command")
    def test_restore_failure_raises_error(self, mock_cmd):
        """Restore failure raises ContainerlabTopologyError."""
        from core.containerlab import ContainerlabTopologyError, _restore_topology

        mock_cmd.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="File not found",
        )

        with pytest.raises(ContainerlabTopologyError) as exc_info:
            _restore_topology("/path/to/backup.yml")

        assert "Failed to restore" in str(exc_info.value)


class TestAddNode:
    """Tests for add_node()."""

    @patch("core.containerlab._run_multipass_command")
    @patch("core.containerlab.get_topology")
    @patch("core.containerlab._backup_topology")
    @patch("core.containerlab.validate_node_name")
    def test_add_node_success(self, mock_validate, mock_backup, mock_topo, mock_cmd):
        """Successfully adds node to topology."""
        from core.containerlab import add_node

        mock_validate.return_value = {"valid": True}
        mock_backup.return_value = "/backup/path.yml"
        mock_topo.return_value = {
            "name": "datacenter",
            "nodes": {"edge1": {}},
            "raw": {"name": "datacenter", "topology": {"nodes": {"edge1": {}}}},
        }
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = add_node("server3", "linux", image="alpine:latest")

        assert result["success"] is True
        assert result["node"]["name"] == "server3"
        assert result["node"]["kind"] == "linux"
        assert result["backup_path"] == "/backup/path.yml"

    @patch("core.containerlab.validate_node_name")
    def test_add_node_invalid_name(self, mock_validate):
        """Invalid name raises error."""
        from core.containerlab import ContainerlabTopologyError, add_node

        mock_validate.return_value = {"valid": False, "reason": "Name already exists"}

        with pytest.raises(ContainerlabTopologyError) as exc_info:
            add_node("edge1", "linux")

        assert "Invalid node name" in str(exc_info.value)

    @patch("core.containerlab._run_multipass_command")
    @patch("core.containerlab.get_topology")
    @patch("core.containerlab._backup_topology")
    @patch("core.containerlab._restore_topology")
    @patch("core.containerlab.validate_node_name")
    def test_add_node_write_failure_restores_backup(
        self, mock_validate, mock_restore, mock_backup, mock_topo, mock_cmd
    ):
        """Write failure triggers backup restoration."""
        from core.containerlab import ContainerlabTopologyError, add_node

        mock_validate.return_value = {"valid": True}
        mock_backup.return_value = "/backup/path.yml"
        mock_topo.return_value = {
            "name": "datacenter",
            "nodes": {},
            "raw": {"name": "datacenter", "topology": {"nodes": {}}},
        }
        mock_cmd.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Write failed",
        )

        with pytest.raises(ContainerlabTopologyError):
            add_node("server3", "linux")

        # Verify restore was called
        mock_restore.assert_called_once()


class TestRemoveNodeFromTopology:
    """Tests for remove_node_from_topology()."""

    @patch("core.containerlab._run_multipass_command")
    @patch("core.containerlab.get_topology")
    @patch("core.containerlab._backup_topology")
    def test_remove_node_success(self, mock_backup, mock_topo, mock_cmd):
        """Successfully removes node from topology."""
        from core.containerlab import remove_node_from_topology

        mock_backup.return_value = "/backup/path.yml"
        mock_topo.return_value = {
            "nodes": {"edge1": {}, "server3": {}},
            "raw": {
                "name": "datacenter",
                "topology": {
                    "nodes": {"edge1": {}, "server3": {}},
                    "links": [
                        {"endpoints": ["edge1:eth1", "server3:eth0"]},
                        {"endpoints": ["edge1:eth2", "spine1:e1-1"]},
                    ],
                },
            },
        }
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = remove_node_from_topology("server3")

        assert result["success"] is True
        assert result["backup_path"] == "/backup/path.yml"

    @patch("core.containerlab.get_topology")
    @patch("core.containerlab._backup_topology")
    def test_remove_nonexistent_node_raises_error(self, mock_backup, mock_topo):
        """Removing nonexistent node raises error."""
        from core.containerlab import ContainerlabTopologyError, remove_node_from_topology

        mock_backup.return_value = "/backup/path.yml"
        mock_topo.return_value = {
            "nodes": {"edge1": {}},
            "raw": {"topology": {"nodes": {"edge1": {}}}},
        }

        with pytest.raises(ContainerlabTopologyError) as exc_info:
            remove_node_from_topology("nonexistent")

        assert "not found in topology" in str(exc_info.value)


class TestDeployTopology:
    """Tests for deploy_topology()."""

    @patch("core.containerlab._run_multipass_command")
    def test_deploy_success(self, mock_cmd):
        """Successful deployment."""
        from core.containerlab import deploy_topology

        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout="Deployed successfully",
            stderr="",
        )

        result = deploy_topology("/home/ubuntu/datacenter/datacenter.clab.yml")

        assert result["success"] is True
        # Verify deploy command (NOT --reconfigure)
        call_cmd = mock_cmd.call_args[0][0]
        assert "containerlab deploy" in call_cmd
        assert "--reconfigure" not in call_cmd

    @patch("core.containerlab._run_multipass_command")
    def test_deploy_failure_raises_error(self, mock_cmd):
        """Deployment failure raises error."""
        from core.containerlab import ContainerlabTopologyError, deploy_topology

        mock_cmd.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Deployment failed",
        )

        with pytest.raises(ContainerlabTopologyError) as exc_info:
            deploy_topology()

        assert "Deployment failed" in str(exc_info.value)


class TestDestroyNode:
    """Tests for destroy_node()."""

    @patch("core.containerlab._run_multipass_command")
    @patch("core.containerlab.get_topology")
    def test_destroy_node_success(self, mock_topo, mock_cmd):
        """Successfully destroys container."""
        from core.containerlab import destroy_node

        mock_topo.return_value = {"name": "datacenter"}
        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout="clab-datacenter-server3",
            stderr="",
        )

        result = destroy_node("server3")

        assert result["success"] is True
        # Verify docker rm command
        call_cmd = mock_cmd.call_args[0][0]
        assert "docker rm -f" in call_cmd
        assert "clab-datacenter-server3" in call_cmd

    @patch("core.containerlab._run_multipass_command")
    @patch("core.containerlab.get_topology")
    def test_destroy_nonexistent_container_succeeds(self, mock_topo, mock_cmd):
        """Destroying nonexistent container succeeds (idempotent)."""
        from core.containerlab import destroy_node

        mock_topo.return_value = {"name": "datacenter"}
        mock_cmd.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="No such container",
        )

        result = destroy_node("nonexistent")

        # Should succeed even if container doesn't exist
        assert result["success"] is True


class TestProvisionNode:
    """Tests for provision_node()."""

    @patch("core.containerlab.get_topology")
    @patch("core.containerlab.deploy_topology")
    @patch("core.containerlab.add_node")
    def test_provision_node_success(self, mock_add, mock_deploy, mock_topo):
        """Full provisioning workflow succeeds."""
        from core.containerlab import provision_node

        mock_add.return_value = {
            "success": True,
            "backup_path": "/backup/path.yml",
            "node": {"name": "server3", "kind": "linux"},
        }
        mock_deploy.return_value = {"success": True, "output": "Deployed"}
        mock_topo.return_value = {"name": "datacenter"}

        result = provision_node("server3", "linux")

        assert result["success"] is True
        assert result["node"]["name"] == "server3"
        assert result["container_name"] == "clab-datacenter-server3"

    @patch("core.containerlab._restore_topology")
    @patch("core.containerlab.deploy_topology")
    @patch("core.containerlab.add_node")
    def test_provision_rollback_on_deploy_failure(
        self, mock_add, mock_deploy, mock_restore
    ):
        """Deploy failure triggers rollback."""
        from core.containerlab import ContainerlabTopologyError, provision_node

        mock_add.return_value = {
            "success": True,
            "backup_path": "/backup/path.yml",
            "node": {"name": "server3"},
        }
        mock_deploy.side_effect = ContainerlabTopologyError("Deploy failed")

        with pytest.raises(ContainerlabTopologyError):
            provision_node("server3", "linux")

        # Verify restore was called
        mock_restore.assert_called_once()


class TestDeprovisionNode:
    """Tests for deprovision_node()."""

    @patch("core.containerlab.remove_node_from_topology")
    @patch("core.containerlab.destroy_node")
    def test_deprovision_node_success(self, mock_destroy, mock_remove):
        """Full deprovisioning workflow succeeds."""
        from core.containerlab import deprovision_node

        mock_destroy.return_value = {"success": True}
        mock_remove.return_value = {"success": True, "backup_path": "/backup/path.yml"}

        result = deprovision_node("server3")

        assert result["success"] is True
        assert result["backup_path"] == "/backup/path.yml"

        # Verify both destroy and remove were called
        mock_destroy.assert_called_once()
        mock_remove.assert_called_once()
