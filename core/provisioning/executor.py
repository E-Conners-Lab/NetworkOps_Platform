"""
Async provisioning execution.

Runs provisioning jobs in background threads with progress tracking,
rollback on failure, and proper cleanup.
"""

import logging
import os
import threading
from typing import Any, Dict, Optional

from core.provisioning.state import JobStatus, ProvisioningJob, ProvisioningStateManager

logger = logging.getLogger(__name__)


class ProvisioningExecutor:
    """
    Executes provisioning jobs asynchronously.

    Runs provisioning in background threads, updating job status
    as each step completes. On failure, executes rollback actions
    in reverse order.

    Usage:
        executor = ProvisioningExecutor(state_manager)
        executor.start_eve_ng_provisioning(job_id, params)
        executor.start_containerlab_provisioning(job_id, params)
    """

    def __init__(self, state_manager: ProvisioningStateManager):
        """Initialize executor with state manager."""
        self.state_manager = state_manager
        self._active_threads: Dict[str, threading.Thread] = {}

    def start_eve_ng_provisioning(
        self,
        job_id: str,
        name: str,
        template: str,
        cpu: int = 1,
        ram: int = 2048,
        ethernet: int = 4,
        netbox_site_id: Optional[int] = None,
        netbox_role_id: Optional[int] = None,
        netbox_device_type_id: Optional[int] = None,
    ) -> None:
        """
        Start EVE-NG provisioning in background thread.

        Args:
            job_id: Job ID to track
            name: Device name
            template: EVE-NG template/image
            cpu: vCPUs
            ram: RAM in MB
            ethernet: Number of interfaces
            netbox_*: Optional NetBox IDs for device creation
        """
        params = {
            "name": name,
            "template": template,
            "cpu": cpu,
            "ram": ram,
            "ethernet": ethernet,
            "netbox_site_id": netbox_site_id,
            "netbox_role_id": netbox_role_id,
            "netbox_device_type_id": netbox_device_type_id,
        }

        thread = threading.Thread(
            target=self._run_eve_ng_provisioning,
            args=(job_id, params),
            daemon=True,
        )
        self._active_threads[job_id] = thread
        thread.start()

    def start_containerlab_provisioning(
        self,
        job_id: str,
        name: str,
        kind: str,
        image: Optional[str] = None,
        startup_config: Optional[str] = None,
        netbox_site_id: Optional[int] = None,
        netbox_role_id: Optional[int] = None,
        netbox_device_type_id: Optional[int] = None,
    ) -> None:
        """
        Start Containerlab provisioning in background thread.

        Args:
            job_id: Job ID to track
            name: Node name
            kind: Node kind (nokia_srlinux, frr, linux, etc.)
            image: Container image
            startup_config: Startup config path
            netbox_*: Optional NetBox IDs for device creation
        """
        params = {
            "name": name,
            "kind": kind,
            "image": image,
            "startup_config": startup_config,
            "netbox_site_id": netbox_site_id,
            "netbox_role_id": netbox_role_id,
            "netbox_device_type_id": netbox_device_type_id,
        }

        thread = threading.Thread(
            target=self._run_containerlab_provisioning,
            args=(job_id, params),
            daemon=True,
        )
        self._active_threads[job_id] = thread
        thread.start()

    def _run_eve_ng_provisioning(self, job_id: str, params: Dict[str, Any]) -> None:
        """Execute EVE-NG provisioning workflow using single EVE-NG session."""
        from core.eve_ng_client import EVEClient

        job = self.state_manager.get_job(job_id)
        if not job:
            logger.error(f"Job {job_id} not found")
            return

        correlation_id = job.correlation_id
        log_prefix = f"[{correlation_id}]"

        # Use single EVE-NG session for entire workflow to avoid lock issues
        with EVEClient() as client:
            try:
                # Mark as running
                self.state_manager.update_job(job_id, status=JobStatus.RUNNING)

                # Step 1: Validate inputs
                self._update_step(job_id, "validate_inputs")
                self._validate_eve_ng_inputs_with_client(client, params, correlation_id)

                # Step 2: Allocate IP from NetBox
                self._update_step(job_id, "allocate_ip")
                mgmt_ip = self._allocate_netbox_ip(job_id, params["name"], correlation_id)
                self.state_manager.update_job(job_id, mgmt_ip=mgmt_ip)

                # Step 3: Create node in EVE-NG
                self._update_step(job_id, "create_node")
                node_result = self._create_eve_ng_node_with_client(client, job_id, params, correlation_id)
                node_id = node_result["id"]
                mac_address = node_result.get("mac_address")
                self.state_manager.update_job(job_id, eve_ng_node_id=node_id)

                # Step 4: Add DHCP reservation (so node gets correct IP on boot)
                self._update_step(job_id, "add_dhcp_reservation")
                if mac_address and mgmt_ip:
                    self._add_dhcp_reservation_with_client(
                        client, job_id, mac_address, mgmt_ip, params["name"], correlation_id
                    )

                # Step 5: Connect management interface
                self._update_step(job_id, "connect_interface")
                self._connect_eve_ng_interface_with_client(client, node_id, correlation_id)

                # Step 6: Start node
                self._update_step(job_id, "start_node")
                self._start_eve_ng_node_with_client(client, node_id, correlation_id)

                # Step 7: Wait for boot
                self._update_step(job_id, "wait_for_boot")
                ip_only = mgmt_ip.split("/")[0]
                self._wait_for_eve_ng_boot(ip_only, correlation_id)

                # Step 7: Apply ZTP config
                self._update_step(job_id, "apply_ztp")
                self._apply_eve_ng_ztp(ip_only, correlation_id)

                # Step 8: Add to NetBox (if configured)
                self._update_step(job_id, "add_to_netbox")
                netbox_id = self._create_netbox_device(job_id, params, mgmt_ip, correlation_id)
                if netbox_id:
                    self.state_manager.update_job(job_id, netbox_device_id=netbox_id)

                # Step 9: Finalize
                self._update_step(job_id, "finalize")
                self.state_manager.complete_job(job_id)

                logger.info(f"{log_prefix} EVE-NG provisioning completed for {params['name']}")

            except Exception as e:
                logger.error(f"{log_prefix} EVE-NG provisioning failed: {e}")
                self.state_manager.fail_job(job_id, str(e))
                self._execute_rollback(job_id)

            finally:
                self._active_threads.pop(job_id, None)

    def _run_containerlab_provisioning(self, job_id: str, params: Dict[str, Any]) -> None:
        """Execute Containerlab provisioning workflow."""
        job = self.state_manager.get_job(job_id)
        if not job:
            logger.error(f"Job {job_id} not found")
            return

        correlation_id = job.correlation_id
        log_prefix = f"[{correlation_id}]"

        try:
            # Mark as running
            self.state_manager.update_job(job_id, status=JobStatus.RUNNING)

            # Step 1: Validate inputs
            self._update_step(job_id, "validate_inputs")
            self._validate_containerlab_inputs(params, correlation_id)

            # Step 2: Allocate IP (optional for containerlab)
            self._update_step(job_id, "allocate_ip")
            # Containerlab nodes get IPs from docker network, skip NetBox allocation
            logger.info(f"{log_prefix} Skipping IP allocation for containerlab node")

            # Step 3: Backup topology
            self._update_step(job_id, "backup_topology")
            backup_path = self._backup_containerlab_topology(correlation_id)

            # Step 4: Modify topology
            self._update_step(job_id, "modify_topology")
            self._add_containerlab_node(job_id, params, backup_path, correlation_id)
            self.state_manager.update_job(
                job_id, containerlab_node_name=params["name"]
            )

            # Step 5: Deploy node
            self._update_step(job_id, "deploy_node")
            self._deploy_containerlab(correlation_id)

            # Step 6: Wait for boot
            self._update_step(job_id, "wait_for_boot")
            self._wait_for_containerlab_boot(params["name"], correlation_id)

            # Step 7: Add to NetBox (if configured)
            self._update_step(job_id, "add_to_netbox")
            # For containerlab, we add device without IP allocation
            netbox_id = self._create_netbox_device(job_id, params, None, correlation_id)
            if netbox_id:
                self.state_manager.update_job(job_id, netbox_device_id=netbox_id)

            # Step 8: Finalize
            self._update_step(job_id, "finalize")
            self.state_manager.complete_job(job_id)

            logger.info(f"{log_prefix} Containerlab provisioning completed for {params['name']}")

        except Exception as e:
            logger.error(f"{log_prefix} Containerlab provisioning failed: {e}")
            self.state_manager.fail_job(job_id, str(e))
            self._execute_rollback(job_id)

        finally:
            self._active_threads.pop(job_id, None)

    def _update_step(self, job_id: str, step: str) -> None:
        """Update job to current step."""
        job = self.state_manager.get_job(job_id)
        if job:
            logger.info(f"[{job.correlation_id}] Step: {step}")
        self.state_manager.update_job(job_id, step=step)

    # =========================================================================
    # EVE-NG Operations
    # =========================================================================

    def _validate_eve_ng_inputs(self, params: Dict[str, Any], correlation_id: str) -> None:
        """Validate EVE-NG provisioning inputs (creates new session)."""
        from core.eve_ng_client import EVEClient
        with EVEClient() as client:
            self._validate_eve_ng_inputs_with_client(client, params, correlation_id)

    def _validate_eve_ng_inputs_with_client(self, client, params: Dict[str, Any], correlation_id: str) -> None:
        """Validate EVE-NG provisioning inputs using existing client session."""
        from core.eve_ng_client import EVEConnectionError

        log_prefix = f"[{correlation_id}]"

        # Check EVE-NG is configured
        if not os.getenv("EVE_NG_HOST"):
            raise ValueError("EVE_NG_HOST not configured")

        # Verify connection and template exists
        try:
            template = client.get_image(params["template"], correlation_id)
            if not template:
                raise ValueError(f"Template '{params['template']}' not found in EVE-NG")

            # Validate lab exists
            client.validate_lab(correlation_id=correlation_id)

            # Check management network exists
            mgmt_net = client.get_or_validate_mgmt_network(correlation_id=correlation_id)
            if not mgmt_net:
                raise ValueError("Management network 'pnet1' not found in lab")

        except EVEConnectionError as e:
            raise ValueError(f"Cannot connect to EVE-NG: {e}")

        logger.info(f"{log_prefix} EVE-NG inputs validated")

    def _allocate_netbox_ip(
        self, job_id: str, device_name: str, correlation_id: str
    ) -> str:
        """Allocate management IP from NetBox."""
        log_prefix = f"[{correlation_id}]"

        try:
            from config.netbox_client import get_client

            client = get_client()
            if not client:
                raise ValueError("NetBox not configured")

            # Get next available IP
            mgmt_subnet = os.getenv("MGMT_SUBNET", "10.255.255.0/24")
            ip = client.get_next_available_ip(
                prefix=mgmt_subnet,
                correlation_id=correlation_id,
            )

            # Allocate it
            client.allocate_ip(
                prefix=mgmt_subnet,
                device_name=device_name,
                interface_name="GigabitEthernet4",
                description=f"Management IP for {device_name}",
                correlation_id=correlation_id,
            )

            # Add rollback action
            self.state_manager.add_rollback_action(job_id, {
                "action": "release_ip",
                "platform": "netbox",
                "ip_address": ip,
            })

            logger.info(f"{log_prefix} Allocated IP: {ip}")
            return ip

        except ImportError:
            raise ValueError("NetBox client not available")

    def _create_eve_ng_node(
        self, job_id: str, params: Dict[str, Any], correlation_id: str
    ) -> int:
        """Create node in EVE-NG (creates new session)."""
        from core.eve_ng_client import EVEClient
        with EVEClient() as client:
            return self._create_eve_ng_node_with_client(client, job_id, params, correlation_id)

    def _create_eve_ng_node_with_client(
        self, client, job_id: str, params: Dict[str, Any], correlation_id: str
    ) -> Dict[str, Any]:
        """Create node in EVE-NG using existing client session.

        Returns:
            Dict with 'id' (node ID) and 'mac_address' (MAC for DHCP)
        """
        result = client.create_node(
            name=params["name"],
            template=params["template"],
            cpu=params.get("cpu", 1),
            ram=params.get("ram", 2048),
            ethernet=params.get("ethernet", 4),
            correlation_id=correlation_id,
        )

        node_id = result["id"]
        mac_address = result.get("mac_address")

        # Add rollback action
        self.state_manager.add_rollback_action(job_id, {
            "action": "delete_node",
            "platform": "eve-ng",
            "node_id": node_id,
        })

        return {"id": node_id, "mac_address": mac_address}

    def _add_dhcp_reservation_with_client(
        self,
        client,
        job_id: str,
        mac_address: str,
        ip_address: str,
        hostname: str,
        correlation_id: str,
    ) -> None:
        """Add DHCP reservation for the node so it gets the correct IP on boot."""
        log_prefix = f"[{correlation_id}]"

        success = client.add_dhcp_reservation(
            mac_address=mac_address,
            ip_address=ip_address,
            hostname=hostname,
            correlation_id=correlation_id,
        )

        if success:
            # Add rollback action to remove reservation
            self.state_manager.add_rollback_action(job_id, {
                "action": "remove_dhcp_reservation",
                "platform": "eve-ng",
                "mac_address": mac_address,
            })
            logger.info(f"{log_prefix} DHCP reservation added for {hostname}")
        else:
            logger.warning(f"{log_prefix} Could not add DHCP reservation (continuing anyway)")

    def _connect_eve_ng_interface(self, node_id: int, correlation_id: str) -> None:
        """Connect EVE-NG node management interface to pnet1 (creates new session)."""
        from core.eve_ng_client import EVEClient
        with EVEClient() as client:
            self._connect_eve_ng_interface_with_client(client, node_id, correlation_id)

    def _connect_eve_ng_interface_with_client(self, client, node_id: int, correlation_id: str) -> None:
        """Connect EVE-NG node management interface to pnet1 using existing client session."""
        # Get management network
        mgmt_net = client.get_or_validate_mgmt_network(correlation_id=correlation_id)
        if not mgmt_net:
            raise ValueError("Management network not found")

        # Connect Gi4 (interface 3) to management network
        client.connect_to_network(
            node_id=node_id,
            interface_id=3,  # Gi4 is 0-indexed as 3
            network_id=mgmt_net["id"],
            correlation_id=correlation_id,
        )

    def _start_eve_ng_node(self, node_id: int, correlation_id: str) -> None:
        """Start EVE-NG node (creates new session)."""
        from core.eve_ng_client import EVEClient
        with EVEClient() as client:
            self._start_eve_ng_node_with_client(client, node_id, correlation_id)

    def _start_eve_ng_node_with_client(self, client, node_id: int, correlation_id: str) -> None:
        """Start EVE-NG node using existing client session."""
        client.start_node(node_id, correlation_id=correlation_id)

    def _wait_for_eve_ng_boot(self, ip: str, correlation_id: str) -> None:
        """Wait for EVE-NG node to become SSH-reachable."""
        from core.eve_ng_client import EVEClient

        with EVEClient() as client:
            client.wait_for_boot(
                node_ip=ip,
                timeout=180,
                retry_interval=10,
                correlation_id=correlation_id,
            )

    def _apply_eve_ng_ztp(self, ip: str, correlation_id: str) -> None:
        """Apply ZTP config to EVE-NG node."""
        from core.eve_ng_client import EVEClient

        with EVEClient() as client:
            client.apply_ztp_config(
                node_ip=ip,
                username="admin",
                password="admin",
                correlation_id=correlation_id,
            )

    # =========================================================================
    # Containerlab Operations
    # =========================================================================

    def _validate_containerlab_inputs(
        self, params: Dict[str, Any], correlation_id: str
    ) -> None:
        """Validate Containerlab provisioning inputs."""
        from core.containerlab import is_vm_running, validate_node_name

        log_prefix = f"[{correlation_id}]"

        # Check VM is running
        if not is_vm_running(correlation_id):
            raise ValueError("Containerlab VM is not running")

        # Validate node name
        validation = validate_node_name(params["name"], correlation_id)
        if not validation.get("valid"):
            raise ValueError(f"Invalid node name: {validation.get('reason')}")

        logger.info(f"{log_prefix} Containerlab inputs validated")

    def _backup_containerlab_topology(self, correlation_id: str) -> str:
        """Backup containerlab topology file."""
        from core.containerlab import _backup_topology, CONTAINERLAB_TOPOLOGY_PATH

        return _backup_topology(
            topology_path=CONTAINERLAB_TOPOLOGY_PATH,
            correlation_id=correlation_id,
        )

    def _add_containerlab_node(
        self,
        job_id: str,
        params: Dict[str, Any],
        backup_path: str,
        correlation_id: str,
    ) -> None:
        """Add node to containerlab topology."""
        from core.containerlab import add_node

        add_node(
            name=params["name"],
            kind=params["kind"],
            image=params.get("image"),
            startup_config=params.get("startup_config"),
            correlation_id=correlation_id,
        )

        # Add rollback action
        self.state_manager.add_rollback_action(job_id, {
            "action": "restore_topology",
            "platform": "containerlab",
            "backup_path": backup_path,
        })

    def _deploy_containerlab(self, correlation_id: str) -> None:
        """Deploy containerlab topology (additive)."""
        from core.containerlab import deploy_topology

        deploy_topology(correlation_id=correlation_id)

    def _wait_for_containerlab_boot(self, name: str, correlation_id: str) -> None:
        """Wait for containerlab node to be running."""
        import time
        from core.containerlab import get_running_containers

        log_prefix = f"[{correlation_id}]"
        timeout = 60
        interval = 5
        elapsed = 0

        while elapsed < timeout:
            containers = get_running_containers(correlation_id)
            for container in containers:
                if name in container.get("name", ""):
                    logger.info(f"{log_prefix} Node '{name}' is running")
                    return

            time.sleep(interval)
            elapsed += interval
            logger.debug(f"{log_prefix} Waiting for '{name}'... ({elapsed}/{timeout}s)")

        raise ValueError(f"Node '{name}' did not start within {timeout}s")

    # =========================================================================
    # NetBox Operations
    # =========================================================================

    def _create_netbox_device(
        self,
        job_id: str,
        params: Dict[str, Any],
        mgmt_ip: Optional[str],
        correlation_id: str,
    ) -> Optional[int]:
        """Create device in NetBox if configured."""
        log_prefix = f"[{correlation_id}]"

        # Only create if NetBox IDs are provided
        if not params.get("netbox_site_id"):
            logger.info(f"{log_prefix} Skipping NetBox device creation (no site_id)")
            return None

        try:
            from config.netbox_client import get_client

            client = get_client()
            if not client:
                logger.warning(f"{log_prefix} NetBox not configured")
                return None

            # Check if device already exists
            existing = client.get_device(params["name"])
            if existing:
                logger.info(f"{log_prefix} Device '{params['name']}' already exists in NetBox (ID: {existing.get('id')})")
                # Return existing device ID (no rollback action since we didn't create it)
                return existing.get("id")

            # Create device
            device = client.create_device(
                name=params["name"],
                site_id=params.get("netbox_site_id"),
                role_id=params.get("netbox_role_id"),
                device_type_id=params.get("netbox_device_type_id"),
                correlation_id=correlation_id,
            )

            device_id = device.get("id")
            if device_id:
                # Add rollback action
                self.state_manager.add_rollback_action(job_id, {
                    "action": "delete_device",
                    "platform": "netbox",
                    "device_id": device_id,
                })
                logger.info(f"{log_prefix} Created NetBox device: {device_id}")

            return device_id

        except Exception as e:
            # Check for duplicate name error
            err_str = str(e)
            if "must be unique" in err_str.lower() or "already exists" in err_str.lower():
                raise ValueError(f"Device name '{params['name']}' already exists. Choose a unique name.")
            logger.warning(f"{log_prefix} NetBox device creation failed: {e}")
            return None

    # =========================================================================
    # Rollback
    # =========================================================================

    def _execute_rollback(self, job_id: str) -> None:
        """Execute rollback actions in reverse order."""
        job = self.state_manager.get_job(job_id)
        if not job:
            return

        log_prefix = f"[{job.correlation_id}]"
        actions = self.state_manager.get_rollback_actions(job_id)

        if not actions:
            logger.info(f"{log_prefix} No rollback actions to execute")
            return

        logger.warning(f"{log_prefix} Executing {len(actions)} rollback actions")

        for action in actions:
            try:
                self._execute_rollback_action(action, job.correlation_id)
            except Exception as e:
                logger.error(
                    f"{log_prefix} Rollback action failed: {action.get('action')}: {e}"
                )

        self.state_manager.mark_rolled_back(job_id)

    def _execute_rollback_action(
        self, action: Dict[str, Any], correlation_id: str
    ) -> None:
        """Execute a single rollback action."""
        log_prefix = f"[{correlation_id}]"
        action_type = action.get("action")
        platform = action.get("platform")

        logger.info(f"{log_prefix} Rollback: {action_type} on {platform}")

        if action_type == "delete_node" and platform == "eve-ng":
            from core.eve_ng_client import EVEClient

            with EVEClient() as client:
                node_id = action.get("node_id")
                try:
                    # Use wipe instead of stop - more reliable
                    client.wipe_node(node_id, correlation_id=correlation_id)
                except Exception:
                    pass  # Ignore wipe errors
                client.delete_node(node_id, correlation_id=correlation_id)

        elif action_type == "remove_dhcp_reservation" and platform == "eve-ng":
            from core.eve_ng_client import EVEClient

            with EVEClient() as client:
                mac_address = action.get("mac_address")
                if mac_address:
                    client.remove_dhcp_reservation(mac_address, correlation_id=correlation_id)

        elif action_type == "restore_topology" and platform == "containerlab":
            from core.containerlab import _restore_topology, CONTAINERLAB_TOPOLOGY_PATH

            backup_path = action.get("backup_path")
            if backup_path:
                _restore_topology(
                    backup_path=backup_path,
                    topology_path=CONTAINERLAB_TOPOLOGY_PATH,
                    correlation_id=correlation_id,
                )

        elif action_type == "release_ip" and platform == "netbox":
            try:
                from config.netbox_client import get_client

                client = get_client()
                if client:
                    client.release_ip(
                        ip_address=action.get("ip_address"),
                        correlation_id=correlation_id,
                    )
            except Exception as e:
                logger.warning(f"{log_prefix} IP release failed: {e}")

        elif action_type == "delete_device" and platform == "netbox":
            try:
                from config.netbox_client import get_client

                client = get_client()
                if client:
                    client.delete_device(
                        device_id=action.get("device_id"),
                        correlation_id=correlation_id,
                    )
            except Exception as e:
                logger.warning(f"{log_prefix} Device deletion failed: {e}")

    def is_job_running(self, job_id: str) -> bool:
        """Check if a job's thread is still running."""
        thread = self._active_threads.get(job_id)
        return thread is not None and thread.is_alive()

    def cancel_job(self, job_id: str) -> bool:
        """
        Request cancellation of a running job.

        Note: This sets the status to cancelled but doesn't interrupt
        the thread. The thread will complete its current step.
        """
        job = self.state_manager.get_job(job_id)
        if not job or job.status not in (JobStatus.PENDING, JobStatus.RUNNING):
            return False

        self.state_manager.cancel_job(job_id)
        return True


# Global executor instance
_executor: Optional[ProvisioningExecutor] = None


def get_executor(state_manager: ProvisioningStateManager) -> ProvisioningExecutor:
    """Get or create global executor instance."""
    global _executor
    if _executor is None:
        _executor = ProvisioningExecutor(state_manager)
    return _executor
