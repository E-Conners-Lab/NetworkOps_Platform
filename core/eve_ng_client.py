"""
EVE-NG REST API Client for automated device provisioning.

Provides authentication, image listing, and node management operations
for the EVE-NG network emulation platform.

Usage:
    from core.eve_ng_client import EVEClient

    client = EVEClient()  # Uses env vars for credentials
    if client.login():
        images = client.get_images()
        print(images)

Environment Variables:
    EVE_NG_HOST: EVE-NG server hostname/IP (default: 203.0.113.201)
    EVE_NG_USERNAME: API username (default: admin)
    EVE_NG_PASSWORD: API password (default: eve)
    EVE_NG_LAB_PATH: Path to lab file (default: /NetworkOps Lab.unl)
"""

import logging
import os
import re
from typing import Dict, List, Optional
from urllib.parse import quote

import requests
from requests.exceptions import ConnectionError, Timeout, RequestException

logger = logging.getLogger(__name__)


class EVEClientError(Exception):
    """Base exception for EVE-NG client errors."""
    pass


class EVEAuthError(EVEClientError):
    """Authentication failed."""
    pass


class EVEConnectionError(EVEClientError):
    """Cannot connect to EVE-NG server."""
    pass


class EVELabError(EVEClientError):
    """Lab operation failed."""
    pass


class EVEClient:
    """
    EVE-NG REST API client.

    Handles authentication, session management, and API operations
    for the EVE-NG network emulation platform.

    Attributes:
        host: EVE-NG server hostname or IP
        username: API username
        password: API password
        lab_path: Default lab path for operations
        authenticated: Whether client has active session
    """

    def __init__(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        lab_path: Optional[str] = None,
    ):
        """
        Initialize EVE-NG client.

        Args:
            host: Server hostname/IP (env: EVE_NG_HOST)
            username: API username (env: EVE_NG_USERNAME)
            password: API password (env: EVE_NG_PASSWORD)
            lab_path: Default lab path (env: EVE_NG_LAB_PATH)
        """
        self.host = host or os.getenv("EVE_NG_HOST", "203.0.113.201")
        if username is None or password is None:
            from config.vault_client import get_eve_ng_credentials
            default_user, default_pass = get_eve_ng_credentials()
            self.username = username or default_user
            self.password = password or default_pass
        else:
            self.username = username
            self.password = password
        self.lab_path = lab_path or os.getenv("EVE_NG_LAB_PATH", "/NetworkOps Lab.unl")

        # Use HTTPS (EVE-NG redirects HTTP to HTTPS)
        self.base_url = f"https://{self.host}/api"
        self.session = requests.Session()
        self.authenticated = False

        # Disable SSL verification for self-signed certs (EVE-NG default)
        self.session.verify = False

        # Suppress SSL warnings for self-signed certs
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Set default headers
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def _encode_lab_path(self, lab_path: str) -> str:
        """
        Encode lab path for API requests.

        EVE-NG API expects lab paths without leading slash and URL-encoded.

        Args:
            lab_path: Lab path (e.g., "/NetworkOps Lab.unl")

        Returns:
            URL-encoded path (e.g., "NetworkOps%20Lab.unl")

        Examples:
            >>> client._encode_lab_path("/NetworkOps Lab.unl")
            'NetworkOps%20Lab.unl'
            >>> client._encode_lab_path("folder/My Lab.unl")
            'folder/My%20Lab.unl'
        """
        # Remove leading slash
        path = lab_path.lstrip("/")
        # URL encode the path (preserve forward slashes for nested paths)
        return quote(path, safe="/")

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        timeout: int = 30,
        correlation_id: str = "",
    ) -> Dict:
        """
        Make authenticated API request.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., "/auth/login")
            data: Request body data
            timeout: Request timeout in seconds
            correlation_id: For log tracing

        Returns:
            JSON response data

        Raises:
            EVEConnectionError: Cannot connect to server
            EVEAuthError: Authentication required/failed
            EVEClientError: Other API errors
        """
        url = f"{self.base_url}{endpoint}"
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        try:
            logger.debug(f"{log_prefix}EVE-NG {method} {endpoint}")

            response = self.session.request(
                method=method,
                url=url,
                json=data,
                timeout=timeout,
            )

            # Handle authentication errors
            if response.status_code == 401:
                self.authenticated = False
                raise EVEAuthError("Authentication required - please login")

            # Handle other errors
            if response.status_code >= 400:
                error_msg = f"API error {response.status_code}"
                try:
                    error_data = response.json()
                    if "message" in error_data:
                        error_msg = error_data["message"]
                except ValueError:
                    error_msg = response.text or error_msg
                raise EVEClientError(f"{log_prefix}{error_msg}")

            # Parse response
            try:
                result = response.json()
                return result.get("data", result)
            except ValueError:
                return {"raw": response.text}

        except ConnectionError as e:
            raise EVEConnectionError(
                f"{log_prefix}Cannot connect to EVE-NG at {self.host}: {e}"
            )
        except Timeout:
            raise EVEConnectionError(
                f"{log_prefix}Connection to EVE-NG timed out after {timeout}s"
            )
        except RequestException as e:
            raise EVEClientError(f"{log_prefix}Request failed: {e}")

    def login(self, correlation_id: str = "") -> bool:
        """
        Authenticate with EVE-NG API.

        Creates a session cookie that's used for subsequent requests.

        Args:
            correlation_id: For log tracing

        Returns:
            True if authentication successful

        Raises:
            EVEAuthError: Invalid credentials
            EVEConnectionError: Cannot connect to server
        """
        log_prefix = f"[{correlation_id}] " if correlation_id else ""
        logger.info(f"{log_prefix}Logging into EVE-NG at {self.host}")

        try:
            result = self._request(
                "POST",
                "/auth/login",
                data={
                    "username": self.username,
                    "password": self.password,
                    "html5": "-1",
                },
                correlation_id=correlation_id,
            )
            self.authenticated = True
            logger.info(f"{log_prefix}EVE-NG login successful")
            return True

        except EVEClientError as e:
            if "Unauthorized" in str(e) or "Invalid" in str(e):
                raise EVEAuthError(
                    f"{log_prefix}Invalid credentials for user '{self.username}'"
                )
            raise

    def logout(self, correlation_id: str = "") -> bool:
        """
        End EVE-NG session.

        Args:
            correlation_id: For log tracing

        Returns:
            True if logout successful
        """
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        try:
            self._request("GET", "/auth/logout", correlation_id=correlation_id)
            self.authenticated = False
            logger.info(f"{log_prefix}EVE-NG logout successful")
            return True
        except EVEClientError:
            self.authenticated = False
            return True

    def get_status(self, correlation_id: str = "") -> Dict:
        """
        Get EVE-NG server status.

        Returns:
            Dict with server version, uptime, etc.
        """
        return self._request("GET", "/status", correlation_id=correlation_id)

    # =========================================================================
    # Image Management
    # =========================================================================

    def get_images(self, image_type: Optional[str] = None, correlation_id: str = "") -> List[Dict]:
        """
        List available node images/templates.

        Args:
            image_type: Filter keyword (e.g., "cisco", "arista") or None for all
            correlation_id: For log tracing

        Returns:
            List of image dictionaries with name and description.
            Only returns templates that have images installed (no ".missing" suffix).
        """
        log_prefix = f"[{correlation_id}] " if correlation_id else ""
        logger.debug(f"{log_prefix}Fetching EVE-NG images (filter={image_type})")

        all_images = []

        try:
            result = self._request(
                "GET",
                "/list/templates/",
                correlation_id=correlation_id,
            )

            # Result is a dict of template_name -> description
            # Templates with ".missing" suffix don't have images installed
            if isinstance(result, dict):
                for name, description in result.items():
                    # Skip templates without images
                    if description.endswith(".missing"):
                        continue

                    # Apply filter if provided
                    if image_type:
                        filter_lower = image_type.lower()
                        if filter_lower not in name.lower() and filter_lower not in description.lower():
                            continue

                    all_images.append({
                        "name": name,
                        "description": description,
                    })

        except EVEClientError as e:
            logger.warning(f"{log_prefix}Failed to fetch templates: {e}")
            raise

        # Sort by name
        all_images.sort(key=lambda x: x["name"])
        logger.info(f"{log_prefix}Found {len(all_images)} available EVE-NG images")
        return all_images

    def get_image(self, template_name: str, correlation_id: str = "") -> Optional[Dict]:
        """
        Get details for a specific image template.

        Args:
            template_name: Template name (e.g., "vios", "veos")
            correlation_id: For log tracing

        Returns:
            Template details or None if not found
        """
        images = self.get_images(correlation_id=correlation_id)
        for img in images:
            if img["name"] == template_name:
                return img
        return None

    # =========================================================================
    # Lab Management
    # =========================================================================

    def get_labs(self, folder: str = "/", correlation_id: str = "") -> List[Dict]:
        """
        List labs in a folder.

        Args:
            folder: Folder path (default: root)
            correlation_id: For log tracing

        Returns:
            List of lab dictionaries
        """
        encoded_folder = self._encode_lab_path(folder)
        result = self._request(
            "GET",
            f"/folders/{encoded_folder}",
            correlation_id=correlation_id,
        )

        labs = []
        if isinstance(result, dict):
            # Labs are in the "labs" key
            for lab_info in result.get("labs", {}).values():
                labs.append({
                    "name": lab_info.get("name", ""),
                    "path": lab_info.get("path", ""),
                    "filename": lab_info.get("file", ""),
                })

        return labs

    def validate_lab(self, lab_path: Optional[str] = None, correlation_id: str = "") -> bool:
        """
        Verify that a lab exists and is accessible.

        Args:
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            True if lab exists and is accessible

        Raises:
            EVELabError: Lab not found or not accessible
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        try:
            result = self._request(
                "GET",
                f"/labs/{encoded_path}",
                correlation_id=correlation_id,
            )
            logger.info(f"{log_prefix}Lab validated: {path}")
            return True
        except EVEClientError as e:
            if "not found" in str(e).lower() or "404" in str(e):
                raise EVELabError(f"{log_prefix}Lab not found: {path}")
            raise

    def get_lab_topology(self, lab_path: Optional[str] = None, correlation_id: str = "") -> Dict:
        """
        Get full lab topology including nodes and networks.

        Args:
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            Dict with nodes, networks, and links
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)

        # Get lab info
        lab_info = self._request(
            "GET",
            f"/labs/{encoded_path}",
            correlation_id=correlation_id,
        )

        # Get nodes
        nodes = self._request(
            "GET",
            f"/labs/{encoded_path}/nodes",
            correlation_id=correlation_id,
        )

        # Get networks
        networks = self._request(
            "GET",
            f"/labs/{encoded_path}/networks",
            correlation_id=correlation_id,
        )

        return {
            "info": lab_info,
            "nodes": nodes if isinstance(nodes, dict) else {},
            "networks": networks if isinstance(networks, dict) else {},
        }

    def get_networks(self, lab_path: Optional[str] = None, correlation_id: str = "") -> List[Dict]:
        """
        List networks in a lab.

        Args:
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            List of network dictionaries
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)

        result = self._request(
            "GET",
            f"/labs/{encoded_path}/networks",
            correlation_id=correlation_id,
        )

        networks = []
        if isinstance(result, dict):
            for net_id, net_info in result.items():
                networks.append({
                    "id": int(net_id),
                    "name": net_info.get("name", ""),
                    "type": net_info.get("type", ""),
                    "visibility": net_info.get("visibility", 1),
                })

        return networks

    def get_or_validate_mgmt_network(
        self,
        lab_path: Optional[str] = None,
        network_name: str = "pnet1",
        correlation_id: str = "",
    ) -> Optional[Dict]:
        """
        Validate that management network exists in the lab.

        Args:
            lab_path: Lab path (default: self.lab_path)
            network_name: Network name to find (default: pnet1)
            correlation_id: For log tracing

        Returns:
            Network info dict if found, None otherwise

        Note:
            We do NOT auto-create the network - that should be done
            manually by the administrator for safety.
        """
        log_prefix = f"[{correlation_id}] " if correlation_id else ""
        networks = self.get_networks(lab_path, correlation_id)

        for net in networks:
            if net["name"] == network_name or net["type"] == network_name:
                logger.info(f"{log_prefix}Found management network: {network_name}")
                return net

        logger.warning(f"{log_prefix}Management network '{network_name}' not found")
        return None

    # =========================================================================
    # Node Management (Read-Only for Phase 1)
    # =========================================================================

    def get_nodes(self, lab_path: Optional[str] = None, correlation_id: str = "") -> List[Dict]:
        """
        List nodes in a lab.

        Args:
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            List of node dictionaries
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)

        result = self._request(
            "GET",
            f"/labs/{encoded_path}/nodes",
            correlation_id=correlation_id,
        )

        nodes = []
        if isinstance(result, dict):
            for node_id, node_info in result.items():
                nodes.append({
                    "id": int(node_id),
                    "name": node_info.get("name", ""),
                    "template": node_info.get("template", ""),
                    "status": node_info.get("status", 0),
                    "cpu": node_info.get("cpu", 1),
                    "ram": node_info.get("ram", 1024),
                    "ethernet": node_info.get("ethernet", 4),
                    "console": node_info.get("console", ""),
                    "url": node_info.get("url", ""),
                })

        return nodes

    def get_node(
        self,
        node_id: int,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> Optional[Dict]:
        """
        Get details for a specific node.

        Args:
            node_id: Node ID
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            Node details or None if not found
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)

        try:
            result = self._request(
                "GET",
                f"/labs/{encoded_path}/nodes/{node_id}",
                correlation_id=correlation_id,
            )
            return result
        except EVEClientError:
            return None

    def get_node_interfaces(
        self,
        node_id: int,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> List[Dict]:
        """
        Get interfaces for a node.

        Args:
            node_id: Node ID
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            List of interface dictionaries
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)

        result = self._request(
            "GET",
            f"/labs/{encoded_path}/nodes/{node_id}/interfaces",
            correlation_id=correlation_id,
        )

        interfaces = []
        if isinstance(result, dict):
            # Ethernet interfaces
            for intf_id, intf_info in result.get("ethernet", {}).items():
                interfaces.append({
                    "id": int(intf_id),
                    "type": "ethernet",
                    "name": intf_info.get("name", f"e{intf_id}"),
                    "network_id": intf_info.get("network_id", 0),
                })
            # Serial interfaces
            for intf_id, intf_info in result.get("serial", {}).items():
                interfaces.append({
                    "id": int(intf_id),
                    "type": "serial",
                    "name": intf_info.get("name", f"s{intf_id}"),
                    "network_id": intf_info.get("network_id", 0),
                })

        return interfaces

    # =========================================================================
    # Lock Management (EVE-NG bug workaround)
    # =========================================================================

    def _clear_stale_lock(self, correlation_id: str = "") -> None:
        """
        Clear stale lock files via SSH.

        EVE-NG has a bug where lock files can become orphaned, preventing
        lab modifications even when no user has the lab locked. This method
        removes the lock file directly on the server.

        Args:
            correlation_id: For log tracing

        Note:
            Requires SSH access to EVE-NG with password 'eve' (default).
            Silently continues if SSH is unavailable.
        """
        import subprocess

        log_prefix = f"[{correlation_id}] " if correlation_id else ""
        lab_path = self.lab_path.lstrip("/")
        lock_file = f"/opt/unetlab/labs/{lab_path}.lock"

        try:
            # Check for sshpass
            result = subprocess.run(
                ["which", "sshpass"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.debug(f"{log_prefix}sshpass not available, skipping lock clear")
                return

            # Remove lock file via SSH
            cmd = [
                "sshpass", "-p", self.password,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                f"root@{self.host}",
                f"rm -f {lock_file}"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                logger.info(f"{log_prefix}Cleared stale lock file: {lock_file}")
            else:
                logger.debug(f"{log_prefix}Lock file clear returned {result.returncode}")

        except subprocess.TimeoutExpired:
            logger.debug(f"{log_prefix}SSH timeout clearing lock file")
        except Exception as e:
            logger.debug(f"{log_prefix}Could not clear lock file: {e}")

    def add_dhcp_reservation(
        self,
        mac_address: str,
        ip_address: str,
        hostname: str,
        correlation_id: str = "",
    ) -> bool:
        """
        Add a DHCP reservation for a node via SSH.

        Creates a reservation in /etc/dnsmasq.d/dhcp-hosts and reloads dnsmasq
        so the node gets the specified IP address when it boots.

        Args:
            mac_address: Node's MAC address (e.g., "50:00:00:0d:00:00")
            ip_address: IP to assign (e.g., "10.255.255.15")
            hostname: Node hostname
            correlation_id: For log tracing

        Returns:
            True if reservation added successfully
        """
        import subprocess

        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        # Strip CIDR notation if present
        ip_only = ip_address.split("/")[0]

        logger.info(
            f"{log_prefix}Adding DHCP reservation: {mac_address} -> {ip_only} ({hostname})"
        )

        try:
            # Check for sshpass
            result = subprocess.run(
                ["which", "sshpass"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.warning(f"{log_prefix}sshpass not available, cannot add DHCP reservation")
                return False

            # Add reservation to dhcp-hosts file
            reservation = f"{mac_address},{ip_only},{hostname}"
            cmd = [
                "sshpass", "-p", self.password,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                f"root@{self.host}",
                f"echo '{reservation}' >> /etc/dnsmasq.d/dhcp-hosts && "
                f"systemctl reload dnsmasq"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0:
                logger.info(f"{log_prefix}DHCP reservation added and dnsmasq reloaded")
                return True
            else:
                logger.error(f"{log_prefix}DHCP reservation failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"{log_prefix}SSH timeout adding DHCP reservation")
            return False
        except Exception as e:
            logger.error(f"{log_prefix}Could not add DHCP reservation: {e}")
            return False

    def remove_dhcp_reservation(
        self,
        mac_address: str,
        correlation_id: str = "",
    ) -> bool:
        """
        Remove a DHCP reservation for a node via SSH.

        Args:
            mac_address: Node's MAC address to remove
            correlation_id: For log tracing

        Returns:
            True if reservation removed successfully
        """
        import subprocess

        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(f"{log_prefix}Removing DHCP reservation for {mac_address}")

        try:
            # Check for sshpass
            result = subprocess.run(
                ["which", "sshpass"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False

            # Remove reservation from dhcp-hosts file
            cmd = [
                "sshpass", "-p", self.password,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                f"root@{self.host}",
                f"sed -i '/{mac_address}/d' /etc/dnsmasq.d/dhcp-hosts && "
                f"systemctl reload dnsmasq"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0:
                logger.info(f"{log_prefix}DHCP reservation removed")
                return True
            return False

        except Exception as e:
            logger.debug(f"{log_prefix}Could not remove DHCP reservation: {e}")
            return False

    # =========================================================================
    # Node Write Operations (Phase 5)
    # =========================================================================

    def create_node(
        self,
        name: str,
        template: str,
        cpu: int = 1,
        ram: int = 2048,
        ethernet: int = 4,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> Dict:
        """
        Create a new node in the lab.

        Args:
            name: Node name (hostname)
            template: Template name (e.g., "vios", "veos", "csr1000v")
            cpu: Number of vCPUs
            ram: RAM in MB
            ethernet: Number of ethernet interfaces
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            Dict with created node info including 'id'

        Raises:
            EVELabError: Node creation failed
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(f"{log_prefix}Creating node '{name}' with template '{template}'")

        # Clear any stale lock files before modifying lab (EVE-NG bug workaround)
        self._clear_stale_lock(correlation_id)

        # Generate random position to avoid overlap with existing nodes
        import random
        left = random.randint(100, 800)
        top = random.randint(100, 600)

        node_data = {
            "type": "qemu",  # Most templates are QEMU-based
            "template": template,
            "name": name,
            "cpu": cpu,
            "ram": ram,
            "ethernet": ethernet,
            "image": "",  # Use default image for template
            "left": left,  # X position on canvas
            "top": top,    # Y position on canvas
        }

        try:
            result = self._request(
                "POST",
                f"/labs/{encoded_path}/nodes",
                data=node_data,
                correlation_id=correlation_id,
            )

            # Extract node ID from result
            node_id = result.get("id")
            if not node_id:
                raise EVELabError(f"{log_prefix}Node created but no ID returned")

            logger.info(f"{log_prefix}Created node '{name}' with ID {node_id}")

            # Get node details to retrieve MAC address
            mac_address = None
            try:
                node_details = self._request(
                    "GET",
                    f"/labs/{encoded_path}/nodes/{node_id}",
                    correlation_id=correlation_id,
                )
                mac_address = node_details.get("firstmac")
                if mac_address:
                    logger.info(f"{log_prefix}Node MAC address: {mac_address}")
            except Exception as e:
                logger.warning(f"{log_prefix}Could not get MAC address: {e}")

            return {
                "id": node_id,
                "name": name,
                "template": template,
                "cpu": cpu,
                "ram": ram,
                "ethernet": ethernet,
                "mac_address": mac_address,
            }

        except EVEClientError as e:
            raise EVELabError(f"{log_prefix}Failed to create node '{name}': {e}")

    def delete_node(
        self,
        node_id: int,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> bool:
        """
        Delete a node from the lab.

        Args:
            node_id: Node ID to delete
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            True if deleted successfully

        Raises:
            EVELabError: Deletion failed
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(f"{log_prefix}Deleting node {node_id}")

        # Clear any stale lock files before modifying lab (EVE-NG bug workaround)
        self._clear_stale_lock(correlation_id)

        try:
            self._request(
                "DELETE",
                f"/labs/{encoded_path}/nodes/{node_id}",
                correlation_id=correlation_id,
            )
            logger.info(f"{log_prefix}Deleted node {node_id}")
            return True

        except EVEClientError as e:
            # Node might already be deleted
            if "not found" in str(e).lower() or "404" in str(e):
                logger.warning(f"{log_prefix}Node {node_id} not found (already deleted?)")
                return True
            raise EVELabError(f"{log_prefix}Failed to delete node {node_id}: {e}")

    def connect_to_network(
        self,
        node_id: int,
        interface_id: int,
        network_id: int,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> bool:
        """
        Connect a node interface to a network.

        Args:
            node_id: Node ID
            interface_id: Interface number (0-based)
            network_id: Network ID to connect to
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            True if connected successfully

        Raises:
            EVELabError: Connection failed
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(
            f"{log_prefix}Connecting node {node_id} interface {interface_id} "
            f"to network {network_id}"
        )

        # Clear any stale lock files before modifying lab (EVE-NG bug workaround)
        self._clear_stale_lock(correlation_id)

        try:
            self._request(
                "PUT",
                f"/labs/{encoded_path}/nodes/{node_id}/interfaces",
                data={str(interface_id): str(network_id)},
                correlation_id=correlation_id,
            )
            logger.info(f"{log_prefix}Connected interface successfully")
            return True

        except EVEClientError as e:
            raise EVELabError(
                f"{log_prefix}Failed to connect interface {interface_id} "
                f"on node {node_id}: {e}"
            )

    def start_node(
        self,
        node_id: int,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> bool:
        """
        Start a node.

        Args:
            node_id: Node ID to start
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            True if started successfully

        Raises:
            EVELabError: Start failed
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(f"{log_prefix}Starting node {node_id}")

        try:
            self._request(
                "GET",
                f"/labs/{encoded_path}/nodes/{node_id}/start",
                correlation_id=correlation_id,
            )
            logger.info(f"{log_prefix}Node {node_id} started")
            return True

        except EVEClientError as e:
            raise EVELabError(f"{log_prefix}Failed to start node {node_id}: {e}")

    def stop_node(
        self,
        node_id: int,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> bool:
        """
        Stop a node.

        Args:
            node_id: Node ID to stop
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            True if stopped successfully

        Raises:
            EVELabError: Stop failed
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(f"{log_prefix}Stopping node {node_id}")

        try:
            self._request(
                "GET",
                f"/labs/{encoded_path}/nodes/{node_id}/stop",
                correlation_id=correlation_id,
            )
            logger.info(f"{log_prefix}Node {node_id} stopped")
            return True

        except EVEClientError as e:
            raise EVELabError(f"{log_prefix}Failed to stop node {node_id}: {e}")

    def wipe_node(
        self,
        node_id: int,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> bool:
        """
        Wipe (stop and clear) a node.

        More reliable than stop_node for shutdown. Clears the node state
        and stops it if running.

        Args:
            node_id: Node ID to wipe
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            True if wiped successfully
        """
        path = lab_path or self.lab_path
        encoded_path = self._encode_lab_path(path)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(f"{log_prefix}Wiping node {node_id}")

        try:
            self._request(
                "GET",
                f"/labs/{encoded_path}/nodes/{node_id}/wipe",
                correlation_id=correlation_id,
            )
            logger.info(f"{log_prefix}Node {node_id} wiped")
            return True

        except EVEClientError as e:
            # Wipe might fail if node doesn't exist
            if "not found" in str(e).lower() or "404" in str(e):
                logger.warning(f"{log_prefix}Node {node_id} not found")
                return True
            raise EVELabError(f"{log_prefix}Failed to wipe node {node_id}: {e}")

    def wait_for_boot(
        self,
        node_ip: str,
        timeout: int = 180,
        retry_interval: int = 10,
        correlation_id: str = "",
    ) -> bool:
        """
        Wait for a node to become SSH-reachable.

        Args:
            node_ip: Node IP address to check
            timeout: Maximum wait time in seconds
            retry_interval: Seconds between retries
            correlation_id: For log tracing

        Returns:
            True if node is reachable before timeout

        Raises:
            EVELabError: Node didn't become reachable in time
        """
        import socket
        import time

        log_prefix = f"[{correlation_id}] " if correlation_id else ""
        logger.info(f"{log_prefix}Waiting for {node_ip} to become SSH-reachable")

        start_time = time.time()
        elapsed = 0

        while elapsed < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((node_ip, 22))
                sock.close()

                if result == 0:
                    logger.info(
                        f"{log_prefix}Node {node_ip} is SSH-reachable "
                        f"after {int(elapsed)}s"
                    )
                    return True

            except socket.error:
                pass

            time.sleep(retry_interval)
            elapsed = time.time() - start_time
            logger.debug(
                f"{log_prefix}Waiting for {node_ip}... ({int(elapsed)}/{timeout}s)"
            )

        raise EVELabError(
            f"{log_prefix}Node {node_ip} not reachable after {timeout}s"
        )

    def apply_ztp_config(
        self,
        node_ip: str,
        username: str = "admin",
        password: str = "admin",
        correlation_id: str = "",
    ) -> bool:
        """
        Apply Zero-Touch Provisioning config to enable SSH and NETCONF.

        This connects to a freshly booted node and applies basic config
        to enable management connectivity.

        Args:
            node_ip: Node IP address
            username: SSH username
            password: SSH password
            correlation_id: For log tracing

        Returns:
            True if ZTP config applied successfully

        Raises:
            EVELabError: ZTP configuration failed
        """
        log_prefix = f"[{correlation_id}] " if correlation_id else ""
        logger.info(f"{log_prefix}Applying ZTP config to {node_ip}")

        try:
            from netmiko import ConnectHandler

            device = {
                "device_type": "cisco_xe",
                "host": node_ip,
                "username": username,
                "password": password,
                "timeout": 30,
            }

            # Basic ZTP config for SSH and NETCONF
            ztp_commands = [
                "hostname ZTP-DEVICE",
                "ip domain-name lab.local",
                "crypto key generate rsa modulus 2048",
                "ip ssh version 2",
                "line vty 0 4",
                "transport input ssh",
                "login local",
                "netconf-yang",
            ]

            conn = ConnectHandler(**device)
            output = conn.send_config_set(ztp_commands)
            conn.save_config()
            conn.disconnect()

            logger.info(f"{log_prefix}ZTP config applied to {node_ip}")
            return True

        except ImportError:
            logger.warning(f"{log_prefix}netmiko not available, skipping ZTP")
            return False
        except Exception as e:
            raise EVELabError(f"{log_prefix}ZTP config failed for {node_ip}: {e}")

    def get_node_by_name(
        self,
        name: str,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> Optional[Dict]:
        """
        Find a node by name.

        Args:
            name: Node name to find
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            Node info dict or None if not found
        """
        nodes = self.get_nodes(lab_path, correlation_id)
        for node in nodes:
            if node["name"] == name:
                return node
        return None

    def provision_node(
        self,
        name: str,
        template: str,
        mgmt_ip: str,
        cpu: int = 1,
        ram: int = 2048,
        ethernet: int = 4,
        mgmt_interface: int = 3,  # Default: Gi4 (0-indexed as 3)
        mgmt_network_name: str = "pnet1",
        wait_for_boot: bool = True,
        apply_ztp: bool = True,
        boot_timeout: int = 180,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> Dict:
        """
        Full node provisioning workflow.

        1. Validate management network exists
        2. Create node
        3. Connect management interface to network
        4. Start node
        5. Wait for SSH (optional)
        6. Apply ZTP config (optional)

        On failure at any step, performs rollback (deletes node).

        Args:
            name: Node name
            template: Template name (e.g., "vios")
            mgmt_ip: Management IP (for wait_for_boot)
            cpu: Number of vCPUs
            ram: RAM in MB
            ethernet: Number of ethernet interfaces
            mgmt_interface: Interface number for management (0-indexed)
            mgmt_network_name: Management network name (default: pnet1)
            wait_for_boot: Wait for SSH connectivity
            apply_ztp: Apply ZTP config after boot
            boot_timeout: Timeout for boot wait
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            Dict with provisioning result including node_id

        Raises:
            EVELabError: Provisioning failed (with rollback)
        """
        path = lab_path or self.lab_path
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(f"{log_prefix}Starting provisioning for '{name}'")

        node_id = None

        try:
            # Step 1: Validate management network
            mgmt_net = self.get_or_validate_mgmt_network(
                path, mgmt_network_name, correlation_id
            )
            if not mgmt_net:
                raise EVELabError(
                    f"{log_prefix}Management network '{mgmt_network_name}' not found. "
                    "Please create it manually in EVE-NG."
                )

            # Step 2: Create node
            node = self.create_node(
                name=name,
                template=template,
                cpu=cpu,
                ram=ram,
                ethernet=ethernet,
                lab_path=path,
                correlation_id=correlation_id,
            )
            node_id = node["id"]

            # Step 3: Connect management interface
            self.connect_to_network(
                node_id=node_id,
                interface_id=mgmt_interface,
                network_id=mgmt_net["id"],
                lab_path=path,
                correlation_id=correlation_id,
            )

            # Step 4: Start node
            self.start_node(node_id, path, correlation_id)

            # Step 5: Wait for SSH (optional)
            if wait_for_boot:
                # Extract IP without CIDR
                ip_only = mgmt_ip.split("/")[0]
                self.wait_for_boot(
                    node_ip=ip_only,
                    timeout=boot_timeout,
                    correlation_id=correlation_id,
                )

                # Step 6: Apply ZTP (optional)
                if apply_ztp:
                    self.apply_ztp_config(
                        node_ip=ip_only,
                        correlation_id=correlation_id,
                    )

            logger.info(f"{log_prefix}Provisioning complete for '{name}'")

            return {
                "status": "success",
                "node_id": node_id,
                "name": name,
                "template": template,
                "mgmt_ip": mgmt_ip,
            }

        except EVELabError:
            # Rollback: delete the node if it was created
            if node_id:
                logger.warning(
                    f"{log_prefix}Provisioning failed, rolling back node {node_id}"
                )
                try:
                    self.stop_node(node_id, path, correlation_id)
                except EVELabError:
                    pass  # Ignore stop errors during rollback
                self.delete_node(node_id, path, correlation_id)
            raise

    def deprovision_node(
        self,
        node_id: Optional[int] = None,
        name: Optional[str] = None,
        lab_path: Optional[str] = None,
        correlation_id: str = "",
    ) -> bool:
        """
        Remove a node from the lab.

        Stops the node if running, then deletes it.

        Args:
            node_id: Node ID to remove (preferred)
            name: Node name (alternative to node_id)
            lab_path: Lab path (default: self.lab_path)
            correlation_id: For log tracing

        Returns:
            True if node was removed

        Raises:
            EVELabError: Deprovisioning failed
        """
        path = lab_path or self.lab_path
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        # Find node by name if ID not provided
        if node_id is None:
            if name is None:
                raise EVELabError(f"{log_prefix}Either node_id or name required")

            node = self.get_node_by_name(name, path, correlation_id)
            if not node:
                logger.warning(f"{log_prefix}Node '{name}' not found")
                return True  # Already gone
            node_id = node["id"]

        logger.info(f"{log_prefix}Deprovisioning node {node_id}")

        # Stop if running
        try:
            self.stop_node(node_id, path, correlation_id)
        except EVELabError:
            pass  # Might already be stopped

        # Delete
        self.delete_node(node_id, path, correlation_id)

        logger.info(f"{log_prefix}Deprovisioned node {node_id}")
        return True

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def is_connected(self) -> bool:
        """Check if client can reach EVE-NG server."""
        try:
            self.get_status()
            return True
        except EVEClientError:
            return False

    def __enter__(self):
        """Context manager entry - login."""
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - logout."""
        self.logout()
        return False


# =========================================================================
# Module-level convenience functions
# =========================================================================

_client: Optional[EVEClient] = None


def get_client() -> EVEClient:
    """
    Get singleton EVE-NG client instance.

    Creates and authenticates client on first call.

    Returns:
        Authenticated EVEClient instance
    """
    global _client
    if _client is None:
        _client = EVEClient()
        _client.login()
    elif not _client.authenticated:
        _client.login()
    return _client


def is_eve_ng_available() -> bool:
    """
    Check if EVE-NG is configured and reachable.

    Returns:
        True if EVE-NG host is set and reachable
    """
    host = os.getenv("EVE_NG_HOST", "")
    if not host:
        return False

    client = EVEClient(host=host)
    return client.is_connected()
