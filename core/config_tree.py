"""
Config Tree Data Classes.

Defines the data structures for visual config tree builder.
Trees are hierarchical templates that generate Cisco IOS configurations.
"""

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# =============================================================================
# Enums
# =============================================================================


class NodeType(str, Enum):
    """Type of config tree node."""
    SECTION = "section"    # Container node (e.g., "interface", "router ospf")
    COMMAND = "command"    # Leaf command (e.g., "ip address", "no shutdown")
    VARIABLE = "variable"  # Placeholder for user input


class VariableType(str, Enum):
    """Type of variable for user input."""
    STRING = "string"           # Free-form text
    IP_ADDRESS = "ip_address"   # IPv4 address (validated)
    SUBNET_MASK = "subnet_mask" # Subnet mask (validated)
    INTEGER = "integer"         # Number with optional min/max
    CHOICE = "choice"           # Select from predefined options


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ConfigNodeVariable:
    """A variable placeholder within a node's command template."""
    id: str
    node_id: str
    var_name: str                            # e.g., "interface_name"
    var_type: VariableType                   # string, ip_address, etc.
    choices_json: Optional[str] = None       # For CHOICE type: ["Gi1", "Gi2"]
    validation_regex: Optional[str] = None   # Custom regex for STRING type
    min_value: Optional[int] = None          # For INTEGER type
    max_value: Optional[int] = None          # For INTEGER type
    is_required: bool = True
    default_value: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["var_type"] = self.var_type.value if isinstance(self.var_type, VariableType) else self.var_type
        d["choices"] = json.loads(self.choices_json) if self.choices_json else []
        return d

    @classmethod
    def from_row(cls, row) -> "ConfigNodeVariable":
        return cls(
            id=row["id"],
            node_id=row["node_id"],
            var_name=row["var_name"],
            var_type=VariableType(row["var_type"]),
            choices_json=row["choices_json"],
            validation_regex=row["validation_regex"],
            min_value=row["min_value"],
            max_value=row["max_value"],
            is_required=bool(row["is_required"]),
            default_value=row["default_value"],
        )


@dataclass
class ConfigTreeNode:
    """A node in the config tree (section, command, or variable)."""
    id: str
    tree_id: str
    parent_id: Optional[str]                 # NULL for root nodes
    node_type: NodeType                      # section, command, variable
    label: str                               # Display name
    command_template: Optional[str] = None   # e.g., "interface {interface_name}"
    sort_order: int = 0                      # For ordering siblings
    is_required: bool = False                # Must be present in generated config
    is_repeatable: bool = False              # Can appear multiple times
    validation_regex: Optional[str] = None   # Validate generated output
    default_value: Optional[str] = None      # Default command if no variables
    help_text: Optional[str] = None          # User guidance
    created_at: Optional[str] = None
    # Populated when loading tree
    children: list["ConfigTreeNode"] = field(default_factory=list)
    variables: list[ConfigNodeVariable] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "tree_id": self.tree_id,
            "parent_id": self.parent_id,
            "node_type": self.node_type.value if isinstance(self.node_type, NodeType) else self.node_type,
            "label": self.label,
            "command_template": self.command_template,
            "sort_order": self.sort_order,
            "is_required": self.is_required,
            "is_repeatable": self.is_repeatable,
            "validation_regex": self.validation_regex,
            "default_value": self.default_value,
            "help_text": self.help_text,
            "created_at": self.created_at,
            "children": [c.to_dict() for c in self.children],
            "variables": [v.to_dict() for v in self.variables],
        }
        return d

    @classmethod
    def from_row(cls, row) -> "ConfigTreeNode":
        return cls(
            id=row["id"],
            tree_id=row["tree_id"],
            parent_id=row["parent_id"],
            node_type=NodeType(row["node_type"]),
            label=row["label"],
            command_template=row["command_template"],
            sort_order=row["sort_order"],
            is_required=bool(row["is_required"]),
            is_repeatable=bool(row["is_repeatable"]),
            validation_regex=row["validation_regex"],
            default_value=row["default_value"],
            help_text=row["help_text"],
            created_at=row["created_at"],
        )


@dataclass
class ConfigTree:
    """A config tree template."""
    id: str
    name: str
    description: Optional[str]
    platform: str                            # cisco_ios, cisco_nxos, etc.
    version: str
    created_by: str
    created_at: str
    updated_at: str
    # Populated when loading tree
    root_nodes: list[ConfigTreeNode] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "platform": self.platform,
            "version": self.version,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "root_nodes": [n.to_dict() for n in self.root_nodes],
        }

    @classmethod
    def from_row(cls, row) -> "ConfigTree":
        return cls(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            platform=row["platform"],
            version=row["version"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


# =============================================================================
# Predefined Templates
# =============================================================================

# Predefined section templates for the node palette
SECTION_TEMPLATES = [
    {
        "id": "tpl_interface",
        "label": "Interface",
        "node_type": "section",
        "command_template": "interface {interface_name}",
        "help_text": "Configure a physical or logical interface",
        "variables": [
            {"var_name": "interface_name", "var_type": "string", "is_required": True}
        ],
    },
    {
        "id": "tpl_router_ospf",
        "label": "Router OSPF",
        "node_type": "section",
        "command_template": "router ospf {process_id}",
        "help_text": "Configure OSPF routing process",
        "variables": [
            {"var_name": "process_id", "var_type": "integer", "is_required": True, "min_value": 1, "max_value": 65535}
        ],
    },
    {
        "id": "tpl_router_eigrp",
        "label": "Router EIGRP",
        "node_type": "section",
        "command_template": "router eigrp {as_number}",
        "help_text": "Configure EIGRP routing process",
        "variables": [
            {"var_name": "as_number", "var_type": "integer", "is_required": True, "min_value": 1, "max_value": 65535}
        ],
    },
    {
        "id": "tpl_router_bgp",
        "label": "Router BGP",
        "node_type": "section",
        "command_template": "router bgp {as_number}",
        "help_text": "Configure BGP routing process",
        "variables": [
            {"var_name": "as_number", "var_type": "integer", "is_required": True, "min_value": 1, "max_value": 4294967295}
        ],
    },
    {
        "id": "tpl_line_vty",
        "label": "Line VTY",
        "node_type": "section",
        "command_template": "line vty {start_line} {end_line}",
        "help_text": "Configure virtual terminal lines for remote access",
        "variables": [
            {"var_name": "start_line", "var_type": "integer", "is_required": True, "min_value": 0, "max_value": 15},
            {"var_name": "end_line", "var_type": "integer", "is_required": True, "min_value": 0, "max_value": 15},
        ],
    },
    {
        "id": "tpl_line_con",
        "label": "Line Console",
        "node_type": "section",
        "command_template": "line con 0",
        "help_text": "Configure console line",
    },
    {
        "id": "tpl_acl_standard",
        "label": "Standard ACL",
        "node_type": "section",
        "command_template": "ip access-list standard {acl_name}",
        "help_text": "Create a standard named ACL",
        "variables": [
            {"var_name": "acl_name", "var_type": "string", "is_required": True}
        ],
    },
    {
        "id": "tpl_acl_extended",
        "label": "Extended ACL",
        "node_type": "section",
        "command_template": "ip access-list extended {acl_name}",
        "help_text": "Create an extended named ACL",
        "variables": [
            {"var_name": "acl_name", "var_type": "string", "is_required": True}
        ],
    },
]

# Predefined command templates for the node palette
COMMAND_TEMPLATES = [
    # Interface commands
    {
        "id": "tpl_ip_address",
        "label": "IP Address",
        "node_type": "command",
        "command_template": "ip address {ip_address} {subnet_mask}",
        "help_text": "Assign an IP address to the interface",
        "parent_section": "interface",
        "variables": [
            {"var_name": "ip_address", "var_type": "ip_address", "is_required": True},
            {"var_name": "subnet_mask", "var_type": "subnet_mask", "is_required": True},
        ],
    },
    {
        "id": "tpl_description",
        "label": "Description",
        "node_type": "command",
        "command_template": "description {description}",
        "help_text": "Set a description for the interface",
        "parent_section": "interface",
        "variables": [
            {"var_name": "description", "var_type": "string", "is_required": True}
        ],
    },
    {
        "id": "tpl_no_shutdown",
        "label": "No Shutdown",
        "node_type": "command",
        "command_template": "no shutdown",
        "help_text": "Enable the interface",
        "parent_section": "interface",
    },
    {
        "id": "tpl_shutdown",
        "label": "Shutdown",
        "node_type": "command",
        "command_template": "shutdown",
        "help_text": "Disable the interface",
        "parent_section": "interface",
    },
    {
        "id": "tpl_ip_ospf_network",
        "label": "OSPF Network Type",
        "node_type": "command",
        "command_template": "ip ospf network {network_type}",
        "help_text": "Set OSPF network type on interface",
        "parent_section": "interface",
        "variables": [
            {"var_name": "network_type", "var_type": "choice", "is_required": True,
             "choices": ["point-to-point", "broadcast", "non-broadcast", "point-to-multipoint"]}
        ],
    },
    # OSPF commands
    {
        "id": "tpl_ospf_network",
        "label": "Network Statement",
        "node_type": "command",
        "command_template": "network {network} {wildcard} area {area}",
        "help_text": "Advertise a network in OSPF",
        "parent_section": "router_ospf",
        "variables": [
            {"var_name": "network", "var_type": "ip_address", "is_required": True},
            {"var_name": "wildcard", "var_type": "subnet_mask", "is_required": True},
            {"var_name": "area", "var_type": "integer", "is_required": True, "min_value": 0},
        ],
    },
    {
        "id": "tpl_ospf_router_id",
        "label": "Router ID",
        "node_type": "command",
        "command_template": "router-id {router_id}",
        "help_text": "Set OSPF router ID",
        "parent_section": "router_ospf",
        "variables": [
            {"var_name": "router_id", "var_type": "ip_address", "is_required": True}
        ],
    },
    # Global commands
    {
        "id": "tpl_hostname",
        "label": "Hostname",
        "node_type": "command",
        "command_template": "hostname {hostname}",
        "help_text": "Set device hostname",
        "parent_section": "global",
        "variables": [
            {"var_name": "hostname", "var_type": "string", "is_required": True}
        ],
    },
    {
        "id": "tpl_enable_secret",
        "label": "Enable Secret",
        "node_type": "command",
        "command_template": "enable secret {password}",
        "help_text": "Set encrypted enable password",
        "parent_section": "global",
        "variables": [
            {"var_name": "password", "var_type": "string", "is_required": True}
        ],
    },
    {
        "id": "tpl_service_password_encryption",
        "label": "Password Encryption",
        "node_type": "command",
        "command_template": "service password-encryption",
        "help_text": "Encrypt plaintext passwords in config",
        "parent_section": "global",
    },
    {
        "id": "tpl_ip_domain_name",
        "label": "Domain Name",
        "node_type": "command",
        "command_template": "ip domain name {domain}",
        "help_text": "Set default domain name",
        "parent_section": "global",
        "variables": [
            {"var_name": "domain", "var_type": "string", "is_required": True}
        ],
    },
    {
        "id": "tpl_ip_ssh_version",
        "label": "SSH Version 2",
        "node_type": "command",
        "command_template": "ip ssh version 2",
        "help_text": "Enable SSH version 2",
        "parent_section": "global",
    },
    {
        "id": "tpl_logging_buffered",
        "label": "Logging Buffered",
        "node_type": "command",
        "command_template": "logging buffered {size}",
        "help_text": "Enable buffered logging",
        "parent_section": "global",
        "variables": [
            {"var_name": "size", "var_type": "integer", "is_required": True, "min_value": 4096, "max_value": 2147483647, "default_value": "16384"}
        ],
    },
    # VTY commands
    {
        "id": "tpl_transport_input",
        "label": "Transport Input",
        "node_type": "command",
        "command_template": "transport input {protocol}",
        "help_text": "Set allowed transport protocols",
        "parent_section": "line_vty",
        "variables": [
            {"var_name": "protocol", "var_type": "choice", "is_required": True,
             "choices": ["ssh", "telnet", "ssh telnet", "none"]}
        ],
    },
    {
        "id": "tpl_login_local",
        "label": "Login Local",
        "node_type": "command",
        "command_template": "login local",
        "help_text": "Use local user database for login",
        "parent_section": "line_vty",
    },
]
