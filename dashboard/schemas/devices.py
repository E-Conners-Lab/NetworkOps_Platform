"""
Device management request schemas.
"""

import re
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator


class CommandRequest(BaseModel):
    """Execute command on device request."""
    device: str = Field(..., min_length=1, max_length=64, description="Device name")
    command: str = Field(..., min_length=1, max_length=1000, description="Command to execute")

    @field_validator('device')
    @classmethod
    def validate_device(cls, v: str) -> str:
        """Validate device name (prevent injection)."""
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError('Invalid device name')
        if ';' in v or '|' in v or '&' in v:
            raise ValueError('Invalid device name')
        return v.strip()

    @field_validator('command')
    @classmethod
    def validate_command(cls, v: str) -> str:
        """Basic command validation (dangerous commands checked elsewhere)."""
        return v.strip()


class ConfigCommandsRequest(BaseModel):
    """Execute configuration commands on device request."""
    device: str = Field(..., min_length=1, max_length=64, description="Device name")
    commands: List[str] = Field(..., min_length=1, description="Configuration commands")

    @field_validator('device')
    @classmethod
    def validate_device(cls, v: str) -> str:
        """Validate device name."""
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError('Invalid device name')
        return v.strip()

    @field_validator('commands')
    @classmethod
    def validate_commands(cls, v: List[str]) -> List[str]:
        """Validate commands list."""
        if not v or len(v) == 0:
            raise ValueError('At least one command is required')
        if len(v) > 500:
            raise ValueError('Too many commands (max 500)')
        return [cmd.strip() for cmd in v if cmd.strip()]


class CreateDeviceRequest(BaseModel):
    """Create device in NetBox request."""
    name: str = Field(..., min_length=1, max_length=64, description="Device name")
    device_type_id: int = Field(..., ge=1, description="NetBox device type ID")
    role_id: int = Field(..., ge=1, description="NetBox device role ID")
    site_id: int = Field(..., ge=1, description="NetBox site ID")
    location_id: Optional[int] = Field(None, ge=1, description="NetBox location ID")
    primary_ip: Optional[str] = Field(None, description="Primary IP address")
    netmiko_device_type: Optional[str] = Field(None, description="Netmiko device type for SSH")
    container_name: Optional[str] = Field(None, description="Container name for containerlab")

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate device name format."""
        if not re.match(r'^[a-zA-Z0-9_\-.]+$', v):
            raise ValueError('Device name can only contain letters, numbers, underscores, hyphens, and dots')
        return v.strip()

    @field_validator('primary_ip')
    @classmethod
    def validate_primary_ip(cls, v: Optional[str]) -> Optional[str]:
        """Validate primary IP if provided."""
        if v is None:
            return None
        import ipaddress
        try:
            # Handle CIDR notation
            if '/' in v:
                ipaddress.ip_interface(v)
            else:
                ipaddress.ip_address(v)
        except ValueError:
            raise ValueError('Invalid IP address format')
        return v.strip()


class RemediateInterfaceRequest(BaseModel):
    """Interface remediation request."""
    device: str = Field(..., min_length=1, max_length=64, description="Device name")
    interface: str = Field(..., min_length=1, max_length=128, description="Interface name")
    action: str = Field(default="no_shutdown", description="Remediation action")

    @field_validator('device')
    @classmethod
    def validate_device(cls, v: str) -> str:
        """Validate device name."""
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError('Invalid device name')
        return v.strip()

    @field_validator('interface')
    @classmethod
    def validate_interface(cls, v: str) -> str:
        """Validate interface name."""
        if not re.match(r'^[A-Za-z0-9/\-_.]+$', v):
            raise ValueError('Invalid interface name format')
        return v.strip()

    @field_validator('action')
    @classmethod
    def validate_action(cls, v: str) -> str:
        """Validate remediation action."""
        valid_actions = ['no_shutdown', 'shutdown', 'bounce']
        if v.lower() not in valid_actions:
            raise ValueError(f'Action must be one of: {", ".join(valid_actions)}')
        return v.lower()


class ProvisionDeviceRequest(BaseModel):
    """Device provisioning request (EVE-NG or Containerlab)."""
    name: str = Field(..., min_length=1, max_length=64, description="Device name")
    platform: str = Field(..., description="Target platform (eve-ng or containerlab)")

    # EVE-NG specific
    eve_ng_image: Optional[str] = Field(None, description="EVE-NG image/template name")
    eve_ng_cpu: Optional[int] = Field(None, ge=1, le=16, description="Number of vCPUs")
    eve_ng_ram: Optional[int] = Field(None, ge=256, le=32768, description="RAM in MB")
    eve_ng_nics: Optional[int] = Field(None, ge=1, le=16, description="Number of NICs")

    # Containerlab specific
    containerlab_kind: Optional[str] = Field(None, description="Containerlab node kind")
    containerlab_image: Optional[str] = Field(None, description="Container image")

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate device name."""
        if not re.match(r'^[a-zA-Z0-9_\-.]+$', v):
            raise ValueError('Device name can only contain letters, numbers, underscores, hyphens, and dots')
        return v.strip()

    @field_validator('platform')
    @classmethod
    def validate_platform(cls, v: str) -> str:
        """Validate platform."""
        valid_platforms = ['eve-ng', 'containerlab', 'netbox-only']
        if v.lower() not in valid_platforms:
            raise ValueError(f'Platform must be one of: {", ".join(valid_platforms)}')
        return v.lower()
