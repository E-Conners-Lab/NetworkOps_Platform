"""
Common schemas used across multiple route modules.
"""

import re
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class DeviceIdentifier(BaseModel):
    """Device name identifier with security validation."""
    device: str = Field(..., min_length=1, max_length=64, description="Device name")

    @field_validator('device')
    @classmethod
    def validate_device_name(cls, v: str) -> str:
        """Prevent path traversal and command injection in device names."""
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError('Invalid device name: path traversal not allowed')
        if ';' in v or '|' in v or '&' in v or '$' in v or '`' in v:
            raise ValueError('Invalid device name: special characters not allowed')
        return v.strip()


class PaginationParams(BaseModel):
    """Common pagination parameters."""
    limit: int = Field(default=50, ge=1, le=1000, description="Maximum items to return")
    offset: int = Field(default=0, ge=0, description="Number of items to skip")


class InterfaceIdentifier(BaseModel):
    """Interface name identifier with security validation."""
    interface: str = Field(..., min_length=1, max_length=128, description="Interface name")

    @field_validator('interface')
    @classmethod
    def validate_interface_name(cls, v: str) -> str:
        """Validate interface name format."""
        # Allow common interface name patterns
        if not re.match(r'^[A-Za-z0-9/\-_.]+$', v):
            raise ValueError('Invalid interface name format')
        return v.strip()


class IPAddressParam(BaseModel):
    """IP address parameter with validation."""
    ip_address: str = Field(..., min_length=7, max_length=45, description="IP address (v4 or v6)")

    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Basic IP address format validation."""
        import ipaddress
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError('Invalid IP address format')
        return v.strip()
