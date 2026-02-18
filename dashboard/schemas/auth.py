"""
Authentication and authorization request schemas.
"""

import re
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    """User login request."""
    username: str = Field(..., min_length=1, max_length=100, description="Username")
    password: str = Field(..., min_length=1, max_length=200, description="Password")

    @field_validator('username', 'password')
    @classmethod
    def must_be_string(cls, v):
        """Ensure value is a string (prevent type confusion attacks)."""
        if not isinstance(v, str):
            raise ValueError('Must be a string')
        return v.strip() if isinstance(v, str) else v


class CreateUserRequest(BaseModel):
    """Create new user request."""
    username: str = Field(..., min_length=3, max_length=64, description="Username")
    password: str = Field(..., min_length=8, max_length=200, description="Password")
    role: str = Field(default="operator", description="User role")

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format."""
        if not re.match(r'^[a-zA-Z0-9_\-.]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, hyphens, and dots')
        return v.strip()

    @field_validator('role')
    @classmethod
    def validate_role(cls, v: str) -> str:
        """Validate role is allowed."""
        allowed_roles = ['admin', 'operator', 'viewer']
        if v.lower() not in allowed_roles:
            raise ValueError(f'Role must be one of: {", ".join(allowed_roles)}')
        return v.lower()


class UpdateUserRequest(BaseModel):
    """Update existing user request."""
    password: Optional[str] = Field(None, min_length=8, max_length=200, description="New password")
    role: Optional[str] = Field(None, description="New role")
    is_active: Optional[bool] = Field(None, description="Account active status")

    @field_validator('role')
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        """Validate role if provided."""
        if v is None:
            return None
        allowed_roles = ['admin', 'operator', 'viewer']
        if v.lower() not in allowed_roles:
            raise ValueError(f'Role must be one of: {", ".join(allowed_roles)}')
        return v.lower()


class ChangePasswordRequest(BaseModel):
    """Change password request."""
    old_password: str = Field(..., min_length=1, max_length=200, description="Current password")
    new_password: str = Field(..., min_length=8, max_length=200, description="New password")

    @field_validator('new_password')
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        """Validate password meets complexity requirements."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class RefreshTokenRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str = Field(..., min_length=1, description="Refresh token")


class AssignGroupsRequest(BaseModel):
    """Assign groups to user request."""
    group_ids: List[int] = Field(..., description="List of group IDs to assign")

    @field_validator('group_ids')
    @classmethod
    def validate_group_ids(cls, v: List[int]) -> List[int]:
        """Validate group IDs."""
        if not isinstance(v, list):
            raise ValueError('group_ids must be a list')
        if len(v) > 100:
            raise ValueError('Cannot assign more than 100 groups')
        return v


class CreateGroupRequest(BaseModel):
    """Create new group request."""
    name: str = Field(..., min_length=1, max_length=64, description="Group name")
    description: str = Field(default="", max_length=500, description="Group description")
    permissions: List[str] = Field(default_factory=list, description="Permission names")

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate group name format."""
        if not re.match(r'^[a-zA-Z0-9_\- ]+$', v):
            raise ValueError('Group name can only contain letters, numbers, underscores, hyphens, and spaces')
        return v.strip()


class UpdateGroupRequest(BaseModel):
    """Update existing group request."""
    name: Optional[str] = Field(None, min_length=1, max_length=64, description="Group name")
    description: Optional[str] = Field(None, max_length=500, description="Group description")
    permissions: Optional[List[str]] = Field(None, description="Permission names")


class MFACodeRequest(BaseModel):
    """MFA TOTP code request (for confirm/disable)."""
    code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP code")

    @field_validator('code')
    @classmethod
    def validate_code(cls, v: str) -> str:
        """Validate TOTP code format."""
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError('Code must be exactly 6 digits')
        return v


class MFAVerifyRequest(BaseModel):
    """MFA verification request (for login completion)."""
    mfa_token: str = Field(..., min_length=1, description="MFA token from initial login")
    code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP code")

    @field_validator('code')
    @classmethod
    def validate_code(cls, v: str) -> str:
        """Validate TOTP code format."""
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError('Code must be exactly 6 digits')
        return v


class MFARecoveryRequest(BaseModel):
    """MFA recovery code request."""
    mfa_token: str = Field(..., min_length=1, description="MFA token from initial login")
    recovery_code: str = Field(..., min_length=1, max_length=50, description="Recovery code")
