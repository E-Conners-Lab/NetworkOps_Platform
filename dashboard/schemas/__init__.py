"""
Pydantic schemas for request validation.

These schemas provide centralized validation with clear error messages,
replacing scattered manual validation throughout route handlers.
"""

from dashboard.schemas.common import (
    DeviceIdentifier,
    PaginationParams,
)
from dashboard.schemas.auth import (
    LoginRequest,
    CreateUserRequest,
    UpdateUserRequest,
    ChangePasswordRequest,
    RefreshTokenRequest,
    AssignGroupsRequest,
    CreateGroupRequest,
    UpdateGroupRequest,
    MFACodeRequest,
    MFAVerifyRequest,
)
from dashboard.schemas.changes import (
    CreateChangeRequest,
    ApproveRejectRequest,
)
from dashboard.schemas.devices import (
    CommandRequest,
    CreateDeviceRequest,
)

__all__ = [
    # Common
    "DeviceIdentifier",
    "PaginationParams",
    # Auth
    "LoginRequest",
    "CreateUserRequest",
    "UpdateUserRequest",
    "ChangePasswordRequest",
    "RefreshTokenRequest",
    "AssignGroupsRequest",
    "CreateGroupRequest",
    "UpdateGroupRequest",
    "MFACodeRequest",
    "MFAVerifyRequest",
    # Changes
    "CreateChangeRequest",
    "ApproveRejectRequest",
    # Devices
    "CommandRequest",
    "CreateDeviceRequest",
]
