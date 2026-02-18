"""
Change management request schemas.
"""

from typing import Optional, List, Union
from pydantic import BaseModel, Field, field_validator, model_validator


class CreateChangeRequest(BaseModel):
    """Create change request (RFC)."""
    device: str = Field(..., min_length=1, max_length=64, description="Target device name")
    description: str = Field(..., min_length=1, max_length=1000, description="Change description")
    commands: Optional[List[str]] = Field(default=None, description="List of commands to execute")
    command_string: Optional[str] = Field(default=None, description="Commands as newline-separated string")
    change_type: str = Field(default="config", description="Type of change")
    validation_checks: Union[List[str], str] = Field(
        default_factory=list,
        description="Post-change validation commands"
    )
    require_approval: bool = Field(default=True, description="Whether change requires approval")
    auto_rollback: bool = Field(default=True, description="Auto-rollback on validation failure")

    @field_validator('device')
    @classmethod
    def validate_device(cls, v: str) -> str:
        """Validate device name."""
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError('Invalid device name')
        return v.strip()

    @field_validator('change_type')
    @classmethod
    def validate_change_type(cls, v: str) -> str:
        """Validate change type."""
        valid_types = ['config', 'interface', 'routing', 'acl', 'maintenance', 'emergency']
        if v.lower() not in valid_types:
            raise ValueError(f'change_type must be one of: {", ".join(valid_types)}')
        return v.lower()

    @field_validator('validation_checks', mode='before')
    @classmethod
    def parse_validation_checks(cls, v):
        """Parse validation checks from string or list."""
        if isinstance(v, str):
            return [line.strip() for line in v.split('\n') if line.strip()]
        return v or []

    @model_validator(mode='after')
    def validate_commands_present(self):
        """Ensure either commands or command_string is provided."""
        if not self.commands and not self.command_string:
            raise ValueError('Either commands or command_string is required')

        # Parse command_string into commands if needed
        if self.command_string and not self.commands:
            self.commands = [
                line.strip()
                for line in self.command_string.split('\n')
                if line.strip()
            ]
        elif isinstance(self.commands, str):
            self.commands = [
                line.strip()
                for line in self.commands.split('\n')
                if line.strip()
            ]

        return self


class ApproveRejectRequest(BaseModel):
    """Approve or reject change request."""
    notes: Optional[str] = Field(default=None, max_length=2000, description="Approval/rejection notes")


class ExecuteChangeRequest(BaseModel):
    """Execute approved change request."""
    dry_run: bool = Field(default=False, description="Preview commands without executing")


class RollbackRequest(BaseModel):
    """Rollback completed/failed change request."""
    reason: Optional[str] = Field(default=None, max_length=1000, description="Rollback reason")
