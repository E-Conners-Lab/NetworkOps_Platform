"""
Config Tree Generator.

Generates Cisco IOS configuration commands from a config tree template
with variable substitution.
"""

import ipaddress
import logging
import re
from typing import Optional

from core.config_tree import (
    ConfigTree,
    ConfigTreeNode,
    ConfigNodeVariable,
    NodeType,
    VariableType,
)

logger = logging.getLogger(__name__)


class ConfigTreeGenerator:
    """Generate IOS commands from config trees."""

    def generate(self, tree: ConfigTree, values: dict[str, str]) -> dict:
        """
        Generate IOS config from a tree with variable substitution.

        Args:
            tree: The config tree template
            values: Dict mapping variable names to values
                    e.g., {"interface_name": "GigabitEthernet1", "ip_address": "10.0.0.1"}

        Returns:
            Dict with:
                - config: The generated config as a string
                - errors: List of validation errors
                - warnings: List of warnings
        """
        errors = []
        warnings = []
        lines = []

        # Process each root node
        for node in tree.root_nodes:
            node_lines, node_errors, node_warnings = self._render_node(node, values, indent=0)
            lines.extend(node_lines)
            errors.extend(node_errors)
            warnings.extend(node_warnings)

        # Join lines with proper line endings
        config = "\n".join(lines)

        return {
            "config": config,
            "errors": errors,
            "warnings": warnings,
        }

    def _render_node(
        self,
        node: ConfigTreeNode,
        values: dict[str, str],
        indent: int,
    ) -> tuple[list[str], list[str], list[str]]:
        """
        Recursively render a node and its children.

        Returns:
            Tuple of (lines, errors, warnings)
        """
        lines = []
        errors = []
        warnings = []

        # Get the command for this node
        if node.command_template:
            result = self._substitute_variables(
                node.command_template,
                values,
                node.variables,
                node.label,
            )
            command = result["command"]
            errors.extend(result["errors"])
            warnings.extend(result["warnings"])

            if command:
                # Add proper indentation
                prefix = " " * indent
                lines.append(f"{prefix}{command}")
        elif node.default_value:
            # Use default value if no template
            prefix = " " * indent
            lines.append(f"{prefix}{node.default_value}")

        # Process children with increased indentation
        child_indent = indent + 1 if node.node_type == NodeType.SECTION else indent

        for child in node.children:
            child_lines, child_errors, child_warnings = self._render_node(
                child, values, child_indent
            )
            lines.extend(child_lines)
            errors.extend(child_errors)
            warnings.extend(child_warnings)

        # Add blank line after section nodes for readability
        if node.node_type == NodeType.SECTION and lines:
            lines.append("!")

        return lines, errors, warnings

    def _substitute_variables(
        self,
        template: str,
        values: dict[str, str],
        variables: list[ConfigNodeVariable],
        node_label: str,
    ) -> dict:
        """
        Replace {var_name} placeholders with actual values.

        Args:
            template: Command template with {var_name} placeholders
            values: Dict of variable values
            variables: List of variable definitions
            node_label: Node label for error messages

        Returns:
            Dict with command, errors, warnings
        """
        errors = []
        warnings = []
        command = template

        # Find all variables in template
        var_pattern = r"\{(\w+)\}"
        template_vars = re.findall(var_pattern, template)

        # Build lookup for variable definitions
        var_defs = {v.var_name: v for v in variables}

        for var_name in template_vars:
            value = values.get(var_name)
            var_def = var_defs.get(var_name)

            if value is None:
                # Check if there's a default
                if var_def and var_def.default_value:
                    value = var_def.default_value
                    warnings.append(
                        f"Using default value '{value}' for '{var_name}' in '{node_label}'"
                    )
                elif var_def and var_def.is_required:
                    errors.append(
                        f"Missing required variable '{var_name}' for '{node_label}'"
                    )
                    continue
                else:
                    # Optional variable with no value - skip this command
                    warnings.append(
                        f"Optional variable '{var_name}' not provided for '{node_label}'"
                    )
                    continue

            # Validate value if definition exists
            if var_def:
                validation_error = self._validate_value(value, var_def, node_label)
                if validation_error:
                    errors.append(validation_error)
                    continue

            # Substitute the value
            command = command.replace(f"{{{var_name}}}", str(value))

        # Check if any unsubstituted variables remain
        remaining_vars = re.findall(var_pattern, command)
        if remaining_vars:
            # Return empty command if required variables are missing
            if errors:
                return {"command": "", "errors": errors, "warnings": warnings}

        return {"command": command, "errors": errors, "warnings": warnings}

    def _validate_value(
        self,
        value: str,
        var_def: ConfigNodeVariable,
        node_label: str,
    ) -> Optional[str]:
        """
        Validate a value against its variable definition.

        Returns:
            Error message if validation fails, None otherwise
        """
        var_type = var_def.var_type
        var_name = var_def.var_name

        if var_type == VariableType.IP_ADDRESS:
            if not self._is_valid_ipv4(value):
                return f"Invalid IP address '{value}' for '{var_name}' in '{node_label}'"

        elif var_type == VariableType.SUBNET_MASK:
            if not self._is_valid_subnet_mask(value):
                return f"Invalid subnet mask '{value}' for '{var_name}' in '{node_label}'"

        elif var_type == VariableType.INTEGER:
            try:
                int_val = int(value)
                if var_def.min_value is not None and int_val < var_def.min_value:
                    return (
                        f"Value {int_val} is below minimum {var_def.min_value} "
                        f"for '{var_name}' in '{node_label}'"
                    )
                if var_def.max_value is not None and int_val > var_def.max_value:
                    return (
                        f"Value {int_val} exceeds maximum {var_def.max_value} "
                        f"for '{var_name}' in '{node_label}'"
                    )
            except ValueError:
                return f"Invalid integer '{value}' for '{var_name}' in '{node_label}'"

        elif var_type == VariableType.CHOICE:
            choices = var_def.choices_json
            if choices:
                import json
                try:
                    valid_choices = json.loads(choices) if isinstance(choices, str) else choices
                    if value not in valid_choices:
                        return (
                            f"Invalid choice '{value}' for '{var_name}' in '{node_label}'. "
                            f"Valid options: {', '.join(valid_choices)}"
                        )
                except json.JSONDecodeError:
                    pass

        elif var_type == VariableType.STRING:
            # Custom regex validation
            if var_def.validation_regex:
                if not re.match(var_def.validation_regex, value):
                    return (
                        f"Value '{value}' does not match pattern for '{var_name}' "
                        f"in '{node_label}'"
                    )

        return None

    def _is_valid_ipv4(self, value: str) -> bool:
        """Check if value is a valid IPv4 address."""
        try:
            ipaddress.IPv4Address(value)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    def _is_valid_subnet_mask(self, value: str) -> bool:
        """Check if value is a valid subnet mask."""
        # Common subnet masks
        valid_masks = [  # nosec B104 — data values, not bind addresses
            "0.0.0.0",
            "128.0.0.0", "192.0.0.0", "224.0.0.0", "240.0.0.0",
            "248.0.0.0", "252.0.0.0", "254.0.0.0", "255.0.0.0",
            "255.128.0.0", "255.192.0.0", "255.224.0.0", "255.240.0.0",
            "255.248.0.0", "255.252.0.0", "255.254.0.0", "255.255.0.0",
            "255.255.128.0", "255.255.192.0", "255.255.224.0", "255.255.240.0",
            "255.255.248.0", "255.255.252.0", "255.255.254.0", "255.255.255.0",
            "255.255.255.128", "255.255.255.192", "255.255.255.224", "255.255.255.240",
            "255.255.255.248", "255.255.255.252", "255.255.255.254", "255.255.255.255",
        ]
        return value in valid_masks

    def preview(self, tree: ConfigTree, values: dict[str, str]) -> str:
        """
        Generate a preview of the config with placeholders for missing values.

        Args:
            tree: The config tree template
            values: Partial dict of variable values

        Returns:
            Config preview string (may contain {var_name} placeholders)
        """
        result = self.generate(tree, values)
        return result["config"]
