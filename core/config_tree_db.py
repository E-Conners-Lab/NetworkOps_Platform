"""
Config Tree Database Operations.

SQLite-based storage for config trees and nodes.
"""

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from core.config_tree import (
    ConfigTree,
    ConfigTreeNode,
    ConfigNodeVariable,
    NodeType,
    VariableType,
)
from core.db import DatabaseManager

logger = logging.getLogger(__name__)


# =============================================================================
# Database Class
# =============================================================================


class ConfigTreeDB:
    """Database operations for config trees."""

    def __init__(self, db_path: Optional[Path | str] = None):
        # db_path parameter kept for test backward compat but ignored;
        # all connections come from DatabaseManager.
        self._dm = DatabaseManager.get_instance()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection from the pool."""
        return self._dm.get_connection()

    # -------------------------------------------------------------------------
    # Tree Operations
    # -------------------------------------------------------------------------

    def create_tree(
        self,
        name: str,
        created_by: str,
        description: Optional[str] = None,
        platform: str = "cisco_ios",
        version: str = "1.0",
    ) -> ConfigTree:
        """Create a new config tree."""
        tree_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO config_trees
            (id, name, description, platform, version, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (tree_id, name, description, platform, version, created_by, now, now),
        )
        conn.commit()
        self._dm.release_connection(conn)

        return ConfigTree(
            id=tree_id,
            name=name,
            description=description,
            platform=platform,
            version=version,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )

    def get_tree(self, tree_id: str, include_nodes: bool = True) -> Optional[ConfigTree]:
        """Get a tree by ID, optionally including all nodes."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM config_trees WHERE id = ?", (tree_id,))
        row = cursor.fetchone()

        if not row:
            self._dm.release_connection(conn)
            return None

        tree = ConfigTree.from_row(row)

        if include_nodes:
            tree.root_nodes = self._load_nodes(cursor, tree_id, parent_id=None)

        self._dm.release_connection(conn)
        return tree

    def get_tree_by_name(self, name: str) -> Optional[ConfigTree]:
        """Get a tree by name."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM config_trees WHERE name = ?", (name,))
        row = cursor.fetchone()
        self._dm.release_connection(conn)
        return ConfigTree.from_row(row) if row else None

    def list_trees(
        self,
        platform: Optional[str] = None,
        created_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ConfigTree]:
        """List trees with optional filters."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM config_trees WHERE 1=1"
        params: list[Any] = []

        if platform:
            query += " AND platform = ?"
            params.append(platform)
        if created_by:
            query += " AND created_by = ?"
            params.append(created_by)

        query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        self._dm.release_connection(conn)

        return [ConfigTree.from_row(row) for row in rows]

    def update_tree(
        self,
        tree_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        platform: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Optional[ConfigTree]:
        """Update a tree's metadata."""
        conn = self._get_connection()
        cursor = conn.cursor()

        updates = ["updated_at = ?"]
        params: list[Any] = [datetime.now(timezone.utc).isoformat()]

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if platform is not None:
            updates.append("platform = ?")
            params.append(platform)
        if version is not None:
            updates.append("version = ?")
            params.append(version)

        params.append(tree_id)

        cursor.execute(
            f"UPDATE config_trees SET {', '.join(updates)} WHERE id = ?",  # nosec B608
            params,
        )
        conn.commit()

        if cursor.rowcount == 0:
            self._dm.release_connection(conn)
            return None

        cursor.execute("SELECT * FROM config_trees WHERE id = ?", (tree_id,))
        row = cursor.fetchone()
        self._dm.release_connection(conn)
        return ConfigTree.from_row(row) if row else None

    def delete_tree(self, tree_id: str) -> bool:
        """Delete a tree and all its nodes (via CASCADE)."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM config_trees WHERE id = ?", (tree_id,))
        success = cursor.rowcount > 0
        conn.commit()
        self._dm.release_connection(conn)
        return success

    # -------------------------------------------------------------------------
    # Node Operations
    # -------------------------------------------------------------------------

    def create_node(
        self,
        tree_id: str,
        node_type: NodeType,
        label: str,
        parent_id: Optional[str] = None,
        command_template: Optional[str] = None,
        sort_order: Optional[int] = None,
        is_required: bool = False,
        is_repeatable: bool = False,
        validation_regex: Optional[str] = None,
        default_value: Optional[str] = None,
        help_text: Optional[str] = None,
    ) -> ConfigTreeNode:
        """Create a new node in a tree."""
        node_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        conn = self._get_connection()
        cursor = conn.cursor()

        # Auto-calculate sort_order if not provided
        if sort_order is None:
            cursor.execute(
                """
                SELECT COALESCE(MAX(sort_order), -1) + 1 FROM config_tree_nodes
                WHERE tree_id = ? AND (parent_id = ? OR (parent_id IS NULL AND ? IS NULL))
                """,
                (tree_id, parent_id, parent_id),
            )
            sort_order = cursor.fetchone()[0]

        cursor.execute(
            """
            INSERT INTO config_tree_nodes
            (id, tree_id, parent_id, node_type, label, command_template, sort_order,
             is_required, is_repeatable, validation_regex, default_value, help_text, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node_id, tree_id, parent_id, node_type.value, label, command_template,
             sort_order, int(is_required), int(is_repeatable), validation_regex,
             default_value, help_text, now),
        )

        # Update tree's updated_at
        cursor.execute(
            "UPDATE config_trees SET updated_at = ? WHERE id = ?",
            (now, tree_id),
        )

        conn.commit()
        self._dm.release_connection(conn)

        return ConfigTreeNode(
            id=node_id,
            tree_id=tree_id,
            parent_id=parent_id,
            node_type=node_type,
            label=label,
            command_template=command_template,
            sort_order=sort_order,
            is_required=is_required,
            is_repeatable=is_repeatable,
            validation_regex=validation_regex,
            default_value=default_value,
            help_text=help_text,
            created_at=now,
        )

    def get_node(self, node_id: str, include_children: bool = False) -> Optional[ConfigTreeNode]:
        """Get a node by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM config_tree_nodes WHERE id = ?", (node_id,))
        row = cursor.fetchone()

        if not row:
            self._dm.release_connection(conn)
            return None

        node = ConfigTreeNode.from_row(row)
        node.variables = self._load_variables(cursor, node_id)

        if include_children:
            node.children = self._load_nodes(cursor, node.tree_id, parent_id=node_id)

        self._dm.release_connection(conn)
        return node

    def update_node(
        self,
        node_id: str,
        label: Optional[str] = None,
        command_template: Optional[str] = None,
        parent_id: Optional[str] = None,
        sort_order: Optional[int] = None,
        is_required: Optional[bool] = None,
        is_repeatable: Optional[bool] = None,
        validation_regex: Optional[str] = None,
        default_value: Optional[str] = None,
        help_text: Optional[str] = None,
    ) -> Optional[ConfigTreeNode]:
        """Update a node's properties."""
        conn = self._get_connection()
        cursor = conn.cursor()

        updates = []
        params: list[Any] = []

        if label is not None:
            updates.append("label = ?")
            params.append(label)
        if command_template is not None:
            updates.append("command_template = ?")
            params.append(command_template)
        if parent_id is not None:
            updates.append("parent_id = ?")
            params.append(parent_id if parent_id != "" else None)
        if sort_order is not None:
            updates.append("sort_order = ?")
            params.append(sort_order)
        if is_required is not None:
            updates.append("is_required = ?")
            params.append(int(is_required))
        if is_repeatable is not None:
            updates.append("is_repeatable = ?")
            params.append(int(is_repeatable))
        if validation_regex is not None:
            updates.append("validation_regex = ?")
            params.append(validation_regex if validation_regex else None)
        if default_value is not None:
            updates.append("default_value = ?")
            params.append(default_value if default_value else None)
        if help_text is not None:
            updates.append("help_text = ?")
            params.append(help_text if help_text else None)

        if not updates:
            self._dm.release_connection(conn)
            return self.get_node(node_id)

        params.append(node_id)

        cursor.execute(
            f"UPDATE config_tree_nodes SET {', '.join(updates)} WHERE id = ?",  # nosec B608
            params,
        )

        if cursor.rowcount == 0:
            self._dm.release_connection(conn)
            return None

        # Update tree's updated_at
        cursor.execute(
            """
            UPDATE config_trees SET updated_at = ?
            WHERE id = (SELECT tree_id FROM config_tree_nodes WHERE id = ?)
            """,
            (datetime.now(timezone.utc).isoformat(), node_id),
        )

        conn.commit()

        cursor.execute("SELECT * FROM config_tree_nodes WHERE id = ?", (node_id,))
        row = cursor.fetchone()
        self._dm.release_connection(conn)

        if row:
            node = ConfigTreeNode.from_row(row)
            return node
        return None

    def delete_node(self, node_id: str) -> bool:
        """Delete a node and all its children (via CASCADE)."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Get tree_id before deletion
        cursor.execute("SELECT tree_id FROM config_tree_nodes WHERE id = ?", (node_id,))
        row = cursor.fetchone()
        tree_id = row["tree_id"] if row else None

        cursor.execute("DELETE FROM config_tree_nodes WHERE id = ?", (node_id,))
        success = cursor.rowcount > 0

        if success and tree_id:
            cursor.execute(
                "UPDATE config_trees SET updated_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), tree_id),
            )

        conn.commit()
        self._dm.release_connection(conn)
        return success

    def reorder_nodes(self, tree_id: str, node_orders: list[dict]) -> bool:
        """
        Bulk reorder nodes.

        Args:
            tree_id: The tree ID
            node_orders: List of {"id": node_id, "parent_id": parent_id, "sort_order": int}
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        for order in node_orders:
            cursor.execute(
                """
                UPDATE config_tree_nodes
                SET parent_id = ?, sort_order = ?
                WHERE id = ? AND tree_id = ?
                """,
                (order.get("parent_id"), order["sort_order"], order["id"], tree_id),
            )

        cursor.execute(
            "UPDATE config_trees SET updated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), tree_id),
        )

        conn.commit()
        self._dm.release_connection(conn)
        return True

    # -------------------------------------------------------------------------
    # Variable Operations
    # -------------------------------------------------------------------------

    def create_variable(
        self,
        node_id: str,
        var_name: str,
        var_type: VariableType,
        choices: Optional[list[str]] = None,
        validation_regex: Optional[str] = None,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
        is_required: bool = True,
        default_value: Optional[str] = None,
    ) -> ConfigNodeVariable:
        """Create a variable for a node."""
        var_id = str(uuid.uuid4())
        choices_json = json.dumps(choices) if choices else None

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO config_node_variables
            (id, node_id, var_name, var_type, choices_json, validation_regex,
             min_value, max_value, is_required, default_value)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (var_id, node_id, var_name, var_type.value, choices_json,
             validation_regex, min_value, max_value, int(is_required), default_value),
        )
        conn.commit()
        self._dm.release_connection(conn)

        return ConfigNodeVariable(
            id=var_id,
            node_id=node_id,
            var_name=var_name,
            var_type=var_type,
            choices_json=choices_json,
            validation_regex=validation_regex,
            min_value=min_value,
            max_value=max_value,
            is_required=is_required,
            default_value=default_value,
        )

    def update_variable(
        self,
        var_id: str,
        var_name: Optional[str] = None,
        var_type: Optional[VariableType] = None,
        choices: Optional[list[str]] = None,
        validation_regex: Optional[str] = None,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
        is_required: Optional[bool] = None,
        default_value: Optional[str] = None,
    ) -> Optional[ConfigNodeVariable]:
        """Update a variable."""
        conn = self._get_connection()
        cursor = conn.cursor()

        updates = []
        params: list[Any] = []

        if var_name is not None:
            updates.append("var_name = ?")
            params.append(var_name)
        if var_type is not None:
            updates.append("var_type = ?")
            params.append(var_type.value)
        if choices is not None:
            updates.append("choices_json = ?")
            params.append(json.dumps(choices) if choices else None)
        if validation_regex is not None:
            updates.append("validation_regex = ?")
            params.append(validation_regex if validation_regex else None)
        if min_value is not None:
            updates.append("min_value = ?")
            params.append(min_value)
        if max_value is not None:
            updates.append("max_value = ?")
            params.append(max_value)
        if is_required is not None:
            updates.append("is_required = ?")
            params.append(int(is_required))
        if default_value is not None:
            updates.append("default_value = ?")
            params.append(default_value if default_value else None)

        if not updates:
            self._dm.release_connection(conn)
            return None

        params.append(var_id)

        cursor.execute(
            f"UPDATE config_node_variables SET {', '.join(updates)} WHERE id = ?",  # nosec B608
            params,
        )
        conn.commit()

        cursor.execute("SELECT * FROM config_node_variables WHERE id = ?", (var_id,))
        row = cursor.fetchone()
        self._dm.release_connection(conn)
        return ConfigNodeVariable.from_row(row) if row else None

    def delete_variable(self, var_id: str) -> bool:
        """Delete a variable."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM config_node_variables WHERE id = ?", (var_id,))
        success = cursor.rowcount > 0
        conn.commit()
        self._dm.release_connection(conn)
        return success

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------

    def _load_nodes(
        self,
        cursor: sqlite3.Cursor,
        tree_id: str,
        parent_id: Optional[str],
    ) -> list[ConfigTreeNode]:
        """Recursively load nodes for a tree."""
        if parent_id is None:
            cursor.execute(
                """
                SELECT * FROM config_tree_nodes
                WHERE tree_id = ? AND parent_id IS NULL
                ORDER BY sort_order
                """,
                (tree_id,),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM config_tree_nodes
                WHERE tree_id = ? AND parent_id = ?
                ORDER BY sort_order
                """,
                (tree_id, parent_id),
            )

        rows = cursor.fetchall()
        nodes = []

        for row in rows:
            node = ConfigTreeNode.from_row(row)
            node.variables = self._load_variables(cursor, node.id)
            node.children = self._load_nodes(cursor, tree_id, node.id)
            nodes.append(node)

        return nodes

    def _load_variables(self, cursor: sqlite3.Cursor, node_id: str) -> list[ConfigNodeVariable]:
        """Load variables for a node."""
        cursor.execute(
            "SELECT * FROM config_node_variables WHERE node_id = ?",
            (node_id,),
        )
        rows = cursor.fetchall()
        return [ConfigNodeVariable.from_row(row) for row in rows]

    # -------------------------------------------------------------------------
    # Import/Export
    # -------------------------------------------------------------------------

    def export_tree(self, tree_id: str) -> Optional[dict]:
        """Export a tree as a JSON-serializable dict."""
        tree = self.get_tree(tree_id, include_nodes=True)
        if not tree:
            return None
        return tree.to_dict()

    def import_tree(self, data: dict, created_by: str) -> ConfigTree:
        """
        Import a tree from JSON data.

        Creates a new tree with a new ID, preserving structure.
        """
        # Create tree
        tree = self.create_tree(
            name=data["name"],
            created_by=created_by,
            description=data.get("description"),
            platform=data.get("platform", "cisco_ios"),
            version=data.get("version", "1.0"),
        )

        # Import nodes recursively
        def import_nodes(nodes_data: list[dict], parent_id: Optional[str] = None):
            for node_data in nodes_data:
                node = self.create_node(
                    tree_id=tree.id,
                    node_type=NodeType(node_data["node_type"]),
                    label=node_data["label"],
                    parent_id=parent_id,
                    command_template=node_data.get("command_template"),
                    sort_order=node_data.get("sort_order", 0),
                    is_required=node_data.get("is_required", False),
                    is_repeatable=node_data.get("is_repeatable", False),
                    validation_regex=node_data.get("validation_regex"),
                    default_value=node_data.get("default_value"),
                    help_text=node_data.get("help_text"),
                )

                # Import variables
                for var_data in node_data.get("variables", []):
                    self.create_variable(
                        node_id=node.id,
                        var_name=var_data["var_name"],
                        var_type=VariableType(var_data["var_type"]),
                        choices=var_data.get("choices"),
                        validation_regex=var_data.get("validation_regex"),
                        min_value=var_data.get("min_value"),
                        max_value=var_data.get("max_value"),
                        is_required=var_data.get("is_required", True),
                        default_value=var_data.get("default_value"),
                    )

                # Import children
                import_nodes(node_data.get("children", []), node.id)

        import_nodes(data.get("root_nodes", []))

        # Return the complete tree
        return self.get_tree(tree.id, include_nodes=True)


# Global instance
_db_instance: Optional[ConfigTreeDB] = None


def get_config_tree_db() -> ConfigTreeDB:
    """Get or create the global database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = ConfigTreeDB()
    return _db_instance
