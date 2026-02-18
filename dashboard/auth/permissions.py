"""
Authorization: permissions, groups, and RBAC queries.

Handles:
- Permission queries (user has permission, get user permissions)
- Group CRUD operations
- User-group assignments
"""
import sqlite3

from .config import DEFAULT_PERMISSIONS, DEFAULT_GROUPS
from . import database


# =============================================================================
# Permission Queries
# =============================================================================

def get_user_permissions(user_id: int) -> list[str]:
    """Get all permissions for a user through their group memberships.

    Args:
        user_id: User's database ID

    Returns:
        List of permission names
    """
    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DISTINCT p.name
        FROM permissions p
        JOIN group_permissions gp ON p.id = gp.permission_id
        JOIN user_groups ug ON gp.group_id = ug.group_id
        WHERE ug.user_id = ?
    """, (user_id,))
    permissions = [row["name"] for row in cursor.fetchall()]
    conn.close()
    return permissions


def get_user_groups(user_id: int) -> list[dict]:
    """Get all groups a user belongs to.

    Args:
        user_id: User's database ID

    Returns:
        List of group dicts with id, name, description
    """
    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT g.id, g.name, g.description
        FROM groups g
        JOIN user_groups ug ON g.id = ug.group_id
        WHERE ug.user_id = ?
    """, (user_id,))
    groups = [{"id": row["id"], "name": row["name"], "description": row["description"]}
              for row in cursor.fetchall()]
    conn.close()
    return groups


def user_has_permission(user_id: int, permission: str) -> bool:
    """Check if a user has a specific permission.

    Args:
        user_id: User's database ID
        permission: Permission name to check

    Returns:
        True if user has permission
    """
    permissions = get_user_permissions(user_id)
    return permission in permissions


# =============================================================================
# Permission Listing
# =============================================================================

def get_all_permissions() -> list[dict]:
    """Get all available permissions.

    Returns:
        List of permission dicts with id, name, description
    """
    if not database.USE_SQLITE:
        return [{"name": p[0], "description": p[1]} for p in DEFAULT_PERMISSIONS]

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description FROM permissions ORDER BY name")
    perms = [{"id": row["id"], "name": row["name"], "description": row["description"]}
             for row in cursor.fetchall()]
    conn.close()
    return perms


# =============================================================================
# Group Queries
# =============================================================================

def get_all_groups() -> list[dict]:
    """Get all groups with their permissions.

    Returns:
        List of group dicts with permissions and user_count
    """
    if not database.USE_SQLITE:
        return []

    conn = database._get_db_connection()
    cursor = conn.cursor()

    # Get groups
    cursor.execute("SELECT id, name, description, created_at FROM groups ORDER BY name")
    groups = []
    for row in cursor.fetchall():
        group = {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "created_at": row["created_at"],
            "permissions": [],
            "user_count": 0,
        }

        # Get permissions for this group
        cursor.execute("""
            SELECT p.name FROM permissions p
            JOIN group_permissions gp ON p.id = gp.permission_id
            WHERE gp.group_id = ?
        """, (row["id"],))
        group["permissions"] = [r["name"] for r in cursor.fetchall()]

        # Get user count
        cursor.execute("SELECT COUNT(*) FROM user_groups WHERE group_id = ?", (row["id"],))
        group["user_count"] = cursor.fetchone()[0]

        groups.append(group)

    conn.close()
    return groups


def get_group(group_id: int) -> dict | None:
    """Get a single group by ID.

    Args:
        group_id: Group's database ID

    Returns:
        Group dict or None if not found
    """
    if not database.USE_SQLITE:
        return None

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description, created_at FROM groups WHERE id = ?", (group_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    group = {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "created_at": row["created_at"],
        "permissions": [],
    }

    cursor.execute("""
        SELECT p.name FROM permissions p
        JOIN group_permissions gp ON p.id = gp.permission_id
        WHERE gp.group_id = ?
    """, (group_id,))
    group["permissions"] = [r["name"] for r in cursor.fetchall()]

    conn.close()
    return group


# =============================================================================
# Group CRUD Operations
# =============================================================================

def create_group(name: str, description: str, permissions: list[str]) -> tuple[bool, str, int | None]:
    """Create a new group with permissions.

    Args:
        name: Group name (unique)
        description: Group description
        permissions: List of permission names to assign

    Returns:
        (success, message, group_id) tuple
    """
    if not database.USE_SQLITE:
        return False, "Group creation requires SQLite", None

    if not name:
        return False, "Group name is required", None

    conn = database._get_db_connection()
    cursor = conn.cursor()

    try:
        # Create the group
        cursor.execute(
            "INSERT INTO groups (name, description) VALUES (?, ?)",
            (name, description or "")
        )
        group_id = cursor.lastrowid

        # Assign permissions
        for perm_name in permissions:
            cursor.execute("SELECT id FROM permissions WHERE name = ?", (perm_name,))
            perm_row = cursor.fetchone()
            if perm_row:
                cursor.execute(
                    "INSERT INTO group_permissions (group_id, permission_id) VALUES (?, ?)",
                    (group_id, perm_row["id"])
                )

        conn.commit()
        conn.close()
        return True, f"Group '{name}' created successfully", group_id
    except sqlite3.IntegrityError:
        conn.close()
        return False, f"Group '{name}' already exists", None
    except Exception as e:
        conn.close()
        return False, f"Failed to create group: {e}", None


def update_group(group_id: int, name: str = None, description: str = None,
                 permissions: list[str] = None) -> tuple[bool, str]:
    """Update a group.

    Args:
        group_id: Group to update
        name: New name (optional)
        description: New description (optional)
        permissions: New permission list (optional, replaces existing)

    Returns:
        (success, message) tuple
    """
    if not database.USE_SQLITE:
        return False, "Group updates require SQLite"

    conn = database._get_db_connection()
    cursor = conn.cursor()

    # Check group exists
    cursor.execute("SELECT id FROM groups WHERE id = ?", (group_id,))
    if not cursor.fetchone():
        conn.close()
        return False, "Group not found"

    try:
        # Update name/description if provided
        if name is not None:
            cursor.execute("UPDATE groups SET name = ? WHERE id = ?", (name, group_id))
        if description is not None:
            cursor.execute("UPDATE groups SET description = ? WHERE id = ?", (description, group_id))

        # Update permissions if provided
        if permissions is not None:
            # Remove existing permissions
            cursor.execute("DELETE FROM group_permissions WHERE group_id = ?", (group_id,))

            # Add new permissions
            for perm_name in permissions:
                cursor.execute("SELECT id FROM permissions WHERE name = ?", (perm_name,))
                perm_row = cursor.fetchone()
                if perm_row:
                    cursor.execute(
                        "INSERT INTO group_permissions (group_id, permission_id) VALUES (?, ?)",
                        (group_id, perm_row["id"])
                    )

        conn.commit()
        conn.close()
        return True, "Group updated successfully"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Group name already exists"
    except Exception as e:
        conn.close()
        return False, f"Failed to update group: {e}"


def delete_group(group_id: int) -> tuple[bool, str]:
    """Delete a group.

    Args:
        group_id: Group to delete

    Returns:
        (success, message) tuple
    """
    if not database.USE_SQLITE:
        return False, "Group deletion requires SQLite"

    conn = database._get_db_connection()
    cursor = conn.cursor()

    # Check group exists
    cursor.execute("SELECT name FROM groups WHERE id = ?", (group_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False, "Group not found"

    group_name = row["name"]

    # Prevent deleting default groups
    if group_name in DEFAULT_GROUPS:
        conn.close()
        return False, f"Cannot delete default group '{group_name}'"

    try:
        # Delete group (cascade will remove group_permissions and user_groups)
        cursor.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        conn.commit()
        conn.close()
        return True, f"Group '{group_name}' deleted successfully"
    except Exception as e:
        conn.close()
        return False, f"Failed to delete group: {e}"


# =============================================================================
# User-Group Assignment
# =============================================================================

def assign_user_to_groups(username: str, group_ids: list[int]) -> tuple[bool, str]:
    """Assign a user to one or more groups (replaces existing assignments).

    Args:
        username: User to assign
        group_ids: List of group IDs to assign

    Returns:
        (success, message) tuple
    """
    if not database.USE_SQLITE:
        return False, "Group assignment requires SQLite"

    # Import here to avoid circular dependency
    from .identity import _get_user_from_db

    user = _get_user_from_db(username)
    if not user:
        return False, f"User '{username}' not found"

    conn = database._get_db_connection()
    cursor = conn.cursor()

    try:
        # Remove existing group assignments
        cursor.execute("DELETE FROM user_groups WHERE user_id = ?", (user["id"],))

        # Add new assignments
        for group_id in group_ids:
            cursor.execute("SELECT id FROM groups WHERE id = ?", (group_id,))
            if cursor.fetchone():
                cursor.execute(
                    "INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
                    (user["id"], group_id)
                )

        conn.commit()
        conn.close()
        return True, f"User '{username}' group assignments updated"
    except Exception as e:
        conn.close()
        return False, f"Failed to assign groups: {e}"
