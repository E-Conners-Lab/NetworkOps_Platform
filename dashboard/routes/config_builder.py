"""
Config Builder API Routes.

Endpoints for creating, editing, and managing visual config trees.
"""

import logging
from flask import Blueprint, jsonify, request, g
from core.errors import safe_error_response, NotFoundError, ValidationError
from dashboard.auth import jwt_required

logger = logging.getLogger(__name__)

config_builder_bp = Blueprint('config_builder', __name__, url_prefix='/api/config-trees')


def get_current_user():
    """Get the current user from Flask g context."""
    return g.current_user if hasattr(g, 'current_user') else 'api'


# =============================================================================
# Tree Endpoints
# =============================================================================


@config_builder_bp.route('', methods=['GET'])
@jwt_required
def list_trees():
    """List all config trees with optional filtering."""
    try:
        from core.config_tree_db import get_config_tree_db

        platform = request.args.get('platform')
        created_by = request.args.get('created_by')
        limit = max(1, min(1000, int(request.args.get('limit', 50))))
        offset = max(0, int(request.args.get('offset', 0)))

        db = get_config_tree_db()
        trees = db.list_trees(
            platform=platform,
            created_by=created_by,
            limit=limit,
            offset=offset,
        )

        return jsonify({
            "trees": [t.to_dict() for t in trees],
            "count": len(trees),
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, "list config trees")


@config_builder_bp.route('/<tree_id>', methods=['GET'])
@jwt_required
def get_tree(tree_id):
    """Get a config tree by ID with all nodes."""
    try:
        from core.config_tree_db import get_config_tree_db

        db = get_config_tree_db()
        tree = db.get_tree(tree_id, include_nodes=True)

        if not tree:
            raise NotFoundError(f"Config tree '{tree_id}' not found")

        return jsonify({
            "tree": tree.to_dict(),
            "status": "success"
        })
    except NotFoundError:
        raise
    except Exception as e:
        return safe_error_response(e, f"get config tree {tree_id}")


@config_builder_bp.route('', methods=['POST'])
@jwt_required
def create_tree():
    """Create a new config tree."""
    try:
        from core.config_tree_db import get_config_tree_db

        data = request.get_json()
        if not data:
            raise ValidationError("No data provided")

        name = data.get('name')
        if not name:
            raise ValidationError("'name' is required")

        db = get_config_tree_db()

        # Check for duplicate name
        existing = db.get_tree_by_name(name)
        if existing:
            raise ValidationError(f"A tree named '{name}' already exists")

        tree = db.create_tree(
            name=name,
            created_by=get_current_user(),
            description=data.get('description'),
            platform=data.get('platform', 'cisco_ios'),
            version=data.get('version', '1.0'),
        )

        logger.info(f"Created config tree '{name}' by {get_current_user()}")

        return jsonify({
            "tree": tree.to_dict(),
            "message": f"Tree '{name}' created successfully",
            "status": "success"
        }), 201
    except ValidationError:
        raise
    except Exception as e:
        return safe_error_response(e, "create config tree")


@config_builder_bp.route('/<tree_id>', methods=['PUT'])
@jwt_required
def update_tree(tree_id):
    """Update a config tree's metadata."""
    try:
        from core.config_tree_db import get_config_tree_db

        data = request.get_json()
        if not data:
            raise ValidationError("No data provided")

        db = get_config_tree_db()

        # Check name uniqueness if changing
        if 'name' in data:
            existing = db.get_tree_by_name(data['name'])
            if existing and existing.id != tree_id:
                raise ValidationError(f"A tree named '{data['name']}' already exists")

        tree = db.update_tree(
            tree_id=tree_id,
            name=data.get('name'),
            description=data.get('description'),
            platform=data.get('platform'),
            version=data.get('version'),
        )

        if not tree:
            raise NotFoundError(f"Config tree '{tree_id}' not found")

        return jsonify({
            "tree": tree.to_dict(),
            "status": "success"
        })
    except (NotFoundError, ValidationError):
        raise
    except Exception as e:
        return safe_error_response(e, f"update config tree {tree_id}")


@config_builder_bp.route('/<tree_id>', methods=['DELETE'])
@jwt_required
def delete_tree(tree_id):
    """Delete a config tree and all its nodes."""
    try:
        from core.config_tree_db import get_config_tree_db

        db = get_config_tree_db()
        success = db.delete_tree(tree_id)

        if not success:
            raise NotFoundError(f"Config tree '{tree_id}' not found")

        logger.info(f"Deleted config tree '{tree_id}' by {get_current_user()}")

        return jsonify({
            "message": f"Tree '{tree_id}' deleted successfully",
            "status": "success"
        })
    except NotFoundError:
        raise
    except Exception as e:
        return safe_error_response(e, f"delete config tree {tree_id}")


# =============================================================================
# Node Endpoints
# =============================================================================


@config_builder_bp.route('/<tree_id>/nodes', methods=['POST'])
@jwt_required
def create_node(tree_id):
    """Create a new node in a tree."""
    try:
        from core.config_tree_db import get_config_tree_db
        from core.config_tree import NodeType

        data = request.get_json()
        if not data:
            raise ValidationError("No data provided")

        node_type = data.get('node_type')
        label = data.get('label')

        if not node_type or not label:
            raise ValidationError("'node_type' and 'label' are required")

        try:
            node_type_enum = NodeType(node_type)
        except ValueError:
            raise ValidationError(f"Invalid node_type: {node_type}")

        db = get_config_tree_db()

        # Verify tree exists
        tree = db.get_tree(tree_id, include_nodes=False)
        if not tree:
            raise NotFoundError(f"Config tree '{tree_id}' not found")

        node = db.create_node(
            tree_id=tree_id,
            node_type=node_type_enum,
            label=label,
            parent_id=data.get('parent_id'),
            command_template=data.get('command_template'),
            sort_order=data.get('sort_order'),
            is_required=data.get('is_required', False),
            is_repeatable=data.get('is_repeatable', False),
            validation_regex=data.get('validation_regex'),
            default_value=data.get('default_value'),
            help_text=data.get('help_text'),
        )

        return jsonify({
            "node": node.to_dict(),
            "status": "success"
        }), 201
    except (NotFoundError, ValidationError):
        raise
    except Exception as e:
        return safe_error_response(e, f"create node in tree {tree_id}")


@config_builder_bp.route('/<tree_id>/nodes/<node_id>', methods=['PUT'])
@jwt_required
def update_node(tree_id, node_id):
    """Update a node's properties."""
    try:
        from core.config_tree_db import get_config_tree_db

        data = request.get_json()
        if not data:
            raise ValidationError("No data provided")

        db = get_config_tree_db()

        # Verify node belongs to this tree
        existing = db.get_node(node_id)
        if not existing:
            raise NotFoundError(f"Node '{node_id}' not found")
        if existing.tree_id != tree_id:
            raise ValidationError(f"Node '{node_id}' does not belong to tree '{tree_id}'")

        node = db.update_node(
            node_id=node_id,
            label=data.get('label'),
            command_template=data.get('command_template'),
            parent_id=data.get('parent_id'),
            sort_order=data.get('sort_order'),
            is_required=data.get('is_required'),
            is_repeatable=data.get('is_repeatable'),
            validation_regex=data.get('validation_regex'),
            default_value=data.get('default_value'),
            help_text=data.get('help_text'),
        )

        return jsonify({
            "node": node.to_dict() if node else None,
            "status": "success"
        })
    except (NotFoundError, ValidationError):
        raise
    except Exception as e:
        return safe_error_response(e, f"update node {node_id}")


@config_builder_bp.route('/<tree_id>/nodes/<node_id>', methods=['DELETE'])
@jwt_required
def delete_node(tree_id, node_id):
    """Delete a node and all its children."""
    try:
        from core.config_tree_db import get_config_tree_db

        db = get_config_tree_db()

        # Verify node belongs to this tree
        existing = db.get_node(node_id)
        if not existing:
            raise NotFoundError(f"Node '{node_id}' not found")
        if existing.tree_id != tree_id:
            raise ValidationError(f"Node '{node_id}' does not belong to tree '{tree_id}'")

        success = db.delete_node(node_id)

        if not success:
            raise NotFoundError(f"Node '{node_id}' not found")

        return jsonify({
            "message": f"Node '{node_id}' deleted successfully",
            "status": "success"
        })
    except (NotFoundError, ValidationError):
        raise
    except Exception as e:
        return safe_error_response(e, f"delete node {node_id}")


@config_builder_bp.route('/<tree_id>/nodes/reorder', methods=['POST'])
@jwt_required
def reorder_nodes(tree_id):
    """Bulk reorder nodes (update parent_id and sort_order)."""
    try:
        from core.config_tree_db import get_config_tree_db

        data = request.get_json()
        if not data or 'nodes' not in data:
            raise ValidationError("'nodes' array is required")

        node_orders = data['nodes']
        if not isinstance(node_orders, list):
            raise ValidationError("'nodes' must be an array")

        # Validate each item has required fields
        for item in node_orders:
            if 'id' not in item or 'sort_order' not in item:
                raise ValidationError("Each node must have 'id' and 'sort_order'")

        db = get_config_tree_db()

        # Verify tree exists
        tree = db.get_tree(tree_id, include_nodes=False)
        if not tree:
            raise NotFoundError(f"Config tree '{tree_id}' not found")

        db.reorder_nodes(tree_id, node_orders)

        return jsonify({
            "message": "Nodes reordered successfully",
            "status": "success"
        })
    except (NotFoundError, ValidationError):
        raise
    except Exception as e:
        return safe_error_response(e, f"reorder nodes in tree {tree_id}")


# =============================================================================
# Variable Endpoints
# =============================================================================


@config_builder_bp.route('/<tree_id>/nodes/<node_id>/variables', methods=['POST'])
@jwt_required
def create_variable(tree_id, node_id):
    """Create a variable for a node."""
    try:
        from core.config_tree_db import get_config_tree_db
        from core.config_tree import VariableType

        data = request.get_json()
        if not data:
            raise ValidationError("No data provided")

        var_name = data.get('var_name')
        var_type = data.get('var_type')

        if not var_name or not var_type:
            raise ValidationError("'var_name' and 'var_type' are required")

        try:
            var_type_enum = VariableType(var_type)
        except ValueError:
            raise ValidationError(f"Invalid var_type: {var_type}")

        db = get_config_tree_db()

        # Verify node exists and belongs to tree
        node = db.get_node(node_id)
        if not node:
            raise NotFoundError(f"Node '{node_id}' not found")
        if node.tree_id != tree_id:
            raise ValidationError(f"Node '{node_id}' does not belong to tree '{tree_id}'")

        variable = db.create_variable(
            node_id=node_id,
            var_name=var_name,
            var_type=var_type_enum,
            choices=data.get('choices'),
            validation_regex=data.get('validation_regex'),
            min_value=data.get('min_value'),
            max_value=data.get('max_value'),
            is_required=data.get('is_required', True),
            default_value=data.get('default_value'),
        )

        return jsonify({
            "variable": variable.to_dict(),
            "status": "success"
        }), 201
    except (NotFoundError, ValidationError):
        raise
    except Exception as e:
        return safe_error_response(e, f"create variable for node {node_id}")


@config_builder_bp.route('/<tree_id>/nodes/<node_id>/variables/<var_id>', methods=['DELETE'])
@jwt_required
def delete_variable(tree_id, node_id, var_id):
    """Delete a variable."""
    try:
        from core.config_tree_db import get_config_tree_db

        db = get_config_tree_db()
        success = db.delete_variable(var_id)

        if not success:
            raise NotFoundError(f"Variable '{var_id}' not found")

        return jsonify({
            "message": f"Variable '{var_id}' deleted successfully",
            "status": "success"
        })
    except NotFoundError:
        raise
    except Exception as e:
        return safe_error_response(e, f"delete variable {var_id}")


# =============================================================================
# Import/Export Endpoints
# =============================================================================


@config_builder_bp.route('/<tree_id>/export', methods=['GET'])
@jwt_required
def export_tree(tree_id):
    """Export a tree as JSON."""
    try:
        from core.config_tree_db import get_config_tree_db

        db = get_config_tree_db()
        data = db.export_tree(tree_id)

        if not data:
            raise NotFoundError(f"Config tree '{tree_id}' not found")

        return jsonify({
            "export": data,
            "status": "success"
        })
    except NotFoundError:
        raise
    except Exception as e:
        return safe_error_response(e, f"export config tree {tree_id}")


@config_builder_bp.route('/import', methods=['POST'])
@jwt_required
def import_tree():
    """Import a tree from JSON."""
    try:
        from core.config_tree_db import get_config_tree_db

        data = request.get_json()
        if not data:
            raise ValidationError("No data provided")

        if 'name' not in data:
            raise ValidationError("'name' is required in import data")

        db = get_config_tree_db()

        # Check for duplicate name
        existing = db.get_tree_by_name(data['name'])
        if existing:
            raise ValidationError(f"A tree named '{data['name']}' already exists")

        tree = db.import_tree(data, created_by=get_current_user())

        logger.info(f"Imported config tree '{data['name']}' by {get_current_user()}")

        return jsonify({
            "tree": tree.to_dict(),
            "message": f"Tree '{data['name']}' imported successfully",
            "status": "success"
        }), 201
    except ValidationError:
        raise
    except Exception as e:
        return safe_error_response(e, "import config tree")


# =============================================================================
# Generation Endpoint
# =============================================================================


@config_builder_bp.route('/<tree_id>/generate', methods=['POST'])
@jwt_required
def generate_config(tree_id):
    """Generate IOS commands from a tree with variable values."""
    try:
        from core.config_tree_db import get_config_tree_db
        from core.config_tree_generator import ConfigTreeGenerator

        data = request.get_json() or {}
        values = data.get('values', {})

        db = get_config_tree_db()
        tree = db.get_tree(tree_id, include_nodes=True)

        if not tree:
            raise NotFoundError(f"Config tree '{tree_id}' not found")

        generator = ConfigTreeGenerator()
        result = generator.generate(tree, values)

        return jsonify({
            "config": result["config"],
            "errors": result.get("errors", []),
            "warnings": result.get("warnings", []),
            "status": "success"
        })
    except NotFoundError:
        raise
    except Exception as e:
        return safe_error_response(e, f"generate config from tree {tree_id}")


# =============================================================================
# Template Endpoints (Predefined node templates)
# =============================================================================


@config_builder_bp.route('/templates/sections', methods=['GET'])
@jwt_required
def list_section_templates():
    """List predefined section templates."""
    try:
        from core.config_tree import SECTION_TEMPLATES

        return jsonify({
            "sections": SECTION_TEMPLATES,
            "count": len(SECTION_TEMPLATES),
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, "list section templates")


@config_builder_bp.route('/templates/commands', methods=['GET'])
@jwt_required
def list_command_templates():
    """List predefined command templates."""
    try:
        from core.config_tree import COMMAND_TEMPLATES

        parent_section = request.args.get('section')

        templates = COMMAND_TEMPLATES
        if parent_section:
            templates = [t for t in templates if t.get('parent_section') == parent_section]

        return jsonify({
            "commands": templates,
            "count": len(templates),
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, "list command templates")
