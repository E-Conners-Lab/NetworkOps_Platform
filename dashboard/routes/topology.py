"""
Topology and Hierarchy API Routes.

Network topology discovery and hierarchical site view endpoints.
"""

import logging
import os

from flask import Blueprint, jsonify
from core.errors import safe_error_response
from dashboard.auth import jwt_required

logger = logging.getLogger(__name__)

topology_bp = Blueprint('topology', __name__)

# Feature flag for hierarchical view
ENABLE_HIERARCHICAL_VIEW = os.getenv('ENABLE_HIERARCHICAL_VIEW', 'false').lower() == 'true'


@topology_bp.route('/api/topology')
@jwt_required
def get_topology():
    """
    Get network topology
    ---
    tags:
      - Network
    summary: Discover network topology
    description: Returns network topology discovered via CDP/LLDP.
    responses:
      200:
        description: Network topology links
        schema:
          type: object
          properties:
            links:
              type: array
              items:
                type: object
                properties:
                  source:
                    type: string
                  source_intf:
                    type: string
                  target:
                    type: string
                  target_intf:
                    type: string
      500:
        description: Discovery failed
    """
    # Import from api_server to avoid circular imports at module level
    from dashboard.api_server import discover_topology, cache
    from config.hierarchy import get_hierarchy_provider

    try:
        topology = discover_topology()

        # Add hierarchy info to nodes if feature is enabled
        if ENABLE_HIERARCHICAL_VIEW:
            provider = get_hierarchy_provider()
            for node in topology.get('nodes', []):
                device_name = node.get('id')
                if device_name:
                    hierarchy_info = provider.get_device_hierarchy(device_name)
                    if hierarchy_info:
                        node['region'] = hierarchy_info['region']
                        node['site'] = hierarchy_info['site']
                        node['rack'] = hierarchy_info['rack']

        return jsonify(topology)
    except Exception as e:
        return safe_error_response(e, "discover network topology")


@topology_bp.route('/api/hierarchy')
@jwt_required
def get_hierarchy():
    """
    Get hierarchical site view structure
    ---
    tags:
      - Hierarchy
    summary: Get hierarchy tree (Region > Site > Rack)
    description: |
      Returns the 4-level hierarchy tree for enterprise-scale topology navigation.
      Requires ENABLE_HIERARCHICAL_VIEW=true environment variable.
    responses:
      200:
        description: Hierarchy tree
        schema:
          type: object
          properties:
            regions:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: string
                  name:
                    type: string
                  sites:
                    type: array
      403:
        description: Hierarchical view is disabled
    """
    from config.hierarchy import get_hierarchy_provider

    if not ENABLE_HIERARCHICAL_VIEW:
        return jsonify({
            "error": "Hierarchical view is disabled",
            "message": "Set ENABLE_HIERARCHICAL_VIEW=true to enable this feature"
        }), 403

    # Use hierarchy provider (NetBox if available, static fallback)
    provider = get_hierarchy_provider()
    tree = provider.get_hierarchy_tree()
    tree["data_source"] = provider.get_data_source()
    return jsonify(tree)


@topology_bp.route('/api/topology/level/<level_type>/<level_id>')
@jwt_required
def get_topology_level(level_type, level_id):
    """
    Get filtered topology for a specific hierarchy level
    ---
    tags:
      - Hierarchy
    summary: Get devices at a specific hierarchy level
    description: |
      Returns topology filtered to devices within a specific region, site, or rack.
      Requires ENABLE_HIERARCHICAL_VIEW=true environment variable.
    parameters:
      - name: level_type
        in: path
        type: string
        required: true
        enum: [region, site, rack]
        description: Type of hierarchy level
      - name: level_id
        in: path
        type: string
        required: true
        description: ID of the level (e.g., 'us-west', 'eve-ng-lab', 'core-rack')
    responses:
      200:
        description: Filtered topology
        schema:
          type: object
          properties:
            level:
              type: object
              properties:
                type:
                  type: string
                id:
                  type: string
            nodes:
              type: array
            links:
              type: array
      400:
        description: Invalid level type
      403:
        description: Hierarchical view is disabled
      404:
        description: Level not found
    """
    from dashboard.api_server import discover_topology
    from config.hierarchy import get_hierarchy_provider

    if not ENABLE_HIERARCHICAL_VIEW:
        return jsonify({
            "error": "Hierarchical view is disabled",
            "message": "Set ENABLE_HIERARCHICAL_VIEW=true to enable this feature"
        }), 403

    # Validate level type
    if level_type not in ('region', 'site', 'rack'):
        return jsonify({
            "error": "Invalid level type",
            "message": "level_type must be 'region', 'site', or 'rack'"
        }), 400

    # Use hierarchy provider (NetBox if available, static fallback)
    provider = get_hierarchy_provider()

    # Get devices for the level
    if level_type == 'region':
        devices = provider.get_devices_in_region(level_id)
    elif level_type == 'site':
        devices = provider.get_devices_in_site(level_id)
    else:  # rack
        devices = provider.get_devices_in_rack(level_id)

    if not devices:
        return jsonify({
            "error": "Level not found",
            "message": f"No devices found in {level_type} '{level_id}'"
        }), 404

    # Get full topology and filter
    try:
        topology = discover_topology()
    except Exception as e:
        return safe_error_response(e, "get hierarchy topology")

    # Filter nodes
    device_set = set(devices)
    filtered_nodes = [
        node for node in topology.get('nodes', [])
        if node.get('id') in device_set
    ]

    # Add hierarchy info to filtered nodes
    for node in filtered_nodes:
        device_name = node.get('id')
        if device_name:
            hierarchy_info = provider.get_device_hierarchy(device_name)
            if hierarchy_info:
                node['region'] = hierarchy_info['region']
                node['site'] = hierarchy_info['site']
                node['rack'] = hierarchy_info['rack']

    # Filter links to only include internal connections
    filtered_links = [
        link for link in topology.get('links', [])
        if link.get('source') in device_set and link.get('target') in device_set
    ]

    return jsonify({
        "level": {
            "type": level_type,
            "id": level_id
        },
        "nodes": filtered_nodes,
        "links": filtered_links
    })
