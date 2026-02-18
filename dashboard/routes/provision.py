"""
Device Provisioning API Routes.

Endpoints for automated device provisioning in EVE-NG and Containerlab.
Supports async provisioning with job tracking and status polling.
"""

import logging
import os
from functools import wraps

from flask import Blueprint, jsonify, request
from core.errors import safe_error_response, ValidationError, ServiceUnavailableError
from dashboard.auth import jwt_required, permission_required

from core.provisioning import JobStatus, ProvisioningStateManager, get_executor

logger = logging.getLogger(__name__)

provision_bp = Blueprint("provision", __name__)

# Global state manager (initialized on first request)
_state_manager = None


def get_state_manager() -> ProvisioningStateManager:
    """Get or create the global state manager."""
    global _state_manager
    if _state_manager is None:
        _state_manager = ProvisioningStateManager()
        # Clean up stale jobs on startup
        stale = _state_manager.cleanup_stale_jobs()
        if stale:
            logger.warning(f"Cleaned up {len(stale)} stale provisioning jobs")
    return _state_manager


def feature_flag_required(flag_name: str):
    """Decorator to check if a feature flag is enabled."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            from core.feature_flags import is_enabled
            if not is_enabled(flag_name):
                return jsonify({
                    "error": f"Feature '{flag_name}' is not enabled",
                    "message": "Contact your administrator to enable automated provisioning"
                }), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator


# =============================================================================
# Image Listing Endpoints (Read-Only)
# =============================================================================


@provision_bp.route("/api/provision/eve-ng/images")
@jwt_required
def get_eve_ng_images():
    """
    List available EVE-NG images.
    ---
    tags:
      - Provisioning
    summary: List EVE-NG images
    description: Returns available QEMU, IOL, and Docker images from EVE-NG.
    parameters:
      - name: type
        in: query
        type: string
        description: Filter by image type (qemu, iol, docker)
    responses:
      200:
        description: List of available images
        schema:
          type: object
          properties:
            images:
              type: array
              items:
                type: object
                properties:
                  name:
                    type: string
                  type:
                    type: string
            count:
              type: integer
      503:
        description: EVE-NG not available
    """
    try:
        from core.eve_ng_client import EVEClient

        image_type = request.args.get("type")

        with EVEClient() as client:
            images = client.get_images(image_type=image_type)

        return jsonify({
            "images": images,
            "count": len(images),
        })

    except ImportError:
        raise ServiceUnavailableError("EVE-NG client not available")
    except Exception as e:
        return safe_error_response(e, "get EVE-NG images")


@provision_bp.route("/api/provision/containerlab/images")
@jwt_required
def get_containerlab_images():
    """
    List available Containerlab images.
    ---
    tags:
      - Provisioning
    summary: List Containerlab images
    description: Returns available container images for containerlab nodes.
    responses:
      200:
        description: List of available images
        schema:
          type: object
          properties:
            images:
              type: array
              items:
                type: object
                properties:
                  repository:
                    type: string
                  tag:
                    type: string
                  size:
                    type: string
            kinds:
              type: array
              description: Supported node kinds
            count:
              type: integer
      503:
        description: Containerlab not available
    """
    try:
        from core.containerlab import (
            get_node_kinds,
            is_vm_running,
            list_available_images,
        )

        if not is_vm_running():
            raise ServiceUnavailableError("Containerlab VM is not running. Start it with: multipass start containerlab")

        images = list_available_images()
        kinds = get_node_kinds()

        return jsonify({
            "images": images,
            "kinds": kinds,
            "count": len(images),
        })

    except ServiceUnavailableError:
        raise
    except Exception as e:
        return safe_error_response(e, "get containerlab images")


@provision_bp.route("/api/provision/containerlab/topology")
@jwt_required
def get_containerlab_topology():
    """
    Get current Containerlab topology.
    ---
    tags:
      - Provisioning
    summary: Get topology
    description: Returns current containerlab topology with nodes and links.
    responses:
      200:
        description: Topology data
        schema:
          type: object
          properties:
            name:
              type: string
            nodes:
              type: object
            links:
              type: array
      503:
        description: Containerlab not available
    """
    try:
        from core.containerlab import get_topology, is_vm_running

        if not is_vm_running():
            raise ServiceUnavailableError("Containerlab VM is not running")

        topology = get_topology()

        # Remove raw field for cleaner response
        if "raw" in topology:
            del topology["raw"]

        return jsonify(topology)

    except ServiceUnavailableError:
        raise
    except Exception as e:
        return safe_error_response(e, "get containerlab topology")


@provision_bp.route("/api/provision/containerlab/validate-name")
@jwt_required
def validate_containerlab_name():
    """
    Validate a proposed containerlab node name.
    ---
    tags:
      - Provisioning
    summary: Validate node name
    description: Check if a node name is valid and available.
    parameters:
      - name: name
        in: query
        type: string
        required: true
        description: Proposed node name
    responses:
      200:
        description: Validation result
        schema:
          type: object
          properties:
            valid:
              type: boolean
            reason:
              type: string
      400:
        description: Missing name parameter
    """
    name = request.args.get("name")
    if not name:
        raise ValidationError("Missing 'name' parameter")

    try:
        from core.containerlab import validate_node_name

        result = validate_node_name(name)
        return jsonify(result)

    except Exception as e:
        logger.exception(f"Failed to validate containerlab name: {name}")
        return jsonify({"valid": False, "reason": "Validation check failed"})


# =============================================================================
# Job Status Endpoints
# =============================================================================


@provision_bp.route("/api/provision/status/<job_id>")
@jwt_required
def get_provision_status(job_id: str):
    """
    Get provisioning job status.
    ---
    tags:
      - Provisioning
    summary: Get job status
    description: Poll for provisioning job status and progress.
    parameters:
      - name: job_id
        in: path
        type: string
        required: true
        description: Provisioning job ID
    responses:
      200:
        description: Job status
        schema:
          type: object
          properties:
            job_id:
              type: string
            status:
              type: string
              enum: [pending, running, completed, failed, rolled_back, cancelled]
            step:
              type: string
            progress_pct:
              type: integer
            steps_completed:
              type: array
            steps_remaining:
              type: array
            error:
              type: string
      404:
        description: Job not found
    """
    manager = get_state_manager()
    job = manager.get_job(job_id)

    if not job:
        return jsonify({"error": f"Job '{job_id}' not found"}), 404

    return jsonify(job.to_dict())


@provision_bp.route("/api/provision/jobs")
@jwt_required
def list_provision_jobs():
    """
    List provisioning jobs.
    ---
    tags:
      - Provisioning
    summary: List jobs
    description: List all provisioning jobs with optional filters.
    parameters:
      - name: status
        in: query
        type: string
        description: Filter by status
      - name: platform
        in: query
        type: string
        description: Filter by platform (eve-ng, containerlab)
      - name: limit
        in: query
        type: integer
        description: Maximum jobs to return (default 50)
    responses:
      200:
        description: List of jobs
        schema:
          type: object
          properties:
            jobs:
              type: array
            count:
              type: integer
    """
    manager = get_state_manager()

    status = request.args.get("status")
    platform = request.args.get("platform")
    limit = request.args.get("limit", 50, type=int)

    status_filter = None
    if status:
        try:
            status_filter = JobStatus(status)
        except ValueError:
            return jsonify({"error": f"Invalid status: {status}"}), 400

    jobs = manager.list_jobs(status=status_filter, platform=platform, limit=limit)

    return jsonify({
        "jobs": [j.to_dict() for j in jobs],
        "count": len(jobs),
    })


@provision_bp.route("/api/provision/jobs/active")
@jwt_required
def get_active_jobs():
    """
    Get active provisioning jobs.
    ---
    tags:
      - Provisioning
    summary: Get active jobs
    description: Returns jobs that are pending or running.
    responses:
      200:
        description: Active jobs
    """
    manager = get_state_manager()
    jobs = manager.get_active_jobs()

    return jsonify({
        "jobs": [j.to_dict() for j in jobs],
        "count": len(jobs),
    })


@provision_bp.route("/api/provision/stats")
@jwt_required
def get_provision_stats():
    """
    Get provisioning statistics.
    ---
    tags:
      - Provisioning
    summary: Get stats
    description: Returns job counts by status and platform.
    responses:
      200:
        description: Provisioning statistics
    """
    manager = get_state_manager()
    return jsonify(manager.get_stats())


# =============================================================================
# Job Management Endpoints
# =============================================================================


@provision_bp.route("/api/provision/<job_id>/cancel", methods=["POST"])
@jwt_required
@permission_required('run_config_commands')
@feature_flag_required("automated_provisioning")
def cancel_provision_job(job_id: str):
    """
    Cancel a provisioning job.
    ---
    tags:
      - Provisioning
    summary: Cancel job
    description: Cancel a pending or running provisioning job.
    parameters:
      - name: job_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Job cancelled
      400:
        description: Cannot cancel job
      404:
        description: Job not found
    """
    manager = get_state_manager()
    job = manager.get_job(job_id)

    if not job:
        return jsonify({"error": f"Job '{job_id}' not found"}), 404

    if job.status not in (JobStatus.PENDING, JobStatus.RUNNING):
        return jsonify({
            "error": f"Cannot cancel job in status '{job.status.value}'"
        }), 400

    cancelled = manager.cancel_job(job_id)
    return jsonify({
        "message": "Job cancelled",
        "job": cancelled.to_dict()
    })


# =============================================================================
# Provisioning Endpoints (Write - Phase 4/5)
# =============================================================================


@provision_bp.route("/api/provision/eve-ng", methods=["POST"])
@jwt_required
@permission_required('run_config_commands')
@feature_flag_required("automated_provisioning")
def provision_eve_ng():
    """
    Start EVE-NG device provisioning.
    ---
    tags:
      - Provisioning
    summary: Provision EVE-NG device
    description: |
      Start async provisioning of a new device in EVE-NG.
      Returns immediately with job_id for status polling.
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - name
              - template
            properties:
              name:
                type: string
                description: Device name
              template:
                type: string
                description: EVE-NG template/image
              cpu:
                type: integer
                default: 1
              ram:
                type: integer
                default: 2048
              ethernet:
                type: integer
                default: 4
              netbox_device_type_id:
                type: integer
              netbox_role_id:
                type: integer
              netbox_site_id:
                type: integer
    responses:
      202:
        description: Provisioning started
        schema:
          type: object
          properties:
            job_id:
              type: string
            correlation_id:
              type: string
            status:
              type: string
            message:
              type: string
      400:
        description: Invalid request
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    required = ["name", "template"]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    # Get correlation ID from header or generate
    correlation_id = request.headers.get("X-Correlation-ID")

    manager = get_state_manager()
    job = manager.create_job(
        device_name=data["name"],
        platform="eve-ng",
        correlation_id=correlation_id,
    )

    # Start async provisioning
    executor = get_executor(manager)
    executor.start_eve_ng_provisioning(
        job_id=job.job_id,
        name=data["name"],
        template=data["template"],
        cpu=data.get("cpu", 1),
        ram=data.get("ram", 2048),
        ethernet=data.get("ethernet", 4),
        netbox_site_id=data.get("netbox_site_id"),
        netbox_role_id=data.get("netbox_role_id"),
        netbox_device_type_id=data.get("netbox_device_type_id"),
    )

    logger.info(
        f"[{job.correlation_id}] EVE-NG provisioning started for {data['name']}"
    )

    return jsonify({
        "job_id": job.job_id,
        "correlation_id": job.correlation_id,
        "status": job.status.value,
        "message": "Provisioning started. Poll /api/provision/status/{job_id} for progress.",
    }), 202


@provision_bp.route("/api/provision/containerlab", methods=["POST"])
@jwt_required
@permission_required('run_config_commands')
@feature_flag_required("automated_provisioning")
def provision_containerlab():
    """
    Start Containerlab device provisioning.
    ---
    tags:
      - Provisioning
    summary: Provision Containerlab device
    description: |
      Start async provisioning of a new container in Containerlab.
      Returns immediately with job_id for status polling.
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - name
              - kind
            properties:
              name:
                type: string
                description: Node name
              kind:
                type: string
                description: Node kind (nokia_srlinux, frr, linux, etc.)
              image:
                type: string
                description: Container image (uses default if not provided)
              startup_config:
                type: string
                description: Path to startup config file
              netbox_device_type_id:
                type: integer
              netbox_role_id:
                type: integer
              netbox_site_id:
                type: integer
    responses:
      202:
        description: Provisioning started
      400:
        description: Invalid request
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    required = ["name", "kind"]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    # Validate name before creating job
    from core.containerlab import validate_node_name
    validation = validate_node_name(data["name"])
    if not validation.get("valid"):
        return jsonify({
            "error": "Invalid node name",
            "reason": validation.get("reason")
        }), 400

    # Get correlation ID from header or generate
    correlation_id = request.headers.get("X-Correlation-ID")

    manager = get_state_manager()
    job = manager.create_job(
        device_name=data["name"],
        platform="containerlab",
        correlation_id=correlation_id,
    )

    # Start async provisioning
    executor = get_executor(manager)
    executor.start_containerlab_provisioning(
        job_id=job.job_id,
        name=data["name"],
        kind=data["kind"],
        image=data.get("image"),
        startup_config=data.get("startup_config"),
        netbox_site_id=data.get("netbox_site_id"),
        netbox_role_id=data.get("netbox_role_id"),
        netbox_device_type_id=data.get("netbox_device_type_id"),
    )

    logger.info(
        f"[{job.correlation_id}] Containerlab provisioning started for {data['name']}"
    )

    return jsonify({
        "job_id": job.job_id,
        "correlation_id": job.correlation_id,
        "status": job.status.value,
        "message": "Provisioning started. Poll /api/provision/status/{job_id} for progress.",
    }), 202


@provision_bp.route("/api/provision/<device_name>", methods=["DELETE"])
@jwt_required
@permission_required('run_config_commands')
@feature_flag_required("automated_provisioning")
def deprovision_device(device_name: str):
    """
    Deprovision a device.
    ---
    tags:
      - Provisioning
    summary: Deprovision device
    description: Remove a provisioned device from EVE-NG or Containerlab.
    parameters:
      - name: device_name
        in: path
        type: string
        required: true
      - name: platform
        in: query
        type: string
        description: Platform hint (eve-ng or containerlab)
    responses:
      200:
        description: Device deprovisioned
      404:
        description: Device not found
      500:
        description: Deprovisioning failed
    """
    correlation_id = request.headers.get("X-Correlation-ID", "")
    platform_hint = request.args.get("platform")
    log_prefix = f"[{correlation_id}] " if correlation_id else ""

    logger.info(f"{log_prefix}Deprovisioning requested for {device_name}")

    results = {
        "device_name": device_name,
        "eve_ng": None,
        "containerlab": None,
        "netbox": None,
    }
    errors = []

    # Try EVE-NG if no platform hint or hint is eve-ng
    if not platform_hint or platform_hint == "eve-ng":
        try:
            from core.eve_ng_client import EVEClient, EVEClientError

            if os.getenv("EVE_NG_HOST"):
                with EVEClient() as client:
                    node = client.get_node_by_name(device_name, correlation_id=correlation_id)
                    if node:
                        client.deprovision_node(
                            node_id=node["id"],
                            correlation_id=correlation_id,
                        )
                        results["eve_ng"] = "removed"
                        logger.info(f"{log_prefix}Removed {device_name} from EVE-NG")
                    else:
                        results["eve_ng"] = "not_found"

        except EVEClientError as e:
            logger.error(f"{log_prefix}EVE-NG deprovision failed: {e}")
            errors.append(f"EVE-NG: {e}")
        except Exception as e:
            logger.error(f"{log_prefix}EVE-NG error: {e}")
            errors.append(f"EVE-NG: {e}")

    # Try Containerlab if no platform hint or hint is containerlab
    if not platform_hint or platform_hint == "containerlab":
        try:
            from core.containerlab import (
                deprovision_node,
                get_existing_node_names,
                is_vm_running,
                ContainerlabError,
            )

            if is_vm_running(correlation_id):
                existing_nodes = get_existing_node_names(correlation_id)
                if device_name in existing_nodes:
                    deprovision_node(
                        name=device_name,
                        correlation_id=correlation_id,
                    )
                    results["containerlab"] = "removed"
                    logger.info(f"{log_prefix}Removed {device_name} from Containerlab")
                else:
                    results["containerlab"] = "not_found"
            else:
                results["containerlab"] = "vm_not_running"

        except ContainerlabError as e:
            logger.error(f"{log_prefix}Containerlab deprovision failed: {e}")
            errors.append(f"Containerlab: {e}")
        except Exception as e:
            logger.error(f"{log_prefix}Containerlab error: {e}")
            errors.append(f"Containerlab: {e}")

    # Try to clean up NetBox device
    try:
        from config.netbox_client import get_client

        client = get_client()
        if client:
            # Find device by name
            device = client.get_device(device_name)
            if device:
                device_id = device.get("id")
                if device_id:
                    # Release any allocated IPs first
                    primary_ip = device.get("primary_ip4") or device.get("primary_ip")
                    if primary_ip:
                        ip_addr = primary_ip.get("address", "").split("/")[0]
                        if ip_addr:
                            try:
                                client.release_ip(ip_addr, correlation_id)
                            except Exception:
                                pass

                    # Delete device
                    client.delete_device(device_id, correlation_id)
                    results["netbox"] = "removed"
                    logger.info(f"{log_prefix}Removed {device_name} from NetBox")
            else:
                results["netbox"] = "not_found"

    except Exception as e:
        logger.warning(f"{log_prefix}NetBox cleanup failed: {e}")
        # Don't add to errors - NetBox cleanup is optional

    # Determine response
    removed_from = [k for k, v in results.items() if v == "removed"]

    if errors and not removed_from:
        return jsonify({
            "error": "Deprovisioning failed",
            "details": errors,
            "results": results,
        }), 500

    if not removed_from:
        return jsonify({
            "error": f"Device '{device_name}' not found",
            "results": results,
        }), 404

    return jsonify({
        "message": f"Device '{device_name}' deprovisioned",
        "removed_from": removed_from,
        "results": results,
        "warnings": errors if errors else None,
    })


# =============================================================================
# Feature Status Endpoint
# =============================================================================


@provision_bp.route("/api/provision/features")
@jwt_required
def get_provision_features():
    """
    Get provisioning feature status.
    ---
    tags:
      - Provisioning
    summary: Get feature status
    description: Returns which provisioning features are enabled.
    responses:
      200:
        description: Feature status
    """
    from core.feature_flags import is_enabled

    eve_ng_available = False
    containerlab_available = False

    # Check if EVE-NG is configured
    if os.getenv("EVE_NG_HOST"):
        eve_ng_available = True

    # Check if containerlab VM is running
    try:
        from core.containerlab import is_vm_running
        containerlab_available = is_vm_running()
    except Exception:
        pass

    return jsonify({
        "automated_provisioning": is_enabled("automated_provisioning"),
        "eve_ng_enabled": is_enabled("eve_ng_enabled"),
        "containerlab_enabled": is_enabled("containerlab_enabled"),
        "eve_ng_available": eve_ng_available,
        "containerlab_available": containerlab_available,
    })
