#!/bin/bash
# NetworkOps Kubernetes Deployment Script
#
# Usage:
#   ./deploy.sh [environment]
#
# Environments:
#   local       - Local development (minikube/kind)
#   production  - Production cluster
#
# Prerequisites:
#   - kubectl configured with cluster access
#   - kustomize installed (or kubectl with kustomize support)
#   - Docker images built and pushed (for production)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV="${1:-local}"

echo "=============================================="
echo "NetworkOps Kubernetes Deployment"
echo "Environment: $ENV"
echo "=============================================="

# Validate environment
if [[ "$ENV" != "local" && "$ENV" != "production" ]]; then
    echo "Error: Invalid environment '$ENV'"
    echo "Usage: ./deploy.sh [local|production]"
    exit 1
fi

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl not found. Please install kubectl."
    exit 1
fi

# For local development, build images
if [[ "$ENV" == "local" ]]; then
    echo ""
    echo "Building local Docker images..."

    # Check if Docker is running
    if ! docker info &> /dev/null; then
        echo "Error: Docker is not running. Please start Docker."
        exit 1
    fi

    PROJECT_ROOT="$SCRIPT_DIR/.."

    # Build API image
    echo "Building networkops-api:latest..."
    docker build -t networkops-api:latest -f "$PROJECT_ROOT/Dockerfile.api" "$PROJECT_ROOT"

    # Build worker image
    echo "Building networkops-worker:latest..."
    docker build -t networkops-worker:latest -f "$PROJECT_ROOT/Dockerfile.worker" "$PROJECT_ROOT"

    # For minikube, load images into minikube
    if command -v minikube &> /dev/null && minikube status &> /dev/null; then
        echo "Loading images into minikube..."
        minikube image load networkops-api:latest
        minikube image load networkops-worker:latest
    fi

    # For kind, load images into kind
    if command -v kind &> /dev/null && kind get clusters &> /dev/null; then
        CLUSTER=$(kind get clusters | head -1)
        if [[ -n "$CLUSTER" ]]; then
            echo "Loading images into kind cluster '$CLUSTER'..."
            kind load docker-image networkops-api:latest --name "$CLUSTER"
            kind load docker-image networkops-worker:latest --name "$CLUSTER"
        fi
    fi
fi

# Deploy using kustomize
echo ""
echo "Deploying to Kubernetes..."

if [[ "$ENV" == "local" ]]; then
    kubectl apply -k "$SCRIPT_DIR/base"
else
    kubectl apply -k "$SCRIPT_DIR/overlays/$ENV"
fi

# Wait for deployments
echo ""
echo "Waiting for deployments to be ready..."

kubectl -n networkops rollout status deployment/redis --timeout=120s
kubectl -n networkops rollout status deployment/postgres --timeout=120s
kubectl -n networkops rollout status deployment/api --timeout=180s

echo ""
echo "=============================================="
echo "Deployment complete!"
echo "=============================================="
echo ""
echo "Check status:"
echo "  kubectl -n networkops get pods"
echo ""
echo "View logs:"
echo "  kubectl -n networkops logs -f deployment/api"
echo ""
echo "Port forward API:"
echo "  kubectl -n networkops port-forward svc/api 5001:5001"
echo ""

# For local, show port-forward instructions
if [[ "$ENV" == "local" ]]; then
    echo "Quick test:"
    echo "  kubectl -n networkops port-forward svc/api 5001:5001 &"
    echo "  curl http://localhost:5001/healthz"
fi
