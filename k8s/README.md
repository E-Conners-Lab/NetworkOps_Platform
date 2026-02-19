# Kubernetes Deployment

Production deployment manifests for NetworkOps using Kustomize (k8s/) and Helm (helm/).

## Components

| Service | Image | Port | Replicas | Purpose |
|---------|-------|------|----------|---------|
| API Server | `networkops-api` | 5001 | 2-10 (HPA) | Flask + Gunicorn + WebSocket |
| Celery Worker | `networkops-worker` | - | 2-8 (HPA) | Async task processing |
| Celery Beat | `networkops-worker` | - | 1 | Scheduled tasks |
| Redis | `redis:7-alpine` | 6379 | 1 | Cache (DB 0), broker (DB 1), results (DB 2) |
| PostgreSQL | `postgres:16-alpine` | 5432 | 1 | Primary database |

## Kustomize (k8s/)

```bash
# Deploy base
kubectl apply -k k8s/base/

# Deploy production overlay (higher replicas, stricter limits)
kubectl apply -k k8s/overlays/production/
```

### Structure

```
k8s/
├── base/
│   ├── kustomization.yaml
│   ├── namespace.yaml           # networkops namespace
│   ├── configmap.yaml           # Environment configuration
│   ├── secrets.yaml             # JWT, DB credentials (template)
│   ├── api-deployment.yaml      # API server (2 replicas)
│   ├── celery-deployment.yaml   # Worker + Beat
│   ├── redis-deployment.yaml    # Redis with persistence
│   ├── postgres-deployment.yaml # PostgreSQL with persistence
│   ├── services.yaml            # ClusterIP services
│   ├── ingress.yaml             # Nginx ingress with TLS
│   ├── hpa.yaml                 # Horizontal Pod Autoscaler
│   └── pdb.yaml                 # Pod Disruption Budgets
└── overlays/
    └── production/              # 3 API replicas, 4 workers, 20 max HPA
```

## Helm Chart (helm/networkops/)

```bash
# Install with defaults
helm install networkops helm/networkops/

# Install with custom values
helm install networkops helm/networkops/ \
  --set api.replicaCount=3 \
  --set postgresql.auth.password=mypassword \
  --set redis.auth.password=myredispass

# Use external databases
helm install networkops helm/networkops/ \
  --set redis.enabled=false \
  --set externalRedis.url=redis://my-redis:6379 \
  --set postgresql.enabled=false \
  --set externalPostgresql.url=postgresql://user:pass@host/db
```

### Key values.yaml Options

```yaml
api:
  replicaCount: 2
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilization: 70

celeryWorker:
  enabled: true
  replicaCount: 2

redis:
  enabled: true        # Set false to use external Redis
  architecture: standalone

postgresql:
  enabled: true        # Set false to use external PostgreSQL

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: networkops.local

rateLimit:
  default: "500 per minute"
  auth: "10 per minute"
  commands: "60 per minute"

netbox:
  enabled: false
  url: ""
  apiToken: ""
```

## Health Probes

| Service | Probe | Endpoint/Command | Interval |
|---------|-------|-----------------|----------|
| API | Liveness | `GET /healthz` | 15s |
| API | Readiness | `GET /readyz` | 10s |
| Celery | Liveness | `celery inspect ping` | 60s |
| Redis | Liveness | `redis-cli ping` | 10s |
| PostgreSQL | Readiness | `pg_isready` | 5s |

## Scaling

- **API**: HPA scales 2-10 pods based on CPU (70%) and memory (80%)
- **Workers**: HPA scales 2-8 pods based on CPU (70%)
- **Beat**: Fixed at 1 replica (single scheduler)
- **Pod Disruption Budget**: minAvailable=1 for API and workers

## Security

- All containers run as non-root (`runAsUser: 1000`)
- Secrets stored in Kubernetes Secrets (template provided)
- Ingress supports TLS termination
- Rate limiting at both ingress (50 RPS) and application level

## Docker

```bash
# Build images
docker build -f Dockerfile.api -t networkops-api .
docker build -f Dockerfile.worker -t networkops-worker .
docker build -f Dockerfile.mcp -t networkops-mcp .

# Docker Compose (development)
docker compose up

# Docker Compose (production with profiles)
docker compose -f docker-compose.prod.yml --profile worker --profile monitor up
```

### Compose Profiles

| Profile | Services |
|---------|----------|
| (default) | nginx, api, redis, postgres |
| `worker` | + celery-worker, celery-beat |
| `monitor` | + flower (5555), pgadmin (5050) |
| `frontend` | + React dashboard |
| `all` | everything |

## Terraform Provider

A Go-based Terraform provider is available in `terraform-provider-networkops/` for managing NetworkOps resources as infrastructure-as-code.

```hcl
provider "networkops" {
  api_url = "http://localhost:5001"
  token   = var.networkops_token
}
```

Build: `cd terraform-provider-networkops && make install`
