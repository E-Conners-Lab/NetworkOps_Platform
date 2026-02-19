# Dashboard

Full-stack React + Flask web application for network topology visualization, monitoring, and management.

## Quick Start

### Development

```bash
# Terminal 1: React dev server (hot reload, port 3000)
cd dashboard && npm install && npm start

# Terminal 2: Flask API server (port 5001)
DEMO_MODE=true JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
  python dashboard/api_server.py
```

### Production

```bash
cd dashboard && npm run build    # Build React frontend
cd .. && gunicorn -c dashboard/gunicorn.conf.py -w 4 dashboard.api_server:app
```

## Architecture

```
dashboard/
├── api_server.py              # Entry point — starts Flask + MDT collector + WebSocket
├── app.py                     # Application factory (create_app)
├── extensions.py              # Flask extensions (Socket.IO, rate limiter, cache)
├── auth/                      # JWT auth, RBAC, MFA/TOTP, password policy
├── routes/                    # Modular Flask blueprints (18 modules)
│   ├── auth_routes.py         #   Login, user management, groups
│   ├── topology.py            #   Network topology API
│   ├── network_ops.py         #   Device commands, BGP, OSPF, ping
│   ├── interfaces.py          #   Interface stats, DMVPN, switch status
│   ├── devices.py             #   Device inventory CRUD
│   ├── changes.py             #   Change management workflow
│   ├── impact.py              #   Failure blast radius analysis
│   ├── provision.py           #   EVE-NG + Containerlab provisioning
│   ├── chat.py                #   RAG-powered AI chat
│   ├── telemetry.py           #   Streaming telemetry (gRPC MDT)
│   ├── config_builder.py      #   Visual config generation
│   ├── network_tools.py       #   MTU/subnet calculators
│   ├── metrics_routes.py      #   Prometheus /metrics endpoint
│   ├── admin.py               #   Quotas, orgs, feature flags
│   ├── events.py              #   Event log
│   ├── health.py              #   /healthz, /readyz probes
│   ├── websocket.py           #   Socket.IO handlers
│   └── spa.py                 #   SPA fallback (serves React build)
├── src/                       # React 19 frontend (TypeScript)
│   ├── App.tsx                #   Main topology view (force-graph + D3.js)
│   ├── components/
│   │   ├── AuthenticatedApp   #   Layout shell with header, sidebars, panels
│   │   ├── OverlaysSidebar    #   Toggle overlays (BGP, OSPF, DMVPN, telemetry, etc.)
│   │   ├── HierarchySidebar   #   Enterprise nav (Region > Site > Rack)
│   │   ├── UserManagement     #   User/group admin (admin only)
│   │   ├── ChangeManagement   #   ITIL change workflow
│   │   ├── MTUCalculator      #   MTU calculation with tunnel stacks
│   │   ├── SubnetCalculator   #   CIDR/subnet math
│   │   ├── ImpactAnalysis     #   Pre-change risk assessment
│   │   ├── ImpactTrending     #   Multi-metric trending dashboard
│   │   └── IntentDriftEngine  #   Config vs reality drift detection
│   ├── config-builder/        #   Visual drag-drop config generator
│   ├── context/AuthContext    #   JWT state (login, logout, permissions)
│   ├── hooks/useAuthFetch     #   HTTP wrapper with auto Bearer token
│   └── utils/api.ts           #   API endpoint definitions
├── gunicorn.conf.py           # Production WSGI config (gevent workers)
└── package.json               # React build scripts
```

## Features

### Topology Visualization
- Interactive force-directed graph (D3.js + react-force-graph-2d)
- Drag-and-drop node positioning with saved layouts
- Real-time status: healthy (green), degraded (orange), critical (red)
- Enterprise hierarchy navigation (Region > Site > Rack > Device)

### Protocol Overlays
- **BGP Sessions** — iBGP/eBGP differentiation, AS numbers, prefix counts
- **OSPF Neighbors** — adjacency state, area mapping, link costs
- **DMVPN Status** — hub-spoke tunnels, peer states, uptime
- **Switch Fabric** — EIGRP neighbors, uplink status

### Monitoring
- **Streaming Telemetry** — gRPC MDT for CPU, memory, interface stats
- **Ping Sweep** — latency heatmap across all nodes
- **Event Log** — timestamped audit trail with device filtering
- **Impact Analysis** — pre-change risk assessment (LOW to CRITICAL)
- **Intent Drift Engine** — detect config deviation from baseline

### Network Tools
- MTU Calculator (L3/L4, tunnel overhead scenarios)
- Subnet Calculator (CIDR, splitting, netmask conversion)
- Multi-vendor CLI terminal (Cisco, FRR, Nokia SR Linux, Linux)
- RAG-powered documentation chat (Claude AI with source citations)

### Operations
- Change management (create > approve > execute > rollback)
- Device provisioning (EVE-NG + Containerlab)
- Interface remediation (enable, bounce, remove ACL)

### Security
- JWT authentication with configurable expiry
- MFA/TOTP support
- Role-based access control (admin, operator)
- Permission-based route protection
- Rate limiting (Redis-backed with in-memory fallback)
- Security headers (CSP, HSTS, X-Frame-Options)

## Authentication

```python
from dashboard.auth import jwt_required, permission_required

@my_bp.route('/api/foo')
@jwt_required
@permission_required('manage_foo')
def my_endpoint():
    user = g.current_user
    ...
```

**Default users** (when no external auth configured):
- `admin:admin` — full access
- `operator:operator` — read-only + show commands

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Token signing key (required) | random |
| `JWT_EXPIRATION_HOURS` | Token lifetime | `24` |
| `DEMO_MODE` | Use simulated devices | `false` |
| `REDIS_URL` | Redis for caching/rate limiting | `redis://localhost:6379/0` |
| `DATABASE_URL` | PostgreSQL connection | SQLite fallback |
| `CORS_ORIGINS` | Allowed origins | `http://localhost:3000,5001` |
| `LOG_FORMAT` | `json` or `text` | `json` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |
| `RATE_LIMIT_DEFAULT` | Global rate limit | `500 per minute` |
| `RATE_LIMIT_AUTH` | Auth endpoint limit | `10 per minute` |
| `ENABLE_HIERARCHICAL_VIEW` | Region/Site/Rack nav | `false` |

## npm Scripts

| Script | Description |
|--------|-------------|
| `npm start` | Dev server with hot reload (port 3000) |
| `npm run build` | Production build to `build/` |
| `npm test` | Jest unit tests |
| `npm run lint` | ESLint check |
| `npm run test:e2e` | Playwright end-to-end tests |
