"""
OpenAPI/Swagger configuration for NetworkOps API.
"""

SWAGGER_TEMPLATE = {
    "info": {
        "title": "NetworkOps API",
        "description": """
# NetworkOps Network Automation API

AI-powered network operations platform for enterprise network management.

## Features
- Real-time network topology discovery
- Multi-vendor device management (Cisco, Nokia, FRRouting, Linux)
- Health monitoring and alerting
- AI-powered chatbot with live network queries
- Role-based access control

## Authentication
Most endpoints require JWT authentication. Obtain a token via `/api/auth/login`.

Include the token in the Authorization header:
```
Authorization: Bearer <your-token>
```

## Rate Limits
- Default: 500 requests/minute
- Auth endpoints: 10 requests/minute
- Command endpoints: 60 requests/minute
- Read-only endpoints: 1000 requests/minute
        """,
        "version": "1.2.0",
        "contact": {
            "name": "NetworkOps Support",
            "url": "https://github.com/E-Conners-Lab/MCP-with_Claude"
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        }
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT token. Format: 'Bearer <token>'"
        }
    },
    "tags": [
        {"name": "Health", "description": "Health check and readiness probes"},
        {"name": "Authentication", "description": "User authentication and management"},
        {"name": "Devices", "description": "Device inventory and status"},
        {"name": "Network", "description": "Network topology and connectivity"},
        {"name": "Commands", "description": "Execute commands on devices"},
        {"name": "Monitoring", "description": "Interface stats and telemetry"},
        {"name": "AI", "description": "RAG chatbot and document ingestion"},
        {"name": "Cache", "description": "Cache management"},
        {"name": "Metrics", "description": "Prometheus metrics"}
    ]
}

SWAGGER_CONFIG = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs"
}

# Endpoint documentation
ENDPOINT_DOCS = {
    "healthz": {
        "tags": ["Health"],
        "summary": "Liveness probe",
        "description": "Returns basic health status. Used by Kubernetes liveness probe.",
        "responses": {
            200: {
                "description": "Service is alive",
                "schema": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "example": "ok"},
                        "service": {"type": "string", "example": "networkops-api"},
                        "version": {"type": "string", "example": "1.0.0"},
                        "timestamp": {"type": "string", "example": "2025-12-26T12:00:00Z"}
                    }
                }
            }
        }
    },
    "readyz": {
        "tags": ["Health"],
        "summary": "Readiness probe",
        "description": "Checks if service is ready to accept traffic. Validates Redis and database connections.",
        "responses": {
            200: {
                "description": "Service is ready",
                "schema": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "example": "ready"},
                        "checks": {
                            "type": "object",
                            "properties": {
                                "redis": {"type": "string", "example": "ok"},
                                "database": {"type": "string", "example": "ok"}
                            }
                        }
                    }
                }
            },
            503: {"description": "Service not ready"}
        }
    },
    "login": {
        "tags": ["Authentication"],
        "summary": "User login",
        "description": "Authenticate user and receive JWT token.",
        "parameters": [
            {
                "name": "body",
                "in": "body",
                "required": True,
                "schema": {
                    "type": "object",
                    "required": ["username", "password"],
                    "properties": {
                        "username": {"type": "string", "example": "admin"},
                        "password": {"type": "string", "example": "admin"}
                    }
                }
            }
        ],
        "responses": {
            200: {
                "description": "Login successful",
                "schema": {
                    "type": "object",
                    "properties": {
                        "token": {"type": "string"},
                        "user": {
                            "type": "object",
                            "properties": {
                                "username": {"type": "string"},
                                "role": {"type": "string"},
                                "permissions": {"type": "array", "items": {"type": "string"}}
                            }
                        }
                    }
                }
            },
            401: {"description": "Invalid credentials"}
        }
    },
    "devices": {
        "tags": ["Devices"],
        "summary": "List all devices",
        "description": "Returns list of all managed network devices.",
        "responses": {
            200: {
                "description": "List of device names",
                "schema": {
                    "type": "array",
                    "items": {"type": "string"},
                    "example": ["R1", "R2", "R3", "R4", "Switch-R1", "Alpine-1"]
                }
            }
        }
    },
    "topology": {
        "tags": ["Network"],
        "summary": "Get network topology",
        "description": "Discovers and returns network topology via CDP/LLDP.",
        "responses": {
            200: {
                "description": "Network topology",
                "schema": {
                    "type": "object",
                    "properties": {
                        "links": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "source": {"type": "string"},
                                    "source_intf": {"type": "string"},
                                    "target": {"type": "string"},
                                    "target_intf": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "command": {
        "tags": ["Commands"],
        "summary": "Execute command on device",
        "description": "Execute a show command on a network device. Requires 'run_show_commands' permission.",
        "security": [{"Bearer": []}],
        "parameters": [
            {
                "name": "body",
                "in": "body",
                "required": True,
                "schema": {
                    "type": "object",
                    "required": ["device", "command"],
                    "properties": {
                        "device": {"type": "string", "example": "R1"},
                        "command": {"type": "string", "example": "show ip interface brief"}
                    }
                }
            }
        ],
        "responses": {
            200: {
                "description": "Command output",
                "schema": {
                    "type": "object",
                    "properties": {
                        "device": {"type": "string"},
                        "command": {"type": "string"},
                        "output": {"type": "string"}
                    }
                }
            },
            400: {"description": "Command blocked or invalid"},
            403: {"description": "Permission denied"}
        }
    },
    "switch_status": {
        "tags": ["Monitoring"],
        "summary": "Get switch status",
        "description": "Returns health status of all switches including EIGRP neighbors and uplink status.",
        "responses": {
            200: {
                "description": "Switch status",
                "schema": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "example": "success"},
                        "healthy": {"type": "integer", "example": 3},
                        "switches": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "ip": {"type": "string"},
                                    "status": {"type": "string"},
                                    "uplink_status": {"type": "string"},
                                    "eigrp_neighbor": {"type": "object"}
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "interface_stats": {
        "tags": ["Monitoring"],
        "summary": "Get interface statistics",
        "description": "Returns interface statistics for all routers via NETCONF.",
        "responses": {
            200: {
                "description": "Interface statistics per device",
                "schema": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "admin_status": {"type": "string"},
                                "oper_status": {"type": "string"},
                                "in_octets": {"type": "integer"},
                                "out_octets": {"type": "integer"}
                            }
                        }
                    }
                }
            }
        }
    },
    "bgp_summary": {
        "tags": ["Network"],
        "summary": "Get BGP summary",
        "description": "Returns BGP neighbor summary from all routers.",
        "responses": {
            200: {
                "description": "BGP neighbors per device",
                "schema": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "neighbor": {"type": "string"},
                                "as": {"type": "integer"},
                                "state": {"type": "string"},
                                "prefixes_received": {"type": "integer"}
                            }
                        }
                    }
                }
            }
        }
    },
    "dmvpn_status": {
        "tags": ["Network"],
        "summary": "Get DMVPN status",
        "description": "Returns DMVPN tunnel status from all spokes.",
        "responses": {
            200: {
                "description": "DMVPN tunnel status",
                "schema": {
                    "type": "object",
                    "properties": {
                        "hub": {"type": "string"},
                        "spokes": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "tunnel_ip": {"type": "string"},
                                    "nhrp_state": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "chat": {
        "tags": ["AI"],
        "summary": "Chat with AI assistant",
        "description": "Send a message to the RAG-powered AI assistant. Can query documentation and live network data.",
        "parameters": [
            {
                "name": "body",
                "in": "body",
                "required": True,
                "schema": {
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": {"type": "string", "example": "What is the status of R1?"},
                        "session_id": {"type": "string", "description": "Optional session ID for context"}
                    }
                }
            }
        ],
        "responses": {
            200: {
                "description": "AI response",
                "schema": {
                    "type": "object",
                    "properties": {
                        "response": {"type": "string"},
                        "sources": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "tools_used": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    }
                }
            }
        }
    },
    "remediate": {
        "tags": ["Commands"],
        "summary": "Remediate interface",
        "description": "Perform remediation action on an interface (bounce, shutdown, no_shutdown). Requires 'remediate_interfaces' permission.",
        "security": [{"Bearer": []}],
        "parameters": [
            {
                "name": "body",
                "in": "body",
                "required": True,
                "schema": {
                    "type": "object",
                    "required": ["device", "interface", "action"],
                    "properties": {
                        "device": {"type": "string", "example": "R1"},
                        "interface": {"type": "string", "example": "GigabitEthernet1"},
                        "action": {
                            "type": "string",
                            "enum": ["bounce", "shutdown", "no_shutdown"],
                            "example": "bounce"
                        }
                    }
                }
            }
        ],
        "responses": {
            200: {"description": "Remediation successful"},
            403: {"description": "Permission denied"}
        }
    },
    "cache_stats": {
        "tags": ["Cache"],
        "summary": "Get cache statistics",
        "description": "Returns Redis cache statistics including hit rate.",
        "responses": {
            200: {
                "description": "Cache statistics",
                "schema": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "hit_rate": {"type": "number"},
                        "keys": {"type": "integer"},
                        "memory_used": {"type": "string"}
                    }
                }
            }
        }
    },
    "metrics": {
        "tags": ["Metrics"],
        "summary": "Prometheus metrics",
        "description": "Returns metrics in Prometheus format for scraping.",
        "produces": ["text/plain"],
        "responses": {
            200: {
                "description": "Prometheus metrics",
                "schema": {"type": "string"}
            }
        }
    }
}
