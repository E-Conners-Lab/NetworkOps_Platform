#!/bin/bash
#
# NetworkOps Quickstart Script
# Sets up the project for new users with their own network lab
#
# Usage:
#   ./quickstart.sh              # Interactive mode
#   ./quickstart.sh --headless   # Non-interactive (CI/Docker)
#   ./quickstart.sh --help       # Show help
#

set -e

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

HEADLESS=0
SKIP_DASHBOARD=0
AUTO_START=0
DEMO=0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --headless|-h)
            HEADLESS=1
            shift
            ;;
        --skip-dashboard)
            SKIP_DASHBOARD=1
            shift
            ;;
        --auto-start)
            AUTO_START=1
            shift
            ;;
        --demo)
            DEMO=1
            shift
            ;;
        --help)
            echo "NetworkOps Quickstart Script"
            echo ""
            echo "Usage: ./quickstart.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --headless       Non-interactive mode (no prompts, uses defaults)"
            echo "  --skip-dashboard Skip Node.js/dashboard setup"
            echo "  --auto-start     Start API server after setup (headless only)"
            echo "  --demo           Enable demo mode (simulated devices, no lab needed)"
            echo "  --help           Show this help message"
            echo ""
            echo "Examples:"
            echo "  ./quickstart.sh                          # Interactive setup"
            echo "  ./quickstart.sh --demo                   # Demo mode (no devices needed)"
            echo "  ./quickstart.sh --headless               # CI/Docker setup"
            echo "  ./quickstart.sh --headless --auto-start  # Setup and run"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Colors for output (disabled in headless mode for clean logs)
if [[ $HEADLESS -eq 1 ]]; then
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
fi

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_step() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        print_step "$1 found: $(command -v $1)"
        return 0
    else
        print_error "$1 not found"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Main Script
# -----------------------------------------------------------------------------

# Track start time
START_TIME=$(date +%s)

print_header "NetworkOps Quickstart"
echo ""
echo "This script will set up NetworkOps for your network lab."
echo "Estimated time: 5-10 minutes"
echo ""

cd "$PROJECT_ROOT"

# -----------------------------------------------------------------------------
# Step 1: Check Prerequisites
# -----------------------------------------------------------------------------

print_header "Step 1: Checking Prerequisites"

MISSING_DEPS=0

# Python 3.9+
if check_command python3; then
    PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
    PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
    PYTHON_VERSION="${PYTHON_MAJOR}.${PYTHON_MINOR}"

    # Version check: need Python 3.9 or higher
    if [[ $PYTHON_MAJOR -gt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 9 ]]; then
        print_step "Python version $PYTHON_VERSION (3.9+ required)"
    else
        print_error "Python $PYTHON_VERSION found, but 3.9+ required"
        MISSING_DEPS=1
    fi
else
    MISSING_DEPS=1
fi

# Node.js (for dashboard)
if check_command node; then
    NODE_VERSION=$(node -v | sed 's/v//')
    print_step "Node.js version $NODE_VERSION"
else
    print_warn "Node.js not found - dashboard will not work"
    print_info "Install from: https://nodejs.org/"
fi

# npm
check_command npm || print_warn "npm not found - install Node.js"

# Git
check_command git || MISSING_DEPS=1

if [[ $MISSING_DEPS -eq 1 ]]; then
    echo ""
    print_error "Missing required dependencies. Please install them and re-run."
    exit 1
fi

echo ""
print_step "All required dependencies found!"

# -----------------------------------------------------------------------------
# Step 2: Python Virtual Environment
# -----------------------------------------------------------------------------

print_header "Step 2: Setting Up Python Environment"

# Detect uv for faster installs
USE_UV=0
if command -v uv &> /dev/null; then
    print_step "uv found — using fast installer"
    USE_UV=1
else
    print_info "Tip: install uv for 10-50x faster installs (https://docs.astral.sh/uv/)"
fi

if [[ -d ".venv" ]]; then
    print_step "Virtual environment already exists"
else
    print_info "Creating virtual environment..."
    if [[ $USE_UV -eq 1 ]]; then
        uv venv .venv
    else
        python3 -m venv .venv
    fi
    print_step "Virtual environment created"
fi

print_info "Activating virtual environment..."
source .venv/bin/activate
print_step "Virtual environment activated"

print_info "Installing Python dependencies..."
if [[ $USE_UV -eq 1 ]]; then
    uv pip install -r requirements.txt -q
else
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
fi
print_step "Python dependencies installed"

# -----------------------------------------------------------------------------
# Step 3: Node.js Dependencies (Dashboard)
# -----------------------------------------------------------------------------

print_header "Step 3: Setting Up Dashboard"

if [[ $SKIP_DASHBOARD -eq 1 ]]; then
    print_info "Skipping dashboard setup (--skip-dashboard)"
elif command -v npm &> /dev/null; then
    if [[ -d "dashboard/node_modules" ]]; then
        print_step "Dashboard dependencies already installed"
    else
        print_info "Installing dashboard dependencies..."
        cd dashboard
        npm install --silent 2>/dev/null
        cd ..
        print_step "Dashboard dependencies installed"
    fi
else
    print_warn "Skipping dashboard setup (npm not found)"
fi

# -----------------------------------------------------------------------------
# Step 4: Environment Configuration
# -----------------------------------------------------------------------------

print_header "Step 4: Environment Configuration"

if [[ -f ".env" ]]; then
    print_step ".env file already exists"
    print_info "Review and update .env if needed"
else
    if [[ -f ".env.example" ]]; then
        cp .env.example .env
        print_step "Created .env from .env.example"
    else
        cat > .env << 'EOF'
# NetworkOps Environment Configuration
# Generated by quickstart.sh

# =============================================================================
# REQUIRED SETTINGS
# =============================================================================

# Device credentials (used if not specified per-device)
DEFAULT_USERNAME=admin
DEFAULT_PASSWORD=admin

# =============================================================================
# OPTIONAL FEATURES
# =============================================================================

# RAG Chatbot (requires Anthropic API key)
# ANTHROPIC_API_KEY=sk-ant-...

# NetBox Integration
# USE_NETBOX=false
# NETBOX_URL=http://localhost:8000
# NETBOX_API_TOKEN=your-token-here

# Hierarchical Site View
ENABLE_HIERARCHICAL_VIEW=false

# =============================================================================
# PRODUCTION SETTINGS (optional)
# =============================================================================

# Redis (for caching and rate limiting)
# REDIS_URL=redis://localhost:6379

# PostgreSQL (for job history)
# DATABASE_URL=postgresql://user:pass@localhost/networkops

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=text

# Rate Limiting
RATE_LIMIT_DEFAULT=500 per minute
RATE_LIMIT_AUTH=10 per minute
EOF
        print_step "Created .env with default settings"
    fi
    print_warn "Edit .env to add your credentials and API keys"
fi

# Handle demo mode
if [[ $DEMO -eq 1 ]]; then
    # Set DEMO_MODE=true in .env
    if grep -q "^DEMO_MODE=" .env 2>/dev/null; then
        sed -i.bak 's/^DEMO_MODE=.*/DEMO_MODE=true/' .env && rm -f .env.bak
    else
        echo "DEMO_MODE=true" >> .env
    fi
    print_step "Demo mode enabled — no real network devices needed"
elif [[ $HEADLESS -eq 0 ]] && ! grep -q "^DEMO_MODE=true" .env 2>/dev/null; then
    echo ""
    print_info "No network lab? Demo mode simulates devices for testing."
    read -p "Enable demo mode? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if grep -q "^DEMO_MODE=" .env 2>/dev/null; then
            sed -i.bak 's/^DEMO_MODE=.*/DEMO_MODE=true/' .env && rm -f .env.bak
        else
            echo "DEMO_MODE=true" >> .env
        fi
        print_step "Demo mode enabled"
    fi
fi

# -----------------------------------------------------------------------------
# Step 5: Device Inventory Configuration
# -----------------------------------------------------------------------------

print_header "Step 5: Device Inventory"

DEVICES_FILE="config/devices.py"
DEVICES_TEMPLATE="config/devices_template.py"

# Check if devices.py has been customized (not just the template)
if grep -q "10.255.255" "$DEVICES_FILE" 2>/dev/null; then
    print_info "Current devices.py contains example lab IPs (10.255.255.x)"
    if [[ $HEADLESS -eq 1 ]]; then
        # In headless mode, don't overwrite existing config
        print_info "Headless mode: keeping existing devices.py"
        CREATE_TEMPLATE=0
    else
        echo ""
        read -p "Create a fresh template for your own devices? [y/N] " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Backup existing
            cp "$DEVICES_FILE" "${DEVICES_FILE}.backup"
            print_step "Backed up existing devices.py"
            CREATE_TEMPLATE=1
        else
            CREATE_TEMPLATE=0
        fi
    fi
else
    CREATE_TEMPLATE=0
fi

if [[ $CREATE_TEMPLATE -eq 1 ]] || [[ ! -f "$DEVICES_FILE" ]]; then
    cat > "$DEVICES_TEMPLATE" << 'PYEOF'
"""
NetworkOps Device Inventory Template

Instructions:
1. Copy this file to devices.py
2. Replace the example devices with your own
3. Ensure SSH/NETCONF access is configured on your devices

Supported device types:
- cisco_xe: Cisco IOS-XE (routers, switches) - SSH + NETCONF
- cisco_ios: Cisco IOS (legacy) - SSH only
- linux: Linux hosts - SSH only
"""

# Default credentials (can be overridden per device)
USERNAME = "admin"
PASSWORD = "admin"

# =============================================================================
# DEVICE INVENTORY
# =============================================================================
# Add your devices here. Each device needs:
#   - host: IP address or hostname
#   - device_type: Platform type (see above)
#   - username/password: Optional, uses defaults if not specified
#   - port: Optional, defaults to 22 for SSH
#   - netconf_port: Optional, defaults to 830 for NETCONF

DEVICES = {
    # Example router
    "router1": {
        "host": "192.168.1.10",
        "device_type": "cisco_xe",
        "username": USERNAME,
        "password": PASSWORD,
        "netconf_port": 830,
    },

    # Example switch
    "switch1": {
        "host": "192.168.1.20",
        "device_type": "cisco_xe",
        "username": USERNAME,
        "password": PASSWORD,
    },

    # Example Linux host
    "server1": {
        "host": "192.168.1.100",
        "device_type": "linux",
        "username": "root",
        "password": "password",
    },
}

# =============================================================================
# HELPER FUNCTIONS (do not modify)
# =============================================================================

def get_device(name: str) -> dict:
    """Get device config by name."""
    if name not in DEVICES:
        raise ValueError(f"Unknown device: {name}")
    return DEVICES[name]

def get_all_devices() -> dict:
    """Get all devices."""
    return DEVICES

def get_scrapli_device(name: str) -> dict:
    """Convert device config to Scrapli format."""
    device = get_device(name)
    return {
        "host": device["host"],
        "auth_username": device.get("username", USERNAME),
        "auth_password": device.get("password", PASSWORD),
        "auth_strict_key": False,
        "transport": "asyncssh",
        "platform": device["device_type"],
    }
PYEOF

    print_step "Created devices template: $DEVICES_TEMPLATE"
    echo ""
    print_warn "ACTION REQUIRED:"
    echo "    1. Edit $DEVICES_TEMPLATE with your device inventory"
    echo "    2. Copy to devices.py: cp $DEVICES_TEMPLATE $DEVICES_FILE"
    echo ""
fi

# -----------------------------------------------------------------------------
# Step 6: Verify Setup
# -----------------------------------------------------------------------------

print_header "Step 6: Verification"

# Test Python imports
print_info "Testing Python imports..."
python3 -c "
import sys
try:
    from config.devices import DEVICES
    print(f'  Devices configured: {len(DEVICES)}')
except Exception as e:
    print(f'  Warning: {e}')

try:
    import netmiko
    print('  netmiko: OK')
except ImportError:
    print('  netmiko: MISSING')

try:
    import scrapli
    print('  scrapli: OK')
except ImportError:
    print('  scrapli: MISSING')

try:
    import flask
    print('  flask: OK')
except ImportError:
    print('  flask: MISSING')
"
print_step "Python environment verified"

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

# Calculate elapsed time
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
MINUTES=$((ELAPSED / 60))
SECONDS=$((ELAPSED % 60))

print_header "Setup Complete!"

echo ""
if [[ $MINUTES -gt 0 ]]; then
    print_step "Completed in ${MINUTES}m ${SECONDS}s"
else
    print_step "Completed in ${SECONDS}s"
fi

echo ""
if grep -q "^DEMO_MODE=true" .env 2>/dev/null; then
    echo "Next steps (demo mode):"
    echo ""
    echo "  1. Start the API server:"
    echo "     ${YELLOW}source .venv/bin/activate${NC}"
    echo "     ${YELLOW}python dashboard/api_server.py${NC}"
    echo ""
    echo "  2. Start the dashboard (separate terminal):"
    echo "     ${YELLOW}cd dashboard && npm start${NC}"
    echo ""
    echo "  3. Open in browser:"
    echo "     ${YELLOW}http://localhost:3000${NC}  (Login: admin/admin)"
    echo ""
    echo "  Demo mode uses simulated devices — no network lab required."
    echo "  To switch to real devices later, set DEMO_MODE=false in .env"
    echo "  and configure your device inventory in config/devices.py."
else
    echo "Next steps:"
    echo ""
    echo "  1. Configure your devices:"
    echo "     ${YELLOW}vim config/devices.py${NC}"
    echo ""
    echo "  2. Update environment variables:"
    echo "     ${YELLOW}vim .env${NC}"
    echo ""
    echo "  3. Test device connectivity:"
    echo "     ${YELLOW}source .venv/bin/activate${NC}"
    echo "     ${YELLOW}python -c \"from config.devices import DEVICES; print(DEVICES.keys())\"${NC}"
    echo ""
    echo "  4. Start the API server:"
    echo "     ${YELLOW}python dashboard/api_server.py${NC}"
    echo ""
    echo "  5. Start the dashboard (separate terminal):"
    echo "     ${YELLOW}cd dashboard && npm start${NC}"
    echo ""
    echo "  6. Open in browser:"
    echo "     ${YELLOW}http://localhost:3000${NC}"
fi
echo ""

# Handle auto-start or prompt
if [[ $HEADLESS -eq 1 ]]; then
    if [[ $AUTO_START -eq 1 ]]; then
        echo ""
        print_info "Starting API server on http://localhost:5001"
        python dashboard/api_server.py
    else
        print_step "Setup complete. Run: python dashboard/api_server.py"
    fi
else
    echo ""
    read -p "Start the API server now? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        print_info "Starting API server on http://localhost:5001"
        print_info "Press Ctrl+C to stop"
        echo ""
        python dashboard/api_server.py
    fi
fi
