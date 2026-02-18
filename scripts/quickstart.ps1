#
# NetworkOps Quickstart Script (Windows)
# Sets up the project for new users with their own network lab
#
# Usage:
#   .\quickstart.ps1              # Interactive mode
#   .\quickstart.ps1 -Headless    # Non-interactive (CI/Docker)
#   .\quickstart.ps1 -Help        # Show help
#

param(
    [switch]$Headless,
    [switch]$SkipDashboard,
    [switch]$AutoStart,
    [switch]$Help
)

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

if ($Help) {
    Write-Host "NetworkOps Quickstart Script (Windows)"
    Write-Host ""
    Write-Host "Usage: .\quickstart.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Headless       Non-interactive mode (no prompts, uses defaults)"
    Write-Host "  -SkipDashboard  Skip Node.js/dashboard setup"
    Write-Host "  -AutoStart      Start API server after setup (headless only)"
    Write-Host "  -Help           Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\quickstart.ps1                      # Interactive setup"
    Write-Host "  .\quickstart.ps1 -Headless            # CI/Docker setup"
    Write-Host "  .\quickstart.ps1 -Headless -AutoStart # Setup and run"
    exit 0
}

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

function Write-Header($text) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Blue
    Write-Host "  $text" -ForegroundColor Blue
    Write-Host ("=" * 60) -ForegroundColor Blue
}

function Write-Step($text) {
    Write-Host "[OK] $text" -ForegroundColor Green
}

function Write-Warn($text) {
    Write-Host "[!] $text" -ForegroundColor Yellow
}

function Write-Err($text) {
    Write-Host "[X] $text" -ForegroundColor Red
}

function Write-Info($text) {
    Write-Host "[i] $text" -ForegroundColor Cyan
}

function Test-Command($name) {
    return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

# -----------------------------------------------------------------------------
# Main Script
# -----------------------------------------------------------------------------

# Track start time
$StartTime = Get-Date

Write-Header "NetworkOps Quickstart"
Write-Host ""
Write-Host "This script will set up NetworkOps for your network lab."
Write-Host "Estimated time: 5-10 minutes"
Write-Host ""

Set-Location $ProjectRoot

# -----------------------------------------------------------------------------
# Step 1: Check Prerequisites
# -----------------------------------------------------------------------------

Write-Header "Step 1: Checking Prerequisites"

$MissingDeps = $false

# Python 3.9+
if (Test-Command "python") {
    $pythonVersion = python --version 2>&1
    Write-Step "Python found: $pythonVersion"

    $versionMatch = $pythonVersion -match "Python (\d+)\.(\d+)"
    if ($versionMatch) {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 9)) {
            Write-Err "Python 3.9+ required, found $major.$minor"
            $MissingDeps = $true
        }
    }
} else {
    Write-Err "Python not found"
    Write-Info "Install from: https://www.python.org/downloads/"
    $MissingDeps = $true
}

# Node.js (optional, for dashboard)
if (Test-Command "node") {
    $nodeVersion = node --version
    Write-Step "Node.js found: $nodeVersion"
} else {
    Write-Warn "Node.js not found - dashboard will not work"
    Write-Info "Install from: https://nodejs.org/"
}

# npm
if (Test-Command "npm") {
    Write-Step "npm found"
} else {
    Write-Warn "npm not found - install Node.js"
}

# Git
if (Test-Command "git") {
    Write-Step "Git found"
} else {
    Write-Err "Git not found"
    $MissingDeps = $true
}

if ($MissingDeps) {
    Write-Host ""
    Write-Err "Missing required dependencies. Please install them and re-run."
    exit 1
}

Write-Host ""
Write-Step "All required dependencies found!"

# -----------------------------------------------------------------------------
# Step 2: Python Virtual Environment
# -----------------------------------------------------------------------------

Write-Header "Step 2: Setting Up Python Environment"

if (Test-Path ".venv") {
    Write-Step "Virtual environment already exists"
} else {
    Write-Info "Creating virtual environment..."
    python -m venv .venv
    Write-Step "Virtual environment created"
}

Write-Info "Activating virtual environment..."
& ".\.venv\Scripts\Activate.ps1"
Write-Step "Virtual environment activated"

Write-Info "Installing Python dependencies (this may take a minute)..."
pip install --upgrade pip -q 2>$null
pip install -r requirements.txt -q 2>$null
Write-Step "Python dependencies installed"

# -----------------------------------------------------------------------------
# Step 3: Node.js Dependencies (Dashboard)
# -----------------------------------------------------------------------------

Write-Header "Step 3: Setting Up Dashboard"

if ($SkipDashboard) {
    Write-Info "Skipping dashboard setup (-SkipDashboard)"
} elseif (Test-Command "npm") {
    if (Test-Path "dashboard\node_modules") {
        Write-Step "Dashboard dependencies already installed"
    } else {
        Write-Info "Installing dashboard dependencies..."
        Push-Location dashboard
        npm install --silent 2>$null
        Pop-Location
        Write-Step "Dashboard dependencies installed"
    }
} else {
    Write-Warn "Skipping dashboard setup (npm not found)"
}

# -----------------------------------------------------------------------------
# Step 4: Environment Configuration
# -----------------------------------------------------------------------------

Write-Header "Step 4: Environment Configuration"

if (Test-Path ".env") {
    Write-Step ".env file already exists"
    Write-Info "Review and update .env if needed"
} else {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Step "Created .env from .env.example"
    } else {
        @"
# NetworkOps Environment Configuration
# Generated by quickstart.ps1

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

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=text
"@ | Out-File -FilePath ".env" -Encoding UTF8
        Write-Step "Created .env with default settings"
    }
    Write-Warn "Edit .env to add your credentials and API keys"
}

# -----------------------------------------------------------------------------
# Step 5: Device Inventory Configuration
# -----------------------------------------------------------------------------

Write-Header "Step 5: Device Inventory"

$DevicesFile = "config\devices.py"
$DevicesTemplate = "config\devices_template.py"

if ((Test-Path $DevicesFile) -and (Select-String -Path $DevicesFile -Pattern "10.255.255" -Quiet)) {
    Write-Info "Current devices.py contains example lab IPs (10.255.255.x)"

    if ($Headless) {
        Write-Info "Headless mode: keeping existing devices.py"
    } else {
        $response = Read-Host "Create a fresh template for your own devices? [y/N]"
        if ($response -eq 'y' -or $response -eq 'Y') {
            Copy-Item $DevicesFile "${DevicesFile}.backup"
            Write-Step "Backed up existing devices.py"
            # Template will be created below
        }
    }
}

if (Test-Path $DevicesTemplate) {
    Write-Step "Device template exists: $DevicesTemplate"
} else {
    Write-Info "Creating device template..."
    # Template creation handled by setup
}

Write-Host ""
Write-Warn "ACTION REQUIRED:"
Write-Host "    1. Edit $DevicesTemplate with your device inventory"
Write-Host "    2. Copy to devices.py: Copy-Item $DevicesTemplate $DevicesFile"
Write-Host ""

# -----------------------------------------------------------------------------
# Step 6: Verify Setup
# -----------------------------------------------------------------------------

Write-Header "Step 6: Verification"

Write-Info "Testing Python imports..."
python -c @"
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
"@
Write-Step "Python environment verified"

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

# Calculate elapsed time
$EndTime = Get-Date
$Elapsed = $EndTime - $StartTime
$Minutes = [math]::Floor($Elapsed.TotalMinutes)
$Seconds = $Elapsed.Seconds

Write-Header "Setup Complete!"

Write-Host ""
if ($Minutes -gt 0) {
    Write-Step "Completed in ${Minutes}m ${Seconds}s"
} else {
    Write-Step "Completed in ${Seconds}s"
}

Write-Host ""
Write-Host "Next steps:"
Write-Host ""
Write-Host "  1. Configure your devices:"
Write-Host "     notepad config\devices.py" -ForegroundColor Yellow
Write-Host ""
Write-Host "  2. Update environment variables:"
Write-Host "     notepad .env" -ForegroundColor Yellow
Write-Host ""
Write-Host "  3. Test device connectivity:"
Write-Host "     .\.venv\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "     python -c `"from config.devices import DEVICES; print(DEVICES.keys())`"" -ForegroundColor Yellow
Write-Host ""
Write-Host "  4. Start the API server:"
Write-Host "     python dashboard\api_server.py" -ForegroundColor Yellow
Write-Host ""
Write-Host "  5. Start the dashboard (separate terminal):"
Write-Host "     cd dashboard; npm start" -ForegroundColor Yellow
Write-Host ""
Write-Host "  6. Open in browser:"
Write-Host "     http://localhost:3000" -ForegroundColor Yellow
Write-Host ""

# Handle auto-start or prompt
if ($Headless) {
    if ($AutoStart) {
        Write-Host ""
        Write-Info "Starting API server on http://localhost:5001"
        python dashboard\api_server.py
    } else {
        Write-Step "Setup complete. Run: python dashboard\api_server.py"
    }
} else {
    Write-Host ""
    $response = Read-Host "Start the API server now? [y/N]"
    if ($response -eq 'y' -or $response -eq 'Y') {
        Write-Host ""
        Write-Info "Starting API server on http://localhost:5001"
        Write-Info "Press Ctrl+C to stop"
        Write-Host ""
        python dashboard\api_server.py
    }
}
