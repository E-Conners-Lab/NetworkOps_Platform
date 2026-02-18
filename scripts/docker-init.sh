#!/usr/bin/env bash
# docker-init.sh — First-time setup for Docker deployment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_ROOT/.env"
ENV_EXAMPLE="$PROJECT_ROOT/.env.example"

echo "NetworkOps Docker Setup"
echo "======================="

# Check if .env already exists
if [[ -f "$ENV_FILE" ]]; then
    echo "✓ .env file already exists"
    echo "  Delete it and re-run to regenerate."
    exit 0
fi

# Copy from example
if [[ ! -f "$ENV_EXAMPLE" ]]; then
    echo "ERROR: .env.example not found at $ENV_EXAMPLE"
    exit 1
fi

cp "$ENV_EXAMPLE" "$ENV_FILE"
echo "✓ Created .env from .env.example"

# Generate JWT secrets
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
JWT_REFRESH_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)

# Replace placeholder values
if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' "s|JWT_SECRET=change-this-to-a-random-64-character-string|JWT_SECRET=$JWT_SECRET|" "$ENV_FILE"
else
    sed -i "s|JWT_SECRET=change-this-to-a-random-64-character-string|JWT_SECRET=$JWT_SECRET|" "$ENV_FILE"
fi

echo "✓ Generated JWT_SECRET"

# Generate MFA encryption key if cryptography is available
MFA_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || echo "")
if [[ -n "$MFA_KEY" ]]; then
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "s|MFA_ENCRYPTION_KEY=|MFA_ENCRYPTION_KEY=$MFA_KEY|" "$ENV_FILE"
    else
        sed -i "s|MFA_ENCRYPTION_KEY=|MFA_ENCRYPTION_KEY=$MFA_KEY|" "$ENV_FILE"
    fi
    echo "✓ Generated MFA_ENCRYPTION_KEY"
fi

echo ""
echo "Setup complete! Next steps:"
echo "  1. Edit .env with your device credentials"
echo "  2. Run: docker compose up"
echo "  3. Open: http://localhost:3000"
echo ""
echo "For demo mode (no network devices needed):"
echo "  DEMO_MODE=true docker compose up"
