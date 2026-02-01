#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Rebuild frontend if --rebuild flag is passed
if [[ "$1" == "--rebuild" ]]; then
    echo "Rebuilding frontend..."
    rm -rf "$WORKSPACE/ofrak_core/src/ofrak/gui/public"
    cd "$WORKSPACE/frontend"
    npm install
    VERSION=$(python3 -c "exec(open('$WORKSPACE/ofrak_core/version.py').read()); print(VERSION)")
    VITE_OFRAK_VERSION="$VERSION" npm run build
    cp -r dist "$WORKSPACE/ofrak_core/src/ofrak/gui/public"
    echo "Frontend rebuilt."
fi

cd "$WORKSPACE"

# Load environment variables from .env (for OFRAK_DEFAULT_BACKEND)
if [[ -f "$SCRIPT_DIR/../.env" ]]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/../.env"
fi

# Build backend argument if specified
BACKEND_ARG=""
if [[ -n "${OFRAK_DEFAULT_BACKEND:-}" ]]; then
    BACKEND_ARG="--backend $OFRAK_DEFAULT_BACKEND"
    echo "Starting OFRAK GUI with backend: $OFRAK_DEFAULT_BACKEND"
else
    echo "Starting OFRAK GUI (no default backend specified)"
fi

# nginx listens on port 8080 (port updated in /etc/nginx config by Dockerfile.base)
# nginx proxies / to OFRAK API (8877) and /docs/ to mkdocs (8000)
sudo nginx 2>/dev/null || echo "nginx not available"
mkdocs serve --dev-addr 0.0.0.0:8000 &
python3 -m ofrak gui -H 0.0.0.0 -p 8877 --no-browser $BACKEND_ARG
