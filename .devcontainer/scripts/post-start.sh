#!/bin/bash
set -e

# Start Ghidra server if configured (non-empty = yes)
if [[ -n "${OFRAK_START_GHIDRA_SERVER}" ]]; then
    if python3 -c "import ofrak_ghidra" 2>/dev/null; then
        echo "Starting Ghidra server..."
        nohup python3 -m ofrak_ghidra.server start > /tmp/ghidra-server.log 2>&1 &
        sleep 2
        echo "Ghidra server started (log: /tmp/ghidra-server.log)"
    fi
fi

echo "To start the GUI: .devcontainer/scripts/start-gui.sh"
