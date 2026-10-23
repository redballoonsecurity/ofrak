#!/usr/bin/env bash
# Capture Ghidra's auto-analysis of the A/B pair as Ghidra Zip Files (.gzf). The tests replay these
# captures through the real OFRAK Ghidra backend (GhidraProjectConfig) so that their results do not
# depend on Ghidra's run-to-run variance. Re-run after changing the binaries or upgrading Ghidra
# (the committed captures were made with Ghidra 11.3.2), then refresh the experiment reports.
#
# Usage: GHIDRA_INSTALL_DIR=/path/to/ghidra ./capture_ghidra_analysis.sh [OUTPUT_DIR]
set -euo pipefail

: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to the Ghidra installation directory}"
ASSET_DIR=$(realpath "$(dirname "$0")")
OUTPUT_DIR=$(realpath "${1:-$ASSET_DIR}")
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir "$WORK_DIR/project"

for binary in lua-gcc11-O2 lua-gcc15-O2; do
    rm -f "$OUTPUT_DIR/$binary.gzf"
    # Default auto-analysis, the same analysis the OFRAK Ghidra backend runs on an imported ELF.
    # The analyzed program is saved to the project after post-scripts run, and a program with
    # unsaved changes cannot be exported, so export it from a second, read-only invocation.
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$WORK_DIR/project" capture \
        -import "$ASSET_DIR/$binary"
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$WORK_DIR/project" capture \
        -process "$binary" -noanalysis -readOnly \
        -scriptPath "$ASSET_DIR" \
        -postScript ExportGzf.java "$OUTPUT_DIR/$binary.gzf"
    # analyzeHeadless exits successfully even when a script fails
    test -s "$OUTPUT_DIR/$binary.gzf"
done
