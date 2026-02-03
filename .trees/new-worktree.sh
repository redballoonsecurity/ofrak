#!/bin/bash
# Create and set up a new git worktree for OFRAK development
#
# Usage: ./new-worktree.sh <branch-name> [remote]
#
# This script:
#   1. Fetches from remote (default: origin)
#   2. Creates a worktree at .trees/<branch-name>, tracking <remote>/<branch-name> if it exists,
#      otherwise creating a new branch off <remote>/master
#   3. Creates a venv with --system-site-packages
#   4. Installs all packages in development mode (make develop)
#   5. Installs pre-commit hooks

set -e

SCRIPT_DIR="$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && /bin/pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

usage() {
    echo "Usage: $0 <branch-name> [remote]"
    echo ""
    echo "Creates a new worktree at .trees/<branch-name> with a new branch"
    echo "off <remote>/master (or tracking <remote>/<branch-name> if it exists),"
    echo "sets up a Python venv, and editable-installs all OFRAK packages there."
    echo ""
    echo "Arguments:"
    echo "  branch-name   Name for the new branch and worktree directory"
    echo "  remote        Remote to fetch from (default: origin)"
}

if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    usage
    exit 0
fi

if [[ $# -lt 1 ]] || [[ $# -gt 2 ]]; then
    usage
    exit 1
fi

BRANCH_NAME="$1"
REMOTE="${2:-origin}"
WORKTREE_PATH="$REPO_ROOT/.trees/$BRANCH_NAME"

# Check if worktree already exists
if [[ -d "$WORKTREE_PATH" ]]; then
    usage
    echo ""
    echo "Error: Worktree already exists at $WORKTREE_PATH"
    exit 1
fi

cd "$REPO_ROOT"

echo "=== Fetching from $REMOTE ==="
git fetch "$REMOTE"

echo ""
# Check if local branch already exists
if git show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
    echo "=== Creating worktree at $WORKTREE_PATH (using existing branch $BRANCH_NAME) ==="
    git worktree add "$WORKTREE_PATH" "$BRANCH_NAME"
    TRACKING_INFO="Using existing branch: $BRANCH_NAME"
# Check if <remote>/<branch-name> exists
elif git rev-parse --verify "$REMOTE/$BRANCH_NAME" >/dev/null 2>&1; then
    echo "=== Creating worktree at $WORKTREE_PATH (tracking $REMOTE/$BRANCH_NAME) ==="
    git worktree add --track -b "$BRANCH_NAME" "$WORKTREE_PATH" "$REMOTE/$BRANCH_NAME"
    TRACKING_INFO="Tracking: $REMOTE/$BRANCH_NAME"
else
    echo "=== Creating worktree at $WORKTREE_PATH (new branch off $REMOTE/master) ==="
    git worktree add -b "$BRANCH_NAME" "$WORKTREE_PATH" "$REMOTE/master"
    TRACKING_INFO="New branch off $REMOTE/master"
fi

cd "$WORKTREE_PATH"

echo ""
echo "=== Creating virtual environment with --system-site-packages ==="
python3 -m venv --system-site-packages --prompt "$BRANCH_NAME" venv

echo ""
echo "=== Activating virtual environment ==="
source venv/bin/activate

echo ""
echo "=== Installing OFRAK packages in development mode ==="
echo "    (This includes building the frontend GUI)"
make develop

echo ""
echo "=== Installing pre-commit hooks ==="
pre-commit install --install-hooks

echo ""
echo "=== Copying license from main repo ==="
cp "$REPO_ROOT/ofrak_core/src/ofrak/license/license.json" "$WORKTREE_PATH/ofrak_core/src/ofrak/license/license.json"

echo ""
echo "============================================================"
echo "Worktree setup complete!"
echo ""
echo "  Path:     $WORKTREE_PATH"
echo "  Branch:   $BRANCH_NAME"
echo "  $TRACKING_INFO"
echo ""
echo "To use this worktree:"
echo "  cd $WORKTREE_PATH"
echo "  source venv/bin/activate"
echo "============================================================"
