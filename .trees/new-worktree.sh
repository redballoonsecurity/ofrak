#!/bin/bash
# Create and set up a new git worktree for OFRAK development
#
# Usage: source .trees/new-worktree.sh <branch-name> [remote]
#    or: .trees/new-worktree.sh <branch-name> [remote]
#
# This script:
#   1. Fetches from remote (default: origin)
#   2. Creates a worktree at .trees/<branch-name>, tracking <remote>/<branch-name> if it exists,
#      otherwise creating a new branch off <remote>/master
#   3. Creates a venv with --system-site-packages
#   4. Installs all packages in development mode (make develop)
#   5. Installs pre-commit hooks
#
# When sourced, on success (or if worktree already exists),
# this will cd to the worktree and activate the venv for you.

_ofrak_new_worktree() {
    local script_dir repo_root branch_name remote worktree_path

    script_dir="$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && /bin/pwd)"
    repo_root="$(dirname "$script_dir")"

    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        echo "Usage: ${BASH_SOURCE[0]} <branch-name> [remote]"
        echo "       source ${BASH_SOURCE[0]} <branch-name> [remote]"
        echo ""
        echo "Creates a new worktree at .trees/<branch-name> with a new branch"
        echo "off <remote>/master (or tracking <remote>/<branch-name> if it exists),"
        echo "sets up a Python venv, and editable-installs all OFRAK packages there."
        echo ""
        echo "When sourced:"
        echo "  - On success, automatically cd and activate the venv for you"
        echo "  - If worktree already exists, just cd and activate (skip setup)"
        echo ""
        echo "Arguments:"
        echo "  branch-name   Name for the new branch and worktree directory"
        echo "  remote        Remote to fetch from (default: origin)"
        return 0
    fi

    if [[ $# -lt 1 ]] || [[ $# -gt 2 ]]; then
        echo "Usage: [source] ${BASH_SOURCE[0]} <branch-name> [remote]  (use -h for help)"
        return 1
    fi

    branch_name="$1"
    remote="${2:-origin}"
    worktree_path="$repo_root/.trees/$branch_name"

    # Detect sourced vs executed: BASH_SOURCE[0] is script path, $0 is shell when sourced
    local is_sourced=0
    [[ "${BASH_SOURCE[0]}" != "$0" ]] && is_sourced=1

    # Track whether worktree already existed (for final message)
    local worktree_existed=0
    local tracking_info=""

    # If worktree already exists: error if executed, fall through to activation if sourced
    if [[ -d "$worktree_path" ]]; then
        worktree_existed=1
        if [[ "$is_sourced" != "1" ]]; then
            echo "Error: Worktree already exists at $worktree_path"
            echo "To activate: cd $worktree_path && source venv/bin/activate"
            return 1
        fi
        if [[ ! -f "$worktree_path/venv/bin/activate" ]]; then
            echo "Error: Worktree exists at $worktree_path but venv is missing or incomplete"
            return 1
        fi
        echo "Worktree already exists at $worktree_path - activating..."
        # Fall through to activation at end
    else
        # Run setup in a subshell so set -e doesn't leak
        # Use temp file to pass tracking_info back from subshell
        local tracking_info_file
        tracking_info_file=$(mktemp)

        (
            set -e

        cd "$repo_root"

        echo "=== Fetching from $remote ==="
        git fetch "$remote"

        echo ""
        # Check if local branch already exists
        if git show-ref --verify --quiet "refs/heads/$branch_name"; then
            echo "=== Creating worktree at $worktree_path (using existing branch $branch_name) ==="
            git worktree add "$worktree_path" "$branch_name"
            echo "Using existing branch: $branch_name" > "$tracking_info_file"
        # Check if <remote>/<branch-name> exists
        elif git rev-parse --verify "$remote/$branch_name" >/dev/null 2>&1; then
            echo "=== Creating worktree at $worktree_path (tracking $remote/$branch_name) ==="
            git worktree add --track -b "$branch_name" "$worktree_path" "$remote/$branch_name"
            echo "Tracking: $remote/$branch_name" > "$tracking_info_file"
        else
            echo "=== Creating worktree at $worktree_path (new branch off $remote/master) ==="
            git worktree add -b "$branch_name" "$worktree_path" "$remote/master"
            echo "New branch off $remote/master" > "$tracking_info_file"
        fi

        cd "$worktree_path"

        echo ""
        echo "=== Creating virtual environment with --system-site-packages ==="
        python3 -m venv --system-site-packages --prompt "$branch_name" venv

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
        cp "$repo_root/ofrak_core/src/ofrak/license/license.json" \
           "$worktree_path/ofrak_core/src/ofrak/license/license.json"
        )

        local setup_result=$?
        tracking_info=$(cat "$tracking_info_file" 2>/dev/null || true)
        rm -f "$tracking_info_file"

        if [[ $setup_result -ne 0 ]]; then
            echo "Setup failed"
            return $setup_result
        fi
    fi

    # Success - cd and activate in the calling shell (only when sourced)
    if [[ "$is_sourced" == "1" ]]; then
        if [[ ! -f "$worktree_path/venv/bin/activate" ]]; then
            echo "Error: Setup completed but venv is missing"
            return 1
        fi
        cd "$worktree_path" && source venv/bin/activate
    fi

    # Final summary (shared between new setup and existing worktree activation)
    local actual_branch upstream_branch
    actual_branch=$(git -C "$worktree_path" branch --show-current)
    upstream_branch=$(git -C "$worktree_path" rev-parse --abbrev-ref @{upstream} 2>/dev/null || true)

    echo ""
    echo "============================================================"
    if [[ "$worktree_existed" == "1" ]]; then
        echo "Worktree already exists"
    else
        echo "Worktree setup complete!"
    fi
    echo ""
    echo "  Path:     $worktree_path"
    echo "  Branch:   $actual_branch"
    if [[ -n "$tracking_info" ]]; then
        echo "  $tracking_info"
    elif [[ -n "$upstream_branch" ]]; then
        echo "  Tracking: $upstream_branch"
    fi
    if [[ "$worktree_existed" == "1" && "$actual_branch" != "$branch_name" ]]; then
        echo ""
        echo "  WARNING: Requested '$branch_name' but worktree is on '$actual_branch'"
    fi
    echo ""
    if [[ "$is_sourced" == "1" ]]; then
        echo "Activated this worktree for you; to re-enter it later:"
    else
        echo "To use this worktree:"
    fi
    echo "  cd $worktree_path && source venv/bin/activate"
    echo "============================================================"
}

_ofrak_new_worktree "$@"
