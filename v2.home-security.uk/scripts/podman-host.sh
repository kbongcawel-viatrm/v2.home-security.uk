#!/usr/bin/env bash
# Podman wrapper that always runs on the HOST (not inside Toolbox)
# This completely eliminates the nested user namespace issue
#
# Usage:
#   ./scripts/podman-host.sh info
#   ./scripts/podman-host.sh ps
#   ./scripts/podman-host.sh compose up -d
#
# This is a drop-in replacement for 'podman' that works inside Toolbox

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_EXEC="$SCRIPT_DIR/host-exec.sh"

# Check if we're inside Toolbox
if [[ -e /run/.toolboxenv ]]; then
    # Inside Toolbox - run on host via host-exec.sh
    # IMPORTANT: Unset CONTAINER_HOST so Podman uses the host's default socket
    # (CONTAINER_HOST points to Toolbox's socket which doesn't exist on host)
    exec env -u CONTAINER_HOST "$HOST_EXEC" podman "$@"
else
    # Not in Toolbox - run directly
    exec podman "$@"
fi
