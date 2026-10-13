#!/usr/bin/env bash
# podman-compose wrapper that always runs on the HOST (not inside Toolbox)
# This completely eliminates the nested user namespace issue
#
# Usage:
#   ./scripts/podman-compose-host.sh -f compose.yaml up -d
#   ./scripts/podman-compose-host.sh -f compose.yaml ps

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_EXEC="$SCRIPT_DIR/host-exec.sh"

# Check if we're inside Toolbox
if [[ -e /run/.toolboxenv ]]; then
    # Inside Toolbox - run on host via host-exec.sh
    exec "$HOST_EXEC" podman-compose "$@"
else
    # Not in Toolbox - run directly
    exec podman-compose "$@"
fi
