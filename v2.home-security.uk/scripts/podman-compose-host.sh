#!/usr/bin/env bash
# podman-compose wrapper that always runs on the HOST (not inside Toolbox)
# Uses 'podman compose' (built-in) instead of 'podman-compose' (standalone)
# because podman-compose is not installed on the host, but Docker Compose
# is available as a plugin for podman.
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
    # Use 'podman compose' (built-in) instead of 'podman-compose' (standalone)
    exec "$HOST_EXEC" podman compose "$@"
else
    # Not in Toolbox - try podman-compose first, fall back to podman compose
    if command -v podman-compose &>/dev/null; then
        exec podman-compose "$@"
    else
        exec podman compose "$@"
    fi
fi
