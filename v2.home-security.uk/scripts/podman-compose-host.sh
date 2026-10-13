#!/usr/bin/env bash
# podman-compose wrapper that always runs on the HOST (not inside Toolbox)
# Uses 'podman compose' (built-in) instead of 'podman-compose' (standalone)
# because podman-compose is not installed on the host, but Docker Compose
# is available as a plugin for podman.
#
# IMPORTANT: Docker Compose needs DOCKER_HOST to connect to Podman socket.
# We set DOCKER_HOST to the Podman socket path on the host.
#
# Usage:
#   ./scripts/podman-compose-host.sh -f compose.yaml up -d
#   ./scripts/podman-compose-host.sh -f compose.yaml ps

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_EXEC="$SCRIPT_DIR/host-exec.sh"

# Podman socket path on the host (for rootless user)
PODMAN_SOCKET="unix:///run/user/\$(id -u)/podman/podman.sock"

# Check if we're inside Toolbox
if [[ -e /run/.toolboxenv ]]; then
    # Inside Toolbox - run on host via host-exec.sh
    # Unset CONTAINER_HOST (Toolbox's socket) and set DOCKER_HOST (host's socket)
    # Use 'podman compose' (built-in) instead of 'podman-compose' (standalone)
    exec env -u CONTAINER_HOST DOCKER_HOST="$PODMAN_SOCKET" "$HOST_EXEC" podman compose "$@"
else
    # Not in Toolbox - try podman-compose first, fall back to podman compose
    if command -v podman-compose &>/dev/null; then
        exec podman-compose "$@"
    else
        export DOCKER_HOST="$PODMAN_SOCKET"
        exec podman compose "$@"
    fi
fi
