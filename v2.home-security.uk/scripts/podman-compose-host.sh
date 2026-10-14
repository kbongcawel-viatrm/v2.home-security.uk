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

# Find the project root (where containers-policy.json lives)
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
POLICY_FILE="$PROJECT_ROOT/containers-policy.json"

# Use our custom containers policy to allow local storage and our images
# This overrides the host's Secureblue default policy (which is too strict)
# NOTE: Podman 5.x ignores these env vars for pulls made through
# 'podman compose' (the API service still applies the host policy), so we
# pre-pull missing images below with 'podman pull --signature-policy',
# which is the flag that actually works.
if [[ -r "$POLICY_FILE" ]]; then
    export CONTAINERS_POLICY_JSON="$POLICY_FILE"
    # Also set the storage policy path for older Podman versions
    export CONTAINERS_SIGNATURE_POLICY_PATH="$POLICY_FILE"
fi

# Podman socket path on the host (for rootless user)
PODMAN_SOCKET="unix:///run/user/$(id -u)/podman/podman.sock"

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
