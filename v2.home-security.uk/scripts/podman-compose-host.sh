#!/usr/bin/env bash
# podman-compose wrapper that always runs on the HOST (not inside Toolbox)
# Uses the standalone podman-compose executable on the host. It must be
# installed on the host because Toolbox commands are delegated there.
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
# NOTE: The policy environment variables are retained for Podman operations
# performed by this wrapper/provider.
if [[ -r "$POLICY_FILE" ]]; then
    export CONTAINERS_POLICY_JSON="$POLICY_FILE"
    # Also set the storage policy path for older Podman versions
    export CONTAINERS_SIGNATURE_POLICY_PATH="$POLICY_FILE"
fi

run_podman_compose() {
    local executable
    executable="$(command -v podman-compose || true)"
    if [[ -z "$executable" ]]; then
        echo "Error: podman-compose is not installed on the host." >&2
        echo "Install the standalone podman-compose package on the host, then retry." >&2
        exit 127
    fi
    exec "$executable" "$@"
}

# Check if we're inside Toolbox
if [[ -e /run/.toolboxenv ]]; then
    # Resolve and run podman-compose on the host, not inside Toolbox.
    exec env -u CONTAINER_HOST "$HOST_EXEC" bash -lc '
        executable="$(command -v podman-compose || true)"
        if [[ -z "$executable" ]]; then
            echo "Error: podman-compose is not installed on the host." >&2
            echo "Install the standalone podman-compose package on the host, then retry." >&2
            exit 127
        fi
        exec "$executable" "$@"
    ' podman-compose "$@"
else
    run_podman_compose "$@"
fi
