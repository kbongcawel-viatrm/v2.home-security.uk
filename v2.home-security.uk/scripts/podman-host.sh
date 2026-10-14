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

# Find the project root (where containers-policy.json lives)
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
POLICY_FILE="$PROJECT_ROOT/containers-policy.json"

# Use our custom containers policy to allow local storage and our images
# This overrides the host's Secureblue default policy (which is too strict)
if [[ -r "$POLICY_FILE" ]]; then
    export CONTAINERS_POLICY_JSON="$POLICY_FILE"
    # Also set the storage policy path for older Podman versions
    export CONTAINERS_SIGNATURE_POLICY_PATH="$POLICY_FILE"
fi

# NOTE: Podman 5.x does not honor the CONTAINERS_* policy env vars above, so
# 'pull' passes the custom policy explicitly via --signature-policy (a hidden
# flag; it does not appear in 'podman pull --help'). Without it, the host's
# Secureblue default policy rejects pulls such as cr.fluentbit.io.
if [[ "${1:-}" == "pull" && -r "$POLICY_FILE" ]]; then
    set -- pull --signature-policy "$POLICY_FILE" "${@:2}"
fi

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
