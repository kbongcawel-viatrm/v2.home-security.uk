#!/usr/bin/env bash
# Standalone podman-compose entry point. Delegates to the host-aware wrapper,
# which must execute outside Toolbox to use the host's rootless Podman storage.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/podman-compose-host.sh" "$@"