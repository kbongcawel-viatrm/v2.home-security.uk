#!/usr/bin/env bash
# Runs a command in the Fedora host namespace. Inside a Toolbox container the
# command is delegated with flatpak-spawn --host; on the host it runs directly.
set -Eeuo pipefail
[[ $# -gt 0 ]] || { echo "Usage: $0 <command> [args...]" >&2; exit 2; }
if [[ -e /run/.toolboxenv ]]; then
  command -v flatpak-spawn >/dev/null || { echo "flatpak-spawn is required inside Toolbox." >&2; exit 1; }
  exec flatpak-spawn --host "$@"
fi
exec "$@"
