#!/usr/bin/env bash
# Capture a bounded, read-only snapshot of Podman and security-stack state.
set -u -o pipefail

log_dir="${XDG_STATE_HOME:-${HOME:?HOME must be set}/.local/state}/v2-home-security"
log_file="${BOOT_DIAGNOSTICS_LOG:-$log_dir/boot-diagnostics.log}"
mkdir -p -- "$(dirname -- "$log_file")" || exit 1
if [[ -f "$log_file" && "$(wc -c <"$log_file")" -ge 5242880 ]]; then
    mv -f -- "$log_file" "$log_file.1" || exit 1
fi
touch -- "$log_file" || exit 1
chmod 600 -- "$log_file" || exit 1

exec >>"$log_file" 2>&1
printf '\n===== boot diagnostics started %s =====\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
printf 'host=%s user=%s\n' "$(hostname)" "$(id -un)"

run_check() {
    local description="$1"
    shift
    printf '\n--- %s ---\n' "$description"
    if command -v "$1" >/dev/null 2>&1; then
        "$@"
        local result=$?
        printf '[exit=%s]\n' "$result"
        return 0
    fi
    printf '[not available: %s]\n' "$1"
}

sleep "${BOOT_DIAGNOSTICS_DELAY_SECONDS:-30}"
run_check 'Podman version and connection' podman version
run_check 'Container status' podman ps -a --no-trunc
for container in openobserve fluent-bit security-ai ollama; do
    run_check "$container log driver" podman inspect --format '{{.Name}} log={{.HostConfig.LogConfig.Type}}' "$container"
done
for container in fluent-bit security-ai; do
    run_check "$container logs (last 100 lines)" podman logs --tail 100 "$container"
done
run_check 'Suricata systemd status' systemctl --no-pager --full status suricata.service
printf '\n===== boot diagnostics finished %s =====\n' "$(date --iso-8601=seconds 2>/dev/null || date)"