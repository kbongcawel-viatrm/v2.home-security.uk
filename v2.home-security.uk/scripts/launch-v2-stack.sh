#!/usr/bin/env bash
# Start this Compose stack and display live container/health-check progress.
set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/launch-v2-stack.sh [--timeout SECONDS] [--interval SECONDS]

Start the v2.home-security.uk Compose stack and wait for every service to be
running. Services with a Compose health check must also become healthy.
Services without a configured health check are reported as running (not as
health-checked). On timeout, the script prints Compose status and recent logs.

Options:
  --timeout SECONDS  Maximum wait after startup (default: 300)
  --interval SECONDS Poll interval (default: 2)
  -h, --help         Show this help
EOF
}

timeout_seconds=300
interval_seconds=2
while (($#)); do
    case "$1" in
        --timeout)
            (($# >= 2)) || { echo "Missing value for --timeout" >&2; exit 2; }
            timeout_seconds="$2"; shift 2 ;;
        --interval)
            (($# >= 2)) || { echo "Missing value for --interval" >&2; exit 2; }
            interval_seconds="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || { echo "Timeout must be a positive integer." >&2; exit 2; }
[[ "$interval_seconds" =~ ^[1-9][0-9]*$ ]] || { echo "Interval must be a positive integer." >&2; exit 2; }

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
compose_file="$project_dir/compose.yaml"
project_name="v2home-securityuk"
compose="$script_dir/podman-compose.sh"
podman="$script_dir/podman-host.sh"
services=(openobserve ollama fluent-bit security-ai ansible-ai)

[[ -r "$compose_file" ]] || { echo "Compose file not found: $compose_file" >&2; exit 1; }
[[ -x "$compose" && -x "$podman" ]] || { echo "Podman wrapper scripts are missing or not executable." >&2; exit 1; }

printf 'Starting Compose project %s...\n' "$project_name"
"$compose" -p "$project_name" -f "$compose_file" up -d

started_at=$SECONDS
while :; do
    ready=0
    details=()
    for service in "${services[@]}"; do
        # Compose declares a health check only for Ollama. Inspect state through
        # the host-aware Podman wrapper; empty/error means not yet created.
        state="$("$podman" inspect --format '{{.State.Status}}' "$service" 2>/dev/null || true)"
        health="$("$podman" inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$service" 2>/dev/null || true)"
        case "$state:$health" in
            running:healthy) details+=("$service: healthy"); ((ready+=1)) ;;
            running:none) details+=("$service: running (no health check)"); ((ready+=1)) ;;
            running:starting) details+=("$service: health check starting") ;;
            running:*) details+=("$service: $health") ;;
            *:*) details+=("$service: ${state:-starting}") ;;
        esac
    done

    elapsed=$((SECONDS - started_at))
    width=30
    filled=$((ready * width / ${#services[@]}))
    bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$((width - filled))" '' | tr ' ' '-')"
    printf '\r[%s] %d/%d ready (%ds elapsed)\n' "$bar" "$ready" "${#services[@]}" "$elapsed"
    printf '  %s\n' "${details[@]}"

    if ((ready == ${#services[@]})); then
        printf '\nAll services are running; configured health checks are healthy.\n'
        exit 0
    fi
    if ((elapsed >= timeout_seconds)); then
        printf '\nTimed out after %d seconds waiting for services.\n\nCompose status:\n' "$timeout_seconds" >&2
        "$compose" -p "$project_name" -f "$compose_file" ps >&2 || true
        printf '\nRecent logs:\n' >&2
        "$compose" -p "$project_name" -f "$compose_file" logs --tail=40 >&2 || true
        exit 1
    fi
    sleep "$interval_seconds"
done