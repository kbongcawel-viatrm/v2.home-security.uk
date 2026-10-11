#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/kill-v2-stack.sh [--purge] [--yes]

Stop and remove containers for this Compose project. Volumes are preserved by
default. --purge additionally deletes resources labeled as belonging to this
Compose project, including its historical Wazuh resources and Wazuh images.

Options:
  --purge  Permanently delete this project's labeled volumes and networks,
           plus Wazuh images (as well as current Compose-managed resources).
  --yes    Do not prompt for confirmation (required for non-interactive purge).
  -h, --help  Show this help.

Run from anywhere; the Compose file is resolved relative to this script.
This does not stop host-managed services such as Suricata, prune Podman globally,
or remove non-Wazuh images. Project-labeled historical Wazuh volumes are included
in --purge.
EOF
}

purge=false
assume_yes=false
for arg in "$@"; do
    case "$arg" in
        --purge) purge=true ;;
        --yes) assume_yes=true ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
compose_file="$project_dir/compose.yaml"
project_name="v2home-securityuk"

for command in podman podman-compose; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "Required command is not installed or not on PATH: $command" >&2
        exit 1
    }
done
[[ -r "$compose_file" ]] || { echo "Compose file not found: $compose_file" >&2; exit 1; }

# Refuse to operate on a similarly named but different Compose project.
if ! grep -Eq '^name:[[:space:]]*v2\.home-security\.uk[[:space:]]*$' "$compose_file"; then
    echo "Unexpected Compose project name in $compose_file; refusing cleanup." >&2
    exit 1
fi

if [[ "$purge" == true ]]; then
    cat <<'EOF'
WARNING: --purge permanently deletes this project's labeled volumes (including
OpenObserve data, Ollama models, Fluent Bit/AI state, and historical Wazuh data),
project networks, and locally stored Wazuh images. This cannot be undone.
EOF
else
    echo "This will stop/remove only containers in Compose project $project_name; named volumes will be preserved."
fi

if [[ "$assume_yes" != true ]]; then
    [[ -t 0 ]] || { echo "Refusing non-interactive cleanup without --yes." >&2; exit 2; }
    read -r -p "Type '$project_name' to continue: " confirmation
    [[ "$confirmation" == "$project_name" ]] || { echo "Cancelled."; exit 1; }
fi

cd "$project_dir"
if [[ "$purge" == true ]]; then
    podman-compose -p "$project_name" -f "$compose_file" down --volumes --remove-orphans

    # Remove any remaining containers and networks carrying this project's
    # canonical Compose label. This catches orphaned resources from old files.
    mapfile -t project_containers < <(podman ps -aq --filter "label=com.docker.compose.project=$project_name")
    if ((${#project_containers[@]})); then
        podman rm -f "${project_containers[@]}"
    fi
    mapfile -t project_networks < <(podman network ls -q --filter "label=com.docker.compose.project=$project_name")
    if ((${#project_networks[@]})); then
        podman network rm "${project_networks[@]}"
    fi

    # Old Compose versions did not always remove volumes for services no
    # longer declared. Require both the project label and a Wazuh name here.
    while IFS= read -r volume; do
        [[ -n "$volume" ]] || continue
        if [[ "$volume" == *wazuh* ]]; then
            podman volume rm "$volume"
        fi
    done < <(podman volume ls -q --filter "label=io.podman.compose.project=$project_name")

    # Remove only Wazuh repository images; leave shared OpenObserve, Ollama,
    # Fluent Bit, and local worker images untouched.
    mapfile -t wazuh_images < <(podman images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | awk '$1 ~ /(^|\/)wazuh([/:]|$)/ {print $2}' | sort -u)
    if ((${#wazuh_images[@]})); then
        podman rmi "${wazuh_images[@]}"
    fi
else
    podman-compose -p "$project_name" -f "$compose_file" down
fi

echo "Compose project $project_name stopped and removed."
if [[ "$purge" != true ]]; then
    echo "Named volumes and images were preserved. Re-run with --purge only if you intentionally want to delete project data and Wazuh images."
else
    echo "Project-labeled volumes/networks and available Wazuh repository images were removed."
fi