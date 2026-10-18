#!/usr/bin/env bash
set -uo pipefail

# Container Startup Manager
# Compatible with rootless Podman and podman-compose.

COMPOSE_FILE="${COMPOSE_FILE:-compose.yaml}"
APP_NAME="Home Security Stack"
TIMEOUT=120

# ANSI colors
RESET='\033[0m'
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'

if [[ ! -t 1 ]]; then
    RESET='' BOLD='' RED='' GREEN='' YELLOW=''
    BLUE='' CYAN='' MAGENTA='' GRAY=''
fi

log() {
    printf "${BLUE}[INFO]${RESET} %s\n" "$*"
}

success() {
    printf "${GREEN}[  OK ]${RESET} %s\n" "$*"
}

warn() {
    printf "${YELLOW}[WARN ]${RESET} %s\n" "$*"
}

error() {
    printf "${RED}[FAIL ]${RESET} %s\n" "$*"
}

line() {
    printf "${GRAY}────────────────────────────────────────────${RESET}\n"
}

check_dependencies() {
    local missing=0

    for cmd in podman podman-compose; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Missing dependency: $cmd"
            missing=1
        fi
    done

    if [[ ! -f "$COMPOSE_FILE" ]]; then
        error "Compose file not found: $COMPOSE_FILE"
        return 1
    fi

    (( missing == 0 ))
}

draw_progress() {
    local current="$1"
    local total="$2"
    local width=30
    local filled=$((current * width / total))
    local empty=$((width - filled))
    local percent=$((current * 100 / total))

    printf "\r${CYAN}["
    printf '%*s' "$filled" '' | tr ' ' '#'
    printf '%*s' "$empty" '' | tr ' ' '-'
    printf "]${RESET} %3d%%" "$percent"
}

show_banner() {
    clear 2>/dev/null || true

printf '\033[1;36m'
cat <<'EOF'
██╗  ██╗ ██████╗ ███╗   ███╗███████╗      ███████╗███████╗ ██████╗
██║  ██║██╔═══██╗████╗ ████║██╔════╝      ██╔════╝██╔════╝██╔════╝
███████║██║   ██║██╔████╔██║█████╗        ███████╗█████╗  ██║     
██╔══██║██║   ██║██║╚██╔╝██║██╔══╝        ╚════██║██╔══╝  ██║     
██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗      ███████║███████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝      ╚══════╝╚══════╝ ╚═════╝

by: kbongcawel(©)

EOF
    printf '\033[0m'
    printf "${RESET}"
    printf "${BOLD}%s${RESET}\n" "$APP_NAME"
    printf "${GRAY}Interactive Podman Compose Manager${RESET}\n"
    line
}

show_menu() {
    printf "\n${BOLD}Choose an action:${RESET}\n\n"
    printf "  ${GREEN}1${RESET}) Start \n"
    printf "  ${RED}2${RESET}) Shutdown \n"
    printf "  ${BLUE}3${RESET}) Restart \n"
    printf "  ${MAGENTA}4${RESET}) Pod Health \n"
    printf "  ${CYAN}5${RESET}) Pod Logs \n"
    printf "  ${YELLOW}6${RESET}) Memory+Health \n"
    printf "  ${GRAY}0${RESET}) Exit\n\n"
}

run_compose() {
    if [[ -x "$(dirname -- "${BASH_SOURCE[0]}")/podman-compose-host.sh" ]]; then
        "$(dirname -- "${BASH_SOURCE[0]}")/podman-compose-host.sh" -f "$COMPOSE_FILE" "$@" 2>/dev/null
    else
        podman-compose -f "$COMPOSE_FILE" "$@"
    fi
}

get_container_ids() {
    local output compose_status
    output=$(run_compose ps -q 2>/dev/null) || return $?
    printf '%s\n' "$output" | awk 'NF && $0 ~ /^[[:xdigit:]]+$/ { print }'

    inspect_container '{{.Id}}' openobserve-health 2>/dev/null || \
        inspect_container '{{.Id}}' openobserve_health 2>/dev/null || true
}

inspect_container() {
    local format="$1" container="$2"

    if [[ -x "$(dirname -- "${BASH_SOURCE[0]}")/podman-host.sh" ]]; then
        "$(dirname -- "${BASH_SOURCE[0]}")/podman-host.sh" inspect --format "$format" "$container"
    else
        podman inspect --format "$format" "$container"
    fi
}

show_status() {
    local ids id name state health result health_container_found=0

    line
    printf "${BOLD}${CYAN}HOME-SEC CONTAINER STATUS${RESET}\n\n"

    mapfile -t ids < <(get_container_ids | awk 'NF && !seen[$0]++')

    if (( ${#ids[@]} == 0 )); then
        warn "No containers found for this Compose project."
        line
        return 0
    fi

    for id in "${ids[@]}"; do
        result=$(inspect_container \
            '{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' \
            "$id" 2>/dev/null) || result="unknown|missing|unknown"

        IFS='|' read -r name state health <<< "$result"
        name="${name#/}"
        if [[ "$name" == "openobserve-health" || "$name" == "openobserve_health" ]]; then
            health_container_found=1
        fi

        case "$state:$health" in
            running:healthy|running:no-healthcheck)
                printf " ${GREEN}●${RESET} %-24s ${GREEN}%-12s${RESET} %s\n" \
                    "$name" "$state" "$health"
                ;;
            running:*)
                printf " ${YELLOW}◉${RESET} %-24s ${YELLOW}%-12s${RESET} %s\n" \
                    "$name" "$state" "$health"
                ;;
            *)
                printf " ${RED}✖${RESET} %-24s ${RED}%-12s${RESET} %s\n" \
                    "$name" "$state" "$health"
                ;;
        esac
    done

    if (( health_container_found == 0 )); then
        printf " ${RED}✖${RESET} %-24s ${RED}%-12s${RESET} %s\n" \
            "openobserve-health" "missing" "not created"
    fi

    line
}

wait_for_containers() {
    local ids=()
    local id state health result
    local elapsed=0
    local total=0
    local ready=0
    local failed=0
    local pending=0

    mapfile -t ids < <(get_container_ids | awk 'NF && !seen[$0]++')

    total=${#ids[@]}

    if (( total == 0 )); then
        warn "No container IDs returned by podman-compose."
        show_status
        return 1
    fi

    log "Waiting for $total container(s), timeout: ${TIMEOUT}s"

    while (( elapsed < TIMEOUT )); do
        ready=0
        failed=0
        pending=0

        for id in "${ids[@]}"; do
            result=$(inspect_container \
                '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
                "$id" 2>/dev/null) || result="missing|none"

            IFS='|' read -r state health <<< "$result"

            case "$state:$health" in
                running:healthy|running:none)
                    ((ready += 1))
                    ;;
                running:unhealthy|exited:*|stopped:*|dead:*|missing:*)
                    ((failed += 1))
                    ;;
                *)
                    ((pending += 1))
                    ;;
            esac
        done

        draw_progress "$ready" "$total"
        printf "  ${GREEN}%s ready${RESET}, ${YELLOW}%s pending${RESET}, ${RED}%s failed${RESET}" \
            "$ready" "$pending" "$failed"

        if (( ready + failed == total )); then
            printf "\n"
            break
        fi

        sleep 1
        ((elapsed += 1))
    done

    printf "\n\n"
    show_status

    if (( failed > 0 )); then
        error "$failed container(s) failed or became unhealthy."
        warn "Check logs using option 5 or: podman-compose -f '$COMPOSE_FILE' logs"
        return 1
    elif (( ready == total )); then
        success "All $total containers are running."
        return 0
    else
        warn "Timed out waiting for containers. Review their status and logs."
        return 1
    fi
}


# HOME-SEC animated terminal UI

SPINNER_FRAMES=('◐' '◓' '◑' '◒')
BAR_FRAMES=('━' '━' '━' '━' '━')
TICK=0

animate_command() {
    local message="$1"
    shift

    local logfile rc=0 ticks=0
    local width=24
    local position=0 direction=1
    local filled bar elapsed

    logfile=$(mktemp) || {
        error "Could not create temporary log file."
        return 1
    }

    printf "\n${CYAN}${BOLD}◉ %s${RESET}\n" "$message"

    # Non-interactive output: do not animate.
    if [[ ! -t 1 ]]; then
        "$@" >"$logfile" 2>&1 || rc=$?
        if (( rc != 0 )); then
            error "$message failed."
            cat "$logfile"
        else
            success "$message completed."
        fi
        rm -f "$logfile"
        return "$rc"
    fi

    "$@" >"$logfile" 2>&1 &
    local pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        position=$((position + direction))
        if (( position >= width - 5 )); then
            position=$((width - 5))
            direction=-1
        elif (( position <= 0 )); then
            position=0
            direction=1
        fi

        printf -v elapsed '%d.%d' "$((ticks / 10))" "$((ticks % 10))"

        printf "\r${MAGENTA}%s${RESET} ${BOLD}%-28s${RESET} [" \
            "${SPINNER_FRAMES[ticks % ${#SPINNER_FRAMES[@]}]}" "$message"

        for ((i = 0; i < width; i++)); do
            if (( i >= position && i < position + 5 )); then
                printf "${CYAN}●${RESET}"
            else
                printf "${GRAY}·${RESET}"
            fi
        done

        printf "] ${YELLOW}%ss${RESET}" "$elapsed"

        sleep 0.1
        ((ticks += 1))
    done

    wait "$pid" || rc=$?
    printf "\r\033[K"

    if (( rc == 0 )); then
        success "$message completed in ${elapsed}s."
    else
        error "$message failed."
        printf "${GRAY}Command output:${RESET}\n"
        cat "$logfile"
    fi

    rm -f "$logfile"
    return "$rc"
}

# HOME-SEC animated terminal UI

SPINNER_FRAMES=('◐' '◓' '◑' '◒')
BAR_FRAMES=('━' '━' '━' '━' '━')
TICK=0

animate_command() {
    local message="$1"
    shift

    local logfile rc=0 ticks=0
    local width=24
    local position=0 direction=1
    local filled bar elapsed

    logfile=$(mktemp) || {
        error "Could not create temporary log file."
        return 1
    }

    printf "\n${CYAN}${BOLD}◉ %s${RESET}\n" "$message"

    # Non-interactive output: do not animate.
    if [[ ! -t 1 ]]; then
        "$@" >"$logfile" 2>&1 || rc=$?
        if (( rc != 0 )); then
            error "$message failed."
            cat "$logfile"
        else
            success "$message completed."
        fi
        rm -f "$logfile"
        return "$rc"
    fi

    "$@" >"$logfile" 2>&1 &
    local pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        position=$((position + direction))
        if (( position >= width - 5 )); then
            position=$((width - 5))
            direction=-1
        elif (( position <= 0 )); then
            position=0
            direction=1
        fi

        printf -v elapsed '%d.%d' "$((ticks / 10))" "$((ticks % 10))"

        printf "\r${MAGENTA}%s${RESET} ${BOLD}%-28s${RESET} [" \
            "${SPINNER_FRAMES[ticks % ${#SPINNER_FRAMES[@]}]}" "$message"

        for ((i = 0; i < width; i++)); do
            if (( i >= position && i < position + 5 )); then
                printf "${CYAN}●${RESET}"
            else
                printf "${GRAY}·${RESET}"
            fi
        done

        printf "] ${YELLOW}%ss${RESET}" "$elapsed"

        sleep 0.1
        ((ticks += 1))
    done

    wait "$pid" || rc=$?
    printf "\r\033[K"

    if (( rc == 0 )); then
        success "$message completed in ${elapsed}s."
    else
        error "$message failed."
        printf "${GRAY}Command output:${RESET}\n"
        cat "$logfile"
    fi

    rm -f "$logfile"
    return "$rc"
}

start_stack() {
    local mode="$1"

    line

    case "$mode" in
        recreate)
            animate_command "Force-recreating containers" \
                echo "Shutting down containers" && run_compose down --remove-orphans && echo "Re-creating containers" run_compose up -d --force-recreate || {
                show_status
                return 1
            }
            ;;
        restart)
            animate_command "Restarting containers" \
                run_compose restart || {
                show_status
                return 1
            }
            ;;
        start)
            animate_command "Starting HOME-SEC stack" \
                run_compose up -d || {
                show_status
                return 1
            }
            ;;
        *)
            error "Unknown startup mode: $mode"
            return 1
            ;;
    esac

    wait_for_containers
}

get_memory() {
animate_command "HOME-SEC CONTAINER MEMORY USAGE"
echo
podman inspect --format '{{.Name}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}|{{.HostConfig.Memory}}' \
  ollama fluent-bit prometheus openobserve openobserve-health security-ai ansible-ai |
while IFS='|' read -r name health memory; do
    mib=$((memory / 1024 / 1024))
    [[ "$memory" -eq 0 ]] && mib="unlimited"
    printf '%-25s | %-18s | %s MiB\n' "$name" "$health" "$mib"
done

}

pause() {
    printf "\nPress Enter to continue..."
    read -r _
}

main() {
    local choice

    check_dependencies || exit 1

    while true; do
        show_banner
        show_menu

        read -r -p "$(printf "${CYAN}Select option [0-6]: ${RESET}")" choice

        case "$choice" in
            1)
                start_stack start
                pause
                ;;
            2)
		read -r -p "Stop all project containers? [y/N]: " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    run_compose down
                else
                    warn "Stop operation cancelled."
                fi
                pause
                ;;
            3)
                start_stack restart
                pause
                ;;
            4)
                show_status
                pause
                ;;
            5)
                log "Following container logs. Press Ctrl+C to stop viewing."
                run_compose logs -f
                pause
                ;;
            6)
		get_memory
                pause
                ;;
                
            0)
                success "Exiting container manager."
                exit 0
                ;;
            *)
                error "Invalid option."
                sleep 1
                ;;
        esac
    done
}

main "$@"
