#!/usr/bin/env bash
#
# HSYNC Rendezvous - Docker Management Script
# Unified script for Docker operations: build, start, stop, restart, logs, etc.
#
# Usage: ./docker.sh <command> [options]
#
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repository root: build context must include the sibling ../hsync-common package
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly IMAGE_NAME="hsync-rendezvous"
readonly IMAGE_TAG="${HSYNC_VERSION:-1.0.0}"
readonly CONTAINER_NAME="hsync-rendezvous"
# The container always binds this unprivileged port (the image runs as a
# non-root user); the host's public QUIC and TLS/TCP ports are mapped to it.
readonly CONTAINER_PORT="8443"
# Host port clients connect to (UDP and TCP).
RENDEZVOUS_HOST_PORT="${RENDEZVOUS_HOST_PORT:-443}"
# Host directory holding the persistent TLS identity and the readiness PID.
_DATA_DIR_RAW="${HSYNC_RENDEZVOUS_DATA_DIR:-${SCRIPT_DIR}/hsync-data}"
if [[ "${_DATA_DIR_RAW}" = /* ]]; then
    readonly DATA_DIR="${_DATA_DIR_RAW%/}"
else
    readonly DATA_DIR="${SCRIPT_DIR}/${_DATA_DIR_RAW%/}"
fi
unset _DATA_DIR_RAW
readonly READY_FILE="${DATA_DIR}/ready.pid"
# Optional protected-bucket group keys file on the HOST (mounted read-only at
# /keys and opened there as fd 3; never copied into the image). The
# in-container descriptor source is the separate HSYNC_RENDEZVOUS_KEYS_FILE=/keys,
# matching compose.yaml / install.sh.
HSYNC_RENDEZVOUS_KEYS_PATH="${HSYNC_RENDEZVOUS_KEYS_PATH:-}"
# Seconds to wait for the readiness PID file before declaring the start failed.
STARTUP_READY_TIMEOUT="${HSYNC_RENDEZVOUS_STARTUP_TIMEOUT:-30}"

# -----------------------------------------------------------------------------
# Colors (disabled if not a terminal)
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    readonly RED=$'\033[0;31m'
    readonly GREEN=$'\033[0;32m'
    readonly YELLOW=$'\033[0;33m'
    readonly BLUE=$'\033[0;34m'
    readonly CYAN=$'\033[0;36m'
    readonly BOLD=$'\033[1m'
    readonly RESET=$'\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' RESET=''
fi

log_info()  { printf '%s\n' "${BLUE}i${RESET} $*"; }
log_ok()    { printf '%s\n' "${GREEN}✓${RESET} $*"; }
log_warn()  { printf '%s\n' "${YELLOW}!${RESET} $*"; }
log_error() { printf '%s\n' "${RED}✕${RESET} $*" >&2; }
log_step()  { printf '%s\n' "${CYAN}→${RESET} ${BOLD}$*${RESET}"; }

show_help() {
    cat << EOF
${BOLD}HSYNC Rendezvous - Docker Management${RESET}

${BOLD}Usage:${RESET} ./docker.sh <command> [options]

${BOLD}Commands:${RESET}
    build       Build the Docker image
    start       Start the container
    stop        Stop the container
    restart     Restart the container
    status      Show container status
    logs        Show container logs (use -f to follow)
    shell       Open a shell in the running container
    clean       Remove container and image (add --all to also drop the identity)

${BOLD}Options:${RESET}
    -f, --follow    Follow log output (for logs command)
    -h, --help      Show this help message

${BOLD}Environment Variables:${RESET}
    RENDEZVOUS_HOST_PORT             Host UDP/TCP port clients connect to (default: 443)
    HSYNC_RENDEZVOUS_PRIVATE       Set to 1 for a private node (every frame needs a token)
    HSYNC_RENDEZVOUS_KEYS_PATH     Host path of the group-keys file (mounted at /keys, opened as fd 3)
    HSYNC_RENDEZVOUS_DEBUG         Set to 1 for the full operation log (peer identity included)
    HSYNC_RENDEZVOUS_DATA_DIR      Host identity directory (default: ./hsync-data)
    HSYNC_VERSION                Image tag version (default: 1.0.0)

${BOLD}Examples:${RESET}
    ./docker.sh build
    ./docker.sh start
    HSYNC_RENDEZVOUS_PRIVATE=1 HSYNC_RENDEZVOUS_KEYS_PATH=./group-keys ./docker.sh start
    ./docker.sh logs -f

The container binds ${CONTAINER_PORT} internally (UDP and TCP); the host maps
RENDEZVOUS_HOST_PORT to it. The persistent TLS identity lives on the host under
${DATA_DIR}; back it up to keep the certificate fingerprint stable across hosts.
EOF
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
ensure_data_dir() {
    if [[ ! -d "${DATA_DIR}" ]]; then
        mkdir -p "${DATA_DIR}"
        log_info "Created identity directory: ${DATA_DIR}"
    fi
}

wait_for_ready() {
    local deadline=$(( $(date +%s) + STARTUP_READY_TIMEOUT ))
    while (( $(date +%s) < deadline )); do
        [[ -s "${READY_FILE}" ]] && return 0
        sleep 1
    done
    return 1
}

cmd_build() {
    log_step "Building Docker image ${IMAGE_NAME}:${IMAGE_TAG}..."
    docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" -f "${SCRIPT_DIR}/Dockerfile" "${REPO_ROOT}"
    log_ok "Image built: ${IMAGE_NAME}:${IMAGE_TAG}"
}

cmd_start() {
    if docker ps -q -f name="${CONTAINER_NAME}" | grep -q .; then
        log_warn "Container ${CONTAINER_NAME} is already running"
        return
    fi

    log_step "Starting container ${CONTAINER_NAME}..."
    ensure_data_dir

    local docker_args=(
        run -d
        --name "${CONTAINER_NAME}"
        --restart unless-stopped
        --read-only
        --tmpfs /tmp
        -p "${RENDEZVOUS_HOST_PORT}:${CONTAINER_PORT}/udp"
        -p "${RENDEZVOUS_HOST_PORT}:${CONTAINER_PORT}/tcp"
        # Run under the invoking user's ids so the bind-mounted identity
        # directory stays writable (created above as the same user).
        --user "${HSYNC_UID:-$(id -u)}:${HSYNC_GID:-$(id -g)}"
        -v "${DATA_DIR}:/var/lib/hsync-rendezvous"
    )

    if [[ -n "${HSYNC_RENDEZVOUS_PRIVATE:-}" ]]; then
        docker_args+=(-e "HSYNC_RENDEZVOUS_PRIVATE=${HSYNC_RENDEZVOUS_PRIVATE}")
    fi
    if [[ -n "${HSYNC_RENDEZVOUS_DEBUG:-}" ]]; then
        docker_args+=(-e "HSYNC_RENDEZVOUS_DEBUG=${HSYNC_RENDEZVOUS_DEBUG}")
    fi
    if [[ -n "${HSYNC_RENDEZVOUS_KEYS_PATH}" ]]; then
        if [[ ! -f "${HSYNC_RENDEZVOUS_KEYS_PATH}" ]]; then
            log_error "Group keys file not found: ${HSYNC_RENDEZVOUS_KEYS_PATH}"
            exit 1
        fi
        docker_args+=(
            -v "${HSYNC_RENDEZVOUS_KEYS_PATH}:/keys:ro"
            -e "HSYNC_RENDEZVOUS_KEYS_FILE=/keys"
        )
    fi

    rm -f "${READY_FILE}"
    docker "${docker_args[@]}" "${IMAGE_NAME}:${IMAGE_TAG}" \
        run --listen-host 0.0.0.0 --listen-port "${CONTAINER_PORT}"

    log_info "Host port: ${RENDEZVOUS_HOST_PORT}/udp+tcp → container ${CONTAINER_PORT}"
    log_info "Identity:  ${DATA_DIR}"

    if [[ "${STARTUP_READY_TIMEOUT}" =~ ^[0-9]+$ ]] && (( STARTUP_READY_TIMEOUT > 0 )); then
        log_step "Waiting for the listener (up to ${STARTUP_READY_TIMEOUT}s)..."
        if ! wait_for_ready; then
            log_error "The node did not report readiness within ${STARTUP_READY_TIMEOUT}s"
            log_error "Last container logs:"
            docker logs --tail 30 "${CONTAINER_NAME}" >&2 || true
            exit 1
        fi
        log_ok "HSYNC rendezvous is live → udp+tcp/${RENDEZVOUS_HOST_PORT}"
    else
        log_info "Readiness check skipped (HSYNC_RENDEZVOUS_STARTUP_TIMEOUT=0)"
    fi
    if [[ "${HSYNC_RENDEZVOUS_PRIVATE:-}" == "1" ]]; then
        log_warn "Private node: every frame requires a valid bucket_token"
    fi
}

cmd_stop() {
    log_step "Stopping container ${CONTAINER_NAME}..."
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    log_ok "Container stopped"
}

cmd_restart() {
    cmd_stop
    cmd_start
}

cmd_status() {
    printf '%s\n' "${BOLD}Container Status:${RESET}"
    docker ps -a --filter name="${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

cmd_logs() {
    local follow=""
    [[ "${1:-}" == "-f" || "${1:-}" == "--follow" ]] && follow="-f"
    docker logs ${follow} "${CONTAINER_NAME}"
}

cmd_shell() {
    log_step "Opening shell in ${CONTAINER_NAME}..."
    docker exec -it "${CONTAINER_NAME}" /bin/sh
}

cmd_clean() {
    local clean_all=0
    [[ "${1:-}" == "--all" ]] && clean_all=1
    log_step "Cleaning up..."
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    docker rmi "${IMAGE_NAME}:${IMAGE_TAG}" 2>/dev/null || true
    if (( clean_all )); then
        log_warn "Removing ${DATA_DIR} (the persistent TLS identity will be lost)"
        rm -rf "${DATA_DIR}"
    else
        log_info "Keeping ${DATA_DIR} (use 'clean --all' to drop the identity)"
    fi
    log_ok "Cleanup complete"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    cd "${SCRIPT_DIR}"

    case "${1:-}" in
        build)   cmd_build ;;
        start)   cmd_start ;;
        stop)    cmd_stop ;;
        restart) cmd_restart ;;
        status)  cmd_status ;;
        logs)    cmd_logs "${2:-}" ;;
        shell)   cmd_shell ;;
        clean)   cmd_clean "${2:-}" ;;
        -h|--help|help|"") show_help ;;
        *) log_error "Unknown command: $1"; show_help; exit 1 ;;
    esac
}

main "$@"
