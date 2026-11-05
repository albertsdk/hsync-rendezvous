#!/usr/bin/env bash

set -euo pipefail

readonly DEFAULT_VERSION="v1.0.0"
readonly DEFAULT_INSTALL_DIR="${HOME}/.local/share/hsync-rendezvous"
readonly REPO="albertsdk/hsync-rendezvous"
readonly IMAGE_REPO="ghcr.io/albertsdk/hsync-rendezvous"
# The Sigstore identity this installer trusts: the release workflow that signs
# the image, authenticated through GitHub Actions OIDC. Both a tag push and a
# manual dispatch match.
readonly COSIGN_IDENTITY_REGEXP='^https://github\.com/albertsdk/hsync-rendezvous/\.github/workflows/release\.yml@refs/(heads|tags)/.*$'
readonly COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
# The container always binds this unprivileged port (UDP and TCP); the host maps
# RENDEZVOUS_HOST_PORT to it.
readonly CONTAINER_PORT="8443"

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
VERSION="${DEFAULT_VERSION}"
PUBLIC_PORT="443"
PUBLIC_PORT_SET=false
INSTALL_DIR_EXPLICIT=false
PRIVATE=false
KEYS_FILE=""
START_SERVER=true
DRY_RUN=false
VERIFY=true
IMAGE_DIGEST=""
# Resolved from --version/--image-digest in main() and written to .env.
IMAGE_REF=""

usage() {
    cat <<EOF
Install the HSYNC rendezvous with Docker Compose.

Usage: ./install.sh [options]

When installing from the release download, forward options to bash (not curl):
  curl -fsSL "https://github.com/${REPO}/releases/latest/download/install.sh" | bash -s -- [options]

Options:
  --version VERSION       Image version to install, or 'latest' to resolve the
                          latest stable release automatically (default: ${DEFAULT_VERSION})
  --install-dir PATH      Configuration directory
  --public-port PORT      Host UDP port clients connect to (default: 443)
  --private               Run a private node: every frame requires a bucket token
  --keys-file PATH        Group-keys file for protected buckets / private mode
  --image-digest DIGEST   Pin an exact image digest (sha256:…) instead of a tag
  --no-verify             Skip the container image signature verification
  --no-start              Generate and validate files without starting the node
  --dry-run               Show the planned configuration without changing files
  -h, --help              Show this help

By default the installer verifies the container image's Sigstore signature
before starting the node (keyless, signed by the release workflow). This needs
the 'cosign' tool on PATH: when it is missing, the installer prints the install
command for your platform and stops before writing any file. Pass --no-verify
to install without the check.

The installer never installs Docker, invokes sudo, opens firewall ports, or
overwrites an existing partial installation. Re-running it updates the selected
image version while preserving the existing TLS identity.
EOF
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    local name="$1"
    if ! command -v "${name}" >/dev/null 2>&1; then
        print_tool_hint "${name}"
        fail "required command not found: ${name}"
    fi
}

# --- Prerequisite guidance --------------------------------------------------
#
# The installer never installs Docker and never runs sudo: when a prerequisite
# is missing it prints the commands and URLs for the user to run themselves, then
# fails with the same error line as before. Guidance is best-effort per platform
# and always backed by the canonical Docker documentation links.

# linux | macos | windows-shell | unknown
detect_platform_os() {
    case "$(uname -s)" in
        Linux) printf 'linux' ;;
        Darwin) printf 'macos' ;;
        MINGW* | MSYS* | CYGWIN* | Windows_NT) printf 'windows-shell' ;;
        *) printf 'unknown' ;;
    esac
}

# debian | rhel | arch | suse | alpine | unknown
detect_linux_family() {
    local id="" id_like="" key value
    if [[ -r /etc/os-release ]]; then
        while IFS='=' read -r key value; do
            value="${value%\"}"
            value="${value#\"}"
            case "${key}" in
                ID) id="${value}" ;;
                ID_LIKE) id_like="${value}" ;;
            esac
        done < /etc/os-release
    fi
    case " ${id} ${id_like} " in
        *" debian "* | *" ubuntu "*) printf 'debian' ;;
        *" rhel "* | *" fedora "* | *" centos "*) printf 'rhel' ;;
        *" arch "*) printf 'arch' ;;
        *" suse "* | *" opensuse "*) printf 'suse' ;;
        *" alpine "*) printf 'alpine' ;;
        *) printf 'unknown' ;;
    esac
}

print_docker_docs() {
    printf '  Docs: https://docs.docker.com/engine/install/\n' >&2
    printf '        https://docs.docker.com/compose/install/\n' >&2
    printf '        https://docs.docker.com/engine/install/linux-postinstall/\n' >&2
}

print_docker_install_hint() {
    local os family
    os="$(detect_platform_os)"
    family="$(detect_linux_family)"
    printf '\nDocker Engine (or Docker Desktop) with the Compose v2 plugin is required.\n' >&2
    case "${os}" in
        macos)
            printf 'Install Docker Desktop:\n' >&2
            printf '  brew install --cask docker\n' >&2
            printf 'Or a lightweight alternative:\n' >&2
            printf '  brew install colima docker docker-compose && colima start\n' >&2
            ;;
        windows-shell)
            printf 'Use Docker Desktop for Windows with the WSL2 backend and enable WSL\n' >&2
            printf 'integration for this distribution:\n' >&2
            printf '  https://docs.docker.com/desktop/install/windows-install/\n' >&2
            ;;
        linux)
            case "${family}" in
                debian)
                    printf 'Example (Debian/Ubuntu):\n' >&2
                    printf '  sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2\n' >&2
                    printf 'Or the official convenience script: https://get.docker.com\n' >&2
                    ;;
                rhel)
                    printf 'Example (Fedora/RHEL/CentOS/Rocky):\n' >&2
                    printf '  sudo dnf install -y docker docker-compose-plugin\n' >&2
                    ;;
                arch)
                    printf 'Example (Arch):\n' >&2
                    printf '  sudo pacman -S --needed docker docker-compose\n' >&2
                    ;;
                suse)
                    printf 'Example (openSUSE):\n' >&2
                    printf '  sudo zypper install docker docker-compose\n' >&2
                    ;;
                alpine)
                    printf 'Example (Alpine):\n' >&2
                    printf '  sudo apk add docker docker-cli-compose\n' >&2
                    printf '  sudo rc-update add docker && sudo service docker start\n' >&2
                    ;;
                *)
                    printf 'Install Docker Engine and the Compose v2 plugin with your package manager.\n' >&2
                    ;;
            esac
            if [[ "${family}" != "alpine" ]]; then
                printf 'Then enable the service and add your user to the docker group:\n' >&2
                printf '  sudo systemctl enable --now docker\n' >&2
                printf '  sudo usermod -aG docker "$USER"   # then log out and back in\n' >&2
            fi
            ;;
        *)
            printf 'Install Docker Engine and the Compose v2 plugin for your system.\n' >&2
            ;;
    esac
    print_docker_docs
    case "${os}" in
        linux)
            printf 'Note: the snap-packaged Docker works, but its confined home interface\n' >&2
            printf 'cannot read hidden paths under $HOME; Docker Engine is recommended.\n' >&2
            printf 'Prefer not to run Docker? Install the Debian package or run from source:\n' >&2
            printf '  docs/getting-started-deb.md  docs/getting-started-source.md\n' >&2
            ;;
        macos)
            printf 'Prefer not to run Docker? Run from source:\n' >&2
            printf '  docs/getting-started-source.md\n' >&2
            ;;
    esac
}

print_docker_compose_hint() {
    local os family
    os="$(detect_platform_os)"
    family="$(detect_linux_family)"
    printf '\nThe Docker Compose v2 plugin is required (the "docker compose" command).\n' >&2
    if command -v docker-compose >/dev/null 2>&1; then
        printf 'Found Docker Compose v1 (docker-compose); this installer needs the v2 plugin.\n' >&2
    fi
    case "${os}" in
        macos)
            printf 'Docker Desktop bundles Compose v2; with the CLI only:\n' >&2
            printf '  brew install docker-compose\n' >&2
            ;;
        windows-shell)
            printf 'Docker Desktop for Windows bundles Compose v2.\n' >&2
            ;;
        linux)
            case "${family}" in
                debian) printf '  sudo apt-get install -y docker-compose-v2   # or docker-compose-plugin from the Docker repo\n' >&2 ;;
                rhel) printf '  sudo dnf install -y docker-compose-plugin\n' >&2 ;;
                arch) printf '  sudo pacman -S --needed docker-compose\n' >&2 ;;
                suse) printf '  sudo zypper install docker-compose\n' >&2 ;;
                alpine) printf '  sudo apk add docker-cli-compose\n' >&2 ;;
                *) printf '  Install the Compose v2 plugin with your package manager.\n' >&2 ;;
            esac
            ;;
        *)
            printf 'Install the Compose v2 plugin for your system.\n' >&2
            ;;
    esac
    printf '  Docs: https://docs.docker.com/compose/install/\n' >&2
}

print_docker_daemon_hint() {
    local info_output="$1"
    local os
    os="$(detect_platform_os)"
    if [[ "${info_output}" == *"permission denied"* ]]; then
        printf '\nThe Docker daemon is reachable, but this user cannot access it.\n' >&2
        printf 'Add your user to the docker group, then log out and back in (or run newgrp docker):\n' >&2
        printf '  sudo usermod -aG docker "$USER"\n' >&2
        printf '  Docs: https://docs.docker.com/engine/install/linux-postinstall/\n' >&2
        return 0
    fi
    printf '\nCannot reach the Docker daemon (is it running?).\n' >&2
    case "${os}" in
        macos) printf 'Start Docker Desktop and wait until it reports "running".\n' >&2 ;;
        windows-shell) printf 'Start Docker Desktop for Windows.\n' >&2 ;;
        *) printf '  sudo systemctl enable --now docker   # or: sudo service docker start\n' >&2 ;;
    esac
    if [[ -n "${DOCKER_HOST:-}" ]]; then
        printf 'DOCKER_HOST=%s is set: verify it points to a reachable daemon.\n' "${DOCKER_HOST}" >&2
    fi
    printf 'To only generate the files without starting the container, re-run with --no-start.\n' >&2
}

print_package_hint() {
    local os family pkg
    os="$(detect_platform_os)"
    family="$(detect_linux_family)"
    pkg="$1"
    case "${os}" in
        macos) printf '  brew install %s\n' "${pkg}" >&2 ;;
        linux)
            case "${family}" in
                debian) printf '  sudo apt-get install -y %s\n' "${pkg}" >&2 ;;
                rhel) printf '  sudo dnf install -y %s\n' "${pkg}" >&2 ;;
                arch) printf '  sudo pacman -S --needed %s\n' "${pkg}" >&2 ;;
                suse) printf '  sudo zypper install %s\n' "${pkg}" >&2 ;;
                alpine) printf '  sudo apk add %s\n' "${pkg}" >&2 ;;
                *) printf '  Install %s with your package manager.\n' "${pkg}" >&2 ;;
            esac
            ;;
        *) printf '  Install %s with your package manager.\n' "${pkg}" >&2 ;;
    esac
}

# amd64 | arm64 | arm, or empty when sigstore publishes no build for this CPU.
detect_cosign_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) printf 'amd64' ;;
        aarch64 | arm64) printf 'arm64' ;;
        armv6l | armv7l | armv8l) printf 'arm' ;;
        *) printf '' ;;
    esac
}

print_cosign_hint() {
    local os family arch
    os="$(detect_platform_os)"
    family="$(detect_linux_family)"
    arch="$(detect_cosign_arch)"

    printf '\nThe installer verifies the released image signature (Sigstore, keyless)\n' >&2
    printf 'before starting the node, which needs "cosign" on PATH.\n' >&2
    printf 'Install it:\n' >&2
    case "${os}" in
        macos)
            printf '  brew install cosign\n' >&2
            ;;
        windows-shell)
            printf '  Download cosign-windows-amd64.exe from\n' >&2
            printf '  https://github.com/sigstore/cosign/releases/latest\n' >&2
            ;;
        linux)
            case "${family}" in
                arch) printf '  sudo pacman -S cosign\n' >&2 ;;
                alpine) printf '  sudo apk add cosign\n' >&2 ;;
                *)
                    if [[ -n "${arch}" ]]; then
                        printf '  curl -fsSLo /tmp/cosign \\\n' >&2
                        printf '    "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-%s"\n' \
                            "${arch}" >&2
                        printf '  sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign\n' >&2
                    else
                        printf '  Download the build for your CPU from\n' >&2
                        printf '  https://github.com/sigstore/cosign/releases/latest\n' >&2
                    fi
                    ;;
            esac
            ;;
        *)
            printf '  Download it from https://github.com/sigstore/cosign/releases/latest\n' >&2
            ;;
    esac
    printf '  Docs: https://docs.sigstore.dev/cosign/system_config/installation/\n' >&2
    # Releases are signed with cosign v3 bundles, which a v2 cosign cannot read.
    printf 'Install the latest cosign: releases use cosign v3 bundles, and an older\n' >&2
    printf 'cosign reports that the image carries no signature.\n' >&2
    printf '\nOr install without verification (the image is then trusted on the\n' >&2
    printf 'registry reference alone):\n' >&2
    printf '  curl -fsSL "https://github.com/%s/releases/latest/download/install.sh" \\\n' \
        "${REPO}" >&2
    printf '    | bash -s -- --no-verify\n' >&2
    printf '  # already downloaded: ./install.sh --no-verify\n' >&2
}

print_tool_hint() {
    local tool="$1"
    case "${tool}" in
        cosign) print_cosign_hint ;;
        curl)
            printf '\nThe installer resolves the release metadata with "curl".\n' >&2
            print_package_hint "curl"
            ;;
        *)
            printf '\nInstall "%s" with your package manager.\n' "${tool}" >&2
            ;;
    esac
}

require_docker_command() {
    if command -v docker >/dev/null 2>&1; then
        return 0
    fi
    print_docker_install_hint
    fail "required command not found: docker"
}

require_docker_compose_v2() {
    if docker compose version >/dev/null 2>&1; then
        return 0
    fi
    print_docker_compose_hint
    fail "Docker Compose v2 is required"
}

require_docker_daemon() {
    local info_output
    local -a docker_info=(docker info)
    if command -v timeout >/dev/null 2>&1; then
        docker_info=(timeout 10 docker info)
    elif command -v gtimeout >/dev/null 2>&1; then
        docker_info=(gtimeout 10 docker info)
    fi
    if info_output="$("${docker_info[@]}" 2>&1)"; then
        return 0
    fi
    print_docker_daemon_hint "${info_output}"
    fail "cannot connect to the Docker daemon"
}

# The image is verified before anything is written, so a missing verifier or a
# refused signature cannot leave a half-created installation behind.
require_cosign() {
    [[ "${VERIFY}" == true ]] || return 0
    require_command cosign
}

validate_version() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] ||
        fail "invalid version '$1'; expected vX.Y.Z or 'latest'"
}

resolve_latest_version() {
    local url effective tag
    url="https://github.com/${REPO}/releases/latest"
    effective="$(curl -fsSIL -o /dev/null -w '%{url_effective}' "${url}")" ||
        fail "could not resolve the latest release from ${url}"
    tag="${effective##*/}"
    [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] ||
        fail "unexpected latest release tag '${tag}' from ${url}"
    printf '%s' "${tag}"
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)) ||
        fail "invalid port '$1'; expected 1-65535"
}

# True when the docker command comes from the snap package. Snap confinement is
# relevant because the "home" interface denies hidden paths under $HOME.
docker_is_snap() {
    local docker_path
    docker_path="$(command -v docker 2>/dev/null)" || return 1
    case "${docker_path}" in
        /snap/* | */snap/*) return 0 ;;
    esac
    # A wrapper/symlink pointing into the snap tree (readlink without -f stays
    # portable across GNU/BSD userlands).
    case "$(readlink "${docker_path}" 2>/dev/null || true)" in
        /snap/* | */snap/*) return 0 ;;
    esac
    return 1
}

# True when an absolute path contains a hidden component (a name starting with
# '.'), which the snap "home" interface refuses to expose.
path_has_hidden_component() {
    local component
    local IFS='/'
    # shellcheck disable=SC2086
    for component in ${1#/}; do
        case "${component}" in
            "." | "..") continue ;;
            .*) return 0 ;;
        esac
    done
    return 1
}

# Snap docker cannot read hidden paths under $HOME. When a compose failure
# carries that signature, append an actionable hint beyond the pre-flight check.
warn_if_snap_hidden_path() {
    local output="$1"
    if ! docker_is_snap || [[ "${output}" != *"permission denied"* ]]; then
        return 0
    fi
    printf '\nWarning: docker is the snap package and the snap "home" interface denies\n' >&2
    printf 'hidden paths under $HOME, so it cannot read %s/.env.\n' "${INSTALL_DIR}" >&2
    printf 'Fix: install Docker Engine (https://docs.docker.com/engine/install/) instead\n' >&2
    printf 'of the snap, or re-run with a non-hidden directory:\n' >&2
    printf '  curl -fsSL "https://github.com/%s/releases/latest/download/install.sh" | bash -s -- --install-dir "%s"\n' \
        "${REPO}" "${HOME}/hsync-rendezvous" >&2
}

# 'docker compose config' reads .env client-side, so it is the first command to
# fail when snap docker cannot reach the installation directory.
validate_compose_config() {
    local output
    if output="$(docker compose --project-directory "${INSTALL_DIR}" \
            --file "${INSTALL_DIR}/compose.yaml" config --quiet 2>&1)"; then
        return 0
    fi
    printf '%s\n' "${output}" >&2
    warn_if_snap_hidden_path "${output}"
    fail "docker compose could not validate ${INSTALL_DIR}/compose.yaml"
}

validate_digest() {
    [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]] ||
        fail "invalid --image-digest '$1'; expected sha256:<64 lowercase hex>"
}

image_reference() {
    if [[ -n "${IMAGE_DIGEST}" ]]; then
        printf '%s@%s' "${IMAGE_REPO}" "${IMAGE_DIGEST}"
    else
        printf '%s:%s' "${IMAGE_REPO}" "${VERSION}"
    fi
}

# Major version of the cosign on PATH, or empty when it cannot be read.
cosign_major_version() {
    cosign version 2>/dev/null |
        sed -n 's/.*GitVersion:[[:space:]]*v\{0,1\}\([0-9]\{1,\}\).*/\1/p' |
        head -n 1 || true
}

verify_image() {
    local image_ref="$1"
    local output major

    if [[ "${VERIFY}" != true ]]; then
        printf 'WARNING: image signature verification is disabled (--no-verify); the image is trusted on the registry reference alone.\n' >&2
        return 0
    fi
    printf 'Verifying the container image signature (Sigstore keyless)...\n'
    # Capture cosign's diagnostics for the failure report, without its JSON payload.
    if output="$(cosign verify \
            --certificate-identity-regexp "${COSIGN_IDENTITY_REGEXP}" \
            --certificate-oidc-issuer "${COSIGN_OIDC_ISSUER}" \
            "${image_ref}" 2>&1 >/dev/null)"; then
        return 0
    fi
    if [[ -n "${output}" ]]; then
        printf '%s\n' "${output}" >&2
    fi
    major="$(cosign_major_version)"
    if [[ -n "${major}" ]] && ((major < 3)); then
        printf '\ncosign %s.x cannot verify the v3 bundle signature of current releases;\n' "${major}" >&2
        printf 'upgrade to the latest cosign and re-run the installer.\n' >&2
    fi
    fail "image signature verification failed for ${image_ref}; refusing to start an unverified node (use --no-verify to override)"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                VERSION="$2"
                shift 2
                ;;
            --install-dir)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                INSTALL_DIR="$2"
                INSTALL_DIR_EXPLICIT=true
                shift 2
                ;;
            --public-port)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                PUBLIC_PORT="$2"
                PUBLIC_PORT_SET=true
                shift 2
                ;;
            --private)
                PRIVATE=true
                shift
                ;;
            --keys-file)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                KEYS_FILE="$2"
                shift 2
                ;;
            --image-digest)
                [[ -n "${2:-}" ]] || fail "$1 requires a value"
                IMAGE_DIGEST="$2"
                shift 2
                ;;
            --no-verify)
                VERIFY=false
                shift
                ;;
            --no-start)
                START_SERVER=false
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "unknown option: $1"
                ;;
        esac
    done
}

write_compose_file() {
    cat > "${INSTALL_DIR}/compose.yaml" <<'EOF'
name: hsync

services:
  rendezvous:
    image: ${HSYNC_RENDEZVOUS_IMAGE:?Set HSYNC_RENDEZVOUS_IMAGE in .env}
    restart: unless-stopped
    user: "${HSYNC_UID:-1000}:${HSYNC_GID:-1000}"
    command: ["run", "--listen-host", "0.0.0.0", "--listen-port", "8443"]
    ports:
      - "${RENDEZVOUS_HOST_PORT:-443}:8443/udp"
      - "${RENDEZVOUS_HOST_PORT:-443}:8443/tcp"
    env_file:
      - .env
    volumes:
      - ${HSYNC_RENDEZVOUS_DATA_DIR:-./hsync-data}:/var/lib/hsync-rendezvous
      - ${HSYNC_RENDEZVOUS_KEYS_PATH:-/dev/null}:/keys:ro
    # Readiness is the node's own seam: the PID file exists only while a listener
    # is bound (the entrypoint deletes a stale one before exec). With the seam
    # unconfigured there is nothing to assert, so the check passes.
    healthcheck:
      test: ["CMD-SHELL", "test -z \"$${HSYNC_RENDEZVOUS_READY_FILE}\" || test -f \"$${HSYNC_RENDEZVOUS_READY_FILE}\""]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    # Time for the transport teardown (and the readiness-file removal) before the
    # runtime escalates to SIGKILL.
    stop_grace_period: 15s
    read_only: true
    tmpfs:
      - /tmp
EOF
}

write_env_file() {
    cat > "${INSTALL_DIR}/.env" <<EOF
# Generated by the HSYNC rendezvous installer. Keep this file private.
HSYNC_RENDEZVOUS_IMAGE=${IMAGE_REF}
RENDEZVOUS_HOST_PORT=${PUBLIC_PORT}
# Host directory holding the persistent TLS identity and the readiness PID
# (bind-mounted into the container). Back it up to keep the fingerprint stable.
HSYNC_RENDEZVOUS_DATA_DIR=${INSTALL_DIR}/hsync-data
# Container runs under these host ids so the bind-mounted directory stays
# writable (it was created by this installer as the same user).
HSYNC_UID=$(id -u)
HSYNC_GID=$(id -g)
# Container paths for the persistent identity and the readiness PID.
HSYNC_RENDEZVOUS_IDENTITY=/var/lib/hsync-rendezvous/identity.pem
HSYNC_RENDEZVOUS_READY_FILE=/var/lib/hsync-rendezvous/ready.pid
EOF
    if [[ -n "${KEYS_FILE}" ]]; then
        printf 'HSYNC_RENDEZVOUS_KEYS_PATH=%s\n' "${KEYS_FILE}" >> "${INSTALL_DIR}/.env"
        printf 'HSYNC_RENDEZVOUS_KEYS_FILE=/keys\n' >> "${INSTALL_DIR}/.env"
    else
        printf 'HSYNC_RENDEZVOUS_KEYS_PATH=/dev/null\n' >> "${INSTALL_DIR}/.env"
    fi
    if [[ "${PRIVATE}" == true ]]; then
        printf 'HSYNC_RENDEZVOUS_PRIVATE=1\n' >> "${INSTALL_DIR}/.env"
    fi
    chmod 600 "${INSTALL_DIR}/.env"
}

update_env_value() {
    local key="$1"
    local value="$2"
    local env_file="${INSTALL_DIR}/.env"
    local temporary_file="${env_file}.tmp"

    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" == "${key}="* ]]; then
            printf '%s=%s\n' "${key}" "${value}"
        else
            printf '%s\n' "${line}"
        fi
    done < "${env_file}" > "${temporary_file}"
    mv "${temporary_file}" "${env_file}"
    chmod 600 "${env_file}"
}

read_env_value() {
    local wanted_key="$1"
    local key
    local value

    while IFS='=' read -r key value; do
        if [[ "${key}" == "${wanted_key}" ]]; then
            printf '%s\n' "${value}"
            return 0
        fi
    done < "${INSTALL_DIR}/.env"
    return 1
}

install_files() {
    local env_file="${INSTALL_DIR}/.env"
    local compose_file="${INSTALL_DIR}/compose.yaml"

    if [[ -e "${env_file}" || -e "${compose_file}" ]]; then
        [[ -f "${env_file}" && -f "${compose_file}" ]] ||
            fail "partial installation in ${INSTALL_DIR}; refusing to overwrite it"
        update_env_value HSYNC_RENDEZVOUS_IMAGE "${IMAGE_REF}"
        if [[ "${PUBLIC_PORT_SET}" == true ]]; then
            update_env_value RENDEZVOUS_HOST_PORT "${PUBLIC_PORT}"
        fi
        printf 'Reusing existing TLS identity in %s\n' "${INSTALL_DIR}"
        return
    fi

    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${INSTALL_DIR}/hsync-data"
    write_compose_file
    write_env_file
    chmod 600 "${compose_file}"
}

wait_for_ready() {
    local ready_file="$1"
    local deadline=$(( $(date +%s) + 60 ))
    while (( $(date +%s) < deadline )); do
        [[ -s "${ready_file}" ]] && return 0
        sleep 1
    done
    return 1
}

main() {
    local data_dir
    local ready_file

    parse_args "$@"

    if [[ "${INSTALL_DIR}" != /* ]]; then
        INSTALL_DIR="$(pwd)/${INSTALL_DIR}"
    fi

    # Snap-packaged docker is confined and cannot read hidden paths under $HOME,
    # so the default XDG install dir (~/.local/share/...) would break
    # 'docker compose'. When the directory was not chosen explicitly, fall back
    # to a non-hidden default instead of failing the whole install.
    if docker_is_snap && path_has_hidden_component "${INSTALL_DIR}"; then
        if [[ "${INSTALL_DIR_EXPLICIT}" == true ]]; then
            fail "docker is the snap package and ${INSTALL_DIR} is under a hidden path; the snap 'home' interface denies hidden paths in \$HOME, so 'docker compose' cannot read .env there. Re-run with a non-hidden directory:
  curl -fsSL \"https://github.com/${REPO}/releases/latest/download/install.sh\" | bash -s -- --install-dir \"${HOME}/hsync-rendezvous\"
or install Docker Engine from https://docs.docker.com/engine/install/ instead of the snap."
        fi
        printf 'Note: snap Docker cannot read hidden paths under $HOME; using %s instead of %s.\n' \
            "${HOME}/hsync-rendezvous" "${INSTALL_DIR}" >&2
        INSTALL_DIR="${HOME}/hsync-rendezvous"
    fi

    if [[ -f "${INSTALL_DIR}/.env" && "${PUBLIC_PORT_SET}" == false ]]; then
        PUBLIC_PORT="$(read_env_value RENDEZVOUS_HOST_PORT)" ||
            fail "RENDEZVOUS_HOST_PORT is missing from ${INSTALL_DIR}/.env; re-run the installer to regenerate it"
    fi

    if [[ "${VERSION}" == "latest" ]]; then
        require_command curl
        VERSION="$(resolve_latest_version)"
    fi
    validate_version "${VERSION}"
    validate_port "${PUBLIC_PORT}"
    [[ -z "${IMAGE_DIGEST}" ]] || validate_digest "${IMAGE_DIGEST}"
    IMAGE_REF="$(image_reference)"
    if [[ -n "${KEYS_FILE}" && ! -f "${KEYS_FILE}" ]]; then
        fail "group-keys file not found: ${KEYS_FILE}"
    fi

    printf 'Install directory: %s\n' "${INSTALL_DIR}"
    printf 'Image: %s\n' "${IMAGE_REF}"
    printf 'Endpoint: udp/%s\n' "${PUBLIC_PORT}"

    if [[ "${DRY_RUN}" == true ]]; then
        printf 'Dry run: no files were changed.\n'
        exit 0
    fi

    require_docker_command
    require_docker_compose_v2
    require_cosign
    # The daemon is only needed to start containers; --no-start stays client-side.
    if [[ "${START_SERVER}" == true ]]; then
        require_docker_daemon
    fi

    # Read-only registry check: a refused image must leave no files behind.
    verify_image "${IMAGE_REF}"

    umask 077
    install_files
    validate_compose_config

    data_dir="$(read_env_value HSYNC_RENDEZVOUS_DATA_DIR)"
    ready_file="${data_dir}/ready.pid"

    if [[ "${START_SERVER}" == true ]]; then
        docker compose --project-directory "${INSTALL_DIR}" \
            --file "${INSTALL_DIR}/compose.yaml" pull
        rm -f "${ready_file}"
        docker compose --project-directory "${INSTALL_DIR}" \
            --file "${INSTALL_DIR}/compose.yaml" up -d
        if wait_for_ready "${ready_file}"; then
            printf 'HSYNC rendezvous is live on udp/%s\n' "${PUBLIC_PORT}"
        else
            printf 'Started, but readiness was not reported within 60s; check the logs:\n' >&2
            printf '  docker compose --project-directory %q --file %q logs\n' \
                "${INSTALL_DIR}" "${INSTALL_DIR}/compose.yaml" >&2
        fi
    else
        printf 'Configuration validated. Start it with:\n'
        printf '  docker compose --project-directory %q --file %q up -d\n' \
            "${INSTALL_DIR}" "${INSTALL_DIR}/compose.yaml"
    fi
}

main "$@"
