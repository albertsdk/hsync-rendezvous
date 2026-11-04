#!/usr/bin/env bash
#
# HSYNC Rendezvous - Build Script
#
# Builds the HSYNC rendezvous into the requested artifact: a standalone
# executable for the host, Raspberry Pi OS executables (armhf/arm64), or
# Debian/Ubuntu .deb packages. This script (repository root) selects WHICH
# implementation language the embedded executable is built from and delegates
# the binary build to the matching per-language script; the per-language
# scripts build binaries only.
#
#   python → python/compile.sh   (native/onedir; implemented)
#   c      → planned v2 port of the same rdv/1 protocol (not yet available)
#
# Usage:
#   ./compile.sh [options]
#
# Options:
#   -c, --clean             Clean build artifacts before building
#   -t, --target TARGET     Build target (default: native)
#                           Supported:
#                               native    standalone executable for the host
#                                         OS/arch
#                               rpi       Raspberry Pi OS executables: armhf
#                                         (32-bit) and arm64 (64-bit) via
#                                         Docker
#                               deb       .deb for the host architecture
#                               deb-all   .deb for amd64, arm64 and armhf
#                                         (via Docker)
#                               rpm       .rpm for the host architecture
#                               rpm-all   .rpm for x86_64 and aarch64
#                                         (via Docker, Rocky Linux 9 baseline)
#   -l, --language LANG     Implementation language of the executable
#                           (default: python). Values:
#                               python    current rendezvous (implemented)
#                               c         planned v2 port — not yet available
#                           Also settable via the DEB_LANGUAGE environment
#                           variable (the CLI flag takes precedence).
#   -v, --version VERSION   Override the version used for artifacts (default:
#                           the selected language's project file — for python
#                           python/pyproject.toml). Also settable via the
#                           HSYNC_VERSION environment variable. A prerelease
#                           (e.g. 1.2.0-alpha.1) is translated to the Debian
#                           form (1.2.0~alpha.1) for the .deb target.
#   -h, --help              Show this help message
#
# Requirements:
#   - native target: the selected language's toolchain (for python: the
#     committed python/.venv with PyInstaller)
#   - deb target: the selected language's toolchain + dpkg-deb (dpkg-dev);
#     fakeroot optional
#   - rpm target: the selected language's toolchain + rpmbuild (rpm-build)
#   - rpi / deb-all / rpm-all: Docker with qemu-user-static (binfmt) configured
#
# Output:
#   native:   dist/<os>-<arch>/hsync-rendezvous[.exe]
#   rpi:      dist/rpi/armhf/hsync-rendezvous   (Raspberry Pi OS 32-bit)
#             dist/rpi/arm64/hsync-rendezvous   (Raspberry Pi OS 64-bit)
#   deb:      dist/deb/hsync-rendezvous_<ver>_<arch>.deb
#             Installable with dpkg -i / apt install
#   deb-all:  dist/deb/hsync-rendezvous_<ver>_{amd64,arm64,armhf}.deb
#   rpm:      dist/rpm/hsync-rendezvous-<ver>-1.<dist>.<arch>.rpm
#             Installable with dnf install
#   rpm-all:  dist/rpm/hsync-rendezvous-<ver>-1.el9.{x86_64,aarch64}.rpm
#
# Author: Alberto Basso
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Host platform (used by the deb target; deb-all always cross-builds)
case "$(uname -s)" in
    Linux*)               readonly OS_NAME="linux" ;;
    Darwin*)              readonly OS_NAME="darwin" ;;
    MINGW*|CYGWIN*|MSYS*) readonly OS_NAME="windows" ;;
    *)                    readonly OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)   readonly ARCH_NAME="amd64" ;;
    aarch64|arm64)  readonly ARCH_NAME="arm64" ;;
    armv7l|armv7)   readonly ARCH_NAME="armv7" ;;
    i386|i686)      readonly ARCH_NAME="x86" ;;
    *)              readonly ARCH_NAME="$(uname -m)" ;;
esac
readonly PLATFORM="${OS_NAME}-${ARCH_NAME}"

readonly APP_NAME="hsync-rendezvous"
readonly PYTHON_DIR="python"
readonly PYPROJECT="${PYTHON_DIR}/pyproject.toml"
readonly DEB_DIR="packaging/deb"
readonly DEB_SRC_CONTROL="${DEB_DIR}/DEBIAN"
readonly DEB_SRC_DATA="${DEB_DIR}"
readonly DEB_PKG_NAME="${APP_NAME}"
readonly OUTPUT_BASE="dist"
readonly DEB_OUTPUT_DIR="${OUTPUT_BASE}/deb"
readonly BUILD_DIR="build"
readonly DEB_BUILD_DIR="${BUILD_DIR}/deb"
readonly DEB_ALL_BUILD_DIR="${BUILD_DIR}/deb-all"
readonly DEB_ALL_BUILDER_IMAGE_PREFIX="hsync-rendezvous-deb-builder"

# Standalone executable artifacts (native / rpi targets).
readonly OUTPUT_DIR="${OUTPUT_BASE}/${PLATFORM}"
readonly BIN_EXT="$([[ "${OS_NAME}" == "windows" ]] && echo ".exe" || echo "")"
readonly RPI_OUTPUT_DIR="${OUTPUT_BASE}/rpi"
# The Debian builder image (Python 3.12 + Poetry + the armhf source-build
# toolchain) is reused for the Raspberry Pi cross-build, so no separate
# Dockerfile is needed.
readonly RPI_DOCKERFILE="${DEB_DIR}/Dockerfile.builder"
readonly RPI_BUILDER_IMAGE_PREFIX="hsync-rendezvous-rpi-builder"

# -----------------------------------------------------------------------------
# Package language — which implementation the .deb's executable is built from
# -----------------------------------------------------------------------------
# The dispatcher below delegates the binary build to the per-language script;
# add a new language by extending validate_language() and the case blocks in
# the _build_native() / _build_onedir() / _container_native_cmd() /
# _container_build_cmd() dispatchers. Precedence: --language flag >
# DEB_LANGUAGE env > "python".
readonly DEB_LANGUAGE_DEFAULT="python"
DEB_LANGUAGE="${DEB_LANGUAGE:-${DEB_LANGUAGE_DEFAULT}}"

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
    readonly RED=$'\033[0;31m'
    readonly GREEN=$'\033[0;32m'
    readonly YELLOW=$'\033[0;33m'
    readonly BLUE=$'\033[0;34m'
    readonly CYAN=$'\033[0;36m'
    readonly BOLD=$'\033[1m'
    readonly DIM=$'\033[2m'
    readonly RESET=$'\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' RESET=''
fi

# Logging functions
log_info() { echo -e "${BLUE}i${RESET} $*"; }
log_ok() { echo -e "${GREEN}OK${RESET} $*"; }
log_warn() { echo -e "${YELLOW}!${RESET} $*"; }
log_error() { echo -e "${RED}X${RESET} $*" >&2; }
log_step() { echo -e "${CYAN}>${RESET} ${BOLD}$*${RESET}"; }

# Report whether a binfmt_misc handler exists and is enabled.
# $1 = handler name (e.g. qemu-arm, qemu-aarch64)
qemu_handler_active() {
    [[ -d "/proc/sys/fs/binfmt_misc" ]] || return 1
    local f="/proc/sys/fs/binfmt_misc/$1"
    [[ -f "${f}" ]] && grep -q '^enabled' "${f}"
}

# Ensure the qemu-user-static binfmt handlers required for cross-arch Docker
# builds are registered and active. $@ = required handler names.
ensure_qemu_binfmt() {
    local handlers=("$@")
    [[ ${#handlers[@]} -eq 0 ]] && handlers=("qemu-arm")
    log_step "Ensuring qemu-user-static binfmt handlers are active: ${handlers[*]}"
    local missing=()
    local h
    for h in "${handlers[@]}"; do
        qemu_handler_active "${h}" || missing+=("${h}")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
        log_ok "binfmt handlers already active"
        return 0
    fi
    log_info "Registering qemu-user-static binfmt handlers..."
    # Image pinned by digest: this runs --privileged, so it must not move.
    if ! docker run --rm --privileged \
        multiarch/qemu-user-static@sha256:fe60359c92e86a43cc87b3d906006245f77bfc0565676b80004cc666e4feb9f0 \
        --reset -p yes >/dev/null 2>&1; then
        log_error "Failed to run multiarch/qemu-user-static (is the Docker daemon reachable?)."
        exit 1
    fi
    missing=()
    for h in "${handlers[@]}"; do
        qemu_handler_active "${h}" || missing+=("${h}")
    done
    if [[ ${#missing[@]} -ne 0 ]]; then
        log_error "binfmt handlers still inactive after registration: ${missing[*]}"
        log_error "Cross-arch emulation is unavailable; aborting now to avoid a"
        log_error "misleading 'exec format error' later in the build."
        exit 1
    fi
    log_ok "binfmt handlers registered and active"
}

show_help() {
    cat << EOF
${BOLD}HSYNC Rendezvous - Build Script${RESET}

${BOLD}Usage:${RESET}
    ./compile.sh [options]

${BOLD}Options:${RESET}
    -c, --clean              Clean build artifacts before building
    -t, --target TARGET      Build target (default: native)
                             Supported: native, rpi, deb, deb-all, rpm, rpm-all
    -l, --language LANGUAGE  Implementation language of the executable
                             (default: python). Supported: python, c
    -v, --version VERSION    Override the artifact version (default: the
                             selected language's project file; python reads
                             python/pyproject.toml). Also settable via
                             HSYNC_VERSION.
    -h, --help               Show this help message

${BOLD}Examples:${RESET}
    ./compile.sh                                      # host standalone binary
    ./compile.sh -t rpi                               # Raspberry Pi armhf+arm64
    ./compile.sh -t deb                               # .deb for the host arch
    ./compile.sh -t deb-all                           # amd64, arm64, armhf
    ./compile.sh -t rpm                               # .rpm for the host arch
    ./compile.sh -t rpm-all                           # x86_64 + aarch64
    ./compile.sh -l python -t deb                     # explicit language
    DEB_LANGUAGE=c ./compile.sh -t deb                # rejected until the
                                                      # C port exists

${BOLD}Output:${RESET}
    native:   ${OUTPUT_DIR}/${APP_NAME}
    rpi:      ${RPI_OUTPUT_DIR}/armhf/${APP_NAME}
              ${RPI_OUTPUT_DIR}/arm64/${APP_NAME}
    deb:      ${DEB_OUTPUT_DIR}/${DEB_PKG_NAME}_<ver>_<arch>.deb
    deb-all:  ${DEB_OUTPUT_DIR}/${DEB_PKG_NAME}_<ver>_{amd64,arm64,armhf}.deb
    rpm:      ${RPM_OUTPUT_DIR}/${DEB_PKG_NAME}-<ver>-1.<dist>.<arch>.rpm
    rpm-all:  ${RPM_OUTPUT_DIR}/${DEB_PKG_NAME}-<ver>-1.el9.{x86_64,aarch64}.rpm
EOF
}

# Clean build artifacts (staging trees, standalone executables and packages)
clean_artifacts() {
    log_step "Cleaning build artifacts..."
    local cleaned=0 dir
    for dir in "${DEB_OUTPUT_DIR}" "${OUTPUT_DIR}" "${RPI_OUTPUT_DIR}" \
        "${DEB_BUILD_DIR}" "${DEB_ALL_BUILD_DIR}"; do
        if [[ -d "${dir}" ]]; then
            rm -rf "${dir}"
            ((cleaned++)) || true
        fi
    done
    if [[ ${cleaned} -gt 0 ]]; then
        log_ok "Cleaned ${cleaned} artifact dir(s)"
    else
        log_info "No artifacts to clean"
    fi
}

# Version override, set by --version and/or the HSYNC_VERSION environment
# variable. Mutable (not readonly) so main() can assign it.
VERSION_OVERRIDE=""
get_version() {
    if [[ -n "${VERSION_OVERRIDE}" ]]; then
        printf '%s' "${VERSION_OVERRIDE}"
    elif [[ -n "${HSYNC_VERSION:-}" ]]; then
        printf '%s' "${HSYNC_VERSION}"
    else
        case "${DEB_LANGUAGE}" in
            python) grep -E '^version\s*=' "${PYPROJECT}" | head -1 | sed 's/.*"\(.*\)".*/\1/' ;;
        esac
    fi
}

# Translate a SemVer version into a Debian policy version so a prerelease
# sorts before the stable release: 1.2.0-alpha.1 -> 1.2.0~alpha.1.
_semver_to_debian() {
    printf '%s' "$1" | sed 's/-/~/'
}

# Translate a SemVer version into an RPM Version: field (same '~' rule as
# Debian: 1.2.0-alpha.1 -> 1.2.0~alpha.1). The Release: field stays a plain
# number (`1%{?dist}`), so the prerelease marker lives in Version, not Release.
_semver_to_rpm() {
    _semver_to_debian "$1"
}

_arch_to_deb() {
    case "$1" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        armv7l|armv7)   echo "armhf" ;;
        *)              echo "$1" ;;
    esac
}

# RHEL/Rocky is 64-bit only, so only x86_64 and aarch64 are supported (no
# armv7hl); anything else is echoed as-is.
_arch_to_rpm() {
    case "$1" in
        x86_64|amd64)   echo "x86_64" ;;
        aarch64|arm64)  echo "aarch64" ;;
        *)              echo "$1" ;;
    esac
}

# Fail fast if the selected implementation language has no packaging path yet.
# When the C port lands, extend this function and the dispatchers
# (_build_native / _build_onedir / _container_native_cmd / _container_build_cmd).
validate_language() {
    case "${DEB_LANGUAGE}" in
        python) ;;  # implemented today
        c)
            log_error "language 'c' is not yet available (planned v2 port)."
            log_info "Use --language python (or unset DEB_LANGUAGE) for now."
            exit 1
            ;;
        *)
            log_error "unknown language: ${DEB_LANGUAGE}"
            echo "Supported languages: python (c is planned)"
            exit 1
            ;;
    esac
}

# Build the standalone executable with the selected language's toolchain.
# Each implementation directory owns its binary build; this dispatcher only
# fixes the CONTRACT: the executable must land at <outdir>/<APP_NAME>[.exe].
# $1 = outdir (absolute) receiving the executable.
_build_native() {
    local outdir="$1"
    case "${DEB_LANGUAGE}" in
        python)
            ( cd "${SCRIPT_DIR}/${PYTHON_DIR}" && ./compile.sh -t native -o "${outdir}" )
            ;;
        *)
            validate_language
            ;;
    esac
    if [[ ! -f "${outdir}/${APP_NAME}${BIN_EXT}" ]]; then
        log_error "native executable not found at ${outdir}/${APP_NAME}${BIN_EXT}"
        exit 1
    fi
}

# Build the onedir executable payload with the selected language's toolchain.
# Contract: the bundle must land at <distpath>/<APP_NAME>/.
# $1 = distpath (absolute) receiving the <APP_NAME>/ bundle directory.
_build_onedir() {
    local distpath="$1"
    case "${DEB_LANGUAGE}" in
        python)
            ( cd "${SCRIPT_DIR}/${PYTHON_DIR}" && ./compile.sh -t onedir -o "${distpath}" )
            ;;
        *)
            validate_language
            ;;
    esac
    if [[ ! -d "${distpath}/${APP_NAME}" ]]; then
        log_error "onedir bundle not found at ${distpath}/${APP_NAME}"
        exit 1
    fi
}

# In-container command producing the standalone executable at $1 (a path
# relative to the container workdir /repo/hsync-rendezvous/python).
# HSYNC_PREFER_PATH_PYINSTALLER=1 stops the mounted host .venv from shadowing
# the container's own (target-arch) PyInstaller; HSYNC_PYINSTALLER_WORKPATH
# keeps PyInstaller's build/ + .spec intermediates out of the mounted source
# tree (so nothing is written back to the host except the /out artifact).
_container_native_cmd() {
    local outdir="$1"
    case "${DEB_LANGUAGE}" in
        python)
            printf '%s' "poetry install --only main,build && HSYNC_PREFER_PATH_PYINSTALLER=1 HSYNC_PYINSTALLER_WORKPATH=/tmp/work poetry run ./compile.sh -t native -o ${outdir}"
            ;;
        *)
            validate_language
            ;;
    esac
}

# In-container command producing the onedir bundle for $1 (deb_arch). The
# bundle MUST land at build/deb-all/<arch>/pyinstaller/<APP_NAME> (paths are
# relative to the container workdir /repo/hsync-rendezvous/python).
_container_build_cmd() {
    local deb_arch="$1"
    case "${DEB_LANGUAGE}" in
        python)
            printf '%s' "poetry install --only main,build && HSYNC_PREFER_PATH_PYINSTALLER=1 HSYNC_PYINSTALLER_WORKPATH=/tmp/work poetry run ./compile.sh -t onedir -o /build/deb-all/${deb_arch}/pyinstaller"
            ;;
        *)
            validate_language
            ;;
    esac
}

# In-container command producing the onedir bundle for the RPM target of $1
# (rpm_arch). The bundle MUST land at /build/rpm-all/<arch>/pyinstaller/<APP_NAME>.
_container_rpm_build_cmd() {
    local rpm_arch="$1"
    case "${DEB_LANGUAGE}" in
        python)
            printf '%s' "poetry install --only main,build && HSYNC_PREFER_PATH_PYINSTALLER=1 HSYNC_PYINSTALLER_WORKPATH=/tmp/work poetry run ./compile.sh -t onedir -o /build/rpm-all/${rpm_arch}/pyinstaller"
            ;;
        *)
            validate_language
            ;;
    esac
}

# Normalise a staged .deb payload so the resulting package is lintian-clean:
#   * root and directories 0755 / files 0644 under etc/ and usr/;
#   * the main executable keeps its 0755 bit;
#   * the man page is gzip-compressed (-n => reproducible header).
# /etc/hsync-rendezvous (group-keys dir) is NOT shipped: postinst creates it.
_finalize_deb_stage() {
    local stage_dir="$1"
    chmod 0755 "${stage_dir}"
    find "${stage_dir}/etc" "${stage_dir}/usr" -type d -exec chmod 0755 {} + 2>/dev/null || true
    find "${stage_dir}/etc" "${stage_dir}/usr" -type f -exec chmod 0644 {} + 2>/dev/null || true
    chmod 0755 "${stage_dir}/usr/lib/${APP_NAME}/${APP_NAME}"
    local man="${stage_dir}/usr/share/man/man1/${APP_NAME}.1"
    [[ -f "${man}" ]] && gzip -n -9 -f "${man}"
    return 0
}

# Compute the shared-library dependency string for the staged main executable
# using dpkg-shlibdeps (e.g. "libc6 (>= 2.35)"); empty if unavailable. Must
# run in the target architecture's dpkg environment: on the host for
# build_deb, inside the per-arch container for build_deb_all.
# $1 = stage_dir
_compute_shlib_depends() {
    local stage_dir="$1"
    local bin="${stage_dir}/usr/lib/${APP_NAME}/${APP_NAME}"
    command -v dpkg-shlibdeps >/dev/null 2>&1 || { echo ""; return 0; }
    [[ -f "${bin}" ]] || { echo ""; return 0; }
    # dpkg-shlibdeps runs from a scratch dir (it needs a debian/control in the
    # cwd), so the binary path must be absolute: a relative path would stop
    # resolving after the cd below and silently yield no dependencies.
    bin="$(cd "$(dirname "${bin}")" && pwd)/$(basename "${bin}")"
    local tmp deps
    tmp="$(mktemp -d)"
    mkdir -p "${tmp}/debian"
    printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "${DEB_PKG_NAME}" "${DEB_PKG_NAME}" > "${tmp}/debian/control"
    deps="$(cd "${tmp}" && dpkg-shlibdeps -O --ignore-missing-info "${bin}" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
    rm -rf "${tmp}"
    echo "${deps}"
}

# Append the computed shared-library dependencies to the Depends: line of the
# staged DEBIAN/control. No-op (with a warning) if none could be computed.
# $1 = stage_dir
_inject_shlib_depends() {
    local stage_dir="$1"
    local deps
    deps="$(_compute_shlib_depends "${stage_dir}")"
    if [[ -z "${deps}" ]]; then
        if ! command -v dpkg-shlibdeps >/dev/null 2>&1; then
            log_warn "dpkg-shlibdeps not installed; libc6 dependency not added to control"
            log_info "Install it with: apt install dpkg-dev"
        else
            log_warn "dpkg-shlibdeps resolved no shared-library dependencies; nothing added to control"
        fi
        return 0
    fi
    log_step "Adding shared-library dependencies: ${deps}"
    sed -i.bak "s/^Depends: \(.*\)$/Depends: \1, ${deps}/" "${stage_dir}/DEBIAN/control"
    rm -f "${stage_dir}/DEBIAN/control.bak"
}

# Build a .deb package for the host architecture (no Docker).
build_deb() {
    local version deb_version deb_arch
    version="$(get_version)"
    deb_version="$(_semver_to_debian "${version}")"
    deb_arch="$(_arch_to_deb "${ARCH_NAME}")"
    log_step "Building ${DEB_PKG_NAME} v${version} for ${deb_arch} (host build)..."
    if ! command -v dpkg-deb >/dev/null 2>&1; then
        log_error "dpkg-deb is required for the deb target."
        log_info "Install it with: apt install dpkg-dev"
        exit 1
    fi
    mkdir -p "${DEB_OUTPUT_DIR}" "${DEB_BUILD_DIR}"

    # --- onedir bundle via the language dispatcher ------------------------
    # Absolute distpath: python/compile.sh resolves -o relative to its own cwd.
    local bin_distpath="${DEB_BUILD_DIR}/pyinstaller"
    log_step "Building the ${DEB_LANGUAGE} executable payload..."
    _build_onedir "$(pwd)/${bin_distpath}"
    local built_dir="${bin_distpath}/${APP_NAME}"

    # --- stage .deb tree ---------------------------------------------------
    local stage_dir="${DEB_BUILD_DIR}/${DEB_PKG_NAME}_${deb_version}_${deb_arch}"
    rm -rf "${stage_dir}"
    mkdir -p "${stage_dir}"
    log_step "Staging .deb tree at ${stage_dir}..."
    cp -a "${DEB_SRC_CONTROL}" "${stage_dir}/"
    chmod 0755 "${stage_dir}/DEBIAN"/*inst* "${stage_dir}/DEBIAN"/*rm* 2>/dev/null || true
    local item bn
    for item in "${DEB_SRC_DATA}"/*; do
        bn="$(basename "${item}")"
        if [[ "${bn}" == "DEBIAN" || "${bn}" == "Dockerfile.builder" ]]; then
            continue
        fi
        cp -a "${item}" "${stage_dir}/"
    done
    mkdir -p "${stage_dir}/usr/lib"
    cp -a "${built_dir}" "${stage_dir}/usr/lib/${APP_NAME}"
    chmod 0755 "${stage_dir}/usr/lib/${APP_NAME}/${APP_NAME}"
    mkdir -p "${stage_dir}/usr/bin"
    ln -sf "../lib/${APP_NAME}/${APP_NAME}" "${stage_dir}/usr/bin/${APP_NAME}"
    _finalize_deb_stage "${stage_dir}"

    # --- inject version / arch into control --------------------------------
    log_step "Injecting version ${deb_version} and arch ${deb_arch} into control..."
    sed -i.bak -e "s/__VERSION__/${deb_version}/g" -e "s/__ARCH__/${deb_arch}/g" "${stage_dir}/DEBIAN/control"
    rm -f "${stage_dir}/DEBIAN/control.bak"
    _inject_shlib_depends "${stage_dir}"

    # --- build .deb with dpkg-deb ------------------------------------------
    log_step "Building .deb package..."
    local deb_cmd=""
    if command -v fakeroot >/dev/null 2>&1; then
        deb_cmd="fakeroot"
    else
        log_warn "fakeroot not available — building .deb with current user ownership"
    fi
    ${deb_cmd} dpkg-deb --build "${stage_dir}" "${DEB_OUTPUT_DIR}"

    local deb_name="${DEB_PKG_NAME}_${deb_version}_${deb_arch}.deb"
    local deb_path="${DEB_OUTPUT_DIR}/${deb_name}"
    local size deb_abs
    size="$(du -h "${deb_path}" | cut -f1)"
    deb_abs="$(cd "$(dirname "${deb_path}")" && pwd)/$(basename "${deb_path}")"
    rm -rf "${DEB_BUILD_DIR}/pyinstaller" 2>/dev/null || true

    echo
    log_ok "Debian package built!"
    echo
    echo -e "  ${BOLD}Package:${RESET}  ${deb_name}"
    echo -e "  ${BOLD}Language:${RESET} ${DEB_LANGUAGE}"
    echo -e "  ${BOLD}Arch:${RESET}     ${deb_arch}"
    echo -e "  ${BOLD}Size:${RESET}     ${size}"
    echo -e "  ${BOLD}Version:${RESET}  ${deb_version}"
    echo
    echo -e "${DIM}Install with:  sudo dpkg -i ${deb_abs}${RESET}"
    echo
    local sep="────────────────────────────────────────────────────────────"
    echo -e "${GREEN}${BOLD}${sep}${RESET}"
    echo -e "${GREEN}${BOLD}  Installation package:${RESET}"
    echo -e "${GREEN}${BOLD}      ${deb_abs}${RESET}"
    echo -e "${GREEN}${BOLD}${sep}${RESET}"
}

# Build .deb packages for all 3 Debian/Ubuntu architectures (amd64, arm64,
# armhf) via Docker cross-builds — one build per arch (the builder base is the
# multi-arch ``python:3.14.9-bookworm`` image (base glibc 2.36; the produced
# package's measured floor is libc6 >= 2.35, so it runs on Ubuntu 22.04/24.04 LTS
# and Debian 12+), selected via --platform):
#   amd64 → linux/amd64
#   arm64 → linux/arm64
#   armhf → linux/arm/v7
# Output: dist/deb/hsync-rendezvous_<ver>_<arch>.deb
build_deb_all() {
    local version deb_version
    version="$(get_version)"
    deb_version="$(_semver_to_debian "${version}")"
    log_step "Building ${DEB_PKG_NAME} v${version} for all 3 Debian/Ubuntu architectures..."
    if [[ ! -d "${DEB_SRC_CONTROL}" ]]; then
        log_error "DEBIAN control directory missing: ${DEB_SRC_CONTROL}"
        exit 1
    fi
    mkdir -p "${DEB_OUTPUT_DIR}"

    # Monorepo root: mounts hsync-rendezvous AND hsync-common (the Poetry path
    # dependency) into the container at /repo.
    local repo_root
    repo_root="$(cd "${SCRIPT_DIR}/.." && pwd)"

    ensure_qemu_binfmt qemu-aarch64 qemu-arm

    local -A arch_docker_platform
    arch_docker_platform["amd64"]="linux/amd64"
    arch_docker_platform["arm64"]="linux/arm64"
    arch_docker_platform["armhf"]="linux/arm/v7"

    local -a deb_archs=("amd64" "arm64" "armhf")
    local out_abs
    out_abs="$(cd "${DEB_OUTPUT_DIR}" && pwd)"
    # The container workdir is python/, so a relative distpath would land under
    # python/ instead of the repo-root build/: the build tree and the package
    # output are therefore mounted explicitly (/build and /out) and addressed
    # with absolute paths inside the container.
    local build_abs
    mkdir -p "${BUILD_DIR}"
    build_abs="$(cd "${BUILD_DIR}" && pwd)"

    # Container-side staging script: the staging tree and the built payload are
    # addressed under the /build mount (the repo-root build/ dir, mounted
    # because the container workdir is python/), and the finished package is
    # written to the /out mount (the host dist/deb). Both are arch-independent.
    local stage_script
    stage_script=$(cat <<'EOS'
set -eux
deb_arch="$1"; deb_version="$2"; host_uid="$3"; host_gid="$4"
APP_NAME=hsync-rendezvous
stage="/build/deb-all/${deb_arch}/stage"
built="/build/deb-all/${deb_arch}/pyinstaller/${APP_NAME}"
rm -rf "${stage}"
mkdir -p "${stage}"
cp -a ../packaging/deb/DEBIAN "${stage}/"
chmod 0755 "${stage}/DEBIAN"/*inst* "${stage}/DEBIAN"/*rm* 2>/dev/null || true
for item in ../packaging/deb/*; do
    bn="$(basename "${item}")"
    if [ "${bn}" = "DEBIAN" ] || [ "${bn}" = "Dockerfile.builder" ]; then continue; fi
    cp -a "${item}" "${stage}/"
done
chmod 0755 "${stage}"
mkdir -p "${stage}/usr/lib"
cp -a "${built}" "${stage}/usr/lib/${APP_NAME}"
find "${stage}/usr" -type d -exec chmod 0755 {} +
find "${stage}/usr" -type f -exec chmod 0644 {} +
chmod 0755 "${stage}/usr/lib/${APP_NAME}/${APP_NAME}"
mkdir -p "${stage}/usr/bin"
ln -sf "../lib/${APP_NAME}/${APP_NAME}" "${stage}/usr/bin/${APP_NAME}"
man="${stage}/usr/share/man/man1/${APP_NAME}.1"
[ -f "${man}" ] && gzip -n -9 -f "${man}"
sed -i -e "s/__VERSION__/${deb_version}/g" -e "s/__ARCH__/${deb_arch}/g" "${stage}/DEBIAN/control"
bin="${stage}/usr/lib/${APP_NAME}/${APP_NAME}"
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
    tmp="$(mktemp -d)"
    mkdir -p "${tmp}/debian"
    printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "${APP_NAME}" "${APP_NAME}" > "${tmp}/debian/control"
    deps="$(cd "${tmp}" && dpkg-shlibdeps -O --ignore-missing-info "${bin}" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
    rm -rf "${tmp}"
    if [ -n "${deps}" ]; then
        sed -i "s/^Depends: \(.*\)$/Depends: \1, ${deps}/" "${stage}/DEBIAN/control"
        echo "Added shared-library dependencies: ${deps}"
    else
        echo 'WARNING: dpkg-shlibdeps resolved no dependencies' >&2
    fi
else
    echo 'WARNING: dpkg-shlibdeps not installed; libc6 dependency not added to control' >&2
fi
fakeroot dpkg-deb --build "${stage}" /out
chmod 0644 "/out/${APP_NAME}_${deb_version}_${deb_arch}.deb"
chown -R "${host_uid}:${host_gid}" /build "/out/${APP_NAME}_${deb_version}_${deb_arch}.deb"
EOS
)

    for deb_arch in "${deb_archs[@]}"; do
        local docker_platform="${arch_docker_platform[${deb_arch}]}"
        local builder_tag="${DEB_ALL_BUILDER_IMAGE_PREFIX}:${deb_arch}"
        local bin_dir="${DEB_ALL_BUILD_DIR}/${deb_arch}/pyinstaller"
        mkdir -p "${bin_dir}"
        echo
        log_step "─── ${deb_arch} build ───────────────────────────────────────"

        log_step "Building Docker image ${builder_tag}..."
        DOCKER_BUILDKIT=1 docker build --platform "${docker_platform}" --build-arg TARGET_PLATFORM="${docker_platform}" -t "${builder_tag}" -f "${DEB_DIR}/Dockerfile.builder" "${DEB_DIR}"

        # --- binary build in container (per-language dispatch) ----------------
        # Run as the host uid:gid so the bundle written under the mounted /build
        # and the poetry caches stay caller-owned; HOME/XDG_CACHE_HOME point at
        # /tmp because an arbitrary uid has no writable home.
        log_step "Compiling ${deb_arch} binary inside container (${DEB_LANGUAGE})..."
        local build_cmd
        build_cmd="$(_container_build_cmd "${deb_arch}")"
        docker run --rm --platform "${docker_platform}" -u "$(id -u):$(id -g)" -e HOME=/tmp -e XDG_CACHE_HOME=/tmp -v "${repo_root}:/repo" -v "${build_abs}:/build" -w /repo/hsync-rendezvous/python -e LC_ALL=C -e PYTHONWARNINGS=ignore -e PIP_DEFAULT_TIMEOUT=300 -e PIP_RETRIES=10 -e POETRY_REQUESTS_TIMEOUT=300 "${builder_tag}" bash -c "${build_cmd}"

        if [[ ! -d "${bin_dir}/${APP_NAME}" ]]; then
            log_error "onedir bundle not produced for ${deb_arch}"
            exit 1
        fi

        # --- stage + dpkg-deb in container (target-arch dpkg environment) ------
        log_step "Staging .deb tree and building package for ${deb_arch}..."
        docker run --rm --platform "${docker_platform}" -v "${repo_root}:/repo" -v "${build_abs}:/build" -v "${out_abs}:/out" -w /repo/hsync-rendezvous/python "${builder_tag}" bash -c "${stage_script}" stage "${deb_arch}" "${deb_version}" "$(id -u)" "$(id -g)"

        local deb_name="${DEB_PKG_NAME}_${deb_version}_${deb_arch}.deb"
        local deb_path="${out_abs}/${deb_name}"
        if [[ ! -f "${deb_path}" ]]; then
            log_error ".deb not produced for ${deb_arch} at ${deb_path}"
            exit 1
        fi
        local pkg_size
        pkg_size="$(du -h "${deb_path}" | cut -f1)"
        log_ok "  → ${deb_name} (${pkg_size})"
    done

    echo
    log_ok "All 3 Debian packages built!"
    echo
    echo -e "  ${BOLD}Version:${RESET}   ${deb_version}"
    echo -e "  ${BOLD}Language:${RESET}  ${DEB_LANGUAGE}"
    echo -e "  ${BOLD}Output:${RESET}    ${out_abs}/"
    echo
    echo -e "${DIM}Install with:  sudo dpkg -i ${out_abs}/${DEB_PKG_NAME}_${deb_version}_<arch>.deb${RESET}"
}

# -----------------------------------------------------------------------------
# RPM package build (RHEL/Rocky/Alma/Fedora)
# -----------------------------------------------------------------------------

readonly RPM_DIR="packaging/rpm"
readonly RPM_SPEC="${RPM_DIR}/hsync-rendezvous.spec"
readonly RPM_PKG_NAME="${APP_NAME}"
readonly RPM_OUTPUT_DIR="${OUTPUT_BASE}/rpm"
readonly RPM_BUILD_DIR="${BUILD_DIR}/rpm"
readonly RPM_ALL_BUILD_DIR="${BUILD_DIR}/rpm-all"
readonly RPM_BUILDER_IMAGE_PREFIX="hsync-rendezvous-rpm-builder"

# Stage a buildroot for rpmbuild: Debian payload (usr/) + the PyInstaller
# --onedir bundle under /usr/lib/hsync-rendezvous + /usr/bin symlink + gzipped man
# page. No /etc conffile is shipped (the group-keys dir is created in %post).
# $1 = stage_dir   $2 = built onedir dir
_stage_rpm_buildroot() {
    local stage_dir="$1" built_dir="$2"
    rm -rf "${stage_dir}"
    mkdir -p "${stage_dir}"

    local item bn
    for item in "${DEB_SRC_DATA}"/*; do
        bn="$(basename "${item}")"
        if [[ "${bn}" == "DEBIAN" || "${bn}" == "Dockerfile.builder" ]]; then
            continue
        fi
        cp -a "${item}" "${stage_dir}/"
    done

    mkdir -p "${stage_dir}/usr/lib"
    cp -a "${built_dir}" "${stage_dir}/usr/lib/${APP_NAME}"
    chmod 0755 "${stage_dir}/usr/lib/${APP_NAME}/${APP_NAME}"

    mkdir -p "${stage_dir}/usr/bin"
    ln -sf "../lib/${APP_NAME}/${APP_NAME}" "${stage_dir}/usr/bin/${APP_NAME}"

    find "${stage_dir}/usr" -type d -exec chmod 0755 {} + 2>/dev/null || true
    find "${stage_dir}/usr" -type f -exec chmod 0644 {} + 2>/dev/null || true
    chmod 0755 "${stage_dir}/usr/lib/${APP_NAME}/${APP_NAME}"
    local man="${stage_dir}/usr/share/man/man1/${APP_NAME}.1"
    [[ -f "${man}" ]] && gzip -n -9 -f "${man}"
}

# Render the spec with the resolved RPM version and echo its path.
# $1 = version (SemVer)   $2 = work dir
_render_rpm_spec() {
    local version="$1" work_dir="$2"
    local rpm_version rendered
    rpm_version="$(_semver_to_rpm "${version}")"
    rendered="${work_dir}/hsync-rendezvous.spec"
    sed "s/__VERSION__/${rpm_version}/g" "${RPM_SPEC}" > "${rendered}"
    printf '%s' "${rendered}"
}

# Build a .rpm package for the host architecture (native build, no Docker).
build_rpm() {
    local version rpm_arch
    version="$(get_version)"
    rpm_arch="$(_arch_to_rpm "${ARCH_NAME}")"

    log_step "Building ${RPM_PKG_NAME} v${version} for ${rpm_arch} (host build)..."

    if ! command -v rpmbuild >/dev/null 2>&1; then
        log_error "rpmbuild is required for the rpm target."
        log_info "Install it with: dnf install rpm-build (RHEL/Rocky/Fedora)."
        exit 1
    fi
    mkdir -p "${RPM_OUTPUT_DIR}" "${RPM_BUILD_DIR}"

    local bin_distpath="${RPM_BUILD_DIR}/pyinstaller"
    log_step "Building the ${DEB_LANGUAGE} executable payload..."
    _build_onedir "$(pwd)/${bin_distpath}"
    local built_dir="${bin_distpath}/${APP_NAME}"

    _stage_rpm_buildroot "${RPM_BUILD_DIR}/pkg" "${built_dir}"
    local stage_dir
    stage_dir="$(cd "${RPM_BUILD_DIR}/pkg" && pwd)"
    local spec_path
    spec_path="$(_render_rpm_spec "${version}" "${RPM_BUILD_DIR}")"

    log_step "Building .rpm with rpmbuild..."
    local spec_abs topdir_abs dbpath_abs
    spec_abs="$(cd "$(dirname "${spec_path}")" && pwd)/$(basename "${spec_path}")"
    mkdir -p "${RPM_BUILD_DIR}/rpmbuild" "${RPM_BUILD_DIR}/rpmdb"
    topdir_abs="$(cd "${RPM_BUILD_DIR}/rpmbuild" && pwd)"
    dbpath_abs="$(cd "${RPM_BUILD_DIR}/rpmdb" && pwd)"
    rpmbuild -bb "${spec_abs}" \
        --define "pkgdir ${stage_dir}" \
        --define "_topdir ${topdir_abs}" \
        --define "_dbpath ${dbpath_abs}"

    local rpm_file
    rpm_file="$(ls "${RPM_BUILD_DIR}/rpmbuild/RPMS"/*/*.rpm 2>/dev/null | head -1)"
    [[ -n "${rpm_file}" ]] || { log_error "rpmbuild produced no package"; exit 1; }
    mv -f "${rpm_file}" "${RPM_OUTPUT_DIR}/"

    rm -rf "${RPM_BUILD_DIR}/pyinstaller" 2>/dev/null || true

    local rpm_name rpm_path size
    rpm_name="$(basename "$(ls "${RPM_OUTPUT_DIR}"/*.rpm 2>/dev/null | head -1)")"
    rpm_path="${RPM_OUTPUT_DIR}/${rpm_name}"
    size="$(du -h "${rpm_path}" | cut -f1)"
    echo
    log_ok "RPM package built!"
    echo
    echo -e "  ${BOLD}Package:${RESET}  ${rpm_name}"
    echo -e "  ${BOLD}Language:${RESET} ${DEB_LANGUAGE}"
    echo -e "  ${BOLD}Arch:${RESET}     ${rpm_arch}"
    echo -e "  ${BOLD}Size:${RESET}     ${size}"
    echo
    echo -e "${DIM}Install with:  sudo dnf install ${rpm_path}${RESET}"
}

# Build .rpm packages for x86_64 and aarch64 via Docker + qemu on the Rocky 9
# baseline (separate binary build from the Debian one).
build_rpm_all() {
    local version
    version="$(get_version)"

    log_step "Building ${RPM_PKG_NAME} v${version} for x86_64 and aarch64..."

    if ! command -v docker >/dev/null 2>&1; then
        log_error "docker is required for the rpm-all target."
        exit 1
    fi
    mkdir -p "${RPM_OUTPUT_DIR}"

    local repo_root
    repo_root="$(cd "${SCRIPT_DIR}/.." && pwd)"
    local out_abs
    out_abs="$(cd "${RPM_OUTPUT_DIR}" && pwd)"
    local build_abs
    mkdir -p "${BUILD_DIR}"
    build_abs="$(cd "${BUILD_DIR}" && pwd)"

    ensure_qemu_binfmt qemu-aarch64

    local -A arch_docker_platform
    arch_docker_platform["x86_64"]="linux/amd64"
    arch_docker_platform["aarch64"]="linux/arm64"

    local -a rpm_archs=("x86_64" "aarch64")

    for rpm_arch in "${rpm_archs[@]}"; do
        local docker_platform="${arch_docker_platform[${rpm_arch}]}"
        local builder_tag="${RPM_BUILDER_IMAGE_PREFIX}:${rpm_arch}"
        local bin_dir="${RPM_ALL_BUILD_DIR}/${rpm_arch}/pyinstaller"
        mkdir -p "${bin_dir}"

        echo
        log_step "─── ${rpm_arch} build ───────────────────────────────────────"

        log_step "Building Docker image ${builder_tag}..."
        DOCKER_BUILDKIT=1 docker build \
            --platform "${docker_platform}" \
            --build-arg TARGET_PLATFORM="${docker_platform}" \
            -t "${builder_tag}" \
            -f "${RPM_DIR}/Dockerfile.builder" \
            "${RPM_DIR}"

        log_step "Compiling ${rpm_arch} binary inside container (${DEB_LANGUAGE})..."
        local build_cmd
        build_cmd="$(_container_rpm_build_cmd "${rpm_arch}")"
        docker run --rm \
            --platform "${docker_platform}" \
            -u "$(id -u):$(id -g)" \
            -e HOME=/tmp -e XDG_CACHE_HOME=/tmp \
            -v "${repo_root}:/repo" \
            -v "${build_abs}:/build" \
            -w /repo/hsync-rendezvous/python \
            -e LC_ALL=C -e PYTHONWARNINGS=ignore \
            -e PIP_DEFAULT_TIMEOUT=300 -e PIP_RETRIES=10 \
            -e POETRY_REQUESTS_TIMEOUT=300 \
            -e HSYNC_VERSION="${version}" \
            "${builder_tag}" \
            bash -c "${build_cmd}"

        local built_dir="${bin_dir}/${APP_NAME}"
        [[ -d "${built_dir}" ]] || { log_error "onedir bundle not produced for ${rpm_arch}"; exit 1; }
        log_ok "${rpm_arch} binary ready ($(du -sh "${built_dir}" | cut -f1))"

        local stage_dir="${RPM_ALL_BUILD_DIR}/${rpm_arch}/pkg"
        local spec_path
        spec_path="$(_render_rpm_spec "${version}" "${RPM_ALL_BUILD_DIR}/${rpm_arch}")"
        _stage_rpm_buildroot "${stage_dir}" "${built_dir}"
        stage_dir="$(cd "${stage_dir}" && pwd)"
        local spec_abs
        spec_abs="$(cd "$(dirname "${spec_path}")" && pwd)/$(basename "${spec_path}")"

        log_step "Building .rpm for ${rpm_arch}..."
        docker run --rm \
            --platform "${docker_platform}" \
            -u "$(id -u):$(id -g)" \
            -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
            -v "${stage_dir}:/pkg:ro" \
            -v "${spec_abs}:/hsync.spec:ro" \
            -v "${out_abs}:/out" \
            -w /tmp \
            "${builder_tag}" \
            bash -c "
                set -euo pipefail
                topdir=/tmp/rpmbuild-\$\$
                mkdir -p \"\${topdir}/db\"
                rpmbuild -bb /hsync.spec \
                    --define 'pkgdir /pkg' \
                    --define \"_topdir \${topdir}\" \
                    --define \"_dbpath \${topdir}/db\"
                out_rpm=\$(ls \${topdir}/RPMS/*/*.rpm | head -1)
                cp \"\${out_rpm}\" /out/
                chmod 0644 \"/out/\$(basename \"\${out_rpm}\")\"
                chown \"\${HOST_UID}:\${HOST_GID}\" \"/out/\$(basename \"\${out_rpm}\")\"
                rm -rf \"\${topdir}\"
            "

        local rpm_file
        rpm_file="$(ls "${out_abs}/${RPM_PKG_NAME}-"*".${rpm_arch}.rpm" 2>/dev/null | head -1)"
        [[ -n "${rpm_file}" ]] || { log_error ".rpm not produced for ${rpm_arch}"; exit 1; }
        log_ok "  → $(basename "${rpm_file}") ($(du -h "${rpm_file}" | cut -f1))"
    done

    echo
    log_ok "RPM packages built!"
    echo
    echo -e "  ${BOLD}Version:${RESET}   ${version}"
    echo -e "  ${BOLD}Language:${RESET}  ${DEB_LANGUAGE}"
    echo -e "  ${BOLD}Output:${RESET}    ${out_abs}/"
    echo
    echo -e "${DIM}Install with:  sudo dnf install ${out_abs}/${RPM_PKG_NAME}-${version}-1.el9.<arch>.rpm${RESET}"
}

# -----------------------------------------------------------------------------
# Standalone executables
# -----------------------------------------------------------------------------

# Build the standalone executable for the host OS/arch.
# Output: dist/<os>-<arch>/hsync-rendezvous[.exe]
build_native() {
    local version out_abs bin_path size
    version="$(get_version)"

    log_step "Building ${APP_NAME} v${version} for ${PLATFORM}..."
    mkdir -p "${OUTPUT_DIR}"
    out_abs="$(cd "${OUTPUT_DIR}" && pwd)"

    # The resolved version is exported so the per-language script stamps the
    # same version (it reads HSYNC_VERSION).
    export HSYNC_VERSION="${version}"
    _build_native "${out_abs}"

    bin_path="${OUTPUT_DIR}/${APP_NAME}${BIN_EXT}"
    size="$(du -h "${bin_path}" | cut -f1)"

    echo
    log_ok "Build successful!"
    echo
    echo -e "  ${BOLD}Binary:${RESET}   ${bin_path}"
    echo -e "  ${BOLD}Platform:${RESET} ${PLATFORM}"
    echo -e "  ${BOLD}Language:${RESET} ${DEB_LANGUAGE}"
    echo -e "  ${BOLD}Size:${RESET}     ${size}"
    echo -e "  ${BOLD}Version:${RESET}  ${version}"
    echo
    echo -e "${DIM}Run with: ./${bin_path} --version${RESET}"
}

# Build standalone executables for Raspberry Pi OS, one per supported
# architecture: armhf (32-bit, armv7) and arm64 (64-bit, aarch64). PyInstaller
# cannot cross-compile, so each binary is produced by running the selected
# language's script inside an emulated python:3.14.9-bookworm container (Raspberry
# Pi OS Bookworm is Debian 12 / glibc 2.36; the produced binaries require
# libc6 >= 2.35, so Bookworm runs them and Bullseye's 2.31 does not).
#
# Output: dist/rpi/<arch>/hsync-rendezvous
build_rpi() {
    local version
    version="$(get_version)"

    log_step "Building ${APP_NAME} v${version} for Raspberry Pi OS (armhf, arm64)..."

    if ! command -v docker >/dev/null 2>&1; then
        log_error "docker is required for the rpi target."
        exit 1
    fi
    if [[ ! -f "${RPI_DOCKERFILE}" ]]; then
        log_error "Builder Dockerfile missing: ${RPI_DOCKERFILE}"
        exit 1
    fi

    # Monorepo root: mounts hsync-rendezvous AND hsync-common (the Poetry path
    # dependency) into the container at /repo.
    local repo_root
    repo_root="$(cd "${SCRIPT_DIR}/.." && pwd)"

    ensure_qemu_binfmt qemu-arm qemu-aarch64

    local -A arch_docker_platform
    arch_docker_platform["armhf"]="linux/arm/v7"
    arch_docker_platform["arm64"]="linux/arm64"

    local -a rpi_archs=("armhf" "arm64")
    local arch
    for arch in "${rpi_archs[@]}"; do
        local docker_platform="${arch_docker_platform[${arch}]}"
        local builder_tag="${RPI_BUILDER_IMAGE_PREFIX}:${arch}"
        local out_dir="${RPI_OUTPUT_DIR}/${arch}"
        local out_abs
        mkdir -p "${out_dir}"
        out_abs="$(cd "${out_dir}" && pwd)"

        echo
        log_step "─── ${arch} build ───────────────────────────────────────"

        log_step "Building Docker image ${builder_tag}..."
        DOCKER_BUILDKIT=1 docker build \
            --platform "${docker_platform}" \
            --build-arg TARGET_PLATFORM="${docker_platform}" \
            -t "${builder_tag}" \
            -f "${RPI_DOCKERFILE}" \
            "${DEB_DIR}"

        # The per-language script installs its dependencies into a
        # container-local venv (HOME=/tmp) so the mounted source tree stays
        # pristine; only the produced executable is written back under /out.
        local build_cmd
        build_cmd="$(_container_native_cmd "/out")"
        log_step "Compiling ${arch} binary inside container (${DEB_LANGUAGE})..."
        docker run --rm \
            --platform "${docker_platform}" \
            -u "$(id -u):$(id -g)" \
            -e HOME=/tmp -e XDG_CACHE_HOME=/tmp \
            -v "${repo_root}:/repo" \
            -v "${out_abs}:/out" \
            -w /repo/hsync-rendezvous/python \
            -e LC_ALL=C -e PYTHONWARNINGS=ignore \
            -e PIP_DEFAULT_TIMEOUT=300 -e PIP_RETRIES=10 \
            -e POETRY_REQUESTS_TIMEOUT=300 \
            -e HSYNC_VERSION="${version}" \
            "${builder_tag}" \
            bash -c "${build_cmd}"

        local bin_path="${out_dir}/${APP_NAME}"
        if [[ ! -f "${bin_path}" ]]; then
            log_error "${arch} executable not produced at ${bin_path}"
            exit 1
        fi
        log_ok "  → ${RPI_OUTPUT_DIR}/${arch}/${APP_NAME} ($(du -h "${bin_path}" | cut -f1))"
    done

    echo
    log_ok "Raspberry Pi executables built!"
    echo
    echo -e "  ${BOLD}Language:${RESET} ${DEB_LANGUAGE}"
    echo -e "  ${BOLD}Version:${RESET}  ${version}"
    echo -e "  ${BOLD}Output:${RESET}   ${RPI_OUTPUT_DIR}/<arch>/${APP_NAME}"
    echo
    local sep="────────────────────────────────────────────────────────────"
    echo -e "${GREEN}${BOLD}${sep}${RESET}"
    echo -e "${GREEN}${BOLD}  Raspberry Pi executables:${RESET}"
    for arch in "${rpi_archs[@]}"; do
        echo -e "${GREEN}${BOLD}      $(pwd)/${RPI_OUTPUT_DIR}/${arch}/${APP_NAME}${RESET}"
    done
    echo -e "${GREEN}${BOLD}${sep}${RESET}"
}

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------

main() {
    local do_clean=false
    local target="native"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--clean)
                do_clean=true
                shift
                ;;
            -t|--target)
                [[ $# -ge 2 ]] || { log_error "--target requires a value"; exit 1; }
                target="$2"
                shift 2
                ;;
            -l|--language)
                [[ $# -ge 2 ]] || { log_error "--language requires a value"; exit 1; }
                DEB_LANGUAGE="$2"
                shift 2
                ;;
            -v|--version)
                [[ $# -ge 2 ]] || { log_error "--version requires a value"; exit 1; }
                VERSION_OVERRIDE="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information."
                exit 1
                ;;
        esac
    done

    cd "${SCRIPT_DIR}"

    echo -e "${BOLD}HSYNC Rendezvous - Build${RESET}"
    echo -e "${DIM}─────────────────────${RESET}"
    echo

    # The language must have a packaging path before any target runs.
    validate_language

    case "${target}" in
        native)
            if [[ ! -f "${PYPROJECT}" ]]; then
                log_error "${PYPROJECT} not found. Run from the python/ project."
                exit 1
            fi
            if [[ "${do_clean}" == true ]]; then
                clean_artifacts
                echo
            fi
            build_native
            ;;
        rpi)
            if [[ "${do_clean}" == true ]]; then
                log_step "Cleaning rpi artifacts..."
                rm -rf "${RPI_OUTPUT_DIR}"
                docker image rm -f \
                    "${RPI_BUILDER_IMAGE_PREFIX}:armhf" \
                    "${RPI_BUILDER_IMAGE_PREFIX}:arm64" >/dev/null 2>&1 || true
                echo
            fi
            build_rpi
            ;;
        deb)
            if [[ "${do_clean}" == true ]]; then
                clean_artifacts
                echo
            fi
            build_deb
            ;;
        deb-all)
            if ! command -v docker >/dev/null 2>&1; then
                log_error "docker is required for the deb-all target."
                exit 1
            fi
            if [[ "${do_clean}" == true ]]; then
                clean_artifacts
                docker image rm -f "${DEB_ALL_BUILDER_IMAGE_PREFIX}:amd64" "${DEB_ALL_BUILDER_IMAGE_PREFIX}:arm64" "${DEB_ALL_BUILDER_IMAGE_PREFIX}:armhf" >/dev/null 2>&1 || true
                echo
            fi
            build_deb_all
            ;;
        rpm)
            if [[ "${do_clean}" == true ]]; then
                log_step "Cleaning rpm artifacts..."
                rm -rf "${RPM_OUTPUT_DIR}" "${RPM_BUILD_DIR}"
                echo
            fi
            build_rpm
            ;;
        rpm-all)
            if ! command -v docker >/dev/null 2>&1; then
                log_error "docker is required for the rpm-all target."
                exit 1
            fi
            if [[ "${do_clean}" == true ]]; then
                log_step "Cleaning rpm-all artifacts..."
                rm -rf "${RPM_OUTPUT_DIR}" "${RPM_ALL_BUILD_DIR}"
                docker image rm -f \
                    "${RPM_BUILDER_IMAGE_PREFIX}:x86_64" \
                    "${RPM_BUILDER_IMAGE_PREFIX}:aarch64" >/dev/null 2>&1 || true
                echo
            fi
            build_rpm_all
            ;;
        *)
            log_error "Unknown target: ${target}"
            echo "Supported targets: native, rpi, deb, deb-all, rpm, rpm-all"
            exit 1
            ;;
    esac
}

main "$@"
