#!/usr/bin/env bash
# ==============================================================================
# Argus Monitoring Daemon - Universal Installer & Management Tool
# Repository: https://github.com/ahbandegan/argus
# Supports: Ubuntu 20.04+, Debian 11+, RHEL/Rocky 8+, Arch Linux, openSUSE
# ==============================================================================

set -euo pipefail

# Visual formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

REPO_URL="https://github.com/ahbandegan/argus.git"
INSTALL_BIN="/usr/local/bin/argus"
CONFIG_DIR="/etc/argus"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SERVICE_FILE="/etc/systemd/system/argus.service"
LOG_DIR="/var/log/argus"
SERVICE_USER="argus_svc"

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_succ()  { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
    █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
   ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
   ███████║██████╔╝██║  ███╗██║   ██║███████╗
   ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
   ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
      Linux Kernel Security & Telemetry Daemon
EOF
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "This command must be run as root or with sudo."
        echo "Example: sudo bash -c \"\$(curl -fsSL https://github.com/ahbandegan/argus/raw/main/install.sh)\" @ install"
        exit 1
    fi
}

check_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_err "Argus requires a Linux kernel."
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Dependency Installation
# ------------------------------------------------------------------------------
install_dependencies() {
    log_info "Step 1/6: Detecting package manager and installing build dependencies..."

    if command -v apt-get &>/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq build-essential cmake git openssl libssl-dev curl jq
    elif command -v dnf &>/dev/null; then
        dnf install -y -q gcc-c++ cmake make git openssl openssl-devel curl jq
    elif command -v yum &>/dev/null; then
        yum install -y -q gcc-c++ cmake3 make git openssl openssl-devel curl jq
        if ! command -v cmake &>/dev/null && command -v cmake3 &>/dev/null; then
            ln -sf "$(command -v cmake3)" /usr/local/bin/cmake
        fi
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm --needed base-devel cmake git openssl curl jq
    elif command -v zypper &>/dev/null; then
        zypper --non-interactive install gcc-c++ cmake make git openssl libopenssl-devel curl jq
    else
        log_warn "Unknown package manager. Ensure cmake (>=3.20), g++ (C++20 capable), git, openssl, and curl are installed."
    fi

    log_succ "Build dependencies installed."
}

# ------------------------------------------------------------------------------
# Source Acquisition (Local or Remote Clone)
# ------------------------------------------------------------------------------
acquire_source() {
    # Check if currently running inside an existing source repo
    if [[ -f "CMakeLists.txt" && -d "src" ]]; then
        SOURCE_DIR="$(pwd)"
        IS_TEMPORARY_DIR=false
        log_info "Using local source directory: ${SOURCE_DIR}"
    else
        IS_TEMPORARY_DIR=true
        SOURCE_DIR=$(mktemp -d /tmp/argus-source-XXXXXX)
        log_info "Cloning latest source from ${REPO_URL} into ${SOURCE_DIR}..."
        git clone --depth 1 "${REPO_URL}" "${SOURCE_DIR}"
    fi
}

cleanup_source() {
    if [[ "${IS_TEMPORARY_DIR:-false}" == "true" && -n "${SOURCE_DIR:-}" && -d "${SOURCE_DIR}" ]]; then
        rm -rf "${SOURCE_DIR}"
    fi
}

# ------------------------------------------------------------------------------
# Build Binary
# ------------------------------------------------------------------------------
build_binary() {
    log_info "Step 2/6: Compiling Argus daemon in Release mode (-O3)..."

    local nproc_count
    nproc_count=$(nproc 2>/dev/null || echo 2)
    local build_dir="${SOURCE_DIR}/build"

    cmake -B "${build_dir}" -S "${SOURCE_DIR}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_FLAGS_RELEASE="-O3"

    cmake --build "${build_dir}" --config Release -j"${nproc_count}"

    if [[ ! -f "${build_dir}/argus" ]]; then
        log_err "Compilation failed. Binary not found at ${build_dir}/argus"
        cleanup_source
        exit 1
    fi

    log_succ "Argus compiled successfully."
}

# ------------------------------------------------------------------------------
# User & Group Setup
# ------------------------------------------------------------------------------
setup_user() {
    log_info "Step 3/6: Ensuring unprivileged system user '${SERVICE_USER}' exists..."

    if ! getent group "${SERVICE_USER}" &>/dev/null; then
        groupadd --system "${SERVICE_USER}"
        log_info "Created system group '${SERVICE_USER}'."
    fi

    if ! id -u "${SERVICE_USER}" &>/dev/null; then
        useradd --system \
            --gid "${SERVICE_USER}" \
            --no-create-home \
            --home-dir /nonexistent \
            --shell /usr/sbin/nologin \
            --comment "Argus Monitoring Daemon Service Account" \
            "${SERVICE_USER}"
        log_info "Created system user '${SERVICE_USER}'."
    fi

    mkdir -p "${LOG_DIR}" "${CONFIG_DIR}"
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"
    chmod 750 "${LOG_DIR}"
}

# ------------------------------------------------------------------------------
# Configuration & Token Generation
# ------------------------------------------------------------------------------
setup_config() {
    log_info "Step 4/6: Configuring security settings and API authentication token..."

    local api_token=""

    # Preserve existing token if config file exists
    if [[ -f "${CONFIG_FILE}" ]]; then
        api_token=$(grep -o '"api_token": *"[^"]*"' "${CONFIG_FILE}" | cut -d'"' -f4 || echo "")
        log_info "Existing configuration found at ${CONFIG_FILE}. Preserving token."
    fi

    if [[ -z "${api_token}" || "${api_token}" == "CHANGE_ME"* ]]; then
        api_token=$(openssl rand -hex 32)
        log_succ "Generated new 256-bit cryptographically secure Bearer token."
    fi

    cat << EOF > "${CONFIG_FILE}"
{
  "server": {
    "bind_address": "127.0.0.1",
    "port": 9100,
    "threads": 4,
    "require_auth_for_health": false
  },
  "security": {
    "api_token": "${api_token}",
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 120,
      "burst_capacity": 30
    },
    "drop_privileges": {
      "enabled": true,
      "user": "${SERVICE_USER}",
      "group": "${SERVICE_USER}"
    },
    "tls": {
      "enabled": false,
      "cert_file": "${CONFIG_DIR}/certs/server.crt",
      "key_file": "${CONFIG_DIR}/certs/server.key"
    }
  },
  "monitoring": {
    "sample_interval_ms": 1000,
    "connection_audit_history_size": 1000,
    "disk_mount_filter": [
      "/",
      "/home",
      "/var"
    ]
  },
  "logging": {
    "level": "INFO",
    "log_file": "${LOG_DIR}/argus.log"
  }
}
EOF

    chown "${SERVICE_USER}:${SERVICE_USER}" "${CONFIG_FILE}"
    chmod 600 "${CONFIG_FILE}"
    CURRENT_TOKEN="${api_token}"
}

# ------------------------------------------------------------------------------
# Install Files & Systemd Unit
# ------------------------------------------------------------------------------
install_system_files() {
    log_info "Step 5/6: Installing binary and registering hardened systemd service..."

    install -m 755 "${SOURCE_DIR}/build/argus" "${INSTALL_BIN}"

    cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=Argus - High-Performance Linux Kernel Monitoring Daemon
Documentation=https://github.com/ahbandegan/argus
After=network.target network-online.target time-sync.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}

ExecStart=${INSTALL_BIN} --config ${CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID

Restart=always
RestartSec=5s
KillMode=mixed
TimeoutStopSec=15s

StandardOutput=journal
StandardError=journal
SyslogIdentifier=argus

# Zero-Trust Sandboxing & Hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
MemoryDenyWriteExecute=true
LockPersonality=true

AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH

ConfigurationDirectory=argus
LogsDirectory=argus
RuntimeDirectory=argus

ReadOnlyPaths=/proc /sys
ReadWritePaths=${LOG_DIR}

LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "${SERVICE_FILE}"
    systemctl daemon-reload
    log_succ "Systemd service registered."
}

# ------------------------------------------------------------------------------
# Start & Verify Service
# ------------------------------------------------------------------------------
start_and_verify() {
    log_info "Step 6/6: Starting and enabling argus.service..."

    systemctl enable --now argus.service
    sleep 2

    if systemctl is-active --quiet argus.service; then
        log_succ "Argus service is ACTIVE and running."
    else
        log_err "Service failed to start cleanly. Checking logs:"
        journalctl -u argus.service -n 20 --no-pager
        exit 1
    fi
}

display_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}==============================================================================${NC}"
    echo -e "${GREEN}${BOLD}           ARGUS DAEMON SUCCESSFULLY DEPLOYED & HARDENED                     ${NC}"
    echo -e "${GREEN}${BOLD}==============================================================================${NC}"
    echo ""
    echo -e "  ${BOLD}Status:${NC}               $(systemctl is-active argus.service) (systemd: argus.service)"
    echo -e "  ${BOLD}Endpoint:${NC}             http://127.0.0.1:9100"
    echo -e "  ${BOLD}Config Path:${NC}          ${CONFIG_FILE} (mode 600)"
    echo -e "  ${BOLD}Log Path:${NC}             ${LOG_DIR}/argus.log"
    echo ""
    echo -e "  ${BOLD}API BEARER TOKEN:${NC}"
    echo -e "  ${YELLOW}${BOLD}${CURRENT_TOKEN}${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}--- Verification Commands ---${NC}"
    echo ""
    echo -e "1. ${BOLD}Health Check (Liveness Probe):${NC}"
    echo "   curl -s http://127.0.0.1:9100/api/v1/health | jq"
    echo ""
    echo -e "2. ${BOLD}Consolidated System Overview:${NC}"
    echo "   curl -s -H \"Authorization: Bearer ${CURRENT_TOKEN}\" http://127.0.0.1:9100/api/v1/overview | jq"
    echo ""
    echo -e "3. ${BOLD}Hardware Metrics (CPU Core Breakdown, RAM, Disk I/O):${NC}"
    echo "   curl -s -H \"Authorization: Bearer ${CURRENT_TOKEN}\" http://127.0.0.1:9100/api/v1/metrics/hardware | jq"
    echo ""
    echo -e "4. ${BOLD}Network Bandwidth Rates (KB/s & Packets/s):${NC}"
    echo "   curl -s -H \"Authorization: Bearer ${CURRENT_TOKEN}\" http://127.0.0.1:9100/api/v1/metrics/network | jq"
    echo ""
    echo -e "5. ${BOLD}Socket Audit & Connection Tracking (with PID Attribution):${NC}"
    echo "   curl -s -H \"Authorization: Bearer ${CURRENT_TOKEN}\" http://127.0.0.1:9100/api/v1/audit/connections | jq"
    echo ""
    echo -e "${GREEN}Installation completed successfully.${NC}"
}

# ------------------------------------------------------------------------------
# Action Handlers: Update, Uninstall, Status, Token
# ------------------------------------------------------------------------------
do_install() {
    print_banner
    check_root
    check_linux
    install_dependencies
    acquire_source
    build_binary
    setup_user
    setup_config
    install_system_files
    cleanup_source
    start_and_verify
    display_summary
}

do_update() {
    print_banner
    check_root
    check_linux
    log_info "Updating Argus daemon to latest release from ${REPO_URL}..."
    install_dependencies
    acquire_source
    build_binary
    install -m 755 "${SOURCE_DIR}/build/argus" "${INSTALL_BIN}"
    cleanup_source
    systemctl restart argus.service
    log_succ "Argus daemon updated and restarted successfully."
    do_status
}

do_uninstall() {
    print_banner
    check_root
    echo -e "${RED}${BOLD}WARNING: You are about to uninstall the Argus Monitoring Daemon.${NC}"
    read -rp "Are you sure you want to proceed? [y/N]: " confirm
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        echo "Aborted."
        exit 0
    fi

    log_info "Stopping and disabling argus.service..."
    systemctl stop argus.service 2>/dev/null || true
    systemctl disable argus.service 2>/dev/null || true

    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload

    rm -f "${INSTALL_BIN}"
    log_succ "Removed binary ${INSTALL_BIN}."

    read -rp "Do you also want to remove configuration and logs (/etc/argus, /var/log/argus)? [y/N]: " rm_conf
    if [[ "${rm_conf}" == "y" || "${rm_conf}" == "Y" ]]; then
        rm -rf "${CONFIG_DIR}" "${LOG_DIR}"
        userdel -r "${SERVICE_USER}" 2>/dev/null || true
        groupdel "${SERVICE_USER}" 2>/dev/null || true
        log_succ "Configuration and service user removed."
    fi

    log_succ "Argus has been completely uninstalled."
}

do_status() {
    print_banner
    if systemctl is-active --quiet argus.service 2>/dev/null; then
        echo -e "${GREEN}[●] Argus Daemon is ACTIVE (running)${NC}"
    else
        echo -e "${RED}[●] Argus Daemon is INACTIVE / STOPPED${NC}"
    fi

    if [[ -f "${CONFIG_FILE}" ]]; then
        local token
        token=$(grep -o '"api_token": *"[^"]*"' "${CONFIG_FILE}" | cut -d'"' -f4 || echo "N/A")
        echo -e "  Config File:    ${CONFIG_FILE}"
        echo -e "  API Token:      ${YELLOW}${token}${NC}"
    fi

    echo ""
    echo "--- Systemd Status ---"
    systemctl status argus.service --no-pager -n 5 2>/dev/null || true

    echo ""
    echo "--- Health Probe Test ---"
    if command -v curl &>/dev/null; then
        curl -s http://127.0.0.1:9100/api/v1/health || echo "Unable to connect to http://127.0.0.1:9100/api/v1/health"
        echo ""
    fi
}

do_token() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        local token
        token=$(grep -o '"api_token": *"[^"]*"' "${CONFIG_FILE}" | cut -d'"' -f4 || echo "")
        if [[ -n "${token}" ]]; then
            echo "${token}"
        else
            log_err "Token not found in ${CONFIG_FILE}"
            exit 1
        fi
    else
        log_err "Configuration file ${CONFIG_FILE} does not exist."
        exit 1
    fi
}

show_menu() {
    print_banner
    check_root
    echo -e "${BOLD}Select an action:${NC}"
    echo "  1) Install / Reinstall Argus Daemon"
    echo "  2) Update to Latest Release"
    echo "  3) Check Status & Health"
    echo "  4) Show Current API Token"
    echo "  5) Restart Service"
    echo "  6) View Live Service Logs"
    echo "  7) Uninstall Argus"
    echo "  0) Exit"
    echo ""
    read -rp "Enter choice [1-7, 0]: " choice
    case "${choice}" in
        1) do_install ;;
        2) do_update ;;
        3) do_status ;;
        4) do_token ;;
        5) systemctl restart argus.service && log_succ "Restarted argus.service" ;;
        6) journalctl -u argus.service -n 50 -f ;;
        7) do_uninstall ;;
        0) exit 0 ;;
        *) log_err "Invalid selection." ;;
    esac
}

# ------------------------------------------------------------------------------
# Entry Point & Parameter Parsing
# ------------------------------------------------------------------------------
CMD="${1:-}"

# Normalize "@ <command>" syntax (e.g. bash -c "$(curl ...)" @ install)
if [[ "${CMD}" == "@" ]]; then
    CMD="${2:-}"
fi

case "${CMD}" in
    install|--install|-i)
        do_install
        ;;
    update|upgrade|-u)
        do_update
        ;;
    uninstall|remove)
        do_uninstall
        ;;
    status|-s)
        do_status
        ;;
    token)
        do_token
        ;;
    start)
        check_root
        systemctl start argus.service
        log_succ "Started argus.service"
        ;;
    stop)
        check_root
        systemctl stop argus.service
        log_succ "Stopped argus.service"
        ;;
    restart)
        check_root
        systemctl restart argus.service
        log_succ "Restarted argus.service"
        ;;
    logs)
        journalctl -u argus.service -n 50 -f
        ;;
    help|--help|-h)
        print_banner
        echo "Usage: install.sh [command]"
        echo ""
        echo "Commands:"
        echo "  install      Compile and install Argus daemon as a systemd service"
        echo "  update       Pull latest code from GitHub, recompile, and restart"
        echo "  uninstall    Remove Argus service and binary from the system"
        echo "  status       Check daemon status and run health probe"
        echo "  token        Output the currently configured API Bearer token"
        echo "  restart      Restart the argus.service"
        echo "  logs         Tail live systemd logs"
        echo ""
        echo "One-liner remote execution:"
        echo "  sudo bash -c \"\$(curl -fsSL https://github.com/ahbandegan/argus/raw/main/install.sh)\" @ install"
        ;;
    "")
        if [[ -t 0 ]]; then
            show_menu
        else
            do_install
        fi
        ;;
    *)
        log_err "Unknown command: ${CMD}"
        echo "Run '$0 help' for available options."
        exit 1
        ;;
esac
