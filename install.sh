#!/usr/bin/env bash
# ==============================================================================
# Argus Monitoring Daemon - Automated Deployment & Installation Script
# Target: Linux (Ubuntu 22.04+, Debian 11+, RHEL/Rocky 9+, Arch Linux)
# ==============================================================================

set -euo pipefail

# Visual formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_succ()  { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

echo -e "${CYAN}${BOLD}"
cat << 'EOF'
    █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
   ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
   ███████║██████╔╝██║  ███╗██║   ██║███████╗
   ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
   ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
      Automated Production Installer
EOF
echo -e "${NC}"

# ------------------------------------------------------------------------------
# 1. Root & OS Checks
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_err "This installer must be run as root or via sudo."
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    log_err "Argus requires a Linux operating system kernel."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ------------------------------------------------------------------------------
# 2. Install Build Dependencies
# ------------------------------------------------------------------------------
log_info "Step 1/7: Detecting package manager and installing build dependencies..."

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq build-essential cmake git openssl libssl-dev curl
elif command -v dnf &>/dev/null; then
    dnf install -y -q gcc-c++ cmake make git openssl openssl-devel curl
elif command -v yum &>/dev/null; then
    yum install -y -q gcc-c++ cmake3 make git openssl openssl-devel curl
    if ! command -v cmake &>/dev/null && command -v cmake3 &>/dev/null; then
        ln -sf "$(command -v cmake3)" /usr/local/bin/cmake
    fi
elif command -v pacman &>/dev/null; then
    pacman -Sy --noconfirm --needed base-devel cmake git openssl curl
elif command -v zypper &>/dev/null; then
    zypper --non-interactive install gcc-c++ cmake make git openssl libopenssl-devel curl
else
    log_warn "Unknown package manager. Ensure cmake (>=3.20), g++ (C++20 capable), git, and OpenSSL are installed."
fi

log_succ "Build dependencies installed."

# ------------------------------------------------------------------------------
# 3. Compile in Release Mode (-O3)
# ------------------------------------------------------------------------------
log_info "Step 2/7: Compiling Argus daemon in Release mode (-O3)..."

NPROC=$(nproc 2>/dev/null || echo 2)
BUILD_DIR="${SCRIPT_DIR}/build"

cmake -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS_RELEASE="-O3"

cmake --build "$BUILD_DIR" --config Release -j"$NPROC"

if [[ ! -f "$BUILD_DIR/argus" ]]; then
    log_err "Build failed. Binary $BUILD_DIR/argus not found."
    exit 1
fi

log_succ "Argus compiled successfully."

# ------------------------------------------------------------------------------
# 4. Create Dedicated Restricted System User / Group
# ------------------------------------------------------------------------------
log_info "Step 3/7: Creating dedicated unprivileged system user 'argus_svc'..."

if ! getent group argus_svc &>/dev/null; then
    groupadd --system argus_svc
    log_info "Created system group 'argus_svc'."
fi

if ! id -u argus_svc &>/dev/null; then
    useradd --system \
        --gid argus_svc \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        --comment "Argus Monitoring Daemon Service User" \
        argus_svc
    log_info "Created system user 'argus_svc'."
else
    log_info "System user 'argus_svc' already exists."
fi

# ------------------------------------------------------------------------------
# 5. Generate Cryptographic Bearer Token & Configure
# ------------------------------------------------------------------------------
log_info "Step 4/7: Generating cryptographic Bearer token and writing /etc/argus/config.json..."

mkdir -p /etc/argus /var/log/argus
chown -R argus_svc:argus_svc /var/log/argus
chmod 750 /var/log/argus

# Generate a 256-bit cryptographically secure random token
API_TOKEN=$(openssl rand -hex 32)

cat << EOF > /etc/argus/config.json
{
  "server": {
    "bind_address": "127.0.0.1",
    "port": 9100,
    "threads": 4,
    "require_auth_for_health": false
  },
  "security": {
    "api_token": "${API_TOKEN}",
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 120,
      "burst_capacity": 30
    },
    "drop_privileges": {
      "enabled": true,
      "user": "argus_svc",
      "group": "argus_svc"
    },
    "tls": {
      "enabled": false,
      "cert_file": "/etc/argus/certs/server.crt",
      "key_file": "/etc/argus/certs/server.key"
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
    "log_file": "/var/log/argus/argus.log"
  }
}
EOF

# Strict permissions: only root and argus_svc can access
chown argus_svc:argus_svc /etc/argus/config.json
chmod 600 /etc/argus/config.json

log_succ "Configuration written to /etc/argus/config.json with 600 permissions."

# ------------------------------------------------------------------------------
# 6. Install Binary
# ------------------------------------------------------------------------------
log_info "Step 5/7: Installing binary to /usr/local/bin/argus..."

install -m 755 "$BUILD_DIR/argus" /usr/local/bin/argus
log_succ "Installed /usr/local/bin/argus."

# ------------------------------------------------------------------------------
# 7. Configure and Register Hardened Systemd Service
# ------------------------------------------------------------------------------
log_info "Step 6/7: Registering hardened systemd service (/etc/systemd/system/argus.service)..."

cat << 'EOF' > /etc/systemd/system/argus.service
[Unit]
Description=Argus - High-Performance Linux Kernel Monitoring Daemon
Documentation=https://github.com/argus-monitor/argus
After=network.target network-online.target time-sync.target
Wants=network-online.target

[Service]
Type=simple
User=argus_svc
Group=argus_svc

ExecStart=/usr/local/bin/argus --config /etc/argus/config.json
ExecReload=/bin/kill -HUP $MAINPID

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
ReadWritePaths=/var/log/argus

LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/argus.service
systemctl daemon-reload
log_succ "Hardened systemd service registered."

# ------------------------------------------------------------------------------
# 8. Enable, Start, and Verify Service
# ------------------------------------------------------------------------------
log_info "Step 7/7: Enabling and starting argus.service..."

systemctl enable --now argus.service
sleep 2

if systemctl is-active --quiet argus.service; then
    log_succ "Argus service is ACTIVE and running!"
else
    log_err "Service failed to activate cleanly. Checking journalctl logs:"
    journalctl -u argus.service -n 20 --no-pager
    exit 1
fi

# ------------------------------------------------------------------------------
# Deployment Summary & Test Commands
# ------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo -e "${GREEN}${BOLD}           ARGUS DAEMON SUCCESSFULLY DEPLOYED & HARDENED                     ${NC}"
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo ""
echo -e "  ${BOLD}Service Status:${NC}       $(systemctl is-active argus.service) (systemd: argus.service)"
echo -e "  ${BOLD}Listening Endpoint:${NC}   http://127.0.0.1:9100"
echo -e "  ${BOLD}Service User:${NC}         argus_svc"
echo -e "  ${BOLD}Config File:${NC}          /etc/argus/config.json (mode 600)"
echo -e "  ${BOLD}Log File:${NC}             /var/log/argus/argus.log"
echo ""
echo -e "  ${BOLD}GENERATED API TOKEN:${NC}"
echo -e "  ${YELLOW}${BOLD}${API_TOKEN}${NC}"
echo ""
echo -e "${CYAN}${BOLD}--- Sample Verification Commands ---${NC}"
echo ""
echo -e "1. ${BOLD}Health Check (Liveness Probe):${NC}"
echo "   curl -s http://127.0.0.1:9100/api/v1/health | jq"
echo ""
echo -e "2. ${BOLD}Consolidated System Overview:${NC}"
echo "   curl -s -H \"Authorization: Bearer ${API_TOKEN}\" http://127.0.0.1:9100/api/v1/overview | jq"
echo ""
echo -e "3. ${BOLD}Hardware Metrics (CPU breakdown, RAM, Disks):${NC}"
echo "   curl -s -H \"Authorization: Bearer ${API_TOKEN}\" http://127.0.0.1:9100/api/v1/metrics/hardware | jq"
echo ""
echo -e "4. ${BOLD}Network Bandwidth & Instantaneous Rates:${NC}"
echo "   curl -s -H \"Authorization: Bearer ${API_TOKEN}\" http://127.0.0.1:9100/api/v1/metrics/network | jq"
echo ""
echo -e "5. ${BOLD}Connection Audit & Socket Tracking (with PID attribution):${NC}"
echo "   curl -s -H \"Authorization: Bearer ${API_TOKEN}\" http://127.0.0.1:9100/api/v1/audit/connections | jq"
echo ""
echo -e "${GREEN}Deployment completed successfully.${NC}"
