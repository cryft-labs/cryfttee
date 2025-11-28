#!/bin/bash
#
# Deploy Web3Signer on Ubuntu Keyvault Server
# Target: 100.111.2.1
#
# This script sets up and runs a Web3Signer instance for BLS/TLS signing
# that Cryftee can connect to for module signing operations.
#
# Tested on: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS
#
# Prerequisites:
# - Ubuntu server with SSH access
# - Root or sudo access
# - Port 9000 available for Web3Signer
#
# Usage:
#   ./deploy-web3signer.sh              # Deploy to remote Ubuntu server
#   ./deploy-web3signer.sh --local      # Deploy on current Ubuntu machine
#   ./deploy-web3signer.sh --install    # Install Docker on remote first
#   ./deploy-web3signer.sh --env        # Generate Cryftee env vars
#

set -euo pipefail

# Configuration
KEYVAULT_HOST="${KEYVAULT_HOST:-100.111.2.1}"
KEYVAULT_USER="${KEYVAULT_USER:-root}"
WEB3SIGNER_VERSION="${WEB3SIGNER_VERSION:-24.4.0}"
WEB3SIGNER_PORT="${WEB3SIGNER_PORT:-9000}"
WEB3SIGNER_METRICS_PORT="${WEB3SIGNER_METRICS_PORT:-9001}"
DATA_DIR="/opt/web3signer"
KEYS_DIR="${DATA_DIR}/keys"
CONFIG_DIR="${DATA_DIR}/config"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

show_banner() {
    cat << 'EOF'
  __        __   _    _____   ____  _                       
  \ \      / /__| |__|___ /  / ___|(_) __ _ _ __   ___ _ __ 
   \ \ /\ / / _ \ '_ \ |_ \  \___ \| |/ _` | '_ \ / _ \ '__|
    \ V  V /  __/ |_) |__) |  ___) | | (_| | | | |  __/ |   
     \_/\_/ \___|_.__/____/  |____/|_|\__, |_| |_|\___|_|   
                                      |___/                 
    Cryftee Web3Signer Deployment Script
    Target: Ubuntu Server @ 100.111.2.1
EOF
}

# Install Docker on Ubuntu
install_docker_ubuntu() {
    log "Installing Docker on Ubuntu..."
    
    # Update package index
    apt-get update -y
    
    # Install prerequisites
    apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release
    
    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Set up the repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker Engine
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Enable and start Docker
    systemctl enable docker
    systemctl start docker
    
    # Verify installation
    docker --version
    log "Docker installed successfully!"
}

# Install Docker on remote Ubuntu server
install_docker_remote() {
    log "Installing Docker on remote Ubuntu server ${KEYVAULT_HOST}..."
    
    ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" 'bash -s' << 'DOCKEREOF'
set -e
echo "[+] Updating package index..."
apt-get update -y

echo "[+] Installing prerequisites..."
apt-get install -y ca-certificates curl gnupg lsb-release

echo "[+] Adding Docker GPG key..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "[+] Setting up Docker repository..."
echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "[+] Installing Docker Engine..."
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "[+] Enabling Docker service..."
systemctl enable docker
systemctl start docker

echo "[+] Docker version:"
docker --version
echo "[+] Docker installed successfully!"
DOCKEREOF
    
    log "Docker installation complete on ${KEYVAULT_HOST}"
}

# Generate Web3Signer configuration
generate_config() {
    cat << EOF
# Web3Signer Configuration for Cryftee
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

# HTTP Server settings
http-listen-host=0.0.0.0
http-listen-port=${WEB3SIGNER_PORT}

# Metrics (Prometheus)
metrics-enabled=true
metrics-host=0.0.0.0
metrics-port=${WEB3SIGNER_METRICS_PORT}

# Enable all CORS origins for development (restrict in production)
http-cors-origins=*
http-host-allowlist=*

# Logging
logging=INFO

# Key store type - use file-based for simplicity
key-store-path=${KEYS_DIR}

# Enable slashing protection
slashing-protection-enabled=true
slashing-protection-db-url=jdbc:h2:file:${DATA_DIR}/slashing-protection

# Network - use mainnet settings (adjustable)
network=mainnet
EOF
}

# Generate Docker Compose file
generate_docker_compose() {
    cat << EOF
version: '3.8'

services:
  web3signer:
    image: consensys/web3signer:${WEB3SIGNER_VERSION}
    container_name: cryftee-web3signer
    restart: unless-stopped
    ports:
      - "${WEB3SIGNER_PORT}:${WEB3SIGNER_PORT}"
      - "${WEB3SIGNER_METRICS_PORT}:${WEB3SIGNER_METRICS_PORT}"
    volumes:
      - ${DATA_DIR}:/data
      - ${KEYS_DIR}:/keys
      - ${CONFIG_DIR}:/config
    command:
      - --config-file=/config/web3signer.yaml
      - eth2
      - --slashing-protection-db-url=jdbc:h2:file:/data/slashing-protection
      - --key-store-path=/keys
    environment:
      - JAVA_OPTS=-Xmx512m -Xms256m
    networks:
      - cryftee-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:${WEB3SIGNER_PORT}/upcheck"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  cryftee-net:
    driver: bridge
EOF
}

# Generate systemd service file
generate_systemd_service() {
    cat << EOF
[Unit]
Description=Web3Signer for Cryftee Module Signing
Documentation=https://docs.web3signer.consensys.net/
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${DATA_DIR}
ExecStartPre=/usr/bin/docker compose -f ${CONFIG_DIR}/docker-compose.yml pull
ExecStart=/usr/bin/docker compose -f ${CONFIG_DIR}/docker-compose.yml up --remove-orphans
ExecStop=/usr/bin/docker compose -f ${CONFIG_DIR}/docker-compose.yml down
Restart=on-failure
RestartSec=10
TimeoutStartSec=120
TimeoutStopSec=30

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF
}

# Generate YAML config for Web3Signer
generate_yaml_config() {
    cat << EOF
# Web3Signer YAML Configuration
# For use with Cryftee TEE runtime

http-listen-host: "0.0.0.0"
http-listen-port: ${WEB3SIGNER_PORT}
http-cors-origins: ["*"]
http-host-allowlist: ["*"]

metrics-enabled: true
metrics-host: "0.0.0.0"
metrics-port: ${WEB3SIGNER_METRICS_PORT}

key-store-path: "/keys"

logging: "INFO"
EOF
}

# Create key generation helper script
generate_key_helper() {
    cat << 'EOF'
#!/bin/bash
#
# Helper script to generate BLS keys for Web3Signer
# Run this inside the container or on the host with web3signer-tools installed
#

KEYS_DIR="${1:-/keys}"
KEY_PASSWORD="${2:-}"

echo "Generating new BLS key pair..."

# Generate a random mnemonic if not provided
if [ -z "${MNEMONIC:-}" ]; then
    echo "No mnemonic provided, generating a new one..."
    # In production, use a secure mnemonic generation tool
    MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    echo "WARNING: Using test mnemonic. Replace with secure mnemonic in production!"
fi

# Create key file structure
KEY_ID=$(date +%s)
KEY_FILE="${KEYS_DIR}/key-${KEY_ID}.json"

cat > "${KEY_FILE}" << KEYEOF
{
  "version": 4,
  "uuid": "$(uuidgen 2>/dev/null || echo "key-${KEY_ID}")",
  "path": "m/12381/3600/0/0/0",
  "pubkey": "",
  "crypto": {
    "kdf": {
      "function": "pbkdf2",
      "params": {
        "dklen": 32,
        "c": 262144,
        "prf": "hmac-sha256",
        "salt": ""
      },
      "message": ""
    },
    "checksum": {
      "function": "sha256",
      "params": {},
      "message": ""
    },
    "cipher": {
      "function": "aes-128-ctr",
      "params": {
        "iv": ""
      },
      "message": ""
    }
  }
}
KEYEOF

echo "Key file created: ${KEY_FILE}"
echo "Note: This is a placeholder. Use proper key generation tools in production:"
echo "  - eth2-deposit-cli"
echo "  - web3signer key generate"
echo "  - Hardware security module (HSM)"
EOF
}

# Remote deployment via SSH
deploy_remote() {
    log "Deploying Web3Signer to Ubuntu server ${KEYVAULT_HOST}..."
    
    # Check SSH connectivity
    info "Testing SSH connection..."
    if ! ssh -o ConnectTimeout=5 "${KEYVAULT_USER}@${KEYVAULT_HOST}" "echo 'SSH OK'" 2>/dev/null; then
        error "Cannot connect to ${KEYVAULT_HOST}. Check SSH access."
    fi
    
    # Check if Docker is installed
    info "Checking Docker installation..."
    if ! ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "command -v docker" >/dev/null 2>&1; then
        warn "Docker not found on ${KEYVAULT_HOST}"
        read -p "Install Docker now? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_docker_remote
        else
            error "Docker is required. Run with --install flag or install manually."
        fi
    fi
    
    # Verify Docker is running
    if ! ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "docker info" >/dev/null 2>&1; then
        warn "Docker is installed but not running. Starting Docker..."
        ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "systemctl start docker"
    fi
    
    log "Creating directories..."
    ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "mkdir -p ${DATA_DIR} ${KEYS_DIR} ${CONFIG_DIR}"
    
    log "Generating configuration files..."
    
    # Upload config files
    generate_yaml_config | ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "cat > ${CONFIG_DIR}/web3signer.yaml"
    generate_docker_compose | ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "cat > ${CONFIG_DIR}/docker-compose.yml"
    generate_systemd_service | ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "cat > /etc/systemd/system/web3signer.service"
    generate_key_helper | ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "cat > ${DATA_DIR}/generate-key.sh && chmod +x ${DATA_DIR}/generate-key.sh"
    
    # Open firewall if ufw is active
    info "Checking firewall..."
    ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "command -v ufw >/dev/null && ufw status | grep -q 'Status: active' && { ufw allow ${WEB3SIGNER_PORT}/tcp; ufw allow ${WEB3SIGNER_METRICS_PORT}/tcp; } || true"
    
    log "Pulling Docker image..."
    ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "docker pull consensys/web3signer:${WEB3SIGNER_VERSION}"
    
    log "Starting Web3Signer service..."
    ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "systemctl daemon-reload && systemctl enable web3signer && systemctl restart web3signer"
    
    # Wait for service to start
    info "Waiting for Web3Signer to start..."
    sleep 5
    
    # Check health
    if ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "curl -sf http://localhost:${WEB3SIGNER_PORT}/upcheck" >/dev/null 2>&1; then
        log "Web3Signer is healthy!"
    else
        warn "Web3Signer may still be starting. Check logs with: ssh ${KEYVAULT_USER}@${KEYVAULT_HOST} journalctl -u web3signer -f"
    fi
    
    echo ""
    log "Deployment complete!"
    info "Web3Signer API:     http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}"
    info "Metrics endpoint:   http://${KEYVAULT_HOST}:${WEB3SIGNER_METRICS_PORT}/metrics"
    info "Health check:       http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}/upcheck"
    echo ""
    info "Configure Cryftee to use:"
    info "  WEB3SIGNER_URL=http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}"
    echo ""
    info "Useful commands on ${KEYVAULT_HOST}:"
    info "  View logs:     journalctl -u web3signer -f"
    info "  Restart:       systemctl restart web3signer"
    info "  Stop:          systemctl stop web3signer"
    info "  Status:        systemctl status web3signer"
}

# Local deployment (on current machine)
deploy_local() {
    log "Deploying Web3Signer locally on Ubuntu..."
    
    # Check if running on Ubuntu
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            warn "This script is optimized for Ubuntu. Detected: $ID"
        fi
        info "Detected: $PRETTY_NAME"
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        warn "Docker is not installed."
        read -p "Install Docker now? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_docker_ubuntu
        else
            error "Docker is required. Install it first."
        fi
    fi
    
    # Ensure Docker is running
    if ! docker info >/dev/null 2>&1; then
        log "Starting Docker..."
        sudo systemctl start docker
    fi
    
    log "Creating directories..."
    sudo mkdir -p ${DATA_DIR} ${KEYS_DIR} ${CONFIG_DIR}
    
    log "Generating configuration files..."
    generate_yaml_config | sudo tee ${CONFIG_DIR}/web3signer.yaml > /dev/null
    generate_docker_compose | sudo tee ${CONFIG_DIR}/docker-compose.yml > /dev/null
    generate_systemd_service | sudo tee /etc/systemd/system/web3signer.service > /dev/null
    generate_key_helper | sudo tee ${DATA_DIR}/generate-key.sh > /dev/null
    sudo chmod +x ${DATA_DIR}/generate-key.sh
    
    # Open firewall if ufw is active
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        log "Opening firewall ports..."
        sudo ufw allow ${WEB3SIGNER_PORT}/tcp
        sudo ufw allow ${WEB3SIGNER_METRICS_PORT}/tcp
    fi
    
    log "Pulling Docker image..."
    sudo docker pull consensys/web3signer:${WEB3SIGNER_VERSION}
    
    log "Starting Web3Signer service..."
    sudo systemctl daemon-reload
    sudo systemctl enable web3signer
    sudo systemctl restart web3signer
    
    # Wait for service to start
    info "Waiting for Web3Signer to start..."
    sleep 5
    
    # Check health
    if curl -sf http://localhost:${WEB3SIGNER_PORT}/upcheck >/dev/null 2>&1; then
        log "Web3Signer is healthy!"
    else
        warn "Web3Signer may still be starting. Check logs with: journalctl -u web3signer -f"
    fi
    
    echo ""
    log "Local deployment complete!"
    info "Web3Signer API:     http://localhost:${WEB3SIGNER_PORT}"
    info "Metrics endpoint:   http://localhost:${WEB3SIGNER_METRICS_PORT}/metrics"
    info "Health check:       http://localhost:${WEB3SIGNER_PORT}/upcheck"
    echo ""
    info "Useful commands:"
    info "  View logs:     journalctl -u web3signer -f"
    info "  Restart:       sudo systemctl restart web3signer"
    info "  Stop:          sudo systemctl stop web3signer"
    info "  Status:        systemctl status web3signer"
}

# Generate environment file for Cryftee
generate_env() {
    cat << EOF
# Cryftee Web3Signer Environment Configuration
# Add these to your .env file or export them

# Web3Signer connection
WEB3SIGNER_URL=http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}
WEB3SIGNER_TIMEOUT=30

# Enable signature verification
CRYFTEE_ENFORCE_SIGNATURES=true
CRYFTEE_ENFORCE_KNOWN_PUBLISHERS=true

# Trust config location
CRYFTEE_TRUST_CONFIG=/path/to/trust.toml
EOF
}

# Main
show_banner
echo ""

case "${1:-}" in
    --local)
        deploy_local
        ;;
    --install)
        info "Installing Docker on remote Ubuntu server..."
        install_docker_remote
        ;;
    --env)
        generate_env
        ;;
    --help|-h)
        echo "Usage: $0 [--local|--install|--env|--help]"
        echo ""
        echo "Deploy Web3Signer to Ubuntu server for Cryftee module signing."
        echo ""
        echo "Options:"
        echo "  (none)       Deploy to remote Ubuntu server at ${KEYVAULT_HOST}"
        echo "  --local      Deploy on the current Ubuntu machine"
        echo "  --install    Install Docker on remote server first, then deploy"
        echo "  --env        Generate environment variables for Cryftee"
        echo "  --help       Show this help message"
        echo ""
        echo "Environment variables:"
        echo "  KEYVAULT_HOST        Remote host (default: 100.111.2.1)"
        echo "  KEYVAULT_USER        SSH user (default: root)"
        echo "  WEB3SIGNER_PORT      API port (default: 9000)"
        echo "  WEB3SIGNER_VERSION   Docker image version (default: 24.4.0)"
        echo ""
        echo "Examples:"
        echo "  $0                                    # Deploy to 100.111.2.1"
        echo "  KEYVAULT_HOST=10.0.0.5 $0             # Deploy to custom host"
        echo "  $0 --install                         # Install Docker + deploy"
        echo "  $0 --local                           # Deploy on this machine"
        ;;
    *)
        deploy_remote
        ;;
esac
