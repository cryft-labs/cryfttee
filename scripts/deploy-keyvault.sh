#!/bin/bash
#
# Deploy CryftTEE KeyVault Stack
# HashiCorp Vault + Web3Signer for Production Key Management
#
# Target: Ubuntu Server (keyvault @ 100.111.2.1)
#
# Architecture:
#   CryftTEE --> Web3Signer --> HashiCorp Vault --> Keys (encrypted at rest)
#
# Usage:
#   ./deploy-keyvault.sh                    # Deploy full stack to remote
#   ./deploy-keyvault.sh --local            # Deploy on current machine
#   ./deploy-keyvault.sh --web3signer-only  # Deploy only Web3Signer (no Vault)
#   ./deploy-keyvault.sh --install-docker   # Install Docker on remote first
#   ./deploy-keyvault.sh --status           # Check service status
#   ./deploy-keyvault.sh --env              # Generate CryftTEE env vars
#
# Tested on: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS
#

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

KEYVAULT_HOST="${KEYVAULT_HOST:-100.111.2.1}"
KEYVAULT_USER="${KEYVAULT_USER:-cryftcreator}"

# Vault settings
VAULT_VERSION="${VAULT_VERSION:-1.15.4}"
VAULT_PORT="${VAULT_PORT:-8200}"

# Web3Signer settings
WEB3SIGNER_VERSION="${WEB3SIGNER_VERSION:-latest}"
WEB3SIGNER_PORT="${WEB3SIGNER_PORT:-9000}"
WEB3SIGNER_METRICS_PORT="${WEB3SIGNER_METRICS_PORT:-9001}"

# Directories
DATA_DIR="/opt/cryfttee-keyvault"
VAULT_DATA="${DATA_DIR}/vault"
WEB3SIGNER_DATA="${DATA_DIR}/web3signer"
CONFIG_DIR="${DATA_DIR}/config"
KEYS_DIR="${DATA_DIR}/keys"
SCRIPTS_DIR="${DATA_DIR}/scripts"

# Deploy mode: "full" (Vault + Web3Signer) or "web3signer" (Web3Signer only)
DEPLOY_MODE="${DEPLOY_MODE:-full}"

# =============================================================================
# Colors and Logging
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
step() { echo -e "${CYAN}[>]${NC} $1"; }

show_banner() {
    echo -e "${BOLD}"
    cat << 'EOF'
   ____             __ _              _  __                           _ _   
  / ___|_ __ _   _ / _| |_ ___  ___  | |/ /___ _   ___   ____ _ _   _| | |_ 
 | |   | '__| | | | |_| __/ _ \/ _ \ | ' // _ \ | | \ \ / / _` | | | | | __|
 | |___| |  | |_| |  _| ||  __/  __/ | . \  __/ |_| |\ V / (_| | |_| | | |_ 
  \____|_|   \__, |_|  \__\___|\___| |_|\_\___|\__, | \_/ \__,_|\__,_|_|\__|
             |___/                             |___/                        
EOF
    echo -e "${NC}"
    echo "    HashiCorp Vault + Web3Signer | Production Key Management"
    echo "    Target: ${KEYVAULT_USER}@${KEYVAULT_HOST}"
    echo ""
}

# =============================================================================
# Docker Installation
# =============================================================================

generate_docker_install_script() {
    cat << 'EOF'
#!/bin/bash
set -e
echo "[+] Updating package index..."
sudo apt-get update -y

echo "[+] Installing prerequisites..."
sudo apt-get install -y ca-certificates curl gnupg lsb-release jq

echo "[+] Adding Docker GPG key..."
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "[+] Setting up Docker repository..."
echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "[+] Installing Docker Engine..."
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "[+] Enabling Docker service..."
sudo systemctl enable docker
sudo systemctl start docker

echo "[+] Adding current user to docker group..."
sudo usermod -aG docker $USER

echo "[+] Docker version:"
sudo docker --version
echo "[+] Docker installed successfully!"
EOF
}

install_docker_remote() {
    log "Installing Docker on ${KEYVAULT_HOST}..."
    
    LOCAL_TMP=$(mktemp -d)
    generate_docker_install_script > "${LOCAL_TMP}/install-docker.sh"
    
    scp "${LOCAL_TMP}/install-docker.sh" "${KEYVAULT_USER}@${KEYVAULT_HOST}:/tmp/"
    ssh -t "${KEYVAULT_USER}@${KEYVAULT_HOST}" "chmod +x /tmp/install-docker.sh && /tmp/install-docker.sh && rm /tmp/install-docker.sh"
    
    rm -rf "${LOCAL_TMP}"
    log "Docker installation complete!"
}

# =============================================================================
# Configuration Generators
# =============================================================================

# Docker Compose - Full Stack (Vault + Web3Signer)
generate_docker_compose_full() {
    cat << EOF
version: '3.8'

services:
  # HashiCorp Vault - Secrets Management
  vault:
    image: hashicorp/vault:${VAULT_VERSION}
    container_name: cryfttee-vault
    restart: unless-stopped
    cap_add:
      - IPC_LOCK
    ports:
      - "${VAULT_PORT}:8200"
    volumes:
      - ${VAULT_DATA}/data:/vault/data
      - ${VAULT_DATA}/logs:/vault/logs
      - ${CONFIG_DIR}/vault.hcl:/vault/config/vault.hcl:ro
    environment:
      - VAULT_ADDR=http://127.0.0.1:8200
      - VAULT_API_ADDR=http://0.0.0.0:8200
    command: server
    networks:
      - cryfttee-keyvault
    healthcheck:
      test: ["CMD-SHELL", "vault status -address=http://127.0.0.1:8200 2>&1 | grep -E '(Sealed.*false|Sealed.*true)' || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s

  # Web3Signer - Ethereum Signing
  web3signer:
    image: consensys/web3signer:${WEB3SIGNER_VERSION}
    container_name: cryfttee-web3signer
    restart: unless-stopped
    depends_on:
      vault:
        condition: service_healthy
    ports:
      - "${WEB3SIGNER_PORT}:9000"
      - "${WEB3SIGNER_METRICS_PORT}:9001"
    volumes:
      - ${WEB3SIGNER_DATA}:/data
      - ${KEYS_DIR}:/keys
      - ${CONFIG_DIR}/web3signer.yaml:/config/web3signer.yaml:ro
    command:
      - --config-file=/config/web3signer.yaml
      - eth2
      - --slashing-protection-db-url=jdbc:h2:file:/data/slashing-protection
      - --keystores-path=/keys
    environment:
      - JAVA_OPTS=-Xmx512m -Xms256m
      - VAULT_ADDR=http://vault:8200
    networks:
      - cryfttee-keyvault
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9000/upcheck"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

networks:
  cryfttee-keyvault:
    driver: bridge
EOF
}

# Docker Compose - Web3Signer Only
generate_docker_compose_web3signer() {
    cat << EOF
version: '3.8'

services:
  web3signer:
    image: consensys/web3signer:${WEB3SIGNER_VERSION}
    container_name: cryfttee-web3signer
    restart: unless-stopped
    ports:
      - "${WEB3SIGNER_PORT}:9000"
      - "${WEB3SIGNER_METRICS_PORT}:9001"
    volumes:
      - ${WEB3SIGNER_DATA}:/data
      - ${KEYS_DIR}:/keys
      - ${CONFIG_DIR}/web3signer.yaml:/config/web3signer.yaml:ro
    command:
      - --config-file=/config/web3signer.yaml
      - eth2
      - --slashing-protection-db-url=jdbc:h2:file:/data/slashing-protection
      - --keystores-path=/keys
    environment:
      - JAVA_OPTS=-Xmx512m -Xms256m
    networks:
      - cryfttee-keyvault
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9000/upcheck"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

networks:
  cryfttee-keyvault:
    driver: bridge
EOF
}

# Vault Configuration
generate_vault_config() {
    cat << 'EOF'
# HashiCorp Vault Configuration for CryftTEE
# Production-ready settings

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true  # Enable TLS in production with real certs
}

api_addr = "http://0.0.0.0:8200"
cluster_addr = "http://0.0.0.0:8201"

ui = true
log_level = "info"
log_format = "json"

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}

disable_mlock = true
EOF
}

# Web3Signer Configuration
generate_web3signer_config() {
    cat << EOF
# Web3Signer Configuration for CryftTEE
# Supports both BLS (consensus) and SECP256k1 (execution/TLS) signing

http-listen-host: "0.0.0.0"
http-listen-port: 9000
http-cors-origins: ["*"]
http-host-allowlist: ["*"]

metrics-enabled: true
metrics-host: "0.0.0.0"
metrics-port: 9001

logging: "INFO"

# Enable Key Manager API for dynamic key management
key-manager-api-enabled: true

# Swagger UI for API exploration (disable in production)
swagger-ui-enabled: true
EOF
}

# Systemd Service
generate_systemd_service() {
    cat << EOF
[Unit]
Description=CryftTEE KeyVault Stack (Vault + Web3Signer)
Documentation=https://github.com/cryft-labs/cryfttee
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
TimeoutStartSec=180
TimeoutStopSec=60

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF
}

# =============================================================================
# Helper Scripts
# =============================================================================

generate_init_vault_script() {
    cat << 'EOF'
#!/bin/bash
#
# Initialize HashiCorp Vault for CryftTEE
# Run this ONCE after first deployment
#

set -e

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_ADDR

echo ""
echo "=== CryftTEE Vault Initialization ==="
echo ""

# Wait for Vault to be ready
echo "[+] Waiting for Vault to be ready..."
for i in {1..30}; do
    if vault status 2>&1 | grep -q "Sealed"; then
        break
    fi
    sleep 1
done

# Check if already initialized
if vault status 2>/dev/null | grep -q "Initialized.*true"; then
    echo "[!] Vault is already initialized"
    
    if vault status 2>/dev/null | grep -q "Sealed.*true"; then
        echo "[!] Vault is sealed. Run: sudo /opt/cryfttee-keyvault/scripts/unseal-vault.sh"
    else
        echo "[+] Vault is unsealed and ready"
    fi
    exit 0
fi

echo "[+] Initializing Vault with 5 key shares, 3 required to unseal..."
INIT_OUTPUT=$(vault operator init -key-shares=5 -key-threshold=3 -format=json)

# Save keys
KEYS_FILE="/opt/cryfttee-keyvault/vault-init-keys.json"
echo "${INIT_OUTPUT}" > "${KEYS_FILE}"
chmod 600 "${KEYS_FILE}"

echo ""
echo "!!! CRITICAL: Vault initialization keys saved to ${KEYS_FILE} !!!"
echo "!!! Back up this file securely - it's required to unseal Vault !!!"
echo ""

# Unseal
UNSEAL_KEY_1=$(echo "${INIT_OUTPUT}" | jq -r '.unseal_keys_b64[0]')
UNSEAL_KEY_2=$(echo "${INIT_OUTPUT}" | jq -r '.unseal_keys_b64[1]')
UNSEAL_KEY_3=$(echo "${INIT_OUTPUT}" | jq -r '.unseal_keys_b64[2]')
ROOT_TOKEN=$(echo "${INIT_OUTPUT}" | jq -r '.root_token')

echo "[+] Unsealing Vault..."
vault operator unseal "${UNSEAL_KEY_1}" > /dev/null
vault operator unseal "${UNSEAL_KEY_2}" > /dev/null
vault operator unseal "${UNSEAL_KEY_3}" > /dev/null
echo "[+] Vault unsealed!"

# Configure
export VAULT_TOKEN="${ROOT_TOKEN}"

echo "[+] Enabling KV secrets engine..."
vault secrets enable -path=cryfttee kv-v2 2>/dev/null || true

echo "[+] Enabling Transit engine for signing..."
vault secrets enable transit 2>/dev/null || true

echo "[+] Creating CryftTEE policy..."
vault policy write cryfttee - << 'POLICY'
# CryftTEE KeyVault Policy
# Supports BLS (consensus) and SECP256k1 (execution/TLS) keys

# BLS keys for ETH2 consensus signing
path "cryfttee/data/keys/bls/*" {
  capabilities = ["read", "list"]
}

# SECP256k1 keys for ETH1/TLS signing
path "cryfttee/data/keys/secp256k1/*" {
  capabilities = ["read", "list"]
}

# TLS certificates and keys
path "cryfttee/data/keys/tls/*" {
  capabilities = ["read", "list"]
}

# List all keys
path "cryfttee/metadata/keys/*" {
  capabilities = ["list"]
}

# Transit engine for cryptographic operations
path "transit/sign/*" {
  capabilities = ["create", "update"]
}
path "transit/verify/*" {
  capabilities = ["create", "update"]
}
path "transit/keys/*" {
  capabilities = ["create", "read", "update", "list"]
}

# PKI for TLS certificate generation (optional)
path "pki/*" {
  capabilities = ["create", "read", "update", "list"]
}
POLICY

echo "[+] Enabling AppRole auth..."
vault auth enable approle 2>/dev/null || true

echo "[+] Creating Web3Signer AppRole..."
vault write auth/approle/role/web3signer \
    token_policies="cryfttee" \
    token_ttl=1h \
    token_max_ttl=24h \
    secret_id_ttl=0 \
    secret_id_num_uses=0

ROLE_ID=$(vault read -format=json auth/approle/role/web3signer/role-id | jq -r '.data.role_id')
SECRET_ID=$(vault write -format=json -f auth/approle/role/web3signer/secret-id | jq -r '.data.secret_id')

cat > /opt/cryfttee-keyvault/vault-approle.json << APPROLE
{
  "vault_addr": "${VAULT_ADDR}",
  "role_id": "${ROLE_ID}",
  "secret_id": "${SECRET_ID}"
}
APPROLE
chmod 600 /opt/cryfttee-keyvault/vault-approle.json

echo ""
echo "=== Vault Setup Complete ==="
echo ""
echo "Vault UI:       ${VAULT_ADDR}/ui"
echo "Root Token:     ${ROOT_TOKEN}"
echo ""
echo "AppRole credentials saved to: /opt/cryfttee-keyvault/vault-approle.json"
echo ""
echo "IMPORTANT:"
echo "  1. Back up /opt/cryfttee-keyvault/vault-init-keys.json to a secure location"
echo "  2. After Vault restarts, run: sudo /opt/cryfttee-keyvault/scripts/unseal-vault.sh"
echo ""
EOF
}

generate_unseal_vault_script() {
    cat << 'EOF'
#!/bin/bash
#
# Unseal Vault after restart
#

set -e

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
KEYS_FILE="/opt/cryfttee-keyvault/vault-init-keys.json"
export VAULT_ADDR

if [ ! -f "${KEYS_FILE}" ]; then
    echo "[x] Keys file not found: ${KEYS_FILE}"
    echo "[i] Run init-vault.sh first, or restore keys from backup"
    exit 1
fi

# Check if already unsealed
if vault status 2>/dev/null | grep -q "Sealed.*false"; then
    echo "[+] Vault is already unsealed"
    exit 0
fi

echo "[+] Unsealing Vault..."
UNSEAL_KEY_1=$(jq -r '.unseal_keys_b64[0]' "${KEYS_FILE}")
UNSEAL_KEY_2=$(jq -r '.unseal_keys_b64[1]' "${KEYS_FILE}")
UNSEAL_KEY_3=$(jq -r '.unseal_keys_b64[2]' "${KEYS_FILE}")

vault operator unseal "${UNSEAL_KEY_1}" > /dev/null
vault operator unseal "${UNSEAL_KEY_2}" > /dev/null
vault operator unseal "${UNSEAL_KEY_3}" > /dev/null

echo "[+] Vault unsealed!"
vault status
EOF
}

generate_import_key_script() {
    cat << 'EOF'
#!/bin/bash
#
# Import keys into Web3Signer
#
# Usage:
#   ./import-key.sh bls <keystore.json> <password>     # Import BLS key (ETH2 consensus)
#   ./import-key.sh secp256k1 <keystore.json> <password>  # Import SECP256k1 key (ETH1/TLS)
#   ./import-key.sh tls <private-key.pem>              # Import TLS private key
#

set -e

KEY_TYPE="${1:-}"
KEYSTORE_FILE="${2:-}"
PASSWORD="${3:-}"
KEYS_DIR="/opt/cryfttee-keyvault/keys"

usage() {
    echo "Usage:"
    echo "  $0 bls <keystore.json> <password>        # BLS key for ETH2 consensus signing"
    echo "  $0 secp256k1 <keystore.json> <password>  # SECP256k1 key for ETH1/TLS signing"
    echo "  $0 tls <private-key.pem>                 # Raw TLS private key (SECP256k1)"
    echo ""
    echo "Examples:"
    echo "  $0 bls ./validator-keystore.json mypassword"
    echo "  $0 secp256k1 ./eth1-keystore.json mypassword"
    echo "  $0 tls ./tls-private-key.pem"
    exit 1
}

if [ -z "${KEY_TYPE}" ]; then
    usage
fi

case "${KEY_TYPE}" in
    bls)
        if [ -z "${KEYSTORE_FILE}" ] || [ -z "${PASSWORD}" ]; then
            usage
        fi
        
        if [ ! -f "${KEYSTORE_FILE}" ]; then
            echo "[x] File not found: ${KEYSTORE_FILE}"
            exit 1
        fi
        
        # Extract pubkey
        PUBKEY=$(jq -r '.pubkey // .public_key // empty' "${KEYSTORE_FILE}")
        if [ -z "${PUBKEY}" ]; then
            echo "[x] Could not extract pubkey from keystore"
            exit 1
        fi
        PUBKEY="${PUBKEY#0x}"
        
        echo "[+] Importing BLS key: 0x${PUBKEY:0:8}...${PUBKEY: -8}"
        
        # Copy keystore
        cp "${KEYSTORE_FILE}" "${KEYS_DIR}/${PUBKEY}.json"
        chmod 600 "${KEYS_DIR}/${PUBKEY}.json"
        
        # Create password file
        echo -n "${PASSWORD}" > "${KEYS_DIR}/${PUBKEY}.txt"
        chmod 600 "${KEYS_DIR}/${PUBKEY}.txt"
        
        echo "[+] BLS key imported to ${KEYS_DIR}/"
        ;;
        
    secp256k1)
        if [ -z "${KEYSTORE_FILE}" ] || [ -z "${PASSWORD}" ]; then
            usage
        fi
        
        if [ ! -f "${KEYSTORE_FILE}" ]; then
            echo "[x] File not found: ${KEYSTORE_FILE}"
            exit 1
        fi
        
        # Extract address from keystore
        ADDRESS=$(jq -r '.address // empty' "${KEYSTORE_FILE}")
        if [ -z "${ADDRESS}" ]; then
            # Generate a unique ID if no address
            ADDRESS=$(sha256sum "${KEYSTORE_FILE}" | cut -c1-40)
        fi
        ADDRESS="${ADDRESS#0x}"
        
        echo "[+] Importing SECP256k1 key: 0x${ADDRESS}"
        
        # Copy keystore
        cp "${KEYSTORE_FILE}" "${KEYS_DIR}/secp256k1-${ADDRESS}.json"
        chmod 600 "${KEYS_DIR}/secp256k1-${ADDRESS}.json"
        
        # Create password file
        echo -n "${PASSWORD}" > "${KEYS_DIR}/secp256k1-${ADDRESS}.txt"
        chmod 600 "${KEYS_DIR}/secp256k1-${ADDRESS}.txt"
        
        # Create key config for Web3Signer
        cat > "${KEYS_DIR}/secp256k1-${ADDRESS}.yaml" << KEYCONFIG
type: file-keystore
keyType: SECP256K1
keystoreFile: /keys/secp256k1-${ADDRESS}.json
keystorePasswordFile: /keys/secp256k1-${ADDRESS}.txt
KEYCONFIG
        
        echo "[+] SECP256k1 key imported to ${KEYS_DIR}/"
        ;;
        
    tls)
        PEM_FILE="${KEYSTORE_FILE}"
        
        if [ -z "${PEM_FILE}" ]; then
            usage
        fi
        
        if [ ! -f "${PEM_FILE}" ]; then
            echo "[x] File not found: ${PEM_FILE}"
            exit 1
        fi
        
        # Generate key ID from public key hash
        KEY_ID=$(openssl ec -in "${PEM_FILE}" -pubout 2>/dev/null | sha256sum | cut -c1-16)
        
        echo "[+] Importing TLS private key: ${KEY_ID}"
        
        # Copy PEM file
        cp "${PEM_FILE}" "${KEYS_DIR}/tls-${KEY_ID}.pem"
        chmod 600 "${KEYS_DIR}/tls-${KEY_ID}.pem"
        
        # Create key config for Web3Signer
        cat > "${KEYS_DIR}/tls-${KEY_ID}.yaml" << KEYCONFIG
type: file-raw
keyType: SECP256K1
privateKeyFile: /keys/tls-${KEY_ID}.pem
KEYCONFIG
        
        echo "[+] TLS key imported to ${KEYS_DIR}/"
        ;;
        
    *)
        echo "[x] Unknown key type: ${KEY_TYPE}"
        usage
        ;;
esac

echo ""
echo "[!] Restart Web3Signer to load the new key:"
echo "    sudo docker restart cryfttee-web3signer"
echo ""
echo "[i] Check loaded keys:"
echo "    curl -s http://localhost:9000/api/v1/eth2/publicKeys | jq     # BLS keys"
echo "    curl -s http://localhost:9000/api/v1/eth1/publicKeys | jq     # SECP256k1 keys"
EOF
}

generate_status_script() {
    cat << 'EOF'
#!/bin/bash
#
# Check CryftTEE KeyVault stack status
#

echo "=== CryftTEE KeyVault Status ==="
echo ""

# Check systemd service
echo "[Service Status]"
systemctl status cryfttee-keyvault --no-pager -l 2>/dev/null | head -10 || echo "Service not found"
echo ""

# Check containers
echo "[Container Status]"
docker ps --filter "name=cryfttee" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "Docker not available"
echo ""

# Check Vault
echo "[Vault Status]"
if curl -sf http://127.0.0.1:8200/v1/sys/health 2>/dev/null | jq -r '"Initialized: \(.initialized), Sealed: \(.sealed)"' 2>/dev/null; then
    :
else
    echo "Not running or not deployed"
fi
echo ""

# Check Web3Signer
echo "[Web3Signer Status]"
if curl -sf http://127.0.0.1:9000/upcheck 2>/dev/null; then
    echo " - Health: OK"
else
    echo "Not responding"
fi
echo ""

# Check loaded BLS keys
echo "[BLS Keys (ETH2 Consensus)]"
BLS_KEYS=$(curl -sf http://127.0.0.1:9000/api/v1/eth2/publicKeys 2>/dev/null)
if [ -n "${BLS_KEYS}" ] && [ "${BLS_KEYS}" != "[]" ]; then
    echo "${BLS_KEYS}" | jq -r '.[]' 2>/dev/null | while read key; do
        echo "  - ${key:0:18}...${key: -8}"
    done
else
    echo "  (none loaded)"
fi
echo ""

# Check loaded SECP256k1 keys
echo "[SECP256k1 Keys (ETH1/TLS)]"
SECP_KEYS=$(curl -sf http://127.0.0.1:9000/api/v1/eth1/publicKeys 2>/dev/null)
if [ -n "${SECP_KEYS}" ] && [ "${SECP_KEYS}" != "[]" ]; then
    echo "${SECP_KEYS}" | jq -r '.[]' 2>/dev/null | while read key; do
        echo "  - ${key:0:18}...${key: -8}"
    done
else
    echo "  (none loaded)"
fi
echo ""

# Show key files
echo "[Key Files on Disk]"
ls -la /opt/cryfttee-keyvault/keys/*.json 2>/dev/null | awk '{print "  " $NF}' || echo "  (none)"
ls -la /opt/cryfttee-keyvault/keys/*.pem 2>/dev/null | awk '{print "  " $NF}' || true
EOF
}

# =============================================================================
# Deployment Functions
# =============================================================================

deploy_remote() {
    local mode="${1:-full}"
    
    log "Deploying CryftTEE KeyVault Stack to ${KEYVAULT_HOST}..."
    info "Mode: ${mode}"
    echo ""
    
    # Check SSH
    step "Testing SSH connection..."
    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "${KEYVAULT_USER}@${KEYVAULT_HOST}" "echo 'OK'" 2>/dev/null; then
        # Try with password
        if ! ssh -o ConnectTimeout=5 "${KEYVAULT_USER}@${KEYVAULT_HOST}" "echo 'OK'" 2>/dev/null; then
            error "Cannot connect to ${KEYVAULT_HOST}"
        fi
    fi
    
    # Check Docker
    step "Checking Docker..."
    if ! ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "command -v docker" >/dev/null 2>&1; then
        warn "Docker not found on ${KEYVAULT_HOST}"
        read -p "Install Docker now? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_docker_remote
        else
            error "Docker is required"
        fi
    fi
    
    # Create temp directory
    LOCAL_TMP=$(mktemp -d)
    trap "rm -rf ${LOCAL_TMP}" EXIT
    
    # Generate configs
    step "Generating configuration files..."
    
    if [ "${mode}" = "full" ]; then
        generate_docker_compose_full > "${LOCAL_TMP}/docker-compose.yml"
        generate_vault_config > "${LOCAL_TMP}/vault.hcl"
        generate_init_vault_script > "${LOCAL_TMP}/init-vault.sh"
        generate_unseal_vault_script > "${LOCAL_TMP}/unseal-vault.sh"
    else
        generate_docker_compose_web3signer > "${LOCAL_TMP}/docker-compose.yml"
    fi
    
    generate_web3signer_config > "${LOCAL_TMP}/web3signer.yaml"
    generate_systemd_service > "${LOCAL_TMP}/cryfttee-keyvault.service"
    generate_import_key_script > "${LOCAL_TMP}/import-key.sh"
    generate_status_script > "${LOCAL_TMP}/status.sh"
    
    # Create deploy script
    cat > "${LOCAL_TMP}/deploy.sh" << DEPLOYEOF
#!/bin/bash
set -e

MODE="${mode}"

echo "[+] Creating directories..."
sudo mkdir -p ${DATA_DIR}/{vault/data,vault/logs,web3signer,keys,config,scripts}
sudo chmod 700 ${DATA_DIR}/vault ${DATA_DIR}/keys

echo "[+] Installing configuration files..."
sudo cp /tmp/cryfttee-deploy/docker-compose.yml ${CONFIG_DIR}/
sudo cp /tmp/cryfttee-deploy/web3signer.yaml ${CONFIG_DIR}/
sudo cp /tmp/cryfttee-deploy/cryfttee-keyvault.service /etc/systemd/system/

if [ "\${MODE}" = "full" ]; then
    sudo cp /tmp/cryfttee-deploy/vault.hcl ${CONFIG_DIR}/
    sudo cp /tmp/cryfttee-deploy/init-vault.sh ${SCRIPTS_DIR}/
    sudo cp /tmp/cryfttee-deploy/unseal-vault.sh ${SCRIPTS_DIR}/
fi

sudo cp /tmp/cryfttee-deploy/import-key.sh ${SCRIPTS_DIR}/
sudo cp /tmp/cryfttee-deploy/status.sh ${SCRIPTS_DIR}/
sudo chmod +x ${SCRIPTS_DIR}/*.sh

echo "[+] Checking firewall..."
if command -v ufw >/dev/null && sudo ufw status | grep -q 'Status: active'; then
    [ "\${MODE}" = "full" ] && sudo ufw allow ${VAULT_PORT}/tcp
    sudo ufw allow ${WEB3SIGNER_PORT}/tcp
    sudo ufw allow ${WEB3SIGNER_METRICS_PORT}/tcp
fi

echo "[+] Pulling Docker images..."
if [ "\${MODE}" = "full" ]; then
    sudo docker pull hashicorp/vault:${VAULT_VERSION}
fi
sudo docker pull consensys/web3signer:${WEB3SIGNER_VERSION}

echo "[+] Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable cryfttee-keyvault
sudo systemctl restart cryfttee-keyvault

echo "[+] Cleaning up..."
rm -rf /tmp/cryfttee-deploy

echo "[+] Deployment complete!"
DEPLOYEOF

    # Upload files
    step "Uploading files to ${KEYVAULT_HOST}..."
    ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "mkdir -p /tmp/cryfttee-deploy"
    scp -q "${LOCAL_TMP}"/* "${KEYVAULT_USER}@${KEYVAULT_HOST}:/tmp/cryfttee-deploy/"
    
    # Execute
    step "Running deployment..."
    ssh -t "${KEYVAULT_USER}@${KEYVAULT_HOST}" "chmod +x /tmp/cryfttee-deploy/deploy.sh && /tmp/cryfttee-deploy/deploy.sh"
    
    # Wait for services
    info "Waiting for services to start..."
    sleep 8
    
    # Check health
    echo ""
    if ssh "${KEYVAULT_USER}@${KEYVAULT_HOST}" "curl -sf http://localhost:${WEB3SIGNER_PORT}/upcheck" >/dev/null 2>&1; then
        log "Web3Signer is healthy!"
    else
        warn "Web3Signer may still be starting..."
    fi
    
    # Print summary
    echo ""
    log "Deployment complete!"
    echo ""
    info "Services:"
    if [ "${mode}" = "full" ]; then
        info "  Vault:            http://${KEYVAULT_HOST}:${VAULT_PORT}"
        info "  Vault UI:         http://${KEYVAULT_HOST}:${VAULT_PORT}/ui"
    fi
    info "  Web3Signer API:   http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}"
    info "  Metrics:          http://${KEYVAULT_HOST}:${WEB3SIGNER_METRICS_PORT}/metrics"
    echo ""
    
    if [ "${mode}" = "full" ]; then
        warn "NEXT STEPS:"
        echo "  1. SSH to ${KEYVAULT_HOST}"
        echo "  2. Initialize Vault: sudo ${SCRIPTS_DIR}/init-vault.sh"
        echo "  3. Back up vault-init-keys.json securely!"
        echo ""
    fi
    
    info "Useful commands:"
    echo "  Status:      sudo ${SCRIPTS_DIR}/status.sh"
    echo "  Import key:  sudo ${SCRIPTS_DIR}/import-key.sh <keystore.json> <password>"
    echo "  Logs:        sudo journalctl -u cryfttee-keyvault -f"
    echo "  Restart:     sudo systemctl restart cryfttee-keyvault"
    if [ "${mode}" = "full" ]; then
        echo "  Unseal:      sudo ${SCRIPTS_DIR}/unseal-vault.sh"
    fi
}

check_status() {
    log "Checking status on ${KEYVAULT_HOST}..."
    ssh -t "${KEYVAULT_USER}@${KEYVAULT_HOST}" "sudo ${SCRIPTS_DIR}/status.sh 2>/dev/null || echo 'Stack not deployed'"
}

generate_env() {
    cat << EOF
# CryftTEE KeyVault Environment Configuration
# Add to your environment or .env file

# Web3Signer
WEB3SIGNER_URL=http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}
WEB3SIGNER_TIMEOUT=30

# Vault (if using full stack)
VAULT_ADDR=http://${KEYVAULT_HOST}:${VAULT_PORT}

# CryftTEE settings
CRYFTTEE_ENFORCE_SIGNATURES=true
CRYFTTEE_ENFORCE_KNOWN_PUBLISHERS=true
EOF
}

# =============================================================================
# Main
# =============================================================================

show_banner

case "${1:-}" in
    --local)
        error "Local deployment not yet implemented. Use remote deployment."
        ;;
    --web3signer-only)
        deploy_remote "web3signer"
        ;;
    --install-docker)
        install_docker_remote
        ;;
    --status)
        check_status
        ;;
    --env)
        generate_env
        ;;
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Deploy HashiCorp Vault + Web3Signer for CryftTEE key management."
        echo ""
        echo "Options:"
        echo "  (none)              Deploy full stack (Vault + Web3Signer)"
        echo "  --web3signer-only   Deploy only Web3Signer (no Vault)"
        echo "  --install-docker    Install Docker on remote server"
        echo "  --status            Check service status"
        echo "  --env               Generate environment variables"
        echo "  --help              Show this help"
        echo ""
        echo "Environment variables:"
        echo "  KEYVAULT_HOST       Remote host (default: ${KEYVAULT_HOST})"
        echo "  KEYVAULT_USER       SSH user (default: ${KEYVAULT_USER})"
        echo "  VAULT_PORT          Vault port (default: ${VAULT_PORT})"
        echo "  WEB3SIGNER_PORT     Web3Signer port (default: ${WEB3SIGNER_PORT})"
        echo ""
        echo "Examples:"
        echo "  $0                              # Deploy full stack"
        echo "  $0 --web3signer-only            # Deploy Web3Signer only"
        echo "  KEYVAULT_HOST=10.0.0.5 $0       # Deploy to custom host"
        echo ""
        ;;
    *)
        deploy_remote "full"
        ;;
esac
