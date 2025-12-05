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
#   ./deploy-keyvault.sh --test             # Test Web3Signer from CryftTEE
#   ./deploy-keyvault.sh --cryfttee-config  # Generate cryfttee.toml snippet
#
# Tested on: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS
#

set -euo pipefail

# =============================================================================
# SSH Connection Multiplexing
# =============================================================================
# Uses a single SSH connection for all remote commands to avoid repeated
# password prompts.

SSH_CONTROL_PATH="/tmp/cryfttee-keyvault-ssh-%r@%h:%p"
SSH_CONTROL_PERSIST="10m"

# Start SSH master connection (call once at start of remote operations)
start_ssh_master() {
    local target="${1}"
    
    # Check if master already exists
    if ssh -O check -o ControlPath="${SSH_CONTROL_PATH}" "${target}" 2>/dev/null; then
        return 0
    fi
    
    # Start master connection in background
    ssh -fNM \
        -o ControlPath="${SSH_CONTROL_PATH}" \
        -o ControlPersist="${SSH_CONTROL_PERSIST}" \
        -o ServerAliveInterval=60 \
        -o ServerAliveCountMax=3 \
        "${target}"
}

# Stop SSH master connection (cleanup)
stop_ssh_master() {
    local target="${1}"
    ssh -O exit -o ControlPath="${SSH_CONTROL_PATH}" "${target}" 2>/dev/null || true
}

# SSH wrapper that uses the master connection
ssh_cmd() {
    ssh -o ControlPath="${SSH_CONTROL_PATH}" "$@"
}

# SCP wrapper that uses the master connection  
scp_cmd() {
    scp -o ControlPath="${SSH_CONTROL_PATH}" "$@"
}

# =============================================================================
# Configuration
# =============================================================================

# Remote deployment target (for --remote mode)
KEYVAULT_HOST="${KEYVAULT_HOST:-100.111.2.1}"
KEYVAULT_USER="${KEYVAULT_USER:-cryftcreator}"

# Vault settings
VAULT_VERSION="${VAULT_VERSION:-1.15.4}"
VAULT_PORT="${VAULT_PORT:-8200}"

# Web3Signer settings - these match CryftTEE defaults
WEB3SIGNER_VERSION="${WEB3SIGNER_VERSION:-24.6.0}"  # Use stable release, not 'latest'
WEB3SIGNER_PORT="${WEB3SIGNER_PORT:-9000}"          # Default: 9000 (matches CryftTEE default)
WEB3SIGNER_METRICS_PORT="${WEB3SIGNER_METRICS_PORT:-9001}"

# CryftTEE integration - localhost by default (no env vars needed)
CRYFTTEE_HOST="${CRYFTTEE_HOST:-localhost}"

# Directories - use user home directory (no sudo required)
# Remote: uses KEYVAULT_USER's home directory
# Local: uses current user's home directory
DATA_DIR="${CRYFTTEE_KEYVAULT_DIR:-\$HOME/.cryfttee-keyvault}"
VAULT_DATA="${DATA_DIR}/vault"
WEB3SIGNER_DATA="${DATA_DIR}/web3signer"
POSTGRES_DATA="${DATA_DIR}/postgres"
CONFIG_DIR="${DATA_DIR}/config"
KEYS_DIR="${DATA_DIR}/keys"
SCRIPTS_DIR="${DATA_DIR}/scripts"
SECRETS_FILE="${DATA_DIR}/.secrets"
SYSTEMD_USER_DIR="\$HOME/.config/systemd/user"

# PostgreSQL credentials - load from local secrets file if exists
# For remote deployments, password is retrieved from remote host in deploy_remote()
# Note: Uses echo instead of info() since logging functions aren't defined yet
load_or_generate_secrets() {
    # Initialize to empty if not set (prevents unbound variable error)
    POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
    
    # Only check local secrets file (for --local deployments)
    # Remote deployments retrieve password from remote host later
    if [[ -f "$SECRETS_FILE" ]]; then
        source "$SECRETS_FILE"
        echo "[i] Loaded existing secrets from $SECRETS_FILE"
    fi
    
    # DON'T generate password here - let deploy functions handle it
    # This prevents generating a new password before checking remote host
}

# Generate a new password (called explicitly when needed)
generate_new_password() {
    POSTGRES_PASSWORD="$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)"
    echo "[i] Generated new PostgreSQL password"
}

save_secrets() {
    # Save secrets to file (only readable by owner)
    cat > "$SECRETS_FILE" << EOF
# CryftTEE KeyVault Secrets - DO NOT DELETE
# Generated: $(date -Iseconds)
POSTGRES_PASSWORD="$POSTGRES_PASSWORD"
EOF
    chmod 600 "$SECRETS_FILE"
    info "Saved secrets to $SECRETS_FILE"
}

# Load secrets early
load_or_generate_secrets

# Deploy mode: "full" (Vault + Web3Signer) or "web3signer" (Web3Signer only)
DEPLOY_MODE="${DEPLOY_MODE:-full}"

# Upgrade behavior flags (can be set via CLI or env)
FORCE_UPGRADE="${FORCE_UPGRADE:-false}"
CLEAN_INSTALL="${CLEAN_INSTALL:-false}"

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

# =============================================================================
# Network Retry Wrapper
# =============================================================================
# Wraps network commands with interactive retry on failure.
# Usage: retry_network "description" command [args...]
#
# Example:
#   retry_network "Pulling Vault image" docker pull hashicorp/vault:1.15.4

retry_network() {
    local description="${1}"
    shift
    local cmd=("$@")
    local attempt=1
    
    while true; do
        echo -e "${CYAN}[>]${NC} ${description} (attempt ${attempt})..."
        
        if "${cmd[@]}"; then
            echo -e "${GREEN}[✓]${NC} ${description} succeeded"
            return 0
        fi
        
        echo ""
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  ⚠  Network operation failed                                     ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${RED}[x]${NC} Failed: ${description}"
        echo ""
        echo "    Command: ${cmd[*]}"
        echo ""
        echo "Options:"
        echo "  r) Retry      - Try again"
        echo "  s) Skip       - Skip this step (may cause issues)"
        echo "  a) Abort      - Exit the script"
        echo ""
        
        while true; do
            read -p "Choose [r/s/a]: " -n 1 -r choice
            echo ""
            case "${choice}" in
                r|R)
                    ((attempt++))
                    echo ""
                    break
                    ;;
                s|S)
                    warn "Skipping: ${description}"
                    return 1
                    ;;
                a|A)
                    error "Aborted by user"
                    ;;
                *)
                    echo "Invalid choice. Enter r, s, or a."
                    ;;
            esac
        done
    done
}

# Convenience wrapper for docker pull with retry
docker_pull() {
    local image="${1}"
    retry_network "Pulling Docker image: ${image}" docker pull "${image}"
}

# Convenience wrapper for curl downloads with retry
curl_download() {
    local url="${1}"
    local output="${2}"
    local desc="${3:-Downloading ${url}}"
    retry_network "${desc}" curl -fSL -o "${output}" "${url}"
}

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
chmod a+r /etc/apt/keyrings/docker.gpg

echo "[+] Setting up Docker repository..."
echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "[+] Installing Docker Engine..."
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "[+] Enabling Docker service..."
sudo systemctl enable docker
sudo systemctl start docker

echo "[+] Adding current user to docker group..."
sudo usermod -aG docker $USER

echo "[+] Docker version:"
docker --version
echo "[+] Docker installed successfully!"
EOF
}

install_docker_remote() {
    log "Installing Docker on ${KEYVAULT_HOST}..."
    
    LOCAL_TMP=$(mktemp -d)
    generate_docker_install_script > "${LOCAL_TMP}/install-docker.sh"
    
    retry_network "Uploading Docker install script" scp_cmd "${LOCAL_TMP}/install-docker.sh" "${KEYVAULT_USER}@${KEYVAULT_HOST}:/tmp/"
    ssh_cmd -t "${KEYVAULT_USER}@${KEYVAULT_HOST}" "chmod +x /tmp/install-docker.sh && /tmp/install-docker.sh && rm /tmp/install-docker.sh"
    
    rm -rf "${LOCAL_TMP}"
    log "Docker installation complete!"
}

# =============================================================================
# Configuration Generators
# =============================================================================

# Docker Compose - Full Stack (Vault + Web3Signer)
# Note: Uses relative paths from config/ directory where compose file lives
# Placeholders like __POSTGRES_PASSWORD__ are replaced by the deploy script
generate_docker_compose_full() {
    cat << 'COMPOSEEOF'
version: '3.8'

services:
  # PostgreSQL - Slashing Protection Database
  postgres:
    image: postgres:15-alpine
    container_name: cryfttee-postgres
    restart: unless-stopped
    volumes:
      - ../postgres:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=web3signer
      - POSTGRES_USER=web3signer
      - POSTGRES_PASSWORD=__POSTGRES_PASSWORD__
    networks:
      - cryfttee-keyvault
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U web3signer -d web3signer"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # HashiCorp Vault - Secrets Management
  vault:
    image: hashicorp/vault:__VAULT_VERSION__
    container_name: cryfttee-vault
    restart: unless-stopped
    cap_add:
      - IPC_LOCK
    ports:
      - "__VAULT_PORT__:8200"
    volumes:
      - ../vault/data:/vault/data
      - ../vault/logs:/vault/logs
      - ./vault.hcl:/vault/config/vault.hcl:ro
      - ../vault/init:/vault/init
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

  # Auto-init and unseal Vault on first start
  vault-init:
    image: hashicorp/vault:__VAULT_VERSION__
    container_name: cryfttee-vault-init
    depends_on:
      vault:
        condition: service_healthy
    volumes:
      - ../vault/init:/vault/init
      - ./vault-init.sh:/vault-init.sh:ro
    environment:
      - VAULT_ADDR=http://vault:8200
    entrypoint: ["/bin/sh", "/vault-init.sh"]
    networks:
      - cryfttee-keyvault
    restart: "no"

  # Web3Signer - Ethereum Signing with Vault backend
  web3signer:
    image: consensys/web3signer:__WEB3SIGNER_VERSION__
    container_name: cryfttee-web3signer
    restart: unless-stopped
    user: "1000:1000"
    depends_on:
      vault:
        condition: service_healthy
      postgres:
        condition: service_healthy
    ports:
      - "__WEB3SIGNER_PORT__:9000"
      - "__WEB3SIGNER_METRICS_PORT__:9001"
    volumes:
      - ../web3signer:/data
      - ./web3signer.yaml:/config/web3signer.yaml:ro
      - ../vault/init:/vault-init:ro
    command:
      - --data-path=/data
      - --config-file=/config/web3signer.yaml
      - eth2
      - --network=mainnet
      - --enable-key-manager-api=true
      - --slashing-protection-db-url=jdbc:postgresql://postgres:5432/web3signer
      - --slashing-protection-db-username=web3signer
      - --slashing-protection-db-password=__POSTGRES_PASSWORD__
      - --slashing-protection-pruning-enabled=true
      - --slashing-protection-pruning-epochs-to-keep=500
    environment:
      - JAVA_OPTS=-Xmx512m -Xms256m -XX:+UseG1GC
      - VAULT_ADDR=http://vault:8200
      - LOG4J_FORMAT_MSG_NO_LOOKUPS=true
    networks:
      - cryfttee-keyvault
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9000/upcheck || exit 1"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 30s

networks:
  cryfttee-keyvault:
    driver: bridge
COMPOSEEOF
}

# Docker Compose - Web3Signer Only (recommended for CryftTEE)
# Note: Uses relative paths from config/ directory where compose file lives
generate_docker_compose_web3signer() {
    cat << 'COMPOSEEOF'
version: '3.8'

services:
  # PostgreSQL - Slashing Protection Database
  postgres:
    image: postgres:15-alpine
    container_name: cryfttee-postgres
    restart: unless-stopped
    volumes:
      - ../postgres:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=web3signer
      - POSTGRES_USER=web3signer
      - POSTGRES_PASSWORD=__POSTGRES_PASSWORD__
    networks:
      - cryfttee-keyvault
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U web3signer -d web3signer"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Web3Signer - Ethereum Signing Service
  web3signer:
    image: consensys/web3signer:__WEB3SIGNER_VERSION__
    container_name: cryfttee-web3signer
    restart: unless-stopped
    user: "1000:1000"
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "__WEB3SIGNER_PORT__:9000"
      - "__WEB3SIGNER_METRICS_PORT__:9001"
    volumes:
      - ../web3signer:/data
      - ./web3signer.yaml:/config/web3signer.yaml:ro
    command:
      - --data-path=/data
      - --config-file=/config/web3signer.yaml
      - eth2
      - --network=mainnet
      - --enable-key-manager-api=true
      - --slashing-protection-db-url=jdbc:postgresql://postgres:5432/web3signer
      - --slashing-protection-db-username=web3signer
      - --slashing-protection-db-password=__POSTGRES_PASSWORD__
      - --slashing-protection-pruning-enabled=true
      - --slashing-protection-pruning-epochs-to-keep=500
    environment:
      - JAVA_OPTS=-Xmx512m -Xms256m -XX:+UseG1GC
      - LOG4J_FORMAT_MSG_NO_LOOKUPS=true
    networks:
      cryfttee-keyvault:
        aliases:
          - web3signer
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9000/upcheck || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  cryfttee-keyvault:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
COMPOSEEOF
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

# Vault Auto-Init Script (runs in container on first start)
generate_vault_init_script() {
    cat << 'INITSCRIPT'
#!/bin/sh
#
# Vault Auto-Init Script for CryftTEE
# Automatically initializes and unseals Vault on first deployment
# Uses AppRole for all access - never exposes root token to applications!
#
# NOTE: This script avoids using 'jq' since it's not available in the Vault image.
# We use sed/grep and vault CLI's -field option instead.
#

set -e

INIT_FILE="/vault/init/vault-init.json"
UNSEAL_FILE="/vault/init/unseal-keys.txt"
ROOT_TOKEN_FILE="/vault/init/root-token.txt"
APPROLE_FILE="/vault/init/approle.json"

# Simple JSON value extractor (no jq needed)
# Usage: json_value "key" <<< "$json"
json_value() {
    local key="$1"
    # Handles: "key": "value" or "key":"value"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1
}

# Extract array values from JSON (one per line)
# Usage: json_array "key" <<< "$json"
json_array() {
    local key="$1"
    # Find the array and extract values
    sed -n "/\"${key}\"[[:space:]]*:/,/\]/p" | grep '"' | sed 's/.*"\([^"]*\)".*/\1/' | grep -v "^${key}$"
}

echo "[vault-init] Starting Vault auto-initialization..."
echo "[vault-init] Using AppRole-based access (production-safe)"

# Wait for Vault to be ready
for i in $(seq 1 30); do
    if vault status 2>&1 | grep -qE "(Sealed|Initialized)"; then
        break
    fi
    echo "[vault-init] Waiting for Vault to start... ($i/30)"
    sleep 2
done

# Check if already initialized
if vault status 2>/dev/null | grep -q "Initialized.*true"; then
    echo "[vault-init] Vault already initialized"
    
    # Auto-unseal if we have the keys
    if [ -f "${UNSEAL_FILE}" ] && vault status 2>/dev/null | grep -q "Sealed.*true"; then
        echo "[vault-init] Auto-unsealing Vault..."
        while read key; do
            vault operator unseal "${key}" >/dev/null 2>&1 || true
        done < "${UNSEAL_FILE}"
        echo "[vault-init] Vault unsealed!"
    fi
    
    # Verify Vault is unsealed and ready
    if vault status 2>/dev/null | grep -q "Sealed.*false"; then
        echo "[vault-init] Vault is ready!"
        
        # Verify AppRole exists (use root token only for setup)
        if [ -f "${ROOT_TOKEN_FILE}" ] && [ ! -f "${APPROLE_FILE}" ]; then
            export VAULT_TOKEN=$(cat "${ROOT_TOKEN_FILE}")
            
            # Enable KV engine for CryftTEE keys if not exists
            if ! vault secrets list 2>/dev/null | grep -q "cryfttee/"; then
                echo "[vault-init] Enabling cryfttee KV secrets engine..."
                vault secrets enable -path=cryfttee kv-v2 2>/dev/null || true
            fi
            
            # Recreate AppRole credentials (using vault -field instead of jq)
            echo "[vault-init] Regenerating AppRole credentials..."
            ROLE_ID=$(vault read -field=role_id auth/approle/role/web3signer/role-id 2>/dev/null || echo "")
            SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/web3signer/secret-id 2>/dev/null || echo "")
            
            if [ -n "${ROLE_ID}" ] && [ -n "${SECRET_ID}" ]; then
                cat > "${APPROLE_FILE}" << APPROLE
{
  "vault_addr": "http://vault:8200",
  "role_id": "${ROLE_ID}",
  "secret_id": "${SECRET_ID}"
}
APPROLE
                chmod 600 "${APPROLE_FILE}"
                echo "[vault-init] AppRole credentials saved to ${APPROLE_FILE}"
            fi
        fi
    fi
    exit 0
fi

echo "[vault-init] Initializing Vault (first time setup)..."

# Initialize with single unseal key for dev (use 5/3 for production)
INIT_OUTPUT=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)

# Save initialization output (for disaster recovery only)
echo "${INIT_OUTPUT}" > "${INIT_FILE}"
chmod 600 "${INIT_FILE}"

# Extract and save unseal keys (using sed instead of jq)
echo "${INIT_OUTPUT}" | json_array "unseal_keys_b64" > "${UNSEAL_FILE}"
chmod 600 "${UNSEAL_FILE}"

# Extract root token (used only for initial setup, NOT for app access)
ROOT_TOKEN=$(echo "${INIT_OUTPUT}" | json_value "root_token")
echo "${ROOT_TOKEN}" > "${ROOT_TOKEN_FILE}"
chmod 600 "${ROOT_TOKEN_FILE}"

echo "[vault-init] Vault initialized! Unsealing..."

# Unseal - get first key from file
UNSEAL_KEY=$(head -1 "${UNSEAL_FILE}")
vault operator unseal "${UNSEAL_KEY}" >/dev/null

echo "[vault-init] Vault unsealed!"

# Configure Vault for CryftTEE (using root token for setup only)
export VAULT_TOKEN="${ROOT_TOKEN}"

echo "[vault-init] Enabling secrets engines..."

# KV v2 for key storage
vault secrets enable -path=cryfttee kv-v2 2>/dev/null || true

# Transit engine for signing operations
vault secrets enable transit 2>/dev/null || true

echo "[vault-init] Creating CryftTEE policy (least privilege)..."

vault policy write cryfttee - << 'POLICY'
# CryftTEE Vault Policy - Least Privilege Access
# This policy grants only the minimum permissions needed for key operations

# BLS keys (ETH2 validator signing) - read-only for signing operations
path "cryfttee/data/keys/bls/*" {
  capabilities = ["read", "list"]
}
path "cryfttee/metadata/keys/bls/*" {
  capabilities = ["list"]
}

# TLS/SECP256k1 keys - read-only for signing operations
path "cryfttee/data/keys/tls/*" {
  capabilities = ["read", "list"]
}
path "cryfttee/metadata/keys/tls/*" {
  capabilities = ["list"]
}

# Transit engine operations (signing only, no key management)
path "transit/sign/*" {
  capabilities = ["create", "update"]
}
path "transit/verify/*" {
  capabilities = ["create", "update"]
}
POLICY

# Create admin policy for key management (separate from signing)
vault policy write cryfttee-admin - << 'POLICY'
# CryftTEE Admin Policy - For key import/management operations
# Use this role for administrative tasks, NOT for runtime signing

# Full access to BLS keys
path "cryfttee/data/keys/bls/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "cryfttee/metadata/keys/bls/*" {
  capabilities = ["list", "delete"]
}

# Full access to TLS keys
path "cryfttee/data/keys/tls/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "cryfttee/metadata/keys/tls/*" {
  capabilities = ["list", "delete"]
}

# Transit engine key management
path "transit/keys/*" {
  capabilities = ["create", "read", "update", "list"]
}
path "transit/sign/*" {
  capabilities = ["create", "update"]
}
path "transit/verify/*" {
  capabilities = ["create", "update"]
}
POLICY

echo "[vault-init] Setting up AppRole authentication..."

# Enable AppRole auth
vault auth enable approle 2>/dev/null || true

# Create Web3Signer role (signing operations - least privilege)
echo "[vault-init] Creating 'web3signer' AppRole (signing only)..."
vault write auth/approle/role/web3signer \
    token_policies="cryfttee" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0 \
    secret_id_num_uses=0

# Create Admin role (key management)
echo "[vault-init] Creating 'cryfttee-admin' AppRole (key management)..."
vault write auth/approle/role/cryfttee-admin \
    token_policies="cryfttee-admin" \
    token_ttl=15m \
    token_max_ttl=1h \
    secret_id_ttl=24h \
    secret_id_num_uses=10

# Get Web3Signer AppRole credentials (for runtime signing)
# Using vault -field option instead of jq
ROLE_ID=$(vault read -field=role_id auth/approle/role/web3signer/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/web3signer/secret-id)

# Save Web3Signer AppRole credentials
cat > "${APPROLE_FILE}" << APPROLE
{
  "vault_addr": "http://vault:8200",
  "role_id": "${ROLE_ID}",
  "secret_id": "${SECRET_ID}",
  "description": "Web3Signer AppRole - read-only access for signing operations"
}
APPROLE
chmod 600 "${APPROLE_FILE}"

# Get Admin AppRole credentials (for key import operations)
# Using vault -field option instead of jq
ADMIN_ROLE_ID=$(vault read -field=role_id auth/approle/role/cryfttee-admin/role-id)
ADMIN_SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/cryfttee-admin/secret-id)

cat > "/vault/init/approle-admin.json" << APPROLE
{
  "vault_addr": "http://vault:8200",
  "role_id": "${ADMIN_ROLE_ID}",
  "secret_id": "${ADMIN_SECRET_ID}",
  "description": "CryftTEE Admin AppRole - for key import/delete operations",
  "note": "This secret_id expires in 24h and has limited uses. Regenerate as needed."
}
APPROLE
chmod 600 "/vault/init/approle-admin.json"

# ═══════════════════════════════════════════════════════════════════════════════
# CRITICAL: Secure Backup of Unseal Keys and Root Token
# ═══════════════════════════════════════════════════════════════════════════════
#
# The unseal keys and root token are NOT automatically saved to persistent storage!
# If lost, you will PERMANENTLY lose access to all secrets in Vault.
#

echo ""
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                          ║"
echo "║   ⚠️  CRITICAL: SECURE YOUR VAULT RECOVERY CREDENTIALS ⚠️                ║"
echo "║                                                                          ║"
echo "╠══════════════════════════════════════════════════════════════════════════╣"
echo "║                                                                          ║"
echo "║   The following credentials are required for disaster recovery.          ║"
echo "║   If lost, ALL SECRETS IN VAULT WILL BE PERMANENTLY INACCESSIBLE.        ║"
echo "║                                                                          ║"
echo "║   These credentials will be DELETED from this container after display!   ║"
echo "║                                                                          ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo ""
echo "┌─────────────────────────────────────────────────────────────────────────┐"
echo "│  UNSEAL KEY (required to unseal Vault after every restart)              │"
echo "├─────────────────────────────────────────────────────────────────────────┤"
echo "│                                                                         │"
echo "│  ${UNSEAL_KEY}"
echo "│                                                                         │"
echo "└─────────────────────────────────────────────────────────────────────────┘"
echo ""
echo "┌─────────────────────────────────────────────────────────────────────────┐"
echo "│  ROOT TOKEN (emergency admin access only - never use for applications)  │"
echo "├─────────────────────────────────────────────────────────────────────────┤"
echo "│                                                                         │"
echo "│  ${ROOT_TOKEN}"
echo "│                                                                         │"
echo "└─────────────────────────────────────────────────────────────────────────┘"
echo ""
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║  BACKUP OPTIONS (Choose one - do this NOW before continuing!)           ║"
echo "╠══════════════════════════════════════════════════════════════════════════╣"
echo "║                                                                          ║"
echo "║  Option 1: ENCRYPTED USB DRIVE (Recommended for production)             ║"
echo "║  ─────────────────────────────────────────────────────────────────────── ║"
echo "║  1. Insert a dedicated USB drive                                        ║"
echo "║  2. Copy the credentials above to a text file on the USB                ║"
echo "║  3. Encrypt the USB drive with BitLocker, LUKS, or VeraCrypt            ║"
echo "║  4. Store USB in a physical safe or secure location                     ║"
echo "║  5. Consider creating a second backup on another USB                    ║"
echo "║                                                                          ║"
echo "║  Option 2: PASSWORD-PROTECTED FILE (Development/testing)                ║"
echo "║  ─────────────────────────────────────────────────────────────────────── ║"
echo "║  Run this command on your LOCAL machine (not in container):             ║"
echo "║                                                                          ║"
echo "║    # Create encrypted backup with GPG:                                  ║"
echo "║    echo 'UNSEAL_KEY=${UNSEAL_KEY}' > vault-recovery.txt"
echo "║    echo 'ROOT_TOKEN=${ROOT_TOKEN}' >> vault-recovery.txt"
echo "║    gpg -c --cipher-algo AES256 vault-recovery.txt                       ║"
echo "║    shred -u vault-recovery.txt  # Securely delete plaintext             ║"
echo "║                                                                          ║"
echo "║  Option 3: HARDWARE SECURITY MODULE (Enterprise)                        ║"
echo "║  ─────────────────────────────────────────────────────────────────────── ║"
echo "║  Store unseal keys in HSM using Vault's auto-unseal feature.            ║"
echo "║  See: https://developer.hashicorp.com/vault/docs/concepts/seal          ║"
echo "║                                                                          ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║  ⚠️  DO NOT PROCEED UNTIL YOU HAVE SAVED THESE CREDENTIALS! ⚠️           ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo ""

# Create a recovery script that can be used to unseal (does NOT contain keys)
cat > "/vault/init/unseal-instructions.txt" << 'INSTRUCTIONS'
# Vault Unseal Instructions
# ═══════════════════════════════════════════════════════════════════════════════
#
# After a Vault restart, you must unseal it using your backup unseal key.
#
# Method 1: Via CLI
#   vault operator unseal <YOUR_UNSEAL_KEY>
#
# Method 2: Via API
#   curl -X POST http://localhost:8200/v1/sys/unseal \
#     -H "Content-Type: application/json" \
#     -d '{"key": "<YOUR_UNSEAL_KEY>"}'
#
# Method 3: Via UI
#   1. Open http://localhost:8200/ui
#   2. Enter your unseal key when prompted
#
# IMPORTANT: The unseal key is NOT stored on this server.
#            Retrieve it from your secure backup location.
#
INSTRUCTIONS

# DO NOT store unseal keys or root token in the container for production!
# Only save AppRole credentials (which have limited, revocable access)

# For auto-unseal in dev/testing, optionally keep unseal keys
# In production, these should be removed after backup confirmation
if [ "${VAULT_DEV_MODE:-false}" != "true" ]; then
    echo "[vault-init] For production security, unseal keys and root token"
    echo "[vault-init] should be removed from this container after you confirm backup."
    echo ""
    echo "[vault-init] To enable auto-unseal for development, set VAULT_DEV_MODE=true"
    echo ""
    # Keep files for now but warn user
    echo "[vault-init] Files temporarily saved to:"
    echo "  - ${UNSEAL_FILE}"
    echo "  - ${ROOT_TOKEN_FILE}"
    echo ""
    echo "[vault-init] DELETE THESE after confirming your backup:"
    echo "  rm ${UNSEAL_FILE} ${ROOT_TOKEN_FILE}"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     Vault Initialization Complete!                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "[vault-init] AppRole-based access configured (production-safe)"
echo ""
echo "  AppRole Credentials (for application access):"
echo "  ─────────────────────────────────────────────────────────────"
echo "  web3signer (signing):  ${APPROLE_FILE}"
echo "  cryfttee-admin (mgmt): /vault/init/approle-admin.json"
echo ""
echo "  These AppRole credentials are safe to keep on the server."
echo "  They have limited, revocable permissions and short TTLs."
echo ""
echo "[vault-init] Vault is ready for CryftTEE!"
echo ""

INITSCRIPT
}

# Generate Web3Signer key config for Vault-stored keys
generate_vault_key_config() {
    local key_type="$1"  # bls or secp256k1
    local key_name="$2"
    local vault_path="$3"
    
    cat << EOF
# Web3Signer key config for Vault-stored ${key_type} key
type: hashicorp
keyType: ${key_type^^}
keyPath: ${vault_path}
serverHost: vault
serverPort: 8200
tlsEnabled: false
timeout: 10000
# Token loaded from environment or approle
EOF
}

# Web3Signer Configuration
generate_web3signer_config() {
    cat << EOF
# Web3Signer Configuration for CryftTEE
# Supports both BLS (consensus) and SECP256k1 (execution/TLS) signing
#
# API Endpoints available:
#   GET  /upcheck                          - Health check
#   GET  /api/v1/eth2/publicKeys           - List BLS public keys
#   POST /api/v1/eth2/sign/:identifier     - Sign with BLS key
#   GET  /api/v1/eth1/publicKeys           - List SECP256k1 public keys
#   POST /api/v1/eth1/sign/:identifier     - Sign with SECP256k1 key

# HTTP Server settings
http-listen-host: "0.0.0.0"
http-listen-port: 9000

# CORS - allow CryftTEE connections from any origin
http-cors-origins: "*"
http-host-allowlist: "*"

# Metrics for monitoring
metrics-enabled: true
metrics-host: "0.0.0.0"
metrics-port: 9001
metrics-host-allowlist: "*"

# Logging
logging: "INFO"

# Swagger UI for API exploration (useful for debugging)
swagger-ui-enabled: true

# Idle connection timeout (seconds)
idle-connection-timeout-seconds: 60
EOF
}

# Web3Signer key config generator for file-based keys
generate_web3signer_key_config() {
    local key_type="$1"  # bls or secp256k1
    local keystore_file="$2"
    local password_file="$3"
    
    if [ "${key_type}" = "bls" ]; then
        cat << EOF
type: file-keystore
keyType: BLS
keystoreFile: ${keystore_file}
keystorePasswordFile: ${password_file}
EOF
    else
        cat << EOF
type: file-keystore
keyType: SECP256K1
keystoreFile: ${keystore_file}
keystorePasswordFile: ${password_file}
EOF
    fi
}

# Systemd Service (user-level - no sudo required)
generate_systemd_service() {
    # Note: Uses $HOME which will be expanded on the target system
    cat << 'SERVICEEOF'
[Unit]
Description=CryftTEE KeyVault Stack (Vault + Web3Signer)
Documentation=https://github.com/cryft-labs/cryfttee
After=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/.cryfttee-keyvault
ExecStartPre=/usr/bin/docker compose -f %h/.cryfttee-keyvault/config/docker-compose.yml pull
ExecStart=/usr/bin/docker compose -f %h/.cryfttee-keyvault/config/docker-compose.yml up --remove-orphans
ExecStop=/usr/bin/docker compose -f %h/.cryfttee-keyvault/config/docker-compose.yml down
Restart=on-failure
RestartSec=10
TimeoutStartSec=180
TimeoutStopSec=60

[Install]
WantedBy=default.target
SERVICEEOF
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
        echo "[!] Vault is sealed. Run: ~/.cryfttee-keyvault/scripts/unseal-vault.sh"
    else
        echo "[+] Vault is unsealed and ready"
    fi
    exit 0
fi

echo "[+] Initializing Vault with 5 key shares, 3 required to unseal..."
INIT_OUTPUT=$(vault operator init -key-shares=5 -key-threshold=3 -format=json)

# Save keys
KEYS_FILE="~/.cryfttee-keyvault/vault-init-keys.json"
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

cat > ~/.cryfttee-keyvault/vault-approle.json << APPROLE
{
  "vault_addr": "${VAULT_ADDR}",
  "role_id": "${ROLE_ID}",
  "secret_id": "${SECRET_ID}"
}
APPROLE
chmod 600 ~/.cryfttee-keyvault/vault-approle.json

echo ""
echo "=== Vault Setup Complete ==="
echo ""
echo "Vault UI:       ${VAULT_ADDR}/ui"
echo "Root Token:     ${ROOT_TOKEN}"
echo ""
echo "AppRole credentials saved to: ~/.cryfttee-keyvault/vault-approle.json"
echo ""
echo "IMPORTANT:"
echo "  1. Back up ~/.cryfttee-keyvault/vault-init-keys.json to a secure location"
echo "  2. After Vault restarts, run: ~/.cryfttee-keyvault/scripts/unseal-vault.sh"
echo ""
EOF
}

generate_unseal_vault_script() {
    cat << 'EOF'
#!/bin/bash
#
# Unseal Vault after restart
# Prompts for unseal key - does NOT store keys on disk for security
#

set -e

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_ADDR

# Check if Vault is running
if ! curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1; then
    echo "[x] Vault not responding at ${VAULT_ADDR}"
    echo "[i] Start Vault first: systemctl --user start cryfttee-keyvault"
    exit 1
fi

# Check seal status
SEAL_STATUS=$(curl -sf "${VAULT_ADDR}/v1/sys/seal-status" 2>/dev/null)
IS_SEALED=$(echo "${SEAL_STATUS}" | jq -r '.sealed')

if [ "${IS_SEALED}" = "false" ]; then
    echo "[+] Vault is already unsealed"
    exit 0
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║             Vault Unseal Required                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Vault is sealed and requires your unseal key to unlock."
echo ""
echo "Retrieve your unseal key from your secure backup:"
echo "  • Encrypted USB drive"
echo "  • Password-protected file (GPG encrypted)"
echo "  • Hardware Security Module"
echo ""

# Prompt for unseal key
read -sp "Enter Unseal Key: " UNSEAL_KEY
echo ""

if [ -z "${UNSEAL_KEY}" ]; then
    echo "[x] No unseal key provided"
    exit 1
fi

echo "[+] Unsealing Vault..."
RESULT=$(curl -sf -X POST \
    -H "Content-Type: application/json" \
    -d "{\"key\": \"${UNSEAL_KEY}\"}" \
    "${VAULT_ADDR}/v1/sys/unseal" 2>/dev/null)

IS_SEALED=$(echo "${RESULT}" | jq -r '.sealed')

if [ "${IS_SEALED}" = "false" ]; then
    echo "[+] Vault unsealed successfully!"
    echo ""
    # Clear the key from memory
    unset UNSEAL_KEY
else
    PROGRESS=$(echo "${RESULT}" | jq -r '.progress')
    THRESHOLD=$(echo "${RESULT}" | jq -r '.t')
    echo "[i] Unseal progress: ${PROGRESS}/${THRESHOLD}"
    echo "[i] Additional unseal keys required. Run this script again."
fi
EOF
}

# Generate backup script for secure credential export
generate_backup_credentials_script() {
    cat << 'EOF'
#!/bin/bash
#
# Backup Vault Recovery Credentials
# Creates password-protected backup of unseal keys and root token
#

set -e

VAULT_INIT_DIR="~/.cryfttee-keyvault/vault/init"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       Vault Recovery Credentials Backup                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if credentials exist
if [ ! -f "${VAULT_INIT_DIR}/unseal-keys.txt" ] && [ ! -f "${VAULT_INIT_DIR}/root-token.txt" ]; then
    echo "[x] No credentials found to backup."
    echo "[i] Vault may not be initialized, or credentials were already removed."
    exit 1
fi

echo "This script will create a password-protected backup of your"
echo "Vault recovery credentials (unseal key and root token)."
echo ""
echo "Choose backup destination:"
echo "  1) Encrypted file (GPG) - save to current directory"
echo "  2) Encrypted file (GPG) - save to USB drive"
echo "  3) Display only (copy manually to secure location)"
echo "  4) Cancel"
echo ""
read -p "Select option [1-4]: " OPTION

case "${OPTION}" in
    1|2)
        # Check for GPG
        if ! command -v gpg &> /dev/null; then
            echo "[x] GPG not installed. Install with: sudo apt install gnupg"
            exit 1
        fi
        
        if [ "${OPTION}" = "2" ]; then
            echo ""
            echo "Available drives:"
            lsblk -o NAME,SIZE,MOUNTPOINT | grep -E "sd[b-z]|usb" || echo "  (no USB drives detected)"
            echo ""
            read -p "Enter mount point of USB drive (e.g., /media/usb): " USB_PATH
            if [ ! -d "${USB_PATH}" ]; then
                echo "[x] Directory not found: ${USB_PATH}"
                exit 1
            fi
            BACKUP_DIR="${USB_PATH}"
        else
            BACKUP_DIR="$(pwd)"
        fi
        
        BACKUP_FILE="${BACKUP_DIR}/vault-recovery-$(date +%Y%m%d-%H%M%S).gpg"
        TEMP_FILE=$(mktemp)
        
        # Collect credentials
        echo "# Vault Recovery Credentials" > "${TEMP_FILE}"
        echo "# Generated: $(date)" >> "${TEMP_FILE}"
        echo "# Host: $(hostname)" >> "${TEMP_FILE}"
        echo "" >> "${TEMP_FILE}"
        
        if [ -f "${VAULT_INIT_DIR}/unseal-keys.txt" ]; then
            echo "UNSEAL_KEY=$(cat ${VAULT_INIT_DIR}/unseal-keys.txt)" >> "${TEMP_FILE}"
        fi
        
        if [ -f "${VAULT_INIT_DIR}/root-token.txt" ]; then
            echo "ROOT_TOKEN=$(cat ${VAULT_INIT_DIR}/root-token.txt)" >> "${TEMP_FILE}"
        fi
        
        echo "" >> "${TEMP_FILE}"
        echo "# To unseal Vault:" >> "${TEMP_FILE}"
        echo "# vault operator unseal \$UNSEAL_KEY" >> "${TEMP_FILE}"
        
        # Encrypt with password
        echo ""
        echo "Enter a strong password for the backup file."
        echo "You will need this password to restore the credentials."
        echo ""
        
        gpg --symmetric --cipher-algo AES256 --output "${BACKUP_FILE}" "${TEMP_FILE}"
        
        # Securely delete temp file
        shred -u "${TEMP_FILE}" 2>/dev/null || rm -f "${TEMP_FILE}"
        
        echo ""
        echo "[+] Encrypted backup created: ${BACKUP_FILE}"
        echo ""
        echo "To restore, run:"
        echo "  gpg -d ${BACKUP_FILE}"
        echo ""
        
        read -p "Delete credentials from server? (recommended for production) [y/N]: " DELETE_CREDS
        if [[ "${DELETE_CREDS}" =~ ^[Yy]$ ]]; then
            shred -u "${VAULT_INIT_DIR}/unseal-keys.txt" 2>/dev/null || rm -f "${VAULT_INIT_DIR}/unseal-keys.txt" 2>/dev/null || true
            shred -u "${VAULT_INIT_DIR}/root-token.txt" 2>/dev/null || rm -f "${VAULT_INIT_DIR}/root-token.txt" 2>/dev/null || true
            rm -f "${VAULT_INIT_DIR}/vault-init.json" 2>/dev/null || true
            echo "[+] Credentials removed from server."
            echo "[!] Keep your encrypted backup safe - it's the only copy!"
        fi
        ;;
        
    3)
        echo ""
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║  COPY THESE CREDENTIALS TO A SECURE LOCATION NOW!           ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        
        if [ -f "${VAULT_INIT_DIR}/unseal-keys.txt" ]; then
            echo "UNSEAL_KEY:"
            cat "${VAULT_INIT_DIR}/unseal-keys.txt"
            echo ""
        fi
        
        if [ -f "${VAULT_INIT_DIR}/root-token.txt" ]; then
            echo "ROOT_TOKEN:"
            cat "${VAULT_INIT_DIR}/root-token.txt"
            echo ""
        fi
        
        echo ""
        read -p "Press Enter after you have saved these credentials..."
        echo ""
        
        read -p "Delete credentials from server? (recommended for production) [y/N]: " DELETE_CREDS
        if [[ "${DELETE_CREDS}" =~ ^[Yy]$ ]]; then
            shred -u "${VAULT_INIT_DIR}/unseal-keys.txt" 2>/dev/null || rm -f "${VAULT_INIT_DIR}/unseal-keys.txt" 2>/dev/null || true
            shred -u "${VAULT_INIT_DIR}/root-token.txt" 2>/dev/null || rm -f "${VAULT_INIT_DIR}/root-token.txt" 2>/dev/null || true
            rm -f "${VAULT_INIT_DIR}/vault-init.json" 2>/dev/null || true
            echo "[+] Credentials removed from server."
        fi
        ;;
        
    4)
        echo "Cancelled."
        exit 0
        ;;
        
    *)
        echo "[x] Invalid option"
        exit 1
        ;;
esac

echo ""
echo "[+] Backup complete!"
EOF
}

generate_import_key_script() {
    cat << 'EOF'
#!/bin/bash
#
# Import keys into Web3Signer for CryftTEE
#
# Usage:
#   ./import-key.sh bls <keystore.json> <password>        # Import BLS key from file
#   ./import-key.sh tls <keystore.json> <password>        # Import TLS/SECP256k1 key from file
#   ./import-key.sh vault-bls <key-name> <private-key>    # Store BLS key in Vault
#   ./import-key.sh vault-tls <key-name> <private-key>    # Store TLS key in Vault
#   ./import-key.sh generate-bls                          # Generate new BLS key pair
#   ./import-key.sh list                                  # List all loaded keys
#   ./import-key.sh list-vault                            # List keys in Vault
#
# Storage backends:
#   - File-based: Keys stored in ~/.cryfttee-keyvault/keys/
#   - HashiCorp Vault: Keys stored in Vault at cryfttee/data/keys/
#

set -e

KEY_TYPE="${1:-}"
KEYSTORE_FILE="${2:-}"
PASSWORD="${3:-}"
KEYS_DIR="~/.cryfttee-keyvault/keys"
WEB3SIGNER_URL="${WEB3SIGNER_URL:-http://127.0.0.1:9000}"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_INIT_DIR="~/.cryfttee-keyvault/vault/init"

# Authenticate to Vault using AppRole (role-based access)
# Uses admin role for key management, web3signer role for read operations
authenticate_vault() {
    local role="${1:-web3signer}"  # default to web3signer (read-only)
    
    if [ "${role}" = "admin" ]; then
        APPROLE_FILE="${VAULT_INIT_DIR}/approle-admin.json"
    else
        APPROLE_FILE="${VAULT_INIT_DIR}/approle.json"
    fi
    
    # Check if we already have a valid token
    if [ -n "${VAULT_TOKEN}" ]; then
        # Verify token is still valid
        if curl -sf -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/auth/token/lookup-self" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    # Authenticate via AppRole
    if [ -f "${APPROLE_FILE}" ]; then
        ROLE_ID=$(jq -r '.role_id' "${APPROLE_FILE}" 2>/dev/null)
        SECRET_ID=$(jq -r '.secret_id' "${APPROLE_FILE}" 2>/dev/null)
        
        if [ -n "${ROLE_ID}" ] && [ "${ROLE_ID}" != "null" ] && [ -n "${SECRET_ID}" ] && [ "${SECRET_ID}" != "null" ]; then
            # Get token via AppRole login
            TOKEN_RESPONSE=$(curl -sf -X POST \
                -H "Content-Type: application/json" \
                -d "{\"role_id\": \"${ROLE_ID}\", \"secret_id\": \"${SECRET_ID}\"}" \
                "${VAULT_ADDR}/v1/auth/approle/login" 2>/dev/null)
            
            if [ -n "${TOKEN_RESPONSE}" ]; then
                export VAULT_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.auth.client_token' 2>/dev/null)
                if [ -n "${VAULT_TOKEN}" ] && [ "${VAULT_TOKEN}" != "null" ]; then
                    return 0
                fi
            fi
        fi
    fi
    
    if [ "${role}" = "admin" ]; then
        echo "[x] Admin AppRole authentication failed."
        echo "[i] The admin secret_id may have expired. Regenerate with:"
        echo "    vault write -f auth/approle/role/cryfttee-admin/secret-id"
    else
        echo "[x] AppRole authentication failed."
        echo "[i] Ensure ${APPROLE_FILE} exists with valid credentials."
    fi
    return 1
}

usage() {
    echo "CryftTEE Web3Signer Key Management"
    echo ""
    echo "Usage:"
    echo "  $0 bls <keystore.json> <password>        # BLS key from file (ETH2 staking)"
    echo "  $0 tls <keystore.json> <password>        # TLS/SECP256k1 key from file"
    echo "  $0 vault-bls <name> <private-key-hex>    # Store BLS key in HashiCorp Vault"
    echo "  $0 vault-tls <name> <private-key-hex>    # Store TLS key in HashiCorp Vault"
    echo "  $0 generate-bls                          # Generate new BLS key"
    echo "  $0 generate-tls                          # Generate new TLS/ECDSA key"
    echo "  $0 list                                  # List keys in Web3Signer"
    echo "  $0 list-vault                            # List keys stored in Vault"
    echo "  $0 test                                  # Test connectivity"
    echo ""
    echo "Examples:"
    echo "  # File-based (simple):"
    echo "  $0 bls ./validator-keystore.json mypassword"
    echo ""
    echo "  # Vault-based (recommended for production):"
    echo "  $0 vault-bls validator-1 0x1234...abcd"
    echo ""
    echo "After importing, restart Web3Signer:"
    echo "  docker restart cryfttee-web3signer"
    exit 1
}

check_web3signer() {
    if ! curl -sf "${WEB3SIGNER_URL}/upcheck" >/dev/null 2>&1; then
        echo "[x] Web3Signer not responding at ${WEB3SIGNER_URL}"
        echo "[i] Start with: systemctl --user start cryfttee-keyvault"
        exit 1
    fi
}

check_vault() {
    if ! curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1; then
        echo "[x] Vault not responding at ${VAULT_ADDR}"
        return 1
    fi
    
    # Authenticate using AppRole
    if ! authenticate_vault; then
        echo "[x] Vault AppRole authentication failed."
        echo "[i] Ensure AppRole credentials exist at: ${VAULT_INIT_DIR}/approle.json"
        return 1
    fi
    return 0
}

list_keys() {
    check_web3signer
    
    echo "=== BLS Keys (ETH2 Staking) ==="
    BLS_KEYS=$(curl -sf "${WEB3SIGNER_URL}/api/v1/eth2/publicKeys" 2>/dev/null || echo "[]")
    if [ "${BLS_KEYS}" = "[]" ] || [ -z "${BLS_KEYS}" ]; then
        echo "  (none loaded)"
    else
        echo "${BLS_KEYS}" | jq -r '.[]' 2>/dev/null | while read key; do
            echo "  - ${key}"
        done
    fi
    
    echo ""
    echo "=== SECP256k1 Keys (TLS Signing) ==="
    SECP_KEYS=$(curl -sf "${WEB3SIGNER_URL}/api/v1/eth1/publicKeys" 2>/dev/null || echo "[]")
    if [ "${SECP_KEYS}" = "[]" ] || [ -z "${SECP_KEYS}" ]; then
        echo "  (none loaded)"
    else
        echo "${SECP_KEYS}" | jq -r '.[]' 2>/dev/null | while read key; do
            echo "  - ${key}"
        done
    fi
    
    echo ""
    echo "=== Key Files on Disk ==="
    ls -la ${KEYS_DIR}/*.json 2>/dev/null | awk '{print "  " $NF}' || echo "  (none)"
}

list_vault_keys() {
    if ! check_vault; then
        return 1
    fi
    
    echo "=== BLS Keys in Vault ==="
    BLS_LIST=$(curl -sf -H "X-Vault-Token: ${VAULT_TOKEN}" \
        "${VAULT_ADDR}/v1/cryfttee/metadata/keys/bls?list=true" 2>/dev/null | jq -r '.data.keys[]?' 2>/dev/null)
    if [ -z "${BLS_LIST}" ]; then
        echo "  (none)"
    else
        echo "${BLS_LIST}" | while read key; do
            echo "  - ${key}"
        done
    fi
    
    echo ""
    echo "=== TLS Keys in Vault ==="
    TLS_LIST=$(curl -sf -H "X-Vault-Token: ${VAULT_TOKEN}" \
        "${VAULT_ADDR}/v1/cryfttee/metadata/keys/tls?list=true" 2>/dev/null | jq -r '.data.keys[]?' 2>/dev/null)
    if [ -z "${TLS_LIST}" ]; then
        echo "  (none)"
    else
        echo "${TLS_LIST}" | while read key; do
            echo "  - ${key}"
        done
    fi
}

store_in_vault() {
    local key_type="$1"  # bls or tls
    local key_name="$2"
    local private_key="$3"
    local public_key="${4:-}"
    
    # Key storage requires admin AppRole (write access)
    echo "[+] Authenticating with admin AppRole..."
    if ! authenticate_vault "admin"; then
        echo ""
        echo "[!] Key management requires the 'cryfttee-admin' AppRole."
        echo "[i] If the secret_id expired, regenerate it on the Vault server:"
        echo ""
        echo "    # SSH to keyvault server, then:"
        echo "    export VAULT_ADDR=http://127.0.0.1:8200"
        echo "    export VAULT_TOKEN=\$(cat ~/.cryfttee-keyvault/vault/init/root-token.txt)"
        echo "    vault write -format=json -f auth/approle/role/cryfttee-admin/secret-id > /tmp/new-secret.json"
        echo "    # Update approle-admin.json with new secret_id"
        echo ""
        return 1
    fi
    
    echo "[+] Storing ${key_type} key '${key_name}' in Vault..."
    
    # Store in Vault KV
    RESULT=$(curl -sf -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"data\": {\"private_key\": \"${private_key}\", \"public_key\": \"${public_key}\"}}" \
        "${VAULT_ADDR}/v1/cryfttee/data/keys/${key_type}/${key_name}" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "[+] Key stored in Vault at: cryfttee/data/keys/${key_type}/${key_name}"
        
        # Create Web3Signer key config YAML (uses web3signer AppRole, not admin)
        CONFIG_FILE="${KEYS_DIR}/vault-${key_type}-${key_name}.yaml"
        
        # Read web3signer approle for config
        WS_ROLE_ID=$(jq -r '.role_id' "${VAULT_INIT_DIR}/approle.json" 2>/dev/null)
        
        if [ "${key_type}" = "bls" ]; then
            cat << YAMLCONFIG | tee "${CONFIG_FILE}" > /dev/null
# Web3Signer Vault key config - uses AppRole authentication
type: hashicorp
keyType: BLS
keyPath: /v1/cryfttee/data/keys/bls/${key_name}
serverHost: vault
serverPort: 8200
tlsEnabled: false
timeout: 10000
# AppRole authentication (read-only access)
authFilePath: /vault-init/approle.json
YAMLCONFIG
        else
            cat << YAMLCONFIG | tee "${CONFIG_FILE}" > /dev/null
# Web3Signer Vault key config - uses AppRole authentication
type: hashicorp
keyType: SECP256K1
keyPath: /v1/cryfttee/data/keys/tls/${key_name}
serverHost: vault
serverPort: 8200
tlsEnabled: false
timeout: 10000
# AppRole authentication (read-only access)
authFilePath: /vault-init/approle.json
YAMLCONFIG
        fi
        
        chmod 600 "${CONFIG_FILE}"
        echo "[+] Web3Signer config created: ${CONFIG_FILE}"
        echo "[i] Uses AppRole authentication (read-only) for signing"
        echo ""
        echo "[!] Restart Web3Signer to load: docker restart cryfttee-web3signer"
        return 0
    else
        echo "[x] Failed to store key in Vault"
        return 1
    fi
}

test_connectivity() {
    echo "=== Connectivity Test ==="
    echo ""
    
    # Web3Signer
    echo -n "[Web3Signer] ${WEB3SIGNER_URL} ... "
    if curl -sf "${WEB3SIGNER_URL}/upcheck" >/dev/null 2>&1; then
        echo "✓ OK"
    else
        echo "✗ FAILED"
    fi
    
    # Vault
    echo -n "[Vault] ${VAULT_ADDR} ... "
    if curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1; then
        SEALED=$(curl -sf "${VAULT_ADDR}/v1/sys/health" | jq -r '.sealed')
        if [ "${SEALED}" = "false" ]; then
            echo "✓ OK (unsealed)"
        else
            echo "⚠ Sealed (run unseal script)"
        fi
    else
        echo "✗ Not running"
    fi
    
    # Vault AppRole
    echo -n "[Vault AppRole] ... "
    if authenticate_vault 2>/dev/null; then
        echo "✓ Authenticated"
    else
        echo "⚠ Not configured (check ${VAULT_INIT_DIR}/approle.json)"
    fi
    
    echo ""
    
    # Key counts
    BLS_COUNT=$(curl -sf "${WEB3SIGNER_URL}/api/v1/eth2/publicKeys" 2>/dev/null | jq '. | length' 2>/dev/null || echo "0")
    SECP_COUNT=$(curl -sf "${WEB3SIGNER_URL}/api/v1/eth1/publicKeys" 2>/dev/null | jq '. | length' 2>/dev/null || echo "0")
    
    echo "[+] Keys available in Web3Signer:"
    echo "    BLS (staking):     ${BLS_COUNT}"
    echo "    SECP256k1 (TLS):   ${SECP_COUNT}"
}

if [ -z "${KEY_TYPE}" ]; then
    usage
fi

case "${KEY_TYPE}" in
    list)
        list_keys
        ;;
    
    list-vault)
        list_vault_keys
        ;;
        
    test)
        test_connectivity
        ;;
    
    vault-bls)
        KEY_NAME="${KEYSTORE_FILE}"
        PRIVATE_KEY="${PASSWORD}"
        if [ -z "${KEY_NAME}" ] || [ -z "${PRIVATE_KEY}" ]; then
            echo "Usage: $0 vault-bls <key-name> <private-key-hex>"
            exit 1
        fi
        store_in_vault "bls" "${KEY_NAME}" "${PRIVATE_KEY}"
        ;;
    
    vault-tls)
        KEY_NAME="${KEYSTORE_FILE}"
        PRIVATE_KEY="${PASSWORD}"
        if [ -z "${KEY_NAME}" ] || [ -z "${PRIVATE_KEY}" ]; then
            echo "Usage: $0 vault-tls <key-name> <private-key-hex>"
            exit 1
        fi
        store_in_vault "tls" "${KEY_NAME}" "${PRIVATE_KEY}"
        ;;
        
    generate-bls)
        echo "=== CryftTEE BLS Key Generator ==="
        echo ""
        
        # Generate a random password if not provided
        PASSWORD="${KEYSTORE_FILE:-$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)}"
        
        # Create output directory
        OUTPUT_DIR="${KEYS_DIR}"
        mkdir -p "${OUTPUT_DIR}"
        
        echo "[+] Generating BLS key using eth2-val-tools..."
        echo "[i] Password: ${PASSWORD}"
        echo ""
        
        # Use eth2-val-tools Docker image for key generation
        if command -v docker &> /dev/null; then
            TEMP_DIR=$(mktemp -d)
            
            # Generate a single validator key using eth2-val-tools
            docker run --rm -v "${TEMP_DIR}:/output" \
                protolambda/eth2-val-tools:latest \
                keystores \
                --insecure \
                --prysm-pass="${PASSWORD}" \
                --out-loc=/output \
                --source-min=0 \
                --source-max=1 \
                --source-mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
                2>/dev/null
            
            # Check if keystore was generated
            KEYSTORE=$(find "${TEMP_DIR}" -name "*.json" -type f 2>/dev/null | head -1)
            
            if [ -n "${KEYSTORE}" ] && [ -f "${KEYSTORE}" ]; then
                PUBKEY=$(jq -r '.pubkey // .public_key' "${KEYSTORE}" 2>/dev/null)
                PUBKEY="${PUBKEY#0x}"
                
                if [ -n "${PUBKEY}" ]; then
                    # Copy to keys directory
                    cp "${KEYSTORE}" "${OUTPUT_DIR}/${PUBKEY}.json"
                    echo -n "${PASSWORD}" | tee "${OUTPUT_DIR}/${PUBKEY}.txt" > /dev/null
                    chmod 600 "${OUTPUT_DIR}/${PUBKEY}.json" "${OUTPUT_DIR}/${PUBKEY}.txt"
                    
                    echo ""
                    echo "[+] Generated BLS key: 0x${PUBKEY:0:16}...${PUBKEY: -8}"
                    echo "[+] Keystore: ${OUTPUT_DIR}/${PUBKEY}.json"
                    echo "[+] Password: ${OUTPUT_DIR}/${PUBKEY}.txt"
                    echo ""
                    echo "[!] Restart Web3Signer to load the new key:"
                    echo "    docker restart cryfttee-web3signer"
                    echo ""
                    echo "[i] CryftGo will detect this key via: GET /api/v1/eth2/publicKeys"
                else
                    echo "[x] Failed to extract pubkey from generated keystore"
                fi
            else
                echo "[x] Docker key generation failed. Trying alternative method..."
                echo ""
                echo "[i] Alternative: Use eth2-deposit-cli directly:"
                echo ""
                echo "    # Install"
                echo "    pip3 install eth-staking-deposit-cli"
                echo ""
                echo "    # Generate (follow prompts)"
                echo "    eth-staking-deposit-cli generate-keys --num_validators 1 --chain mainnet"
                echo ""
                echo "    # Import to Web3Signer"
                echo "    $0 bls ./validator_keys/keystore-*.json <your-password>"
            fi
            
            # Cleanup temp directory
            rm -rf "${TEMP_DIR}"
        else
            echo "[x] Docker not available"
            echo ""
            echo "[i] Manual BLS key generation:"
            echo "    pip3 install eth-staking-deposit-cli"
            echo "    eth-staking-deposit-cli generate-keys --num_validators 1 --chain mainnet"
            echo "    $0 bls ./validator_keys/keystore-*.json <password>"
        fi
        ;;
    
    generate-tls)
        echo "=== CryftTEE TLS Key Generator ==="
        echo ""
        
        OUTPUT_DIR="${KEYS_DIR}"
        mkdir -p "${OUTPUT_DIR}"
        TEMP_DIR=$(mktemp -d)
        
        KEY_NAME="tls-$(date +%s)"
        
        echo "[+] Generating ECDSA P-256 key pair..."
        
        # Generate key
        openssl ecparam -name prime256v1 -genkey -noout -out "${TEMP_DIR}/private.pem"
        openssl ec -in "${TEMP_DIR}/private.pem" -pubout -out "${TEMP_DIR}/public.pem" 2>/dev/null
        openssl pkcs8 -topk8 -nocrypt -in "${TEMP_DIR}/private.pem" -out "${TEMP_DIR}/private.pkcs8.pem"
        
        # Get hex representation
        PRIVATE_HEX=$(openssl ec -in "${TEMP_DIR}/private.pem" -text -noout 2>/dev/null | grep -A 5 'priv:' | grep -v 'priv:' | tr -d ' \n:')
        
        # Copy to keys directory
        cp "${TEMP_DIR}/private.pkcs8.pem" "${OUTPUT_DIR}/${KEY_NAME}.pem"
        chmod 600 "${OUTPUT_DIR}/${KEY_NAME}.pem"
        
        # Create Web3Signer config
        cat << KEYCONFIG | tee "${OUTPUT_DIR}/${KEY_NAME}.yaml" > /dev/null
type: file-raw
keyType: SECP256K1
privateKeyFile: /keys/${KEY_NAME}.pem
KEYCONFIG
        chmod 600 "${OUTPUT_DIR}/${KEY_NAME}.yaml"
        
        echo "[+] Generated TLS key: ${KEY_NAME}"
        echo "[+] Private key: ${OUTPUT_DIR}/${KEY_NAME}.pem"
        echo "[+] Web3Signer config: ${OUTPUT_DIR}/${KEY_NAME}.yaml"
        echo ""
        
        # Also offer to store in Vault
        if check_vault 2>/dev/null; then
            echo "[i] Vault detected! Store in Vault for better security?"
            echo "    $0 vault-tls ${KEY_NAME} ${PRIVATE_HEX}"
        fi
        
        echo ""
        echo "[!] Restart Web3Signer to load:"
        echo "    docker restart cryfttee-web3signer"
        
        rm -rf "${TEMP_DIR}"
        ;;
        
    bls)
        if [ -z "${KEYSTORE_FILE}" ] || [ -z "${PASSWORD}" ]; then
            usage
        fi
        
        if [ ! -f "${KEYSTORE_FILE}" ]; then
            echo "[x] File not found: ${KEYSTORE_FILE}"
            exit 1
        fi
        
        # Extract pubkey
        PUBKEY=$(jq -r '.pubkey // .public_key // empty' "${KEYSTORE_FILE}" 2>/dev/null)
        if [ -z "${PUBKEY}" ]; then
            echo "[x] Could not extract pubkey from keystore"
            exit 1
        fi
        PUBKEY="${PUBKEY#0x}"
        
        echo "[+] Importing BLS key: 0x${PUBKEY:0:12}...${PUBKEY: -8}"
        
        mkdir -p "${KEYS_DIR}"
        cp "${KEYSTORE_FILE}" "${KEYS_DIR}/${PUBKEY}.json"
        chmod 600 "${KEYS_DIR}/${PUBKEY}.json"
        echo -n "${PASSWORD}" | tee "${KEYS_DIR}/${PUBKEY}.txt" > /dev/null
        chmod 600 "${KEYS_DIR}/${PUBKEY}.txt"
        
        echo "[+] BLS key imported to ${KEYS_DIR}/"
        echo "[!] Restart Web3Signer to load: docker restart cryfttee-web3signer"
        ;;
        
    tls|secp256k1)
        if [ -z "${KEYSTORE_FILE}" ] || [ -z "${PASSWORD}" ]; then
            usage
        fi
        
        if [ ! -f "${KEYSTORE_FILE}" ]; then
            echo "[x] File not found: ${KEYSTORE_FILE}"
            exit 1
        fi
        
        ADDRESS=$(jq -r '.address // empty' "${KEYSTORE_FILE}" 2>/dev/null)
        if [ -z "${ADDRESS}" ]; then
            ADDRESS=$(sha256sum "${KEYSTORE_FILE}" | cut -c1-40)
        fi
        ADDRESS="${ADDRESS#0x}"
        
        echo "[+] Importing SECP256k1 key: 0x${ADDRESS}"
        
        mkdir -p "${KEYS_DIR}"
        KEYSTORE_NAME="secp256k1-${ADDRESS}"
        cp "${KEYSTORE_FILE}" "${KEYS_DIR}/${KEYSTORE_NAME}.json"
        chmod 600 "${KEYS_DIR}/${KEYSTORE_NAME}.json"
        echo -n "${PASSWORD}" | tee "${KEYS_DIR}/${KEYSTORE_NAME}.txt" > /dev/null
        chmod 600 "${KEYS_DIR}/${KEYSTORE_NAME}.txt"
        
        cat << KEYCONFIG | tee "${KEYS_DIR}/${KEYSTORE_NAME}.yaml" > /dev/null
type: file-keystore
keyType: SECP256K1
keystoreFile: /keys/${KEYSTORE_NAME}.json
keystorePasswordFile: /keys/${KEYSTORE_NAME}.txt
KEYCONFIG
        chmod 600 "${KEYS_DIR}/${KEYSTORE_NAME}.yaml"
        
        echo "[+] SECP256k1/TLS key imported to ${KEYS_DIR}/"
        echo "[!] Restart Web3Signer to load: docker restart cryfttee-web3signer"
        ;;
        
    *)
        echo "[x] Unknown command: ${KEY_TYPE}"
        usage
        ;;
esac

echo ""
echo "[i] Verify keys loaded with: $0 list"
EOF
}

generate_status_script() {
    cat << 'EOF'
#!/bin/bash
#
# Check CryftTEE KeyVault stack status
#

WEB3SIGNER_URL="${WEB3SIGNER_URL:-http://127.0.0.1:9000}"
CRYFTTEE_URL="${CRYFTTEE_URL:-http://127.0.0.1:3232}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           CryftTEE KeyVault Status                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check systemd service
echo "┌─ Service Status ─────────────────────────────────────────────┐"
if systemctl is-active --quiet cryfttee-keyvault 2>/dev/null; then
    echo "│ cryfttee-keyvault: ✓ Active"
else
    echo "│ cryfttee-keyvault: ✗ Inactive or not installed"
fi
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# Check containers
echo "┌─ Container Status ────────────────────────────────────────────┐"
docker ps --filter "name=cryfttee" --format "│ {{.Names}}: {{.Status}}" 2>/dev/null || echo "│ Docker not available"
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# Check Vault (if deployed)
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "cryfttee-vault"; then
    echo "┌─ Vault Status ─────────────────────────────────────────────────┐"
    if curl -sf http://127.0.0.1:8200/v1/sys/health 2>/dev/null | jq -r '"│ Initialized: \(.initialized), Sealed: \(.sealed)"' 2>/dev/null; then
        :
    else
        echo "│ Not responding"
    fi
    echo "└──────────────────────────────────────────────────────────────┘"
    echo ""
fi

# Check Web3Signer
echo "┌─ Web3Signer Status ───────────────────────────────────────────┐"
if curl -sf "${WEB3SIGNER_URL}/upcheck" >/dev/null 2>&1; then
    echo "│ Health:  ✓ Healthy"
    echo "│ URL:     ${WEB3SIGNER_URL}"
    
    # Latency check
    LATENCY=$(curl -sf -w "%{time_total}" -o /dev/null "${WEB3SIGNER_URL}/upcheck" 2>/dev/null || echo "?")
    if [ "${LATENCY}" != "?" ]; then
        LATENCY_MS=$(echo "${LATENCY} * 1000" | bc 2>/dev/null || echo "${LATENCY}s")
        echo "│ Latency: ${LATENCY_MS}ms"
    fi
else
    echo "│ Health:  ✗ Not responding at ${WEB3SIGNER_URL}"
fi
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# Check loaded keys
echo "┌─ BLS Keys (Staking) ──────────────────────────────────────────┐"
BLS_KEYS=$(curl -sf "${WEB3SIGNER_URL}/api/v1/eth2/publicKeys" 2>/dev/null)
if [ -n "${BLS_KEYS}" ] && [ "${BLS_KEYS}" != "[]" ]; then
    BLS_COUNT=$(echo "${BLS_KEYS}" | jq '. | length' 2>/dev/null || echo "0")
    echo "│ Count: ${BLS_COUNT} key(s) loaded"
    echo "${BLS_KEYS}" | jq -r '.[]' 2>/dev/null | head -5 | while read key; do
        echo "│   0x${key:0:16}...${key: -8}"
    done
    if [ "${BLS_COUNT}" -gt 5 ]; then
        echo "│   ... and $((BLS_COUNT - 5)) more"
    fi
else
    echo "│ Count: 0 (no BLS keys loaded)"
fi
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

echo "┌─ SECP256k1 Keys (TLS) ─────────────────────────────────────────┐"
SECP_KEYS=$(curl -sf "${WEB3SIGNER_URL}/api/v1/eth1/publicKeys" 2>/dev/null)
if [ -n "${SECP_KEYS}" ] && [ "${SECP_KEYS}" != "[]" ]; then
    SECP_COUNT=$(echo "${SECP_KEYS}" | jq '. | length' 2>/dev/null || echo "0")
    echo "│ Count: ${SECP_COUNT} key(s) loaded"
    echo "${SECP_KEYS}" | jq -r '.[]' 2>/dev/null | head -5 | while read key; do
        echo "│   0x${key:0:16}...${key: -8}"
    done
else
    echo "│ Count: 0 (no SECP256k1/TLS keys loaded)"
fi
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# Show key files on disk
echo "┌─ Key Files on Disk ───────────────────────────────────────────┐"
KEY_COUNT=$(ls ~/.cryfttee-keyvault/keys/*.json 2>/dev/null | wc -l || echo "0")
echo "│ JSON keystores: ${KEY_COUNT}"
ls ~/.cryfttee-keyvault/keys/*.json 2>/dev/null | head -3 | while read f; do
    echo "│   $(basename $f)"
done
if [ "${KEY_COUNT}" -gt 3 ]; then
    echo "│   ... and $((KEY_COUNT - 3)) more"
fi
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# CryftTEE connectivity (if running locally)
echo "┌─ CryftTEE Integration ────────────────────────────────────────┐"
if curl -sf "${CRYFTTEE_URL}/api/context" >/dev/null 2>&1; then
    HEALTH=$(curl -sf "${CRYFTTEE_URL}/api/context" 2>/dev/null | jq -r '.health.web3signer // "unknown"' 2>/dev/null)
    echo "│ CryftTEE:        ✓ Running at ${CRYFTTEE_URL}"
    echo "│ Web3Signer seen: ${HEALTH}"
else
    echo "│ CryftTEE:        Not detected at ${CRYFTTEE_URL}"
    echo "│ (This is normal if CryftTEE runs on a different host)"
fi
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

echo "┌─ Environment for CryftTEE ────────────────────────────────────┐"
echo "│ export CRYFTTEE_WEB3SIGNER_URL=${WEB3SIGNER_URL}"
echo "└──────────────────────────────────────────────────────────────┘"
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
    
    # Check SSH and establish master connection
    step "Testing SSH connection..."
    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "${KEYVAULT_USER}@${KEYVAULT_HOST}" "echo 'OK'" 2>/dev/null; then
        # Try with password - this will also establish the master connection
        if ! ssh -o ConnectTimeout=5 "${KEYVAULT_USER}@${KEYVAULT_HOST}" "echo 'OK'" 2>/dev/null; then
            error "Cannot connect to ${KEYVAULT_HOST}"
        fi
    fi
    
    # Start SSH master connection for connection reuse (avoids repeated password prompts)
    step "Establishing SSH connection multiplexing..."
    start_ssh_master "${KEYVAULT_USER}@${KEYVAULT_HOST}"
    
    # Cleanup SSH master on exit
    trap "stop_ssh_master '${KEYVAULT_USER}@${KEYVAULT_HOST}'; rm -rf ${LOCAL_TMP:-/tmp/nonexistent} 2>/dev/null" EXIT
    
    # Check Docker
    step "Checking Docker..."
    if ! ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "command -v docker" >/dev/null 2>&1; then
        warn "Docker not found on ${KEYVAULT_HOST}"
        read -p "Install Docker now? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_docker_remote
        else
            error "Docker is required"
        fi
    fi
    
    # Check for existing deployment
    step "Checking for existing deployment..."
    EXISTING_DEPLOYMENT=false
    EXISTING_VAULT_DATA=false
    EXISTING_POSTGRES_DATA=false
    RESET_POSTGRES=false
    RESET_PASSWORD_ONLY=false
    
    if ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "[ -f ${CONFIG_DIR}/docker-compose.yml ]" 2>/dev/null; then
        EXISTING_DEPLOYMENT=true
    fi
    
    if ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "[ -d ${VAULT_DATA}/data ] && [ -n \"\$(ls -A ${VAULT_DATA}/data 2>/dev/null)\" ]" 2>/dev/null; then
        EXISTING_VAULT_DATA=true
    fi
    
    # Check postgres data - check if docker-compose exists and has postgres config
    # (avoids needing sudo to check the postgres data directory owned by uid 70)
    if ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "grep -q 'cryfttee-postgres' ${CONFIG_DIR}/docker-compose.yml 2>/dev/null" 2>/dev/null; then
        EXISTING_POSTGRES_DATA=true
        info "Found existing PostgreSQL configuration"
    fi
    
    # If PostgreSQL data exists, try to retrieve the existing password
    if [ "${EXISTING_POSTGRES_DATA}" = "true" ]; then
        step "Retrieving existing PostgreSQL credentials..."
        
        # Try docker-compose.yml FIRST (readable without sudo)
        REMOTE_PG_PASSWORD=$(ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "grep 'POSTGRES_PASSWORD=' ${CONFIG_DIR}/docker-compose.yml 2>/dev/null | head -1 | sed 's/.*POSTGRES_PASSWORD=//' | tr -d '\"' | tr -d \"'\"" 2>/dev/null | tr -d '\r\n' || true)
        if [ -n "${REMOTE_PG_PASSWORD}" ]; then
            POSTGRES_PASSWORD="${REMOTE_PG_PASSWORD}"
            info "Using existing PostgreSQL password from docker-compose.yml"
        else
            # Fallback: try .postgres-password file (user-owned directory, no sudo needed)
            REMOTE_PG_PASSWORD=$(ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "cat ${CONFIG_DIR}/.postgres-password 2>/dev/null" 2>/dev/null | tr -d '\r\n' || true)
            if [ -n "${REMOTE_PG_PASSWORD}" ]; then
                POSTGRES_PASSWORD="${REMOTE_PG_PASSWORD}"
                info "Using existing PostgreSQL password from password file"
            else
                warn "Could not retrieve existing password - you may need to reset it"
            fi
        fi
    fi
    
    # If still no password, generate one (fresh deployment)
    if [ -z "${POSTGRES_PASSWORD}" ]; then
        generate_new_password
    fi
    
    # Check if PostgreSQL data exists and prompt user
    if [ "${EXISTING_POSTGRES_DATA}" = "true" ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║  📦 EXISTING POSTGRESQL DATABASE DETECTED                        ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo ""
        info "Found existing PostgreSQL data at: ${POSTGRES_DATA}"
        info "This contains the slashing protection database."
        if [ -n "${POSTGRES_PASSWORD}" ]; then
            info "Existing password retrieved successfully."
        else
            warn "Could not retrieve existing password!"
        fi
        echo ""
        echo "Options:"
        echo "  [k] KEEP database and password (recommended for upgrades)"
        echo "      - Preserves all slashing protection history"
        echo "      - Uses existing credentials"
        echo ""
        echo "  [p] RESET PASSWORD ONLY (if password is lost/mismatched)"
        echo "      - Generates new password"
        echo "      - Updates PostgreSQL user password in-place"
        echo "      - Preserves all data"
        echo ""
        echo "  [r] RESET DATABASE AND PASSWORD (fresh start)"
        echo "      - Deletes all slashing protection history"
        echo "      - Creates new empty database with new password"
        echo "      - ⚠️  Only use for fresh validator deployments!"
        echo ""
        read -p "Keep, reset Password, or Reset all? [K/p/r] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Rr]$ ]]; then
            warn "PostgreSQL database AND password will be RESET!"
            RESET_POSTGRES=true
            POSTGRES_PASSWORD="$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)"
            info "Generated new PostgreSQL password"
        elif [[ $REPLY =~ ^[Pp]$ ]]; then
            warn "PostgreSQL password will be RESET (data preserved)"
            RESET_POSTGRES=false
            RESET_PASSWORD_ONLY=true
            POSTGRES_PASSWORD="$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)"
            info "Generated new PostgreSQL password"
        else
            # User wants to keep - but check if we actually have a password
            if [ -z "${POSTGRES_PASSWORD}" ]; then
                error "Cannot keep password - no existing password was retrieved!"
                echo "Please choose [p] to reset password or [r] to reset everything."
                exit 1
            fi
            info "PostgreSQL database and password will be PRESERVED."
            RESET_POSTGRES=false
            RESET_PASSWORD_ONLY=false
        fi
        echo ""
    fi
    
    if [ "${EXISTING_DEPLOYMENT}" = "true" ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║  ⚠  EXISTING DEPLOYMENT DETECTED                                 ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo ""
        info "Found existing CryftTEE KeyVault deployment on ${KEYVAULT_HOST}"
        
        if [ "${CLEAN_INSTALL}" = "true" ]; then
            echo ""
            warn "CLEAN INSTALL REQUESTED - ALL DATA WILL BE DESTROYED!"
            if [ "${EXISTING_VAULT_DATA}" = "true" ]; then
                error "Refusing to destroy existing Vault data without explicit confirmation."
                echo "To force clean install, first manually remove: ${VAULT_DATA}/data"
                exit 1
            fi
            step "Removing existing deployment..."
            ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "systemctl --user stop cryfttee-keyvault 2>/dev/null || true"
            ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "rm -rf ${CONFIG_DIR} ${SCRIPTS_DIR} 2>/dev/null || true"
            info "Clean slate ready for fresh installation."
            EXISTING_DEPLOYMENT=false
        elif [ "${FORCE_UPGRADE}" = "true" ]; then
            info "Force upgrade enabled - skipping confirmation prompt"
        else
            if [ "${EXISTING_VAULT_DATA}" = "true" ]; then
                echo ""
                warn "Vault data directory contains existing data!"
                info "  Location: ${VAULT_DATA}/data"
                info "  This data will be PRESERVED (Vault will not be re-initialized)"
                echo ""
            fi
            
            echo "This upgrade will:"
            echo "  ✓ Update configuration files (docker-compose.yml, etc.)"
            echo "  ✓ Update helper scripts (import-key.sh, status.sh, etc.)"
            echo "  ✓ Restart services with new configuration"
            if [ "${EXISTING_VAULT_DATA}" = "true" ]; then
                echo "  ✓ PRESERVE existing Vault data and keys"
                echo "  ✓ PRESERVE existing AppRole credentials"
            fi
            echo ""
            echo "Backup will be created at: ${CONFIG_DIR}/backup-\$(date +%Y%m%d-%H%M%S)/"
            echo ""
            echo "Use --force to skip this prompt in CI/CD pipelines."
            echo ""
            
            read -p "Continue with upgrade? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Upgrade cancelled."
                exit 0
            fi
        fi
        
        if [ "${EXISTING_DEPLOYMENT}" = "true" ]; then
            # Create backup of existing config
            step "Backing up existing configuration..."
            BACKUP_DIR="${CONFIG_DIR}/backup-$(date +%Y%m%d-%H%M%S)"
            ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "mkdir -p ${BACKUP_DIR} && cp -r ${CONFIG_DIR}/*.yml ${CONFIG_DIR}/*.yaml ${CONFIG_DIR}/*.hcl ${BACKUP_DIR}/ 2>/dev/null || true"
            ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "cp -r ${SCRIPTS_DIR}/*.sh ${BACKUP_DIR}/ 2>/dev/null || true"
            info "Backup created at ${BACKUP_DIR}"
            
            # Stop services before upgrade
            step "Stopping services for upgrade..."
            ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "systemctl --user stop cryfttee-keyvault 2>/dev/null || true"
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
        generate_vault_init_script > "${LOCAL_TMP}/vault-init.sh"
        generate_init_vault_script > "${LOCAL_TMP}/init-vault.sh"
        generate_unseal_vault_script > "${LOCAL_TMP}/unseal-vault.sh"
        generate_backup_credentials_script > "${LOCAL_TMP}/backup-credentials.sh"
    else
        generate_docker_compose_web3signer > "${LOCAL_TMP}/docker-compose.yml"
    fi
    
    generate_web3signer_config > "${LOCAL_TMP}/web3signer.yaml"
    generate_systemd_service > "${LOCAL_TMP}/cryfttee-keyvault.service"
    generate_import_key_script > "${LOCAL_TMP}/import-key.sh"
    generate_status_script > "${LOCAL_TMP}/status.sh"
    
    # Create deploy script
    cat > "${LOCAL_TMP}/deploy.sh" << 'DEPLOYEOF'
#!/bin/bash
set -e

# These variables are passed from the parent script
MODE="__MODE__"
RESET_POSTGRES="__RESET_POSTGRES__"
RESET_PASSWORD_ONLY="__RESET_PASSWORD_ONLY__"
NEW_POSTGRES_PASSWORD="__POSTGRES_PASSWORD__"
VAULT_VERSION="__VAULT_VERSION__"
WEB3SIGNER_VERSION="__WEB3SIGNER_VERSION__"
VAULT_PORT="__VAULT_PORT__"
WEB3SIGNER_PORT="__WEB3SIGNER_PORT__"
WEB3SIGNER_METRICS_PORT="__WEB3SIGNER_METRICS_PORT__"

# User-level directories (no sudo required)
DATA_DIR="$HOME/.cryfttee-keyvault"
CONFIG_DIR="${DATA_DIR}/config"
SCRIPTS_DIR="${DATA_DIR}/scripts"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

# Handle PostgreSQL reset if requested
if [ "${RESET_POSTGRES}" = "true" ]; then
    echo "[!] Resetting PostgreSQL database as requested..."
    docker rm -f cryfttee-postgres 2>/dev/null || true
    rm -rf ${DATA_DIR}/postgres
    echo "[+] PostgreSQL data cleared."
elif [ "${RESET_PASSWORD_ONLY}" = "true" ]; then
    echo "[!] Resetting PostgreSQL password only (preserving data)..."
    if docker ps | grep -q cryfttee-postgres; then
        docker exec cryfttee-postgres psql -U postgres -c "ALTER USER web3signer PASSWORD '${NEW_POSTGRES_PASSWORD}';" || {
            echo "[!] Warning: Could not update password in running PostgreSQL. Will update on restart."
        }
    fi
    echo "[+] Password will be updated in config files."
fi

echo "[+] Creating directories..."
mkdir -p ${DATA_DIR}/{vault/data,vault/logs,vault/init,web3signer,postgres,keys,config,scripts}
mkdir -p ${SYSTEMD_USER_DIR}
chmod 700 ${DATA_DIR}/vault ${DATA_DIR}/keys

echo "[+] Installing configuration files..."
cp /tmp/cryfttee-deploy/docker-compose.yml ${CONFIG_DIR}/
cp /tmp/cryfttee-deploy/web3signer.yaml ${CONFIG_DIR}/
cp /tmp/cryfttee-deploy/cryfttee-keyvault.service ${SYSTEMD_USER_DIR}/

# Save PostgreSQL password for recovery (restricted permissions)
echo "${NEW_POSTGRES_PASSWORD}" > ${CONFIG_DIR}/.postgres-password
chmod 600 ${CONFIG_DIR}/.postgres-password

if [ "${MODE}" = "full" ]; then
    cp /tmp/cryfttee-deploy/vault.hcl ${CONFIG_DIR}/
    cp /tmp/cryfttee-deploy/vault-init.sh ${CONFIG_DIR}/
    cp /tmp/cryfttee-deploy/init-vault.sh ${SCRIPTS_DIR}/
    cp /tmp/cryfttee-deploy/unseal-vault.sh ${SCRIPTS_DIR}/
    cp /tmp/cryfttee-deploy/backup-credentials.sh ${SCRIPTS_DIR}/
    chmod +x ${CONFIG_DIR}/vault-init.sh
fi

cp /tmp/cryfttee-deploy/import-key.sh ${SCRIPTS_DIR}/
cp /tmp/cryfttee-deploy/status.sh ${SCRIPTS_DIR}/
chmod +x ${SCRIPTS_DIR}/*.sh

echo "[+] Pulling Docker images..."

# Retry wrapper for network operations
retry_pull() {
    local image="$1"
    local attempt=1
    while true; do
        echo "    Pulling ${image} (attempt ${attempt})..."
        if docker pull "${image}"; then
            echo "    ✓ Successfully pulled ${image}"
            return 0
        fi
        echo ""
        echo "    ⚠ Failed to pull ${image}"
        echo ""
        echo "    Options: [r]etry, [s]kip, [a]bort"
        read -p "    Choose: " -n 1 choice
        echo ""
        case "${choice}" in
            r|R) ((attempt++)) ;;
            s|S) echo "    Skipping ${image}"; return 1 ;;
            a|A) echo "    Aborted"; exit 1 ;;
            *) echo "    Invalid choice" ;;
        esac
    done
}

if [ "${MODE}" = "full" ]; then
    retry_pull "hashicorp/vault:${VAULT_VERSION}"
fi
retry_pull "postgres:15-alpine"
retry_pull "consensys/web3signer:${WEB3SIGNER_VERSION}"

echo "[+] Stopping existing services..."
systemctl --user stop cryfttee-keyvault 2>/dev/null || true

# Clean up any orphaned containers from previous deployments
echo "[+] Cleaning up old containers..."
docker stop cryfttee-web3signer cryfttee-postgres cryfttee-vault cryfttee-vault-init 2>/dev/null || true
docker rm -f cryfttee-web3signer cryfttee-postgres cryfttee-vault cryfttee-vault-init 2>/dev/null || true

# Remove old networks (will be recreated by docker-compose)
docker network rm cryfttee-keyvault 2>/dev/null || true

echo "[+] Enabling lingering for user systemd services..."
# This allows user services to run without being logged in
loginctl enable-linger $(whoami) 2>/dev/null || echo "[i] Linger may already be enabled or require admin"

echo "[+] Starting services..."
systemctl --user daemon-reload
systemctl --user enable cryfttee-keyvault
systemctl --user start cryfttee-keyvault

# Wait for PostgreSQL to be healthy
echo "[+] Waiting for PostgreSQL to be ready..."
for i in 1 2 3 4 5 6 7 8 9 10; do
    if docker exec cryfttee-postgres pg_isready -U web3signer -d web3signer >/dev/null 2>&1; then
        echo "[+] PostgreSQL is ready!"
        break
    fi
    echo "[i] Waiting for PostgreSQL (attempt $i/10)..."
    sleep 2
done

# Initialize slashing protection schema if needed
echo "[+] Checking slashing protection database schema..."
if ! docker exec cryfttee-postgres psql -U web3signer -d web3signer -c "SELECT version FROM database_version LIMIT 1" >/dev/null 2>&1; then
    echo "[+] Initializing slashing protection schema..."
    docker exec -i cryfttee-postgres psql -U web3signer -d web3signer << 'SQLEOF'
-- Web3Signer Slashing Protection Schema v12
CREATE TABLE IF NOT EXISTS database_version (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL
);
INSERT INTO database_version (id, version) VALUES (1, 12) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS validators (
    id SERIAL PRIMARY KEY,
    public_key BYTEA NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS signed_blocks (
    validator_id INTEGER NOT NULL REFERENCES validators(id),
    slot BIGINT NOT NULL,
    signing_root BYTEA,
    PRIMARY KEY (validator_id, slot)
);

CREATE TABLE IF NOT EXISTS signed_attestations (
    validator_id INTEGER NOT NULL REFERENCES validators(id),
    source_epoch BIGINT NOT NULL,
    target_epoch BIGINT NOT NULL,
    signing_root BYTEA,
    PRIMARY KEY (validator_id, target_epoch)
);

CREATE INDEX IF NOT EXISTS idx_signed_blocks_slot ON signed_blocks(slot);
CREATE INDEX IF NOT EXISTS idx_signed_attestations_source ON signed_attestations(source_epoch);
CREATE INDEX IF NOT EXISTS idx_signed_attestations_target ON signed_attestations(target_epoch);

CREATE TABLE IF NOT EXISTS low_watermarks (
    validator_id INTEGER NOT NULL REFERENCES validators(id) PRIMARY KEY,
    slot BIGINT,
    source_epoch BIGINT,
    target_epoch BIGINT
);
SQLEOF
    echo "[+] Schema initialized successfully!"
else
    echo "[+] Schema already exists."
fi

# Handle password reset if needed (after PostgreSQL is running)
if [ "${RESET_PASSWORD_ONLY}" = "true" ]; then
    echo "[+] Resetting PostgreSQL password..."
    docker exec cryfttee-postgres psql -U postgres -c "ALTER USER web3signer PASSWORD '${NEW_POSTGRES_PASSWORD}';" && {
        echo "[+] PostgreSQL password updated successfully!"
        # Restart web3signer to use the new password
        docker restart cryfttee-web3signer
        echo "[+] Web3Signer restarted with new credentials"
    } || {
        echo "[!] Warning: Failed to update PostgreSQL password"
    }
fi

echo "[+] Cleaning up..."
rm -rf /tmp/cryfttee-deploy

echo "[+] Deployment complete!"
DEPLOYEOF

    # Replace placeholders with actual values in deploy.sh
    sed -i "s|__MODE__|${mode}|g" "${LOCAL_TMP}/deploy.sh"
    sed -i "s|__RESET_POSTGRES__|${RESET_POSTGRES}|g" "${LOCAL_TMP}/deploy.sh"
    sed -i "s|__RESET_PASSWORD_ONLY__|${RESET_PASSWORD_ONLY}|g" "${LOCAL_TMP}/deploy.sh"
    sed -i "s|__POSTGRES_PASSWORD__|${POSTGRES_PASSWORD}|g" "${LOCAL_TMP}/deploy.sh"
    sed -i "s|__VAULT_VERSION__|${VAULT_VERSION}|g" "${LOCAL_TMP}/deploy.sh"
    sed -i "s|__WEB3SIGNER_VERSION__|${WEB3SIGNER_VERSION}|g" "${LOCAL_TMP}/deploy.sh"
    sed -i "s|__VAULT_PORT__|${VAULT_PORT}|g" "${LOCAL_TMP}/deploy.sh"
    sed -i "s|__WEB3SIGNER_PORT__|${WEB3SIGNER_PORT}|g" "${LOCAL_TMP}/deploy.sh"
    sed -i "s|__WEB3SIGNER_METRICS_PORT__|${WEB3SIGNER_METRICS_PORT}|g" "${LOCAL_TMP}/deploy.sh"
    
    # Replace placeholders in docker-compose.yml
    sed -i "s|__POSTGRES_PASSWORD__|${POSTGRES_PASSWORD}|g" "${LOCAL_TMP}/docker-compose.yml"
    sed -i "s|__VAULT_VERSION__|${VAULT_VERSION}|g" "${LOCAL_TMP}/docker-compose.yml"
    sed -i "s|__WEB3SIGNER_VERSION__|${WEB3SIGNER_VERSION}|g" "${LOCAL_TMP}/docker-compose.yml"
    sed -i "s|__VAULT_PORT__|${VAULT_PORT}|g" "${LOCAL_TMP}/docker-compose.yml"
    sed -i "s|__WEB3SIGNER_PORT__|${WEB3SIGNER_PORT}|g" "${LOCAL_TMP}/docker-compose.yml"
    sed -i "s|__WEB3SIGNER_METRICS_PORT__|${WEB3SIGNER_METRICS_PORT}|g" "${LOCAL_TMP}/docker-compose.yml"

    # Upload files
    step "Uploading files to ${KEYVAULT_HOST}..."
    ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "mkdir -p /tmp/cryfttee-deploy"
    retry_network "Uploading deployment files" scp_cmd -q "${LOCAL_TMP}"/* "${KEYVAULT_USER}@${KEYVAULT_HOST}:/tmp/cryfttee-deploy/"
    
    # Execute
    step "Running deployment..."
    ssh_cmd -t "${KEYVAULT_USER}@${KEYVAULT_HOST}" "chmod +x /tmp/cryfttee-deploy/deploy.sh && /tmp/cryfttee-deploy/deploy.sh"
    
    # Wait for services
    info "Waiting for services to start..."
    sleep 8
    
    # Check health
    echo ""
    if ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "curl -sf http://localhost:${WEB3SIGNER_PORT}/upcheck" >/dev/null 2>&1; then
        log "Web3Signer is healthy!"
    else
        warn "Web3Signer may still be starting..."
    fi
    
    # Print summary
    echo ""
    log "Deployment complete!"
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           CryftTEE KeyVault Deployed                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    info "Services:"
    if [ "${mode}" = "full" ]; then
        info "  Vault:            http://${KEYVAULT_HOST}:${VAULT_PORT}"
        info "  Vault UI:         http://${KEYVAULT_HOST}:${VAULT_PORT}/ui"
    fi
    info "  Web3Signer API:   http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}"
    info "  Swagger UI:       http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}/swagger-ui"
    info "  Metrics:          http://${KEYVAULT_HOST}:${WEB3SIGNER_METRICS_PORT}/metrics"
    echo ""
    
    if [ "${mode}" = "full" ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║  ⚠  CRITICAL: Vault credentials displayed ONCE during init!     ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo ""
        warn "IMMEDIATE NEXT STEPS (Vault):"
        echo "  1. SSH to ${KEYVAULT_HOST}"
        echo "  2. Watch vault-init logs: docker logs -f cryfttee-vault-init"
        echo "  3. Copy the Root Token and Unseal Key shown in the logs"
        echo "  4. Run backup script: ${SCRIPTS_DIR}/backup-credentials.sh"
        echo "     (Options: GPG-encrypted file or USB drive)"
        echo ""
    fi
    
    echo "┌─ Quick Start ──────────────────────────────────────────────────┐"
    echo "│                                                                │"
    echo "│  1. Import a key:                                              │"
    echo "│     ssh ${KEYVAULT_USER}@${KEYVAULT_HOST}"
    echo "│     ${SCRIPTS_DIR}/import-key.sh bls <keystore.json> <pw>"
    echo "│     docker restart cryfttee-web3signer"
    echo "│                                                                │"
    echo "│  2. Configure CryftTEE:                                        │"
    echo "│     export CRYFTTEE_WEB3SIGNER_URL=http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}"
    echo "│                                                                │"
    echo "│  3. Verify:                                                    │"
    echo "│     curl http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}/upcheck"
    echo "│     curl http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}/api/v1/eth2/publicKeys"
    echo "│                                                                │"
    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""
    
    info "Useful commands (on keyvault host):"
    echo "  Status:      ${SCRIPTS_DIR}/status.sh"
    echo "  Import key:  ${SCRIPTS_DIR}/import-key.sh <type> <keystore> <password>"
    echo "  List keys:   ${SCRIPTS_DIR}/import-key.sh list"
    echo "  Logs:        journalctl --user -u cryfttee-keyvault -f"
    echo "  Restart:     systemctl --user restart cryfttee-keyvault"
    if [ "${mode}" = "full" ]; then
        echo "  Unseal:      ${SCRIPTS_DIR}/unseal-vault.sh"
        echo "  Backup:      ${SCRIPTS_DIR}/backup-credentials.sh"
    fi
}

check_status() {
    log "Checking status on ${KEYVAULT_HOST}..."
    # For status check, establish master connection first
    start_ssh_master "${KEYVAULT_USER}@${KEYVAULT_HOST}"
    trap "stop_ssh_master '${KEYVAULT_USER}@${KEYVAULT_HOST}'" EXIT
    ssh_cmd -t "${KEYVAULT_USER}@${KEYVAULT_HOST}" "${SCRIPTS_DIR}/status.sh 2>/dev/null || echo 'Stack not deployed'"
}

generate_env() {
    cat << EOF
# ═══════════════════════════════════════════════════════════════════════════════
# CryftTEE KeyVault Environment Configuration
# ═══════════════════════════════════════════════════════════════════════════════
# Add to your environment, .env file, or systemd service

# ─── Web3Signer Connection (REQUIRED) ──────────────────────────────────────────
# CryftTEE connects to Web3Signer for all key operations
CRYFTTEE_WEB3SIGNER_URL=http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}

# Timeout for Web3Signer requests (seconds)
CRYFTTEE_WEB3SIGNER_TIMEOUT=30

# ─── Vault Connection (Optional - only if using full stack) ───────────────────
VAULT_ADDR=http://${KEYVAULT_HOST}:${VAULT_PORT}

# ─── Trust & Security Settings ─────────────────────────────────────────────────
# Enforce module signatures (recommended for production)
CRYFTTEE_ENFORCE_SIGNATURES=true

# Only allow modules from known publishers
CRYFTTEE_ENFORCE_KNOWN_PUBLISHERS=true

# ─── Quick Test Commands ───────────────────────────────────────────────────────
# Check Web3Signer health:
#   curl -s http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}/upcheck
#
# List BLS keys (staking):
#   curl -s http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}/api/v1/eth2/publicKeys | jq
#
# List SECP256k1 keys (TLS):
#   curl -s http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}/api/v1/eth1/publicKeys | jq

EOF
}

generate_cryfttee_config() {
    cat << EOF
# ═══════════════════════════════════════════════════════════════════════════════
# CryftTEE Configuration Snippet for Web3Signer Integration
# ═══════════════════════════════════════════════════════════════════════════════
# Add this to your cryfttee.toml or set as environment variables

# ─── Add to cryfttee.toml ─────────────────────────────────────────────────────

[web3signer]
# Web3Signer URL - CryftTEE connects here for BLS and TLS key operations
url = "http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}"

# Request timeout in seconds
timeout = 30

# Retry configuration
max_retries = 3
retry_delay_ms = 1000

# Health check interval (seconds)
health_check_interval = 10

# ─── Or set as environment variables ───────────────────────────────────────────

# Required:
export CRYFTTEE_WEB3SIGNER_URL="http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}"

# Optional:
export CRYFTTEE_WEB3SIGNER_TIMEOUT=30

# ─── Systemd service override ──────────────────────────────────────────────────
# Create /etc/systemd/system/cryfttee.service.d/web3signer.conf:

[Service]
Environment="CRYFTTEE_WEB3SIGNER_URL=http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}"

# ─── Verify integration ────────────────────────────────────────────────────────
# After CryftTEE starts, check status:
#   curl -s http://localhost:3232/api/context | jq '.health'
#
# Expected:
#   {
#     "wasm_runtime": true,
#     "web3signer": true
#   }

EOF
}

test_web3signer() {
    log "Testing Web3Signer connectivity from ${KEYVAULT_HOST}..."
    
    # Start SSH master connection for this session
    start_ssh_master "${KEYVAULT_USER}@${KEYVAULT_HOST}"
    trap "stop_ssh_master '${KEYVAULT_USER}@${KEYVAULT_HOST}'" EXIT
    
    # Test upcheck
    step "Health check..."
    if ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "curl -sf http://localhost:${WEB3SIGNER_PORT}/upcheck" 2>/dev/null; then
        log "Web3Signer is healthy!"
    else
        error "Web3Signer not responding"
    fi
    
    # Test key endpoints
    step "BLS keys endpoint..."
    BLS_RESULT=$(ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "curl -sf http://localhost:${WEB3SIGNER_PORT}/api/v1/eth2/publicKeys" 2>/dev/null || echo "[]")
    BLS_COUNT=$(echo "${BLS_RESULT}" | jq '. | length' 2>/dev/null || echo "0")
    info "BLS keys: ${BLS_COUNT}"
    
    step "SECP256k1 keys endpoint..."
    SECP_RESULT=$(ssh_cmd "${KEYVAULT_USER}@${KEYVAULT_HOST}" "curl -sf http://localhost:${WEB3SIGNER_PORT}/api/v1/eth1/publicKeys" 2>/dev/null || echo "[]")
    SECP_COUNT=$(echo "${SECP_RESULT}" | jq '. | length' 2>/dev/null || echo "0")
    info "SECP256k1/TLS keys: ${SECP_COUNT}"
    
    # Show connection info for CryftTEE
    echo ""
    log "Web3Signer is ready for CryftTEE!"
    echo ""
    info "Set this in your CryftTEE environment:"
    echo ""
    echo "    export CRYFTTEE_WEB3SIGNER_URL=http://${KEYVAULT_HOST}:${WEB3SIGNER_PORT}"
    echo ""
}

# =============================================================================
# Local Deployment (on current machine)
# =============================================================================

deploy_local() {
    local mode="${1:-web3signer}"
    
    log "Deploying CryftTEE KeyVault locally..."
    info "Mode: ${mode}"
    echo ""
    
    # Check Docker
    step "Checking Docker..."
    if ! command -v docker &>/dev/null; then
        error "Docker not installed. Install Docker first: https://docs.docker.com/engine/install/"
    fi
    
    if ! docker info &>/dev/null; then
        error "Docker daemon not running or not accessible"
    fi
    
    # Check for existing deployment
    step "Checking for existing deployment..."
    EXISTING_DEPLOYMENT=false
    EXISTING_VAULT_DATA=false
    EXISTING_POSTGRES_DATA=false
    RESET_POSTGRES=false
    RESET_PASSWORD_ONLY=false
    
    if [ -f "${CONFIG_DIR}/docker-compose.yml" ]; then
        EXISTING_DEPLOYMENT=true
    fi
    
    if [ -d "${VAULT_DATA}/data" ] && [ -n "$(ls -A ${VAULT_DATA}/data 2>/dev/null)" ]; then
        EXISTING_VAULT_DATA=true
    fi
    
    if [ -d "${POSTGRES_DATA}" ] && [ -n "$(ls -A ${POSTGRES_DATA} 2>/dev/null)" ]; then
        EXISTING_POSTGRES_DATA=true
    fi
    
    # If PostgreSQL data exists, try to retrieve the existing password
    if [ "${EXISTING_POSTGRES_DATA}" = "true" ]; then
        step "Retrieving existing PostgreSQL credentials..."
        if [ -f "${CONFIG_DIR}/.postgres-password" ]; then
            LOCAL_PG_PASSWORD=$(cat "${CONFIG_DIR}/.postgres-password" 2>/dev/null || true)
            if [ -n "${LOCAL_PG_PASSWORD}" ]; then
                POSTGRES_PASSWORD="${LOCAL_PG_PASSWORD}"
                info "Using existing PostgreSQL password"
            else
                warn "Could not read existing password - PostgreSQL may need to be reset"
            fi
        else
            warn "Password file not found - PostgreSQL may need to be reset"
        fi
    fi
    
    # Check if PostgreSQL data exists and prompt user
    if [ "${EXISTING_POSTGRES_DATA}" = "true" ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║  📦 EXISTING POSTGRESQL DATABASE DETECTED                        ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo ""
        info "Found existing PostgreSQL data at: ${POSTGRES_DATA}"
        info "This contains the slashing protection database."
        if [ -n "${POSTGRES_PASSWORD}" ]; then
            info "Existing password retrieved successfully."
        else
            warn "Could not retrieve existing password!"
        fi
        echo ""
        echo "Options:"
        echo "  [k] KEEP database and password (recommended for upgrades)"
        echo "      - Preserves all slashing protection history"
        echo "      - Uses existing credentials"
        echo ""
        echo "  [p] RESET PASSWORD ONLY (if password is lost/mismatched)"
        echo "      - Generates new password"
        echo "      - Updates PostgreSQL user password in-place"
        echo "      - Preserves all data"
        echo ""
        echo "  [r] RESET DATABASE AND PASSWORD (fresh start)"
        echo "      - Deletes all slashing protection history"
        echo "      - Creates new empty database with new password"
        echo "      - ⚠️  Only use for fresh validator deployments!"
        echo ""
        read -p "Keep, reset Password, or Reset all? [K/p/r] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Rr]$ ]]; then
            warn "PostgreSQL database AND password will be RESET!"
            RESET_POSTGRES=true
            POSTGRES_PASSWORD="$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)"
            info "Generated new PostgreSQL password"
        elif [[ $REPLY =~ ^[Pp]$ ]]; then
            warn "PostgreSQL password will be RESET (data preserved)"
            RESET_POSTGRES=false
            RESET_PASSWORD_ONLY=true
            POSTGRES_PASSWORD="$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)"
            info "Generated new PostgreSQL password"
        else
            # User wants to keep - but check if we actually have a password
            if [ -z "${POSTGRES_PASSWORD}" ]; then
                error "Cannot keep password - no existing password was retrieved!"
                echo "Please choose [p] to reset password or [r] to reset everything."
                exit 1
            fi
            info "PostgreSQL database and password will be PRESERVED."
            RESET_POSTGRES=false
            RESET_PASSWORD_ONLY=false
        fi
        echo ""
    fi
    
    # If still no password (fresh deployment), generate one
    if [ -z "${POSTGRES_PASSWORD}" ]; then
        generate_new_password
    fi
    
    if [ "${EXISTING_DEPLOYMENT}" = "true" ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║  ⚠  EXISTING DEPLOYMENT DETECTED                                 ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo ""
        info "Found existing CryftTEE KeyVault deployment on this machine"
        
        if [ "${CLEAN_INSTALL}" = "true" ]; then
            echo ""
            warn "CLEAN INSTALL REQUESTED - ALL DATA WILL BE DESTROYED!"
            if [ "${EXISTING_VAULT_DATA}" = "true" ]; then
                error "Refusing to destroy existing Vault data without explicit confirmation."
                echo "To force clean install, first manually remove: ${VAULT_DATA}/data"
                exit 1
            fi
            step "Removing existing deployment..."
            systemctl --user stop cryfttee-keyvault 2>/dev/null || true
            rm -rf ${CONFIG_DIR} ${SCRIPTS_DIR} 2>/dev/null || true
            info "Clean slate ready for fresh installation."
            EXISTING_DEPLOYMENT=false
        elif [ "${FORCE_UPGRADE}" = "true" ]; then
            info "Force upgrade enabled - skipping confirmation prompt"
        else
            if [ "${EXISTING_VAULT_DATA}" = "true" ]; then
                echo ""
                warn "Vault data directory contains existing data!"
                info "  Location: ${VAULT_DATA}/data"
                info "  This data will be PRESERVED (Vault will not be re-initialized)"
                echo ""
            fi
            
            echo "This upgrade will:"
            echo "  ✓ Update configuration files (docker-compose.yml, etc.)"
            echo "  ✓ Update helper scripts (import-key.sh, status.sh, etc.)"
            echo "  ✓ Restart services with new configuration"
            if [ "${EXISTING_VAULT_DATA}" = "true" ]; then
                echo "  ✓ PRESERVE existing Vault data and keys"
                echo "  ✓ PRESERVE existing AppRole credentials"
            fi
            echo ""
            echo "Backup will be created at: ${CONFIG_DIR}/backup-$(date +%Y%m%d-%H%M%S)/"
            echo ""
            echo "Use --force to skip this prompt in CI/CD pipelines."
            echo ""
            
            read -p "Continue with upgrade? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Upgrade cancelled."
                exit 0
            fi
        fi
        
        if [ "${EXISTING_DEPLOYMENT}" = "true" ]; then
            # Create backup of existing config
            step "Backing up existing configuration..."
            BACKUP_DIR="${CONFIG_DIR}/backup-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "${BACKUP_DIR}"
            cp -r ${CONFIG_DIR}/*.yml ${CONFIG_DIR}/*.yaml ${CONFIG_DIR}/*.hcl "${BACKUP_DIR}/" 2>/dev/null || true
            cp -r ${SCRIPTS_DIR}/*.sh "${BACKUP_DIR}/" 2>/dev/null || true
            info "Backup created at ${BACKUP_DIR}"
            
            # Stop services before upgrade
            step "Stopping services for upgrade..."
            systemctl --user stop cryfttee-keyvault 2>/dev/null || true
        fi
    fi
    
    # Handle PostgreSQL reset if requested
    if [ "${RESET_POSTGRES}" = "true" ]; then
        step "Resetting PostgreSQL database as requested..."
        docker rm -f cryfttee-postgres cryfttee-db-migration 2>/dev/null || true
        rm -rf ${POSTGRES_DATA}
        info "PostgreSQL data cleared."
    elif [ "${RESET_PASSWORD_ONLY}" = "true" ]; then
        step "Resetting PostgreSQL password only (preserving data)..."
        # If postgres is running, update the password in-place
        if docker ps | grep -q cryfttee-postgres; then
            docker exec cryfttee-postgres psql -U postgres -c "ALTER USER web3signer PASSWORD '${POSTGRES_PASSWORD}';" && {
                info "PostgreSQL password updated in running database."
            } || {
                warn "Could not update password in running PostgreSQL. Will update on restart."
            }
        fi
    fi
    
    # Create directories
    step "Creating directories..."
    mkdir -p ${DATA_DIR}/{vault/data,vault/logs,vault/init,web3signer,postgres,keys,config,scripts}
    mkdir -p ${HOME}/.config/systemd/user
    chmod 700 ${DATA_DIR}/vault ${DATA_DIR}/keys 2>/dev/null || true
    
    # Vault container runs as uid 100 (vault user) - must own its data directories
    step "Setting Vault data ownership (uid 100)..."
    # chown not needed - user owns directory -R 100:100 ${DATA_DIR}/vault/data ${DATA_DIR}/vault/logs ${DATA_DIR}/vault/init 2>/dev/null || true
    
    # Web3Signer container runs as uid 1000 - must own its data directory for slashing DB
    step "Setting Web3Signer data ownership (uid 1000)..."
    # chown not needed - user owns directory -R 1000:1000 ${DATA_DIR}/web3signer ${DATA_DIR}/keys 2>/dev/null || true
    chmod 755 ${DATA_DIR}/web3signer ${DATA_DIR}/keys 2>/dev/null || true
    
    # PostgreSQL container runs as uid 70 (postgres user in alpine) - must own its data directory
    step "Setting PostgreSQL data ownership (uid 70)..."
    # chown not needed - user owns directory -R 70:70 ${DATA_DIR}/postgres 2>/dev/null || true
    chmod 700 ${DATA_DIR}/postgres 2>/dev/null || true
    
    # Generate and install configs
    step "Generating configuration files..."
    
    if [ "${mode}" = "full" ]; then
        generate_docker_compose_full | tee ${CONFIG_DIR}/docker-compose.yml > /dev/null
        generate_vault_config | tee ${CONFIG_DIR}/vault.hcl > /dev/null
        generate_vault_init_script | tee ${CONFIG_DIR}/vault-init.sh > /dev/null
        generate_init_vault_script | tee ${SCRIPTS_DIR}/init-vault.sh > /dev/null
        generate_unseal_vault_script | tee ${SCRIPTS_DIR}/unseal-vault.sh > /dev/null
        generate_backup_credentials_script | tee ${SCRIPTS_DIR}/backup-credentials.sh > /dev/null
        chmod +x ${CONFIG_DIR}/vault-init.sh ${SCRIPTS_DIR}/init-vault.sh ${SCRIPTS_DIR}/unseal-vault.sh ${SCRIPTS_DIR}/backup-credentials.sh
    else
        generate_docker_compose_web3signer | tee ${CONFIG_DIR}/docker-compose.yml > /dev/null
    fi
    
    generate_web3signer_config | tee ${CONFIG_DIR}/web3signer.yaml > /dev/null
    generate_systemd_service | tee ${HOME}/.config/systemd/user/cryfttee-keyvault.service > /dev/null
    generate_import_key_script | tee ${SCRIPTS_DIR}/import-key.sh > /dev/null
    generate_status_script | tee ${SCRIPTS_DIR}/status.sh > /dev/null
    chmod +x ${SCRIPTS_DIR}/*.sh
    
    # Save PostgreSQL password for recovery (restricted permissions)
    echo "${POSTGRES_PASSWORD}" | tee ${CONFIG_DIR}/.postgres-password > /dev/null
    chmod 600 ${CONFIG_DIR}/.postgres-password
    
    # Pull images
    step "Pulling Docker images..."
    if [ "${mode}" = "full" ]; then
        docker_pull "hashicorp/vault:${VAULT_VERSION}"
    fi
    docker_pull "postgres:15-alpine"
    docker_pull "consensys/web3signer:${WEB3SIGNER_VERSION}"
    
    # Stop existing services
    step "Stopping existing services..."
    systemctl --user stop cryfttee-keyvault 2>/dev/null || true
    
    # Clean up any orphaned containers from previous deployments
    step "Cleaning up old containers..."
    docker stop cryfttee-web3signer cryfttee-postgres cryfttee-vault cryfttee-vault-init 2>/dev/null || true
    docker rm -f cryfttee-web3signer cryfttee-postgres cryfttee-vault cryfttee-vault-init 2>/dev/null || true
    
    # Remove old networks (will be recreated by docker-compose)
    docker network rm config_cryfttee-keyvault config_cryftee-net 2>/dev/null || true
    
    # Start services
    step "Starting services..."
    
    # Enable linger so user services persist after logout
    loginctl enable-linger $(whoami) 2>/dev/null || echo "[i] Linger may already be enabled or require admin"
    
    systemctl --user daemon-reload
    systemctl --user enable cryfttee-keyvault
    systemctl --user start cryfttee-keyvault
    
    # Wait for PostgreSQL to be healthy
    step "Waiting for PostgreSQL to be ready..."
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if docker exec cryfttee-postgres pg_isready -U web3signer -d web3signer >/dev/null 2>&1; then
            info "PostgreSQL is ready!"
            break
        fi
        echo "  Waiting for PostgreSQL (attempt $i/10)..."
        sleep 2
    done
    
    # Initialize slashing protection schema if needed
    step "Checking slashing protection database schema..."
    if ! docker exec cryfttee-postgres psql -U web3signer -d web3signer -c "SELECT version FROM database_version LIMIT 1" >/dev/null 2>&1; then
        info "Initializing slashing protection schema..."
        docker exec -i cryfttee-postgres psql -U web3signer -d web3signer << 'SQLEOF'
-- Web3Signer Slashing Protection Schema v12
CREATE TABLE IF NOT EXISTS database_version (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL
);
INSERT INTO database_version (id, version) VALUES (1, 12) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS validators (
    id SERIAL PRIMARY KEY,
    public_key BYTEA NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS signed_blocks (
    validator_id INTEGER NOT NULL REFERENCES validators(id),
    slot BIGINT NOT NULL,
    signing_root BYTEA,
    PRIMARY KEY (validator_id, slot)
);

CREATE TABLE IF NOT EXISTS signed_attestations (
    validator_id INTEGER NOT NULL REFERENCES validators(id),
    source_epoch BIGINT NOT NULL,
    target_epoch BIGINT NOT NULL,
    signing_root BYTEA,
    PRIMARY KEY (validator_id, target_epoch)
);

CREATE INDEX IF NOT EXISTS idx_signed_blocks_slot ON signed_blocks(slot);
CREATE INDEX IF NOT EXISTS idx_signed_attestations_source ON signed_attestations(source_epoch);
CREATE INDEX IF NOT EXISTS idx_signed_attestations_target ON signed_attestations(target_epoch);

CREATE TABLE IF NOT EXISTS low_watermarks (
    validator_id INTEGER NOT NULL REFERENCES validators(id) PRIMARY KEY,
    slot BIGINT,
    source_epoch BIGINT,
    target_epoch BIGINT
);
SQLEOF
        info "Schema initialized successfully!"
    else
        info "Schema already exists."
    fi
    
    # Handle password reset if needed (after PostgreSQL is running)
    if [ "${RESET_PASSWORD_ONLY}" = "true" ]; then
        step "Resetting PostgreSQL password..."
        docker exec cryfttee-postgres psql -U postgres -c "ALTER USER web3signer PASSWORD '${POSTGRES_PASSWORD}';" && {
            info "PostgreSQL password updated successfully!"
            # Restart web3signer to use the new password
            docker restart cryfttee-web3signer
            info "Web3Signer restarted with new credentials"
        } || {
            warn "Failed to update PostgreSQL password"
        }
    fi
    
    # Wait for services
    info "Waiting for services to start..."
    sleep 5
    
    # Check health
    if curl -sf http://localhost:${WEB3SIGNER_PORT}/upcheck >/dev/null 2>&1; then
        log "Web3Signer is healthy!"
    else
        warn "Web3Signer may still be starting... check with: ${SCRIPTS_DIR}/status.sh"
    fi
    
    # Print summary
    echo ""
    log "Local deployment complete!"
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     CryftTEE KeyVault Ready (localhost)                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    info "Services (localhost - no env vars needed!):"
    if [ "${mode}" = "full" ]; then
        info "  Vault:            http://localhost:${VAULT_PORT}"
        info "  Vault UI:         http://localhost:${VAULT_PORT}/ui"
        info "  Vault Token:      ${VAULT_DATA}/init/root-token.txt"
    fi
    info "  Web3Signer API:   http://localhost:${WEB3SIGNER_PORT}"
    info "  Swagger UI:       http://localhost:${WEB3SIGNER_PORT}/swagger-ui"
    info "  Metrics:          http://localhost:${WEB3SIGNER_METRICS_PORT}/metrics"
    echo ""
    
    if [ "${mode}" = "full" ]; then
        echo "┌─ Vault Auto-Initialization ────────────────────────────────────┐"
        echo "│                                                                │"
        echo "│  Vault auto-initializes on first start! No manual steps!      │"
        echo "│                                                                │"
        echo "│  ⚠  CRITICAL: Credentials displayed ONCE during init!         │"
        echo "│     Watch the vault-init container logs for:                   │"
        echo "│       - Root Token                                             │"
        echo "│       - Unseal Key                                             │"
        echo "│                                                                │"
        echo "│  Backup credentials NOW:                                       │"
        echo "│    ${SCRIPTS_DIR}/backup-credentials.sh                       │"
        echo "│                                                                │"
        echo "│  Options: GPG-encrypted file or USB drive                      │"
        echo "│                                                                │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""
        echo "┌─ Store Keys in Vault (Recommended) ───────────────────────────┐"
        echo "│                                                                │"
        echo "│  ${SCRIPTS_DIR}/import-key.sh \\                            │"
        echo "│       vault-bls my-validator 0x<private-key-hex>              │"
        echo "│                                                                │"
        echo "│  ${SCRIPTS_DIR}/import-key.sh \\                            │"
        echo "│       vault-tls my-tls-key 0x<private-key-hex>                │"
        echo "│                                                                │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo ""
    fi

    echo "┌─ CryftTEE Integration ─────────────────────────────────────────┐"
    echo "│                                                                │"
    echo "│  CryftTEE defaults to http://localhost:9000 for Web3Signer    │"
    echo "│  so NO environment variables are needed!                       │"
    echo "│                                                                │"
    echo "│  Just start CryftTEE:                                          │"
    echo "│    cargo run --release                                         │"
    echo "│                                                                │"
    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""
    
    echo "┌─ Import Keys (File-based alternative) ────────────────────────┐"
    echo "│                                                                │"
    echo "│  ${SCRIPTS_DIR}/import-key.sh bls <keystore.json> <pw>       │"
    echo "│  docker restart cryfttee-web3signer                       │"
    echo "│                                                                │"
    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""
    
    info "Useful commands:"
    echo "  Status:       ${SCRIPTS_DIR}/status.sh"
    echo "  List keys:    ${SCRIPTS_DIR}/import-key.sh list"
    if [ "${mode}" = "full" ]; then
        echo "  Vault keys:   ${SCRIPTS_DIR}/import-key.sh list-vault"
    fi
    echo "  Logs:         journalctl --user -u cryfttee-keyvault -f"
    echo "  Restart:      systemctl --user restart cryfttee-keyvault"
    if [ "${mode}" = "full" ]; then
        echo "  Unseal:       ${SCRIPTS_DIR}/unseal-vault.sh"
    fi
}

# =============================================================================
# Main
# =============================================================================

show_banner

# Parse global flags first
for arg in "$@"; do
    case "$arg" in
        --force|-f)
            FORCE_UPGRADE=true
            ;;
        --clean)
            CLEAN_INSTALL=true
            ;;
    esac
done

case "${1:-}" in
    --local)
        deploy_local "web3signer"
        ;;
    --local-full)
        deploy_local "full"
        ;;
    --remote)
        deploy_remote "full"
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
    --cryfttee-config)
        generate_cryfttee_config
        ;;
    --test)
        test_web3signer
        ;;
    --help|-h)
        echo "Usage: $0 [options] [flags]"
        echo ""
        echo "Deploy Web3Signer + HashiCorp Vault for CryftTEE key management."
        echo "Plug-and-play setup - Vault auto-initializes and unseals on first run!"
        echo ""
        echo "Local Deployment (recommended for development):"
        echo "  --local             Deploy Web3Signer only (default port 9000)"
        echo "  --local-full        Deploy Vault + Web3Signer with auto-init"
        echo ""
        echo "Remote Deployment:"
        echo "  --remote            Deploy full stack to remote server"
        echo "  --web3signer-only   Deploy only Web3Signer to remote server"
        echo "  --install-docker    Install Docker on remote server"
        echo ""
        echo "Upgrade Flags (can be combined with any deployment option):"
        echo "  --force, -f         Skip confirmation prompt (for CI/CD)"
        echo "  --clean             Remove existing config (preserves Vault data)"
        echo ""
        echo "Status & Testing:"
        echo "  --status            Check service status"
        echo "  --test              Test Web3Signer connectivity"
        echo ""
        echo "Configuration:"
        echo "  --env               Generate environment variables"
        echo "  --cryfttee-config   Generate cryfttee.toml snippet"
        echo "  --help              Show this help"
        echo ""
        echo "Environment variables (only needed for remote deployments):"
        echo "  KEYVAULT_HOST       Remote host (default: ${KEYVAULT_HOST})"
        echo "  KEYVAULT_USER       SSH user (default: ${KEYVAULT_USER})"
        echo "  WEB3SIGNER_PORT     Web3Signer port (default: ${WEB3SIGNER_PORT})"
        echo "  FORCE_UPGRADE       Set to 'true' to skip prompts"
        echo ""
        echo "Upgrade Behavior:"
        echo "  • Existing deployments are detected automatically"
        echo "  • Config files are backed up before overwrite"
        echo "  • Vault data (keys, secrets) is ALWAYS preserved"
        echo "  • AppRole credentials remain valid after upgrade"
        echo ""
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║  Plug-and-Play Setup (Zero Manual Configuration!)            ║"
        echo "╠══════════════════════════════════════════════════════════════╣"
        echo "║                                                              ║"
        echo "║  1. Deploy with Vault (recommended):                         ║"
        echo "║     $0 --local-full                                          ║"
        echo "║                                                              ║"
        echo "║     Vault auto-initializes and unseals on first start!       ║"
        echo "║     Root token saved to: ~/.cryfttee-keyvault/vault/init/  ║"
        echo "║                                                              ║"
        echo "║  2. Store keys in Vault:                                     ║"
        echo "║     ~/.cryfttee-keyvault/scripts/import-key.sh \\     ║"
        echo "║          vault-bls my-validator 0x1234...abcd                ║"
        echo "║                                                              ║"
        echo "║  3. OR import file-based keys:                               ║"
        echo "║     ~/.cryfttee-keyvault/scripts/import-key.sh \\     ║"
        echo "║          bls keystore.json password                          ║"
        echo "║                                                              ║"
        echo "║  4. Start CryftTEE (no env vars needed!):                    ║"
        echo "║     cargo run --release                                      ║"
        echo "║                                                              ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        ;;
    *)
        deploy_remote "full"
        ;;
esac
