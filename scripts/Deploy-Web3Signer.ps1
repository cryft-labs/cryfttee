<#
.SYNOPSIS
    Deploy Web3Signer on Keyvault Server for Cryftee module signing
    
.DESCRIPTION
    This script sets up and runs a Web3Signer instance on the keyvault server
    at 100.111.2.1. It can also deploy locally for testing.
    
.PARAMETER Target
    The target server IP or hostname. Default: 100.111.2.1
    
.PARAMETER User
    SSH username for remote deployment. Default: root
    
.PARAMETER Local
    Deploy locally instead of to remote server
    
.PARAMETER GenerateEnv
    Output environment variables for Cryftee configuration
    
.EXAMPLE
    .\Deploy-Web3Signer.ps1
    Deploys to 100.111.2.1
    
.EXAMPLE
    .\Deploy-Web3Signer.ps1 -Local
    Deploys locally using Docker Desktop
    
.EXAMPLE
    .\Deploy-Web3Signer.ps1 -GenerateEnv
    Outputs Cryftee environment configuration
#>

[CmdletBinding()]
param(
    [string]$Target = "100.111.2.1",
    [string]$User = "root",
    [switch]$Local,
    [switch]$GenerateEnv
)

$ErrorActionPreference = "Stop"

# Configuration
$Script:Config = @{
    Web3SignerVersion = "24.4.0"
    ApiPort = 9000
    MetricsPort = 9001
    DataDir = "/opt/web3signer"
    KeysDir = "/opt/web3signer/keys"
    ConfigDir = "/opt/web3signer/config"
}

function Write-Banner {
    Write-Host @"

  __        __   _    _____   ____  _                       
  \ \      / /__| |__|___ /  / ___|(_) __ _ _ __   ___ _ __ 
   \ \ /\ / / _ \ '_ \ |_ \  \___ \| |/ _` | '_ \ / _ \ '__|
    \ V  V /  __/ |_) |__) |  ___) | | (_| | | | |  __/ |   
     \_/\_/ \___|_.__/____/  |____/|_|\__, |_| |_|\___|_|   
                                      |___/                 
    Cryftee Web3Signer Deployment Script
    Target: $Target

"@ -ForegroundColor Cyan
}

function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    
    $color = switch ($Level) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        default { "White" }
    }
    
    $prefix = switch ($Level) {
        "Success" { "[+]" }
        "Warning" { "[!]" }
        "Error" { "[x]" }
        default { "[i]" }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Get-DockerComposeContent {
    @"
version: '3.8'

services:
  web3signer:
    image: consensys/web3signer:$($Script:Config.Web3SignerVersion)
    container_name: cryftee-web3signer
    restart: unless-stopped
    ports:
      - "$($Script:Config.ApiPort):$($Script:Config.ApiPort)"
      - "$($Script:Config.MetricsPort):$($Script:Config.MetricsPort)"
    volumes:
      - $($Script:Config.DataDir):/data
      - $($Script:Config.KeysDir):/keys
      - $($Script:Config.ConfigDir):/config
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
      test: ["CMD", "curl", "-f", "http://localhost:$($Script:Config.ApiPort)/upcheck"]
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
"@
}

function Get-Web3SignerConfig {
    @"
# Web3Signer YAML Configuration
# For use with Cryftee TEE runtime

http-listen-host: "0.0.0.0"
http-listen-port: $($Script:Config.ApiPort)
http-cors-origins: ["*"]
http-host-allowlist: ["*"]

metrics-enabled: true
metrics-host: "0.0.0.0"
metrics-port: $($Script:Config.MetricsPort)

key-store-path: "/keys"

logging: "INFO"
"@
}

function Get-SystemdService {
    @"
[Unit]
Description=Web3Signer for Cryftee Module Signing
Documentation=https://docs.web3signer.consensys.net/
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=$($Script:Config.DataDir)
ExecStartPre=/usr/bin/docker compose -f $($Script:Config.ConfigDir)/docker-compose.yml pull
ExecStart=/usr/bin/docker compose -f $($Script:Config.ConfigDir)/docker-compose.yml up --remove-orphans
ExecStop=/usr/bin/docker compose -f $($Script:Config.ConfigDir)/docker-compose.yml down
Restart=on-failure
RestartSec=10
TimeoutStartSec=120
TimeoutStopSec=30

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$($Script:Config.DataDir)

[Install]
WantedBy=multi-user.target
"@
}

function Deploy-Remote {
    param([string]$Host, [string]$SshUser)
    
    Write-Log "Deploying Web3Signer to $Host..." "Success"
    
    # Test SSH connectivity
    Write-Log "Testing SSH connection..."
    try {
        $result = ssh -o ConnectTimeout=5 "${SshUser}@${Host}" "echo 'SSH OK'" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "SSH connection failed"
        }
    }
    catch {
        Write-Log "Cannot connect to $Host. Check SSH access." "Error"
        exit 1
    }
    
    Write-Log "Creating directories..." "Success"
    ssh "${SshUser}@${Host}" "mkdir -p $($Script:Config.DataDir) $($Script:Config.KeysDir) $($Script:Config.ConfigDir)"
    
    Write-Log "Generating configuration files..." "Success"
    
    # Upload config files
    $yamlConfig = Get-Web3SignerConfig
    $dockerCompose = Get-DockerComposeContent
    $systemdService = Get-SystemdService
    
    $yamlConfig | ssh "${SshUser}@${Host}" "cat > $($Script:Config.ConfigDir)/web3signer.yaml"
    $dockerCompose | ssh "${SshUser}@${Host}" "cat > $($Script:Config.ConfigDir)/docker-compose.yml"
    $systemdService | ssh "${SshUser}@${Host}" "cat > /etc/systemd/system/web3signer.service"
    
    Write-Log "Pulling Docker image..." "Success"
    ssh "${SshUser}@${Host}" "docker pull consensys/web3signer:$($Script:Config.Web3SignerVersion)"
    
    Write-Log "Starting Web3Signer service..." "Success"
    ssh "${SshUser}@${Host}" "systemctl daemon-reload; systemctl enable web3signer; systemctl restart web3signer"
    
    # Wait for service to start
    Write-Log "Waiting for Web3Signer to start..."
    Start-Sleep -Seconds 5
    
    # Check health
    try {
        $health = ssh "${SshUser}@${Host}" "curl -sf http://localhost:$($Script:Config.ApiPort)/upcheck"
        if ($health) {
            Write-Log "Web3Signer is healthy!" "Success"
        }
    }
    catch {
        Write-Log "Web3Signer may still be starting. Check logs with: ssh ${SshUser}@${Host} journalctl -u web3signer -f" "Warning"
    }
    
    Write-Host ""
    Write-Log "Deployment complete!" "Success"
    Write-Log "Web3Signer API:     http://${Host}:$($Script:Config.ApiPort)"
    Write-Log "Metrics endpoint:   http://${Host}:$($Script:Config.MetricsPort)/metrics"
    Write-Log "Health check:       http://${Host}:$($Script:Config.ApiPort)/upcheck"
    Write-Host ""
    Write-Log "Configure Cryftee to use:"
    Write-Log "  WEB3SIGNER_URL=http://${Host}:$($Script:Config.ApiPort)"
}

function Deploy-Local {
    Write-Log "Deploying Web3Signer locally..." "Success"
    
    # Check Docker
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Log "Docker is not installed. Please install Docker Desktop first." "Error"
        exit 1
    }
    
    # Create local directories (Windows paths)
    $localDataDir = Join-Path $env:USERPROFILE ".cryftee\web3signer"
    $localKeysDir = Join-Path $localDataDir "keys"
    $localConfigDir = Join-Path $localDataDir "config"
    
    Write-Log "Creating directories at $localDataDir..."
    New-Item -ItemType Directory -Path $localDataDir -Force | Out-Null
    New-Item -ItemType Directory -Path $localKeysDir -Force | Out-Null
    New-Item -ItemType Directory -Path $localConfigDir -Force | Out-Null
    
    Write-Log "Generating configuration files..." "Success"
    
    # Adjust paths for local Docker on Windows
    $localDockerCompose = @"
version: '3.8'

services:
  web3signer:
    image: consensys/web3signer:$($Script:Config.Web3SignerVersion)
    container_name: cryftee-web3signer
    restart: unless-stopped
    ports:
      - "$($Script:Config.ApiPort):$($Script:Config.ApiPort)"
      - "$($Script:Config.MetricsPort):$($Script:Config.MetricsPort)"
    volumes:
      - web3signer-data:/data
      - web3signer-keys:/keys
    command:
      - eth2
      - --http-listen-host=0.0.0.0
      - --http-listen-port=$($Script:Config.ApiPort)
      - --http-cors-origins=*
      - --http-host-allowlist=*
      - --metrics-enabled=true
      - --metrics-host=0.0.0.0
      - --metrics-port=$($Script:Config.MetricsPort)
      - --slashing-protection-db-url=jdbc:h2:file:/data/slashing-protection
      - --key-store-path=/keys
    environment:
      - JAVA_OPTS=-Xmx512m -Xms256m
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:$($Script:Config.ApiPort)/upcheck"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

volumes:
  web3signer-data:
  web3signer-keys:
"@
    
    $composeFile = Join-Path $localConfigDir "docker-compose.yml"
    $localDockerCompose | Set-Content -Path $composeFile -Encoding UTF8
    
    Write-Log "Pulling Docker image..." "Success"
    docker pull "consensys/web3signer:$($Script:Config.Web3SignerVersion)"
    
    Write-Log "Starting Web3Signer..." "Success"
    Push-Location $localConfigDir
    try {
        docker compose up -d
    }
    finally {
        Pop-Location
    }
    
    # Wait for service to start
    Write-Log "Waiting for Web3Signer to start..."
    Start-Sleep -Seconds 5
    
    # Check health
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:$($Script:Config.ApiPort)/upcheck" -TimeoutSec 5
        Write-Log "Web3Signer is healthy!" "Success"
    }
    catch {
        Write-Log "Web3Signer may still be starting. Check: docker logs cryftee-web3signer" "Warning"
    }
    
    Write-Host ""
    Write-Log "Local deployment complete!" "Success"
    Write-Log "Web3Signer API:     http://localhost:$($Script:Config.ApiPort)"
    Write-Log "Metrics endpoint:   http://localhost:$($Script:Config.MetricsPort)/metrics"
    Write-Log "Health check:       http://localhost:$($Script:Config.ApiPort)/upcheck"
    Write-Host ""
    Write-Log "Docker compose file: $composeFile"
    Write-Log "To stop: docker compose -f `"$composeFile`" down"
}

function Show-EnvConfig {
    Write-Host @"
# Cryftee Web3Signer Environment Configuration
# Add these to your .env file or set as environment variables

# Web3Signer connection
WEB3SIGNER_URL=http://${Target}:$($Script:Config.ApiPort)
WEB3SIGNER_TIMEOUT=30

# Enable signature verification
CRYFTEE_ENFORCE_SIGNATURES=true
CRYFTEE_ENFORCE_KNOWN_PUBLISHERS=true

# Trust config location
CRYFTEE_TRUST_CONFIG=.\config\trust.toml
"@ -ForegroundColor Gray
}

# Main execution
Write-Banner

if ($GenerateEnv) {
    Show-EnvConfig
}
elseif ($Local) {
    Deploy-Local
}
else {
    Deploy-Remote -Host $Target -SshUser $User
}
