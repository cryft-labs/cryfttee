#
# Cryftee Build Script for Windows PowerShell
# Builds the cryftee runtime and all WASM modules with consistent settings
#

param(
    [switch]$Help,
    [switch]$Debug,
    [switch]$RuntimeOnly,
    [switch]$ModulesOnly,
    [switch]$NoCopy,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

# Build configuration
$ReleaseMode = -not $Debug
$BuildRuntime = -not $ModulesOnly
$BuildModules = -not $RuntimeOnly
$CopyWasm = -not $NoCopy

function Write-Header {
    param([string]$Message)
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Blue
    Write-Host "  $Message" -ForegroundColor Blue
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Blue
}

function Write-Step {
    param([string]$Message)
    Write-Host "▶ $Message" -ForegroundColor Green
}

function Write-Warning-Msg {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Write-Error-Msg {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Show-Help {
    Write-Host "Cryftee Build Script"
    Write-Host ""
    Write-Host "Usage: .\build.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Help         Show this help message"
    Write-Host "  -Debug        Build in debug mode (default: release)"
    Write-Host "  -RuntimeOnly  Build runtime only"
    Write-Host "  -ModulesOnly  Build modules only"
    Write-Host "  -NoCopy       Don't copy .wasm files to module directories"
    Write-Host "  -Clean        Clean all build artifacts first"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\build.ps1                    # Build everything in release mode"
    Write-Host "  .\build.ps1 -Debug             # Build everything in debug mode"
    Write-Host "  .\build.ps1 -RuntimeOnly       # Build runtime only"
    Write-Host "  .\build.ps1 -ModulesOnly       # Build modules only"
    Write-Host "  .\build.ps1 -Clean             # Clean and rebuild everything"
}

function Test-Prerequisites {
    Write-Header "Checking Prerequisites"
    
    # Check Rust
    try {
        $rustVersion = (rustc --version) -replace "rustc ", ""
        Write-Success "Rust $rustVersion found"
    }
    catch {
        Write-Error-Msg "Rust/Cargo not found. Install from https://rustup.rs"
        exit 1
    }
    
    # Check wasm32 target
    $targets = rustup target list --installed
    if ($targets -notcontains "wasm32-unknown-unknown") {
        Write-Warning-Msg "wasm32-unknown-unknown target not installed. Installing..."
        rustup target add wasm32-unknown-unknown
    }
    Write-Success "wasm32-unknown-unknown target available"
    
    Write-Host ""
}

function Invoke-CleanBuild {
    Write-Header "Cleaning Build Artifacts"
    
    Push-Location $RootDir
    
    Write-Step "Cleaning runtime..."
    cargo clean --manifest-path cryftee-runtime/Cargo.toml 2>$null
    
    Get-ChildItem -Path "modules" -Directory | ForEach-Object {
        $cargoFile = Join-Path $_.FullName "Cargo.toml"
        if (Test-Path $cargoFile) {
            Write-Step "Cleaning module: $($_.Name)"
            cargo clean --manifest-path $cargoFile 2>$null
        }
    }
    
    # Remove copied .wasm files
    Write-Step "Removing copied .wasm files..."
    Get-ChildItem -Path "modules" -Filter "*.wasm" -Recurse | 
        Where-Object { $_.FullName -notlike "*\target\*" } | 
        Remove-Item -Force
    
    Pop-Location
    
    Write-Success "Clean complete"
    Write-Host ""
}

function Build-Runtime {
    Write-Header "Building Cryftee Runtime"
    
    Push-Location $RootDir
    
    if ($ReleaseMode) {
        Write-Step "Building runtime (release mode)..."
        cargo build --release --manifest-path cryftee-runtime/Cargo.toml
    }
    else {
        Write-Step "Building runtime (debug mode)..."
        cargo build --manifest-path cryftee-runtime/Cargo.toml
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Msg "Runtime build failed"
        Pop-Location
        exit 1
    }
    
    Pop-Location
    
    Write-Success "Runtime built successfully"
    Write-Host ""
}

function Invoke-ModuleBuild {
    param([string]$ModuleName)
    
    $moduleDir = Join-Path $RootDir "modules" $ModuleName
    $cargoFile = Join-Path $moduleDir "Cargo.toml"
    
    if (-not (Test-Path $cargoFile)) {
        Write-Warning-Msg "Module $ModuleName has no Cargo.toml, skipping"
        return
    }
    
    Write-Step "Building module: $ModuleName"
    
    if ($ReleaseMode) {
        cargo build --release --target wasm32-unknown-unknown --manifest-path $cargoFile
    }
    else {
        cargo build --target wasm32-unknown-unknown --manifest-path $cargoFile
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Msg "Module $ModuleName build failed"
        exit 1
    }
}

function Copy-ModuleWasm {
    param([string]$ModuleName)
    
    $moduleDir = Join-Path $RootDir "modules" $ModuleName
    
    if ($ReleaseMode) {
        $wasmDir = Join-Path $moduleDir "target" "wasm32-unknown-unknown" "release"
    }
    else {
        $wasmDir = Join-Path $moduleDir "target" "wasm32-unknown-unknown" "debug"
    }
    
    $wasmFiles = Get-ChildItem -Path $wasmDir -Filter "*.wasm" -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if ($wasmFiles) {
        Copy-Item $wasmFiles.FullName -Destination $moduleDir
        Write-Success "Copied $($wasmFiles.Name) to modules/$ModuleName/"
    }
    else {
        Write-Warning-Msg "No .wasm file found for $ModuleName"
    }
}

function Build-Modules {
    Write-Header "Building WASM Modules"
    
    Push-Location $RootDir
    
    # Find all module directories with Cargo.toml
    $modules = @()
    Get-ChildItem -Path "modules" -Directory | ForEach-Object {
        $cargoFile = Join-Path $_.FullName "Cargo.toml"
        if (Test-Path $cargoFile) {
            $modules += $_.Name
        }
    }
    
    if ($modules.Count -eq 0) {
        Write-Warning-Msg "No modules found to build"
        Pop-Location
        return
    }
    
    Write-Step "Found $($modules.Count) modules: $($modules -join ', ')"
    Write-Host ""
    
    foreach ($module in $modules) {
        Invoke-ModuleBuild -ModuleName $module
    }
    
    Pop-Location
    
    Write-Success "All modules built successfully"
    Write-Host ""
    
    if ($CopyWasm) {
        Write-Header "Copying WASM Files"
        foreach ($module in $modules) {
            Copy-ModuleWasm -ModuleName $module
        }
        Write-Host ""
    }
}

function Show-Summary {
    Write-Header "Build Summary"
    
    $mode = if ($ReleaseMode) { "release" } else { "debug" }
    
    Write-Host "Build mode: " -NoNewline
    Write-Host $mode -ForegroundColor Green
    Write-Host ""
    
    if ($BuildRuntime) {
        $runtimeBin = Join-Path $RootDir "cryftee-runtime" "target" $mode "cryftee.exe"
        if (-not (Test-Path $runtimeBin)) {
            $runtimeBin = Join-Path $RootDir "cryftee-runtime" "target" $mode "cryftee"
        }
        if (Test-Path $runtimeBin) {
            $size = "{0:N2} MB" -f ((Get-Item $runtimeBin).Length / 1MB)
            Write-Host "Runtime binary: " -NoNewline
            Write-Host $runtimeBin -ForegroundColor Green -NoNewline
            Write-Host " ($size)"
        }
    }
    
    Write-Host ""
    Write-Host "WASM Modules:"
    Get-ChildItem -Path (Join-Path $RootDir "modules") -Filter "*.wasm" -Recurse | 
        Where-Object { $_.FullName -notlike "*\target\*" } | 
        ForEach-Object {
            $size = "{0:N2} KB" -f ($_.Length / 1KB)
            $relativePath = $_.FullName.Replace($RootDir, "").TrimStart("\", "/")
            Write-Host "  ✓ " -ForegroundColor Green -NoNewline
            Write-Host "$relativePath ($size)"
        }
    
    Write-Host ""
    Write-Success "Build complete!"
}

# Main
if ($Help) {
    Show-Help
    exit 0
}

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "║           Cryftee Build System v0.4.0                     ║" -ForegroundColor Blue
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""

if ($Clean) {
    Invoke-CleanBuild
}

Test-Prerequisites

if ($BuildRuntime) {
    Build-Runtime
}

if ($BuildModules) {
    Build-Modules
}

Show-Summary
