#!/usr/bin/env bash
#
# Cryftee Build Script
# Builds the cryftee runtime and all WASM modules with consistent settings
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build configuration
RELEASE_MODE="${RELEASE_MODE:-1}"
BUILD_RUNTIME="${BUILD_RUNTIME:-1}"
BUILD_MODULES="${BUILD_MODULES:-1}"
COPY_WASM="${COPY_WASM:-1}"

print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_step() {
    echo -e "${GREEN}▶ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check Rust
    if ! command -v cargo &> /dev/null; then
        print_error "Rust/Cargo not found. Install from https://rustup.rs"
        exit 1
    fi
    print_success "Rust $(rustc --version | cut -d' ' -f2) found"
    
    # Check wasm32 target
    if ! rustup target list --installed | grep -q "wasm32-unknown-unknown"; then
        print_warning "wasm32-unknown-unknown target not installed. Installing..."
        rustup target add wasm32-unknown-unknown
    fi
    print_success "wasm32-unknown-unknown target available"
    
    echo ""
}

build_runtime() {
    print_header "Building Cryftee Runtime"
    
    cd "$ROOT_DIR"
    
    if [[ "$RELEASE_MODE" == "1" ]]; then
        print_step "Building runtime (release mode)..."
        cargo build --release --manifest-path cryftee-runtime/Cargo.toml
    else
        print_step "Building runtime (debug mode)..."
        cargo build --manifest-path cryftee-runtime/Cargo.toml
    fi
    
    print_success "Runtime built successfully"
    echo ""
}

build_module() {
    local module_name=$1
    local module_dir="$ROOT_DIR/modules/$module_name"
    
    if [[ ! -f "$module_dir/Cargo.toml" ]]; then
        print_warning "Module $module_name has no Cargo.toml, skipping"
        return
    fi
    
    print_step "Building module: $module_name"
    
    if [[ "$RELEASE_MODE" == "1" ]]; then
        cargo build --release --target wasm32-unknown-unknown --manifest-path "$module_dir/Cargo.toml"
    else
        cargo build --target wasm32-unknown-unknown --manifest-path "$module_dir/Cargo.toml"
    fi
}

copy_wasm_file() {
    local module_name=$1
    local module_dir="$ROOT_DIR/modules/$module_name"
    
    if [[ "$RELEASE_MODE" == "1" ]]; then
        local wasm_dir="$module_dir/target/wasm32-unknown-unknown/release"
    else
        local wasm_dir="$module_dir/target/wasm32-unknown-unknown/debug"
    fi
    
    # Find the .wasm file (name may differ from directory name)
    local wasm_file=$(find "$wasm_dir" -maxdepth 1 -name "*.wasm" 2>/dev/null | head -1)
    
    if [[ -n "$wasm_file" && -f "$wasm_file" ]]; then
        local wasm_name=$(basename "$wasm_file")
        cp "$wasm_file" "$module_dir/"
        print_success "Copied $wasm_name to modules/$module_name/"
    else
        print_warning "No .wasm file found for $module_name"
    fi
}

build_modules() {
    print_header "Building WASM Modules"
    
    cd "$ROOT_DIR"
    
    # Find all module directories with Cargo.toml
    local modules=()
    for dir in modules/*/; do
        if [[ -f "${dir}Cargo.toml" ]]; then
            modules+=("$(basename "$dir")")
        fi
    done
    
    if [[ ${#modules[@]} -eq 0 ]]; then
        print_warning "No modules found to build"
        return
    fi
    
    print_step "Found ${#modules[@]} modules: ${modules[*]}"
    echo ""
    
    for module in "${modules[@]}"; do
        build_module "$module"
    done
    
    print_success "All modules built successfully"
    echo ""
    
    if [[ "$COPY_WASM" == "1" ]]; then
        print_header "Copying WASM Files"
        for module in "${modules[@]}"; do
            copy_wasm_file "$module"
        done
        echo ""
    fi
}

print_summary() {
    print_header "Build Summary"
    
    if [[ "$RELEASE_MODE" == "1" ]]; then
        local mode="release"
    else
        local mode="debug"
    fi
    
    echo -e "Build mode: ${GREEN}$mode${NC}"
    echo ""
    
    if [[ "$BUILD_RUNTIME" == "1" ]]; then
        local runtime_bin="$ROOT_DIR/cryftee-runtime/target/$mode/cryftee"
        if [[ -f "$runtime_bin" ]]; then
            local size=$(du -h "$runtime_bin" | cut -f1)
            echo -e "Runtime binary: ${GREEN}$runtime_bin${NC} ($size)"
        fi
    fi
    
    echo ""
    echo "WASM Modules:"
    for wasm in "$ROOT_DIR"/modules/*/*.wasm; do
        if [[ -f "$wasm" ]]; then
            local size=$(du -h "$wasm" | cut -f1)
            local name=$(basename "$(dirname "$wasm")")/$(basename "$wasm")
            echo -e "  ${GREEN}✓${NC} $name ($size)"
        fi
    done
    
    echo ""
    print_success "Build complete!"
}

show_help() {
    echo "Cryftee Build Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo "  -d, --debug      Build in debug mode (default: release)"
    echo "  -r, --runtime    Build runtime only"
    echo "  -m, --modules    Build modules only"
    echo "  --no-copy        Don't copy .wasm files to module directories"
    echo "  --clean          Clean all build artifacts first"
    echo ""
    echo "Environment variables:"
    echo "  RELEASE_MODE=0   Build in debug mode"
    echo "  BUILD_RUNTIME=0  Skip runtime build"
    echo "  BUILD_MODULES=0  Skip modules build"
    echo "  COPY_WASM=0      Don't copy .wasm files"
    echo ""
    echo "Examples:"
    echo "  $0                    # Build everything in release mode"
    echo "  $0 --debug            # Build everything in debug mode"
    echo "  $0 --runtime          # Build runtime only"
    echo "  $0 --modules          # Build modules only"
    echo "  $0 --clean            # Clean and rebuild everything"
}

clean_build() {
    print_header "Cleaning Build Artifacts"
    
    cd "$ROOT_DIR"
    
    print_step "Cleaning runtime..."
    cargo clean --manifest-path cryftee-runtime/Cargo.toml 2>/dev/null || true
    
    for dir in modules/*/; do
        if [[ -f "${dir}Cargo.toml" ]]; then
            local module=$(basename "$dir")
            print_step "Cleaning module: $module"
            cargo clean --manifest-path "${dir}Cargo.toml" 2>/dev/null || true
        fi
    done
    
    # Remove copied .wasm files
    print_step "Removing copied .wasm files..."
    find modules -maxdepth 2 -name "*.wasm" -not -path "*/target/*" -delete 2>/dev/null || true
    
    print_success "Clean complete"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--debug)
            RELEASE_MODE=0
            shift
            ;;
        -r|--runtime)
            BUILD_MODULES=0
            shift
            ;;
        -m|--modules)
            BUILD_RUNTIME=0
            shift
            ;;
        --no-copy)
            COPY_WASM=0
            shift
            ;;
        --clean)
            clean_build
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main build process
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Cryftee Build System v0.4.0                     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

check_prerequisites

if [[ "$BUILD_RUNTIME" == "1" ]]; then
    build_runtime
fi

if [[ "$BUILD_MODULES" == "1" ]]; then
    build_modules
fi

print_summary
