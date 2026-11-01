#!/usr/bin/env bash
# ==============================================================================
# Bug Killer (bk) - Universal Installation Script
# Autonomous Vulnerability Finder & Virtual Healer
# Author: Mamdouh Aboammar
# ==============================================================================

set -euo pipefail

# ANSI color codes
BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}==> Bug Killer (bk) Universal Installer${NC}"

# Detect OS and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        ;;
    arm64|aarch64)
        TARGET_ARCH="aarch64"
        ;;
    *)
        echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}" >&2
        exit 1
        ;;
esac

echo -e "    Platform: ${BOLD}$OS ($TARGET_ARCH)${NC}"

# Target install directory (default ~/.local/bin)
INSTALL_DIR="${PREFIX:-$HOME/.local/bin}"
BUILD_ALL_SERVICES="${ALL_SERVICES:-0}"

# Parse command line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all|--with-services)
            BUILD_ALL_SERVICES=1
            shift
            ;;
        --prefix)
            INSTALL_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Bug Killer Installer"
            echo "Usage: install.sh [OPTIONS]"
            echo "Options:"
            echo "  --all            Build and install auxiliary Go & inspector services in addition to bk"
            echo "  --prefix <DIR>   Set target installation directory (default: ~/.local/bin or \$PREFIX)"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd || echo "")"

# Check if we are inside the source repository
if [ -n "$REPO_ROOT" ] && [ -f "$REPO_ROOT/Cargo.toml" ]; then
    echo -e "==> Building from local source repository at $REPO_ROOT..."
    cd "$REPO_ROOT"
    
    if ! command -v cargo >/dev/null 2>&1; then
        echo -e "${RED}[!] Cargo is required to build from source. Install Rust from https://rustup.rs${NC}" >&2
        exit 1
    fi
    
    cargo build --release --bin bug-killer --bin bk
    
    echo -e "==> Installing binaries to $INSTALL_DIR..."
    install -m 755 target/release/bug-killer "$INSTALL_DIR/bug-killer"
    install -m 755 target/release/bk "$INSTALL_DIR/bk"
    
    # Optional services build if requested
    if [ "$BUILD_ALL_SERVICES" = "1" ]; then
        if command -v go >/dev/null 2>&1; then
            echo -e "==> Building auxiliary Go microservices..."
            if [ -d "services/orchestrator" ]; then
                (cd services/orchestrator && go build -o "$INSTALL_DIR/bug-killer-orchestrator" .) || true
            fi
            if [ -d "services/healer" ]; then
                (cd services/healer && go build -o "$INSTALL_DIR/bug-killer-healer" .) || true
            fi
        fi
        
        if [ -d "services/inspector" ]; then
            echo -e "==> Building auxiliary Rust inspector..."
            (cd services/inspector && cargo build --release && install -m 755 target/release/bug-killer-inspector "$INSTALL_DIR/bug-killer-inspector") || true
        fi
    fi
else
    # Remote execution mode
    echo -e "==> Installing Bug Killer via Cargo..."
    if command -v cargo >/dev/null 2>&1; then
        cargo install --git https://github.com/imMamdouhaboammar/bug-killer.git --bin bug-killer --bin bk
        echo -e "${GREEN}[✓] Installed bk and bug-killer via cargo into $(cargo --version | awk '{print $1}') environment${NC}"
        INSTALL_DIR="$(cargo env 2>/dev/null | grep CARGO_HOME | cut -d= -f2)/bin"
        [ -z "$INSTALL_DIR" ] && INSTALL_DIR="$HOME/.cargo/bin"
    else
        echo -e "${RED}[!] Cargo is required to install Bug Killer. Install Rust from https://rustup.rs${NC}" >&2
        exit 1
    fi
fi

# Generate and install shell completions if bk binary is executable
BK_BIN="$INSTALL_DIR/bk"
if [ ! -x "$BK_BIN" ] && [ -x "$INSTALL_DIR/bug-killer" ]; then
    BK_BIN="$INSTALL_DIR/bug-killer"
fi

if [ -x "$BK_BIN" ]; then
    echo -e "==> Generating shell auto-completions..."
    # Bash
    BASH_COMP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
    mkdir -p "$BASH_COMP_DIR" 2>/dev/null || true
    "$BK_BIN" completion bash > "$BASH_COMP_DIR/bk" 2>/dev/null || true
    "$BK_BIN" completion bash > "$BASH_COMP_DIR/bug-killer" 2>/dev/null || true

    # Zsh
    ZSH_COMP_DIR="${ZDOTDIR:-$HOME}/.zsh/completions"
    mkdir -p "$ZSH_COMP_DIR" 2>/dev/null || true
    "$BK_BIN" completion zsh > "$ZSH_COMP_DIR/_bk" 2>/dev/null || true
    "$BK_BIN" completion zsh > "$ZSH_COMP_DIR/_bug-killer" 2>/dev/null || true

    # Fish
    FISH_COMP_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions"
    mkdir -p "$FISH_COMP_DIR" 2>/dev/null || true
    "$BK_BIN" completion fish > "$FISH_COMP_DIR/bk.fish" 2>/dev/null || true
    "$BK_BIN" completion fish > "$FISH_COMP_DIR/bug-killer.fish" 2>/dev/null || true
fi

# Verify PATH
IN_PATH=false
case ":$PATH:" in
    *":$INSTALL_DIR:"*) IN_PATH=true ;;
esac

echo ""
if [ "$IN_PATH" = "false" ]; then
    echo -e "${YELLOW}[!] Warning: $INSTALL_DIR is not in your PATH.${NC}"
    echo -e "    Add it to your shell configuration:"
    echo -e "    ${BOLD}export PATH=\"$INSTALL_DIR:\$PATH\"${NC}"
    echo ""
fi

# Run doctor diagnostic
echo -e "==> Running Bug Killer system verification..."
if [ -x "$BK_BIN" ]; then
    "$BK_BIN" doctor .
fi

echo -e "${GREEN}${BOLD}==> Installation Complete!${NC}"
echo -e "    Executable: ${BOLD}$BK_BIN${NC}"
echo ""
echo -e "Quick Start Guide:"
echo -e "  1. Initialize Bug Killer in any project:"
echo -e "     ${BOLD}cd /path/to/any-project && bk init${NC}"
echo -e "  2. Run a fast security scan:"
echo -e "     ${BOLD}bk security scan . --profile quick${NC}"
echo -e "  3. Configure MCP for AI Coding Assistants (Cursor, Claude, Gemini):"
echo -e "     ${BOLD}bk mcp config --host all${NC}"
echo -e "  4. Get task security guidance before writing code:"
echo -e "     ${BOLD}bk security guidance \"implement file upload\"${NC}"
