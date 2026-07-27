#!/usr/bin/env bash
set -euo pipefail

# T3MP3ST Install Matrix — installs all tools listed in docs/INSTALL_MATRIX.md
# Usage: chmod +x install_tools.sh && ./install_tools.sh
#
# Supports: Debian/Ubuntu (apt), Red Hat/Fedora (dnf/yum), Arch (pacman), macOS (brew)
# Skips tools already on PATH. Run with --force to reinstall.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
FORCE=false; DRY_RUN=false
[[ "${1:-}" == "--force" ]] && FORCE=true
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; exit 1; }
skip() { echo -e "${YELLOW}[~]${NC} $*"; }

has()  { command -v "$1" &>/dev/null; }
maybe() { if $FORCE || ! has "$1"; then log "installing $1"; if ! $DRY_RUN; then eval "$2"; fi; else skip "$1 already installed"; fi; }

# ── Detect OS ────────────────────────────────────────────────────────────────
OS="linux"
PKG="apt"
case "$(uname -s)" in
    Darwin) OS="macos"; PKG="brew" ;;
    Linux)
        if   has apt; then PKG="apt"
        elif has dnf; then PKG="dnf"
        elif has yum; then PKG="yum"
        elif has pacman; then PKG="pacman"
        else err "unsupported Linux package manager"
        fi ;;
    *) err "unsupported OS: $(uname -s)" ;;
esac
log "detected $OS / $PKG"

# ── Helpers ──────────────────────────────────────────────────────────────────
ensure_brew() {
    if ! has brew; then
        log "installing Homebrew"
        $DRY_RUN && return
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        if [[ "$OS" == "linux" ]]; then eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"; fi
    fi
}

# Shared pipx home + venv fallback. All Python tools land under ~/.local/pipx
# (pipx default) or a fallback venv at ~/.local/t3mp3st-venv if pipx is missing.
PIPX_HOME="${PIPX_HOME:-$HOME/.local/pipx}"
PIPX_BIN_DIR="${PIPX_BIN_DIR:-$HOME/.local/bin}"
PIPX_GLOBAL_FLAG=""
T3MP3ST_VENV="$HOME/.local/t3mp3st-venv"

ensure_pipx() {
    export PATH="$PIPX_BIN_DIR:$PATH"

    if has pipx; then
        # pipx >=1.7 supports --global for installing into PIPX_HOME directly.
        # Older pipx uses `--global` meaning system-wide (needs sudo). Detect the
        # right flag so tools land in the per-user PIPX_HOME without root.
        if pipx install --help 2>&1 | grep -q '\--global'; then
            # pipx 1.7+: --global → PIPX_HOME (~/.local/pipx), no sudo
            PIPX_GLOBAL_FLAG=""
            export PIPX_HOME PIPX_BIN_DIR
            pipx ensurepath --force 2>/dev/null || true
        else
            # pre-1.7 pipx: default install dir is already PIPX_HOME, no flag needed
            PIPX_GLOBAL_FLAG=""
        fi
        return 0
    fi

    log "pipx not found — installing"
    if $DRY_RUN; then return; fi

    case "$PKG" in
        apt) sudo apt install -y pipx ;;
        dnf|yum) sudo "$PKG" install -y pipx ;;
        pacman) sudo pacman -S --noconfirm python-pipx ;;
        brew) brew install pipx ;;
    esac

    # Re-check after install
    if has pipx; then
        export PIPX_HOME PIPX_BIN_DIR
        pipx ensurepath --force 2>/dev/null || true
        export PATH="$PIPX_BIN_DIR:$PATH"
    else
        warn "pipx still unavailable — falling back to shared venv at $T3MP3ST_VENV"
        python3 -m venv "$T3MP3ST_VENV"
        "$T3MP3ST_VENV/bin/pip" install --upgrade pip setuptools wheel
        export PATH="$T3MP3ST_VENV/bin:$PIPX_BIN_DIR:$PATH"
    fi
}

# Install a Python tool — prefers pipx, falls back to the shared venv.
pipx_install() {
    local bin="$1" pkg="${2:-$1}"
    if $FORCE || ! has "$bin"; then
        if has pipx; then
            log "pipx install $pkg"
            if ! $DRY_RUN; then
                PIPX_HOME="$PIPX_HOME" PIPX_BIN_DIR="$PIPX_BIN_DIR" \
                    pipx install $PIPX_GLOBAL_FLAG "$pkg"
            fi
        else
            log "venv install $pkg → $T3MP3ST_VENV"
            if ! $DRY_RUN; then
                "$T3MP3ST_VENV/bin/pip" install "$pkg"
            fi
        fi
    else
        skip "$bin already installed"
    fi
}

# npm install -g with a user-local prefix so no sudo needed.
NPM_PREFIX="${NPM_PREFIX:-$HOME/.local}"
ensure_npm() {
    export PATH="$NPM_PREFIX/bin:$PATH"
    if ! has npm; then
        case "$PKG" in
            apt) sudo apt install -y nodejs npm ;;
            dnf|yum) sudo "$PKG" install -y nodejs npm ;;
            pacman) sudo pacman -S --noconfirm nodejs npm ;;
            brew) brew install node ;;
        esac
    fi
    # Configure npm to install globally into ~/.local (no sudo)
    npm config set prefix "$NPM_PREFIX" 2>/dev/null || true
}

npm_install() {
    local bin="$1" pkg="${2:-$1}"
    if $FORCE || ! has "$bin"; then
        log "npm install -g $pkg"
        if ! $DRY_RUN; then npm install -g "$pkg" --prefix "$NPM_PREFIX"; fi
    else
        skip "$bin already installed"
    fi
}

ensure_go() {
    export PATH="$HOME/go/bin:$PATH"
    if ! has go; then
        case "$PKG" in
            apt) sudo apt install -y golang-go ;;
            dnf|yum) sudo "$PKG" install -y golang ;;
            pacman) sudo pacman -S --noconfirm go ;;
            brew) brew install go ;;
        esac
        export PATH="$HOME/go/bin:$PATH"
    fi
}

ensure_cargo() {
    export PATH="$HOME/.cargo/bin:$PATH"
    if ! has cargo; then
        case "$PKG" in
            apt) sudo apt install -y cargo ;;
            dnf|yum) sudo "$PKG" install -y cargo ;;
            pacman) sudo pacman -S --noconfirm rust ;;
            brew) brew install rust ;;
        esac
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
}

go_install() {
    local bin="$1" pkg="$2"
    maybe "$bin" "go install ${pkg}@latest"
}

# ── Phase 1: Core Evidence ───────────────────────────────────────────────────
log "=== Phase 1: Core Evidence ==="
case "$PKG" in
    apt) sudo apt update -y && sudo apt install -y file curl bind9-dnsutils whois openssl ;;
    dnf|yum) sudo "$PKG" install -y file curl bind-utils whois openssl ;;
    pacman) sudo pacman -S --noconfirm file curl bind whois openssl ;;
    brew)
        ensure_brew
        maybe "file"    "true"   # macOS ships file
        maybe "curl"    "true"   # macOS ships curl
        maybe "dig"     "brew install bind"
        maybe "whois"   "brew install whois"
        maybe "openssl" "brew install openssl@3"
        ;;
esac

# ── Phase 2: Web/API Recon ───────────────────────────────────────────────────
log "=== Phase 2: Web/API Recon ==="
case "$PKG" in
    apt) sudo apt install -y nmap ;;
    dnf|yum) sudo "$PKG" install -y nmap ;;
    pacman) sudo pacman -S --noconfirm nmap ;;
    brew) maybe "nmap" "brew install nmap" ;;
esac

ensure_go
go_install "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
go_install "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx"
go_install "naabu"     "github.com/projectdiscovery/naabu/v2/cmd/naabu"
go_install "katana"    "github.com/projectdiscovery/katana/cmd/katana"
go_install "nuclei"    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

# ── Phase 3: Web/API Pressure ────────────────────────────────────────────────
log "=== Phase 3: Web/API Pressure ==="
go_install "ffuf"       "github.com/ffuf/ffuf/v2"
go_install "gobuster"   "github.com/OJ/gobuster/v3"
maybe "feroxbuster" "cargo install feroxbuster"
maybe "dalfox"      "go install github.com/hahwul/dalfox/v2@latest"
case "$PKG" in
    apt) sudo apt install -y nikto sqlmap ;;
    dnf|yum) sudo "$PKG" install -y nikto sqlmap ;;
    pacman) sudo pacman -S --noconfirm nikto sqlmap ;;
    brew) maybe "nikto" "brew install nikto"; maybe "sqlmap" "brew install sqlmap" ;;
esac

# ── Phase 4: Supply Chain ────────────────────────────────────────────────────
log "=== Phase 4: Supply Chain ==="
ensure_pipx
pipx_install "semgrep"
maybe "gitleaks"   "go install github.com/gitleaks/gitleaks/v8@latest"
maybe "trufflehog" "go install github.com/trufflesecurity/trufflehog/v3@latest"
maybe "syft"       "go install github.com/anchore/syft/cmd/syft@latest"
maybe "grype"      "go install github.com/anchore/grype/cmd/grype@latest"
case "$PKG" in
    apt) sudo apt install -y trivy ;;
    dnf|yum) sudo "$PKG" install -y trivy ;;
    pacman) sudo pacman -S --noconfirm trivy ;;
    brew) maybe "trivy" "brew install trivy" ;;
esac
maybe "osv-scanner" "go install github.com/google/osv-scanner/cmd/osv-scanner@latest"

# ── Phase 5: Cloud/IaC ───────────────────────────────────────────────────────
log "=== Phase 5: Cloud/IaC ==="
pipx_install "checkov"
pipx_install "prowler"

# ── Phase 6: AI/Agent ────────────────────────────────────────────────────────
log "=== Phase 6: AI/Agent ==="
pipx_install "garak"
ensure_npm
npm_install "promptfoo"

# ── Phase 7: Smart Contract ──────────────────────────────────────────────────
log "=== Phase 7: Smart Contract ==="
pipx_install "slither"     "slither-analyzer"
pipx_install "myth"        "mythril"
pipx_install "echidna"     "echidna-test"
if ! has forge || ! has cast; then
    log "installing Foundry (forge, cast)"
    if ! $DRY_RUN; then curl -L https://foundry.paradigm.xyz | bash && foundryup; fi
else
    skip "forge+cast already installed"
fi
npm_install "solhint"

# ── Phase 8: Crypto Audit ────────────────────────────────────────────────────
log "=== Phase 8: Crypto Audit ==="
case "$PKG" in
    apt) sudo apt install -y john hashcat ;;
    dnf|yum) sudo "$PKG" install -y john hashcat ;;
    pacman) sudo pacman -S --noconfirm john hashcat ;;
    brew) maybe "john" "brew install john"; maybe "hashcat" "brew install hashcat" ;;
esac

# ── Phase 9: Reverse / Mobile / Fuzz ─────────────────────────────────────────
log "=== Phase 9: Reverse / Mobile / Fuzz ==="
case "$PKG" in
    apt) sudo apt install -y radamsa afl++ radare2 apktool jadx exiftool binwalk yara ;;
    dnf|yum)
        sudo "$PKG" install -y radamsa american-fuzzy-lop++ radare2 apktool jadx exiftool binwalk yara ;;
    pacman) sudo pacman -S --noconfirm radamsa afl++ radare2 apktool jadx exiftool binwalk yara ;;
    brew)
        maybe "radamsa"  "brew install radamsa"
        maybe "afl-fuzz" "brew install afl-fuzz"
        maybe "r2"       "brew install radare2"
        maybe "apktool"  "brew install apktool"
        maybe "jadx"     "brew install jadx"
        maybe "exiftool" "brew install exiftool"
        maybe "binwalk"  "brew install binwalk"
        maybe "yara"     "brew install yara"
        ;;
esac

# ── Phase 10: Gated / Import ─────────────────────────────────────────────────
log "=== Phase 10: Gated / Import (catalog-only) ==="
warn "msfconsole, hydra, bloodhound — install manually as needed."
warn "  msfconsole:  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"
warn "  hydra:       sudo apt install hydra (or brew install hydra)"
warn "  bloodhound:  pipx install bloodhound"

# ── Done ─────────────────────────────────────────────────────────────────────
log ""
log "=============================================="
log " T3MP3ST tool matrix install complete."
log " Run 'nuclei -update-templates' to fetch latest nuclei templates."
log "=============================================="
