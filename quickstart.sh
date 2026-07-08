#!/usr/bin/env bash
# quickstart.sh — zero-friction first run for T3MP3ST
# Run from the T3MP3ST/ directory:  ./quickstart.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}▸${RESET} $*"; }
ok()      { echo -e "${GREEN}✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}!${RESET} $*"; }
die()     { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }
section() { echo -e "\n${BOLD}$*${RESET}"; }

# ── banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat << 'BANNER'
  ████████╗██████╗ ███╗   ███╗██████╗ ██████╗ ███████╗████████╗
     ██╔══╝╚════██╗████╗ ████║██╔══██╗╚════██╗██╔════╝╚══██╔══╝
     ██║    █████╔╝██╔████╔██║██████╔╝ █████╔╝███████╗   ██║
     ██║    ╚═══██╗██║╚██╔╝██║██╔═══╝  ╚═══██╗╚════██║   ██║
     ██║   ██████╔╝██║ ╚═╝ ██║██║     ██████╔╝███████║   ██║
     ╚═╝   ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═════╝ ╚══════╝   ╚═╝
BANNER
echo -e "${RESET}"
echo "  Multi-agent offensive security operations platform"
echo "  ─────────────────────────────────────────────────"
echo ""

# ── 1. Prerequisite checks ────────────────────────────────────────────────────
section "1/5  Prerequisites"

command -v docker &>/dev/null   || die "Docker not found. Install from https://docs.docker.com/get-docker/"
docker info &>/dev/null         || die "Docker daemon not running. Start Docker and try again."
docker compose version &>/dev/null || die "Docker Compose v2 not found. Update Docker Desktop or install the plugin."
ok "Docker $(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1) + Compose $(docker compose version --short)"

# ── 2. Environment setup ──────────────────────────────────────────────────────
section "2/5  Environment"

if [[ ! -f .env ]]; then
  cp .env.example .env
  info "Created .env from .env.example"
fi

# Check if any provider key is already set
HAS_KEY=""
while IFS='=' read -r key val; do
  [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
  case "$key" in
    OPENROUTER_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|GROQ_API_KEY|\
    TOGETHER_API_KEY|HUGGINGFACE_TOKEN|REPLICATE_API_TOKEN|VENICE_API_KEY)
      # Strip quotes and whitespace
      clean_val=$(echo "$val" | tr -d '"'"'"' ' | tr -d '[:space:]')
      if [[ -n "$clean_val" && "$clean_val" != "sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
            && "$clean_val" != "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
            && "$clean_val" != "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" ]]; then
        HAS_KEY="$key"
      fi
      ;;
  esac
done < .env

if [[ -n "$HAS_KEY" ]]; then
  ok "LLM provider key found ($HAS_KEY)"
else
  echo ""
  echo "  At least one LLM provider key is required."
  echo "  OpenRouter is the easiest (free tier available): https://openrouter.ai/keys"
  echo ""
  echo -n "  Paste your OpenRouter API key (or press Enter to skip and edit .env manually): "
  read -r -s OROUTER_KEY
  echo ""

  if [[ -n "$OROUTER_KEY" ]]; then
    # Replace the placeholder in .env
    if [[ "$(uname)" == "Darwin" ]]; then
      sed -i '' "s|^OPENROUTER_API_KEY=.*|OPENROUTER_API_KEY=${OROUTER_KEY}|" .env
    else
      sed -i "s|^OPENROUTER_API_KEY=.*|OPENROUTER_API_KEY=${OROUTER_KEY}|" .env
    fi
    # Set provider if not already set to something useful
    if grep -q '^LLM_PROVIDER=$' .env 2>/dev/null || ! grep -q '^LLM_PROVIDER=' .env 2>/dev/null; then
      if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' 's|^LLM_PROVIDER=.*|LLM_PROVIDER=openrouter|' .env
      else
        sed -i 's|^LLM_PROVIDER=.*|LLM_PROVIDER=openrouter|' .env
      fi
    fi
    ok "OpenRouter key saved to .env"
  else
    warn "No key set. Edit .env before starting — T3MP3ST needs at least one provider key."
    echo ""
    echo "  Continuing with build anyway..."
  fi
fi

# ── 3. Build ──────────────────────────────────────────────────────────────────
section "3/5  Build"

info "Building tempest-stack image (this takes a few minutes on first run)..."
echo ""
docker compose build
echo ""
ok "Image built: tempest-stack:latest"

# ── 4. Start ──────────────────────────────────────────────────────────────────
section "4/5  Start"

# Stop any existing container cleanly
if docker ps -a --format '{{.Names}}' | grep -q '^tempest-stack$'; then
  info "Stopping existing container..."
  docker compose down 2>/dev/null || true
fi

# Pre-create credential dirs so bind mounts don't fail on first run
mkdir -p "${HOME}/.claude" "${HOME}/.codex" "${HOME}/.hermes"

info "Starting stack..."
docker compose up -d
echo ""

# Wait for T3MP3ST + Nginx to come up (check via HTTPS proxy)
HTTPS_PORT=$(grep -E '^TEMPEST_HTTPS_PORT=' .env 2>/dev/null | cut -d= -f2 | tr -d '"' | tr -d "'" | tr -d '[:space:]')
HTTPS_PORT="${HTTPS_PORT:-8443}"

MAX_WAIT=240
WAITED=0
INTERVAL=3
printf "  Waiting for T3MP3ST to come up (https://localhost:${HTTPS_PORT})"
while true; do
  if curl -sfk --max-time 3 "https://localhost:${HTTPS_PORT}/health" &>/dev/null; then
    echo ""
    ok "T3MP3ST is up"
    break
  fi
  if [[ $WAITED -ge $MAX_WAIT ]]; then
    echo ""
    warn "Still starting after ${MAX_WAIT}s — running smoke suite anyway (stack is likely almost ready)."
    warn "If tests fail: docker compose logs -f"
    break
  fi
  printf "."
  sleep "$INTERVAL"
  WAITED=$((WAITED + INTERVAL))
done

# ── 5. Smoke test ─────────────────────────────────────────────────────────────
section "5/5  Smoke test"

info "Running smoke suite inside the container..."
echo ""
if docker exec tempest-stack /opt/t3mp3st/scripts/test-container.sh; then
  echo ""
  ok "All checks passed"
else
  echo ""
  warn "Some checks failed — see above. The stack may still be usable."
  warn "Try: docker compose logs -f"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Stack is running at https://localhost:${HTTPS_PORT}${RESET}"
echo ""
echo "  Web UI:         https://localhost:${HTTPS_PORT}  (accept the self-signed cert)"
echo "  API health:     https://localhost:${HTTPS_PORT}/health"
echo "  Preflight:      https://localhost:${HTTPS_PORT}/api/preflight  (after login)"
echo ""
echo "  Login:          username: admin"
echo "                  password: run 'make logs' to see it"
echo ""
echo "  Useful commands:"
echo "    make logs      — tail container logs"
echo "    make shell     — open a shell inside the container"
echo "    make test      — re-run smoke suite"
echo "    make down      — stop the stack"
echo "    make help      — all available targets"
echo ""
echo "  Docs:"
echo "    docs/OPERATIONS.md       — how to operate the stack"
echo "    docs/STACK_ARCHITECTURE.md — system architecture"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${RESET}"
echo ""
