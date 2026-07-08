#!/usr/bin/env bash
# =============================================================================
# TEMPEST STACK — Container entrypoint
# =============================================================================
set -euo pipefail

echo "[entrypoint] ============================================="
echo "[entrypoint] TEMPEST STACK starting"
echo "[entrypoint] ============================================="

# ── Ensure volume directories exist ──────────────────────────────────────────
mkdir -p /data/missions /data/uploads /certs
echo "[entrypoint] Data directories: OK"

# ── Self-signed TLS certificate (generated once; persists for container lifetime) ──
if [ ! -f /certs/nginx.key ] || [ ! -f /certs/nginx.crt ]; then
    echo "[entrypoint] Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout /certs/nginx.key \
        -out    /certs/nginx.crt \
        -days   3650 \
        -nodes \
        -subj   "/CN=localhost/O=T3MP3ST" \
        -addext "subjectAltName=DNS:localhost,DNS:tempest-stack,IP:127.0.0.1" \
        2>/dev/null
    chmod 600 /certs/nginx.key
    echo "[entrypoint] TLS certificate: OK (/certs/nginx.crt)"
else
    echo "[entrypoint] TLS certificate: reusing existing (/certs/nginx.crt)"
fi

# ── Default env vars (set if not already set) ────────────────────────────────
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
export OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
export LLM_PROVIDER="${LLM_PROVIDER:-}"
export LLM_MODEL="${LLM_MODEL:-}"
export TEMPEST_HTTPS_PORT="${TEMPEST_HTTPS_PORT:-8443}"

echo "[entrypoint] HTTPS proxy will be available on host port ${TEMPEST_HTTPS_PORT}"
echo "[entrypoint] (password will be printed by T3MP3ST on startup)"

# ── Launch supervisord ────────────────────────────────────────────────────────
echo "[entrypoint] Launching supervisord..."
exec supervisord -c /etc/supervisor/conf.d/tempest-stack.conf
