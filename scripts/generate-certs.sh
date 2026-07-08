#!/usr/bin/env bash
# generate-certs.sh — Generate TLS certs + bearer tokens for T3MP3ST sidecars.
# Run ONCE before first "docker compose build":
#   chmod +x scripts/generate-certs.sh && ./scripts/generate-certs.sh
# Re-run to rotate certs (requires "docker compose build" + "docker compose up" afterward).
set -euo pipefail

CERTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/docker/certs"
ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/.env"

mkdir -p "$CERTS_DIR"

echo "==> Generating TLS certificates in $CERTS_DIR ..."

for NAME in cloud-sidecar binary-sidecar sandbox-sidecar; do
  if [[ -f "$CERTS_DIR/$NAME.crt" && -f "$CERTS_DIR/$NAME.key" ]]; then
    echo "    [$NAME] cert already exists — skipping (delete to regenerate)"
    continue
  fi

  # Determine the Docker service hostname from the cert name
  if [[ "$NAME" == "cloud-sidecar" ]]; then
    CN="tempest-cloud"
  elif [[ "$NAME" == "sandbox-sidecar" ]]; then
    CN="tempest-sandbox"
  else
    CN="tempest-binary"
  fi

  echo "    [$NAME] generating RSA-4096 self-signed cert (CN=$CN)..."
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$CERTS_DIR/$NAME.key" \
    -out    "$CERTS_DIR/$NAME.crt" \
    -subj   "/C=US/ST=Local/O=T3MP3ST/CN=$CN" \
    -addext "subjectAltName=DNS:$CN,DNS:localhost,IP:127.0.0.1" \
    2>/dev/null
  chmod 600 "$CERTS_DIR/$NAME.key"
  echo "    [$NAME] done."
done

echo ""
echo "==> Updating $ENV_FILE with bearer tokens ..."

add_token_if_missing() {
  local KEY="$1"
  if grep -q "^${KEY}=" "$ENV_FILE" 2>/dev/null; then
    echo "    [$KEY] already set — skipping"
  else
    local TOKEN
    TOKEN=$(openssl rand -hex 32)
    echo "${KEY}=${TOKEN}" >> "$ENV_FILE"
    echo "    [$KEY] generated and appended to .env"
  fi
}

# Create .env if it doesn't exist yet
touch "$ENV_FILE"

add_token_if_missing "CLOUD_SIDECAR_TOKEN"
add_token_if_missing "BINARY_SIDECAR_TOKEN"
add_token_if_missing "SANDBOX_SIDECAR_TOKEN"

echo ""
echo "==> Done."
echo ""
echo "    Certs:  $CERTS_DIR/"
echo "    Tokens: $ENV_FILE (CLOUD_SIDECAR_TOKEN, BINARY_SIDECAR_TOKEN, SANDBOX_SIDECAR_TOKEN)"
echo ""
echo "    Next steps:"
echo "      make rebuild                              # rebuild main container"
echo "      docker compose build tempest-cloud tempest-binary"
echo "      docker compose up -d"
