# =============================================================================
# TEMPEST STACK — Single Container
# T3MP3ST
#
# Build context: this directory (T3MP3ST/)
#   docker build -t tempest-stack:latest .
#   docker compose build   ← recommended
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1 — TypeScript compilation (no CUDA needed here)
# ─────────────────────────────────────────────────────────────────────────────
FROM node:22-slim AS node-builder

WORKDIR /build

# Install deps — package.json drives resolution; no lock file needed in builder
COPY package.json ./
RUN npm install

# Compile TypeScript → dist/
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ─────────────────────────────────────────────────────────────────────────────
# STAGE 2 — Runtime image
# node:22-slim is the base; python3-pip is added for semgrep.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:22-slim

LABEL org.opencontainers.image.title="TEMPEST STACK" \
      org.opencontainers.image.description="T3MP3ST offensive-security operations platform" \
      org.opencontainers.image.version="1.0.0"

# ── System packages ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        supervisor \
        nmap \
        unzip \
        python3-pip \
        nginx \
        openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Security scan tools (semgrep, gitleaks, trivy, nuclei, subfinder) ─────
RUN pip install --no-cache-dir --break-system-packages semgrep \
 && GITLEAKS_VER=8.21.2 \
 && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz" \
    | tar xz -C /usr/local/bin gitleaks \
 && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin \
 && NUCLEI_VER=3.3.9 \
 && curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip \
 && unzip -q /tmp/nuclei.zip nuclei -d /tmp/nuclei-bin \
 && mv /tmp/nuclei-bin/nuclei /usr/local/bin/nuclei \
 && chmod +x /usr/local/bin/nuclei \
 && rm -rf /tmp/nuclei.zip /tmp/nuclei-bin \
 && SUBFINDER_VER=2.7.1 \
 && curl -sSfL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VER}/subfinder_${SUBFINDER_VER}_linux_amd64.zip" -o /tmp/subfinder.zip \
 && unzip -q /tmp/subfinder.zip subfinder -d /tmp/subfinder-bin \
 && mv /tmp/subfinder-bin/subfinder /usr/local/bin/subfinder \
 && chmod +x /usr/local/bin/subfinder \
 && rm -rf /tmp/subfinder.zip /tmp/subfinder-bin \
 && nuclei -update-templates -silent 2>/dev/null || true

# ── Node.js: T3MP3ST production dependencies ──────────────────────────────
WORKDIR /opt/t3mp3st
COPY package.json ./
RUN npm install --omit=dev

# Copy compiled TypeScript output from stage 1
COPY --from=node-builder /build/dist ./dist

# ── Optional local agent CLIs (binaries in-image; credentials mounted from host) ──
# Mount ~/.claude, ~/.codex, ~/.hermes read-only from docker-compose.yml to activate.
# Failures are non-fatal — the container starts fine without them.
RUN npm install -g @anthropic-ai/claude-code 2>/dev/null || true

# Copy T3MP3ST static assets and scripts
COPY docs/index.html ./docs/
COPY scripts/ ./scripts/
RUN chmod +x ./scripts/*.sh 2>/dev/null || true

# ── Process manager + startup ─────────────────────────────────────────────
COPY supervisord.conf /etc/supervisor/conf.d/tempest-stack.conf
COPY scripts/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# ── Runtime defaults (all overridable via env / .env file) ────────────────
ENV NODE_ENV=production

# ── Nginx config ─────────────────────────────────────────────────────────
COPY docker/nginx/nginx.conf /etc/nginx/sites-available/tempest
RUN rm -f /etc/nginx/sites-enabled/default \
 && ln -s /etc/nginx/sites-available/tempest /etc/nginx/sites-enabled/tempest \
 && mkdir -p /certs

RUN mkdir -p /data/uploads
VOLUME ["/data/missions", "/data/uploads"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -sf http://localhost:3333/health && curl -sfk https://localhost:8443/health || exit 1

WORKDIR /opt/t3mp3st
ENTRYPOINT ["/docker-entrypoint.sh"]
