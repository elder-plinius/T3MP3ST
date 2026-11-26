# T3MP3ST server running INSIDE the Kali tooling image.
#
# This is the piece that closes the loop: because metasploit / hydra / nmap are on PATH here,
# the arsenal's isToolAvailable() checks pass and the War Room "Capability check" for the
# exploit/credential phases goes 🟢 ready — the server can actually drive those tools.
#
# Base = the attacker image (Kali + metasploit + hydra + nmap). Build that first:
#   docker compose --profile attacker build attacker
# then this image layers Node 22 + the app on top.
#
# Build context is the REPO ROOT (see compose `context: ..`), so `COPY . .` copies the project.
# .dockerignore already drops node_modules / dist / .env / .git.

FROM ctf-attacker

ENV DEBIAN_FRONTEND=noninteractive

# Node + npm from the Kali repos. Kali rolling ships Node 24 (satisfies the project's >=22.19), but
# its `nodejs` package does NOT bundle npm — install both explicitly.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm ca-certificates \
    && node --version && npm --version \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Deps first (better layer caching), then the source + a production build.
COPY package*.json tsconfig.json ./
RUN npm ci
COPY . .
RUN npm run build && mkdir -p docs

# Bind to 0.0.0.0 inside the container, and arm the specialist arsenal so the post-ex /
# credential drivers register (still per-action approval-gated at run time).
ENV DOCKER=true
ENV T3MP3ST_FULL_ARSENAL=1

EXPOSE 3333
HEALTHCHECK --interval=30s --timeout=10s --start-period=45s --retries=3 \
  CMD curl -fsS http://localhost:3333/api/health || exit 1

# tsx is dev-only/unstable in containers — run the compiled prod server.
CMD ["npm", "run", "server:prod"]
