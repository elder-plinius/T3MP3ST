# T3MP3ST cloud-sidecar — cloud security tool execution container
# Tools: awscli, prowler, checkov (small + fast to install)
# Optional: gcloud, az (large — uncomment sections below to enable)

FROM python:3.11-slim

# System dependencies for Node.js (sidecar server) and cloud CLI prereqs
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        gnupg \
        dnsutils \
        nmap \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20.x
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Core cloud security tools (small, quick install)
RUN pip install --no-cache-dir \
        awscli \
        prowler \
        checkov

# ── Optional: Google Cloud SDK (~350MB) ──────────────────────────────────────
# Uncomment to enable gcloud/gsutil support:
# RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" \
#         | tee /etc/apt/sources.list.d/google-cloud-sdk.list \
#     && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
#         | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
#     && apt-get update && apt-get install -y --no-install-recommends google-cloud-sdk \
#     && rm -rf /var/lib/apt/lists/*

# ── Optional: Azure CLI (~200MB) ─────────────────────────────────────────────
# Uncomment to enable az support:
# RUN pip install --no-cache-dir azure-cli

WORKDIR /app
COPY package.json .
COPY server.js .

EXPOSE 8080

# Certs are bind-mounted at runtime from docker/certs/
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsk https://localhost:8080/health || exit 1

CMD ["node", "server.js"]
