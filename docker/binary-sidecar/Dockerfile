# T3MP3ST binary-sidecar — binary analysis tool execution container
# Tools: binutils (strings/nm/readelf/objdump), file, xxd, radare2, yara, binwalk, exiftool

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Core binary analysis tools (universe already enabled in ubuntu:22.04 image)
RUN apt-get update && apt-get install -y --no-install-recommends \
        binutils \
        file \
        xxd \
        bsdmainutils \
        libimage-exiftool-perl \
        yara \
        binwalk \
        python3 \
        python3-pip \
        curl \
        gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20.x
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# radare2 is not in Ubuntu 22.04 apt repos — install from GitHub releases
# Non-fatal: if download fails, sidecar still works for strings/binwalk/yara/etc.
RUN curl -fsSL https://github.com/radareorg/radare2/releases/download/5.9.6/radare2_5.9.6_amd64.deb \
        -o /tmp/r2.deb \
    && apt-get install -y --no-install-recommends /tmp/r2.deb \
    && rm -f /tmp/r2.deb \
    || echo "[binary-sidecar] radare2 not installed — ghidra_decompile fallback will note r2 unavailable"

# r2pipe Python bindings for radare2 scripting + ROPgadget for ROP chain analysis
RUN pip3 install --no-cache-dir r2pipe ropgadget

# r2ghidra plugin — Ghidra's decompiler inside radare2 (pdg command gives C pseudocode).
# Non-fatal: if the download fails the sidecar still works with pdc as fallback.
RUN r2pm update 2>/dev/null; r2pm -ci r2ghidra 2>/dev/null \
    && echo "[binary-sidecar] r2ghidra installed — pdg decompiler available" \
    || echo "[binary-sidecar] r2ghidra not available — pdc fallback active"

# Uploads directory (bind-mounted from host at runtime)
RUN mkdir -p /data/uploads
ENV UPLOADS_DIR=/data/uploads

WORKDIR /app
COPY package.json .
COPY server.js .

EXPOSE 8080

# Certs are bind-mounted at runtime from docker/certs/
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsk https://localhost:8080/health || exit 1

CMD ["node", "server.js"]
