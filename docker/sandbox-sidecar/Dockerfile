# T3MP3ST sandbox-sidecar — controlled dynamic execution environment
# Supports: ELF (QEMU user-mode + strace/ltrace/gdb)
#           Windows PE (Wine64 Win10 Pro disguise)
#           macOS Mach-O (Qiling emulation)
# Anti-debug: LD_PRELOAD shim + Wine relay bypass

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WINEPREFIX=/opt/wine-env
ENV WINEARCH=win64

# ── Core analysis tools ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        strace \
        ltrace \
        gdb \
        tcpdump \
        dnsmasq \
        net-tools \
        iproute2 \
        build-essential \
        gcc \
        util-linux \
        python3 \
        python3-pip \
        curl \
        file \
        xvfb \
        xauth \
        gnupg \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js 20.x ──────────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── QEMU user-mode (defeats hypervisor/CPUID detection on ELF runs) ───────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

# ── Wine64 (Windows PE primary execution) ─────────────────────────────────────
RUN dpkg --add-architecture i386 \
    && apt-get update && apt-get install -y --no-install-recommends \
        wine64 \
        wine32 \
    && rm -rf /var/lib/apt/lists/*

# ── Python dynamic analysis tools ─────────────────────────────────────────────
RUN pip3 install --no-cache-dir frida-tools qiling

# ── Compile LD_PRELOAD anti-debug shim ────────────────────────────────────────
COPY preload-shim/antidebug.c /tmp/antidebug.c
RUN gcc -shared -fPIC -o /usr/local/lib/antidebug.so /tmp/antidebug.c -ldl \
    && chmod 644 /usr/local/lib/antidebug.so \
    && rm /tmp/antidebug.c

# ── Python orchestration scripts ──────────────────────────────────────────────
RUN mkdir -p /scripts
COPY scripts/ /scripts/
RUN chmod +x /scripts/*.py

# ── Wine prefix: initialise headlessly + apply Windows 10 Pro disguise ────────
# Uses Xvfb for headless display. Non-fatal: if Wine init fails the sidecar
# still works for ELF/Mach-O analysis.
RUN Xvfb :99 -screen 0 1024x768x16 & sleep 3 \
    && DISPLAY=:99 WINEDEBUG=-all wine64 wineboot --init 2>/dev/null || true \
    && sleep 5 \
    && DISPLAY=:99 WINEDEBUG=-all wine64 reg add \
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion" \
        /v ProductName /t REG_SZ /d "Windows 10 Pro" /f 2>/dev/null || true \
    && DISPLAY=:99 WINEDEBUG=-all wine64 reg add \
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion" \
        /v CurrentBuildNumber /t REG_SZ /d "19045" /f 2>/dev/null || true \
    && DISPLAY=:99 WINEDEBUG=-all wine64 reg add \
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion" \
        /v CSDVersion /t REG_SZ /d "" /f 2>/dev/null || true \
    && DISPLAY=:99 WINEDEBUG=-all wine64 reg delete \
        "HKCU\\Software\\Wine" /f 2>/dev/null || true \
    && DISPLAY=:99 WINEDEBUG=-all wine64 reg delete \
        "HKLM\\Software\\Wine" /f 2>/dev/null || true \
    && pkill Xvfb 2>/dev/null || true

# ── Uploads directory (bind-mounted from host) ────────────────────────────────
RUN mkdir -p /data/uploads
ENV UPLOADS_DIR=/data/uploads

WORKDIR /app
COPY package.json .
COPY server.js .

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -fsk https://localhost:8080/health || exit 1

CMD ["node", "server.js"]
