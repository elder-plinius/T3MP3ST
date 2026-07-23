# T3MP3ST Kali Linux+ arsenal image  →  cybench-tools:latest  (linux/amd64)
#
# NORTH STAR: a 1337 hacker group of specialist experts wielding a real Kali Linux+ arsenal.
# This is the reproducible loadout — the hunter mounts it via --tools-image for RE/crypto/pwn
# challenges (host has no linux/amd64 tooling), and it is the portable home of the FULL arsenal.
#
# "+" over stock Kali = the AI-native / frontier tooling Kali doesn't ship (the ProjectDiscovery
# Go suite, smart-contract analyzers, semgrep). It also satisfies scripts/check-tools-image.sh:
# radare2/gdb/objdump/upx + python {z3,sympy,pwn,fpylll,Crypto} + pip-audit.
#
# Build:   npm run tools:build           (== bash tools/build.sh)
# Verify:  npm run tools:check           (== scripts/check-tools-image.sh)
# Heavy (~minutes, multi-GB). Built on demand, not in CI.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1

# ── apt: reverse/crypto/pwn + web/recon + osint, plus build deps for the pip layer ──
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git unzip ruby-full build-essential pkg-config \
      python3 python3-pip python3-venv golang-go \
      # reverse / forensics / pwn  (check-tools-image.sh: radare2 gdb objdump upx)
      radare2 gdb binutils upx-ucl file binwalk foremost exiftool yara steghide xxd \
      # crypto
      john hashcat openssl \
      # web exploitation / recon (the ones Kali ships in apt)
      nmap nikto sqlmap gobuster ffuf feroxbuster hydra whois dnsutils \
      # fpylll/pwntools native build deps
      libgmp-dev libmpfr-dev libmpc-dev libfplll-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# ── pip: the RE/crypto/pwn python stack (check-tools-image.sh validates these) + SAST ──
# fpylll needs cysignals (+ cython) present at BUILD time, or `import fpylll` fails at runtime
# with ModuleNotFoundError: cysignals. Install them as a prior layer so fpylll links correctly.
RUN pip3 install --no-cache-dir cython cysignals
# Core stack MUST succeed — it backs the presence smoke test.
RUN pip3 install --no-cache-dir \
      z3-solver sympy pwntools fpylll pycryptodome requests \
      pip-audit semgrep
# Smart-contract analyzers share conflicting deps (web3/eth-* + a shared z3 pin) — a single
# `pip install slither-analyzer mythril` FAILS the resolver, and the old `|| echo WARN` swallowed it
# silently → both ended up MISSING. Fix: pipx gives each its OWN isolated venv (no cross-conflict),
# with binaries on PATH via PIPX_BIN_DIR. Install INDEPENDENTLY so slither (reliable) lands even if
# mythril (notoriously version-pinned) fails — and the layer stays tolerant (never aborts the image).
RUN pip3 install --no-cache-dir pipx \
 && export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin \
 && (pipx install slither-analyzer || echo "WARN: slither pipx install failed") \
 && (pipx install mythril          || echo "WARN: mythril pipx install failed")

# ── go: the "+" — ProjectDiscovery suite + dalfox (not in stock Kali apt) ──
RUN export GOBIN=/usr/local/bin && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest        && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest      && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest     && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest   && \
    go install github.com/hahwul/dalfox/v2@latest                        && \
    rm -rf /root/go/pkg /root/.cache/go-build

# ── npm + foundry: smart-contract "+" (solhint, forge/cast) ──
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && \
    npm install -g solhint && \
    rm -rf /var/lib/apt/lists/* /root/.npm
RUN curl -L https://foundry.paradigm.xyz | bash && /root/.foundry/bin/foundryup && \
    cp /root/.foundry/bin/forge /root/.foundry/bin/cast /root/.foundry/bin/anvil /usr/local/bin/ 2>/dev/null || \
    echo "foundry install skipped (offline build) — re-run foundryup later"

# nuclei templates (best-effort; the scan still runs without a fresh pull)
RUN nuclei -update-templates -silent || true

# ── SageMath (the crypto powerhouse: lattices/LLL, CRT, elliptic curves, poly rings) ──
# Kali apt has NO sagemath candidate; conda-forge does. Heavy (~2-3GB) but NO host/perms issue
# (fresh container, not /opt/homebrew). Best-effort: a resolver/emulation failure must NOT abort
# the image — the rest of the crypto stack (z3/sympy/fpylll) stays usable.
RUN curl -fsSL https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh -o /tmp/mf.sh \
 && bash /tmp/mf.sh -b -p /opt/conda && rm -f /tmp/mf.sh \
 && /opt/conda/bin/conda install -y -c conda-forge sage \
 && ln -sf /opt/conda/bin/sage /usr/local/bin/sage \
 && /opt/conda/bin/conda clean -afy \
 || echo "WARN: sage (conda-forge) install failed/skipped — crypto falls back to z3/sympy/fpylll"

RUN useradd --create-home --shell /bin/bash operator && mkdir -p /work && chown operator:operator /work

USER operator
WORKDIR /work
CMD ["bash"]
