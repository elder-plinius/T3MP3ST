# Rebuild required before live RE/crypto runs: pip-audit added; verify with scripts/check-tools-image.sh.
# CTF-tools agent sandbox for cybench standalone (file-based) challenges.
# The agent's bash runs IN here (linux/amd64) instead of the tool-less macOS
# host — so reversing (upx/gdb/objdump) and crypto (pwntools/pycryptodome) work
# and linux/amd64 ELF binaries actually execute. Only the per-challenge
# task_files are mounted (at /work); the host corpus / answer keys are never
# visible, so the container boundary enforces the integrity jail for free.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive PIP_BREAK_SYSTEM_PACKAGES=1

# Core toolchain — must succeed.
RUN apt-get update && apt-get install -y --no-install-recommends \
      binutils gdb file xxd bsdmainutils ltrace strace \
      unzip zip p7zip-full git curl wget ca-certificates xz-utils netcat-openbsd \
      python3 python3-pip python3-dev gcc make \
      libgmp-dev libmpfr-dev libmpc-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# UPX via official static binary (the Debian pkg moved components; the release
# tarball is arch-correct and reliable) — packedaway et al. need `upx -d`.
RUN curl -fsSL https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-amd64_linux.tar.xz -o /tmp/upx.tar.xz \
 && tar -xJf /tmp/upx.tar.xz -C /tmp \
 && cp /tmp/upx-4.2.4-amd64_linux/upx /usr/local/bin/upx && chmod +x /usr/local/bin/upx \
 && rm -rf /tmp/upx*

# Extra RE tooling — best-effort (component/arch availability varies).
RUN apt-get update && (apt-get install -y --no-install-recommends radare2 foremost steghide || true) \
 && rm -rf /var/lib/apt/lists/*

# pip-audit — promised in the agent's TOOLS_SYSTEM prompt (audits requirements.txt
# against the public vuln DB). Best-effort so a transient PyPI failure won't break
# the image build.
RUN pip3 install --no-cache-dir pip-audit || true

# Crypto/pwn libs — pwntools+pycryptodome must succeed; heavy solvers best-effort.
RUN pip3 install --no-cache-dir pwntools pycryptodome requests \
 && pip3 install --no-cache-dir sympy gmpy2 z3-solver || true

# CRYPTO COMPUTER-ALGEBRA — the system prompt promises fpylll/numpy/scipy; make
# it TRUE. The #1 root cause of crypto misses: the model reaches for lattice
# attacks (LLL/BKZ/Coppersmith/hidden-number — noisy_crc alone names them 100+
# times) and they error out because fpylll isn't installed. fpylll = the lattice
# engine; numpy/scipy = linear algebra. (flatter/Sage are heavier — added best-
# effort below; fpylll covers the bulk of CTF lattice work on its own.)
RUN apt-get update && apt-get install -y --no-install-recommends libfplll-dev libqd-dev pkg-config cmake g++ \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir numpy scipy \
 && pip3 install --no-cache-dir Cython cysignals \
 && pip3 install --no-cache-dir fpylll \
 && python3 -c "from fpylll import LLL, BKZ, IntegerMatrix; print('fpylll OK')"

# SageMath — gold standard for algebraic crypto, but ~GB and slow to install,
# so it's intentionally OMITTED from the core image (fpylll covers the bulk of
# CTF lattice work). Add it out-of-band if a challenge truly needs Groebner/EC:
#   docker build with --build-arg WANT_SAGE=1 (layer kept separate on purpose).
# Deferred SageMath layer: default WANT_SAGE=0 is a pure no-op (base image stays
# byte-identical to today); pass --build-arg WANT_SAGE=1 to actually install it.
ARG WANT_SAGE=0
RUN if [ "$WANT_SAGE" = "1" ]; then apt-get update && apt-get install -y --no-install-recommends sagemath && rm -rf /var/lib/apt/lists/*; fi

WORKDIR /work
CMD ["sleep", "infinity"]
