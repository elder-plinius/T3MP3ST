# T3MP3ST CTF — Attacker / tooling sidecar
#
# A Kali-based box that carries the offensive tooling (metasploit, hydra, nmap, …) so you can
# attack the CTF challenge containers entirely inside Docker — nothing installed on the host.
# It sits on `ctf-network`, so it reaches every challenge by its service name (e.g. `sqli-basic`,
# `bof-basic:9001`, `ssrf-metadata`).
#
# Use:
#   docker compose up -d attacker
#   docker exec -it ctf_attacker bash
#   # then, inside:
#   nmap sqli-basic
#   hydra -l admin -P /usr/share/wordlists/rockyou.txt sqli-basic http-post-form "..."
#   msfconsole -q            # (run `msfdb init` once if you want the DB-backed workspace)
#
# NOTE: metasploit-framework is a large package — the first build pulls ~2GB. That is expected.

FROM kalilinux/kali-rolling

# Non-interactive apt; keep the image lean-ish but complete for CTF post-ex / credential work.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        metasploit-framework \
        hydra \
        nmap \
        netcat-traditional \
        curl \
        wget \
        iproute2 \
        iputils-ping \
        dnsutils \
        python3 \
        python3-pip \
        mimikatz \
        creddump7 \
        rubeus \
        xsser \
        seclists \
        wordlists \
        git \
        vim \
    && rm -rf /var/lib/apt/lists/*

# rockyou ships gzipped in kali — unpack it so hydra/john can use it straight away.
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then gunzip -k /usr/share/wordlists/rockyou.txt.gz; fi

WORKDIR /root

# Keep the container alive so you can `docker exec` into it on demand.
CMD ["sleep", "infinity"]
