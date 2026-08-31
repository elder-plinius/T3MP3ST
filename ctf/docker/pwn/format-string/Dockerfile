# T3MP3ST CTF Challenge: Format String - Arbitrary Read/Write
# Difficulty: Medium (2)
# Category: Binary Exploitation

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge

# Create vulnerable binary source
COPY vuln.c /challenge/

# Compile: NX enabled (default), no PIE, no stack canary, partial RELRO.
RUN gcc -o vuln vuln.c \
    -fno-stack-protector \
    -no-pie \
    -m64

ENV CTF_FLAG=T3MP3ST{f0rm4t_str1ng_g0t_wr1t3}

# Flag file for consistency with the manifest
RUN echo "$CTF_FLAG" > /challenge/flag.txt && \
    chmod 755 /challenge/vuln && \
    chmod 444 /challenge/flag.txt

EXPOSE 9002

# Run with socat
CMD ["socat", "TCP-LISTEN:9002,reuseaddr,fork", "EXEC:/challenge/vuln"]
