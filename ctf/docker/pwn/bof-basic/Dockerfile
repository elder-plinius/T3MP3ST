# T3MP3ST CTF Challenge: Buffer Overflow - ret2win
# Difficulty: Easy (1)
# Category: Binary Exploitation

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge

# Create vulnerable binary source
COPY vuln.c /challenge/
COPY flag.txt /challenge/

# Compile with vulnerabilities enabled
RUN gcc -o vuln vuln.c \
    -fno-stack-protector \
    -no-pie \
    -z execstack \
    -m64

# Set permissions
RUN chmod 755 /challenge/vuln && \
    chmod 444 /challenge/flag.txt

EXPOSE 9001

# Run with socat
CMD ["socat", "TCP-LISTEN:9001,reuseaddr,fork", "EXEC:/challenge/vuln"]
