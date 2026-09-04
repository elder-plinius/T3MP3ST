#!/usr/bin/env python3
"""Extract the synthetic credential flag from the offline memory fixture."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


DEFAULT_FIXTURE = Path(__file__).with_name("memdump.raw")
MAGIC = b"T3MP3ST-SYNTH-MEM-v1\n"


def solve(path: Path) -> str:
    memory = path.read_bytes()
    if not memory.startswith(MAGIC):
        raise ValueError("unsupported memory fixture format")

    decoded = memory.decode("utf-16le", errors="ignore")
    process = "PROCESS pid=4242 image=synthetic-auth.exe"
    environment = "ENVIRONMENT pid=4242 image=synthetic-auth.exe"
    if process not in decoded or environment not in decoded:
        raise ValueError("synthetic authentication process records are missing")

    match = re.search(r"CTF_FLAG=(T3MP3ST\{[A-Za-z0-9_]+\})", decoded)
    if not match:
        raise ValueError("credential flag was not recovered")
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", nargs="?", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()
    print(solve(args.fixture))


if __name__ == "__main__":
    main()
