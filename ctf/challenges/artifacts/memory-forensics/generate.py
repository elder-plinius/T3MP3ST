#!/usr/bin/env python3
"""Generate the deterministic T3MP3ST synthetic memory-forensics fixture."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


FORMAT_VERSION = "T3MP3ST-SYNTH-MEM-v1"
GENERATOR_VERSION = "1.0.0"
FIXTURE_SIZE = 32768
DEFAULT_OUTPUT = Path(__file__).with_name("memdump.raw")


def deterministic_noise(size: int) -> bytearray:
    fixture = bytearray()
    counter = 0
    while len(fixture) < size:
        fixture.extend(
            hashlib.sha256(
                b"T3MP3ST synthetic memory fixture v1\0"
                + counter.to_bytes(4, "little")
            ).digest()
        )
        counter += 1
    return fixture[:size]


def write_record(fixture: bytearray, offset: int, value: str) -> None:
    encoded = (value + "\0").encode("utf-16le")
    fixture[offset : offset + len(encoded)] = encoded


def build_fixture() -> bytes:
    fixture = deterministic_noise(FIXTURE_SIZE)
    header = (
        f"{FORMAT_VERSION}\n"
        "SYNTHETIC TRAINING DATA - NOT A CAPTURED MEMORY IMAGE\n"
        f"size={FIXTURE_SIZE}\n"
    ).encode("ascii")
    fixture[: len(header)] = header

    # Fixed offsets model recoverable process and environment allocations while
    # keeping the fixture small, portable, and byte-for-byte reproducible.
    records = {
        0x1000: "PROCESS pid=4242 image=synthetic-auth.exe",
        0x1200: "USER=T3MP3ST-LAB\\synthetic_analyst",
        0x1400: "PASSWORD=not-a-real-password",
        0x1800: "ENVIRONMENT pid=4242 image=synthetic-auth.exe",
        0x1A00: "CTF_FLAG=T3MP3ST{synthetic_memory_credentials}",
        0x2200: "PROCESS pid=7331 image=synthetic-decoy.exe",
        0x2400: "USER=T3MP3ST-LAB\\decoy_user",
        0x2600: "PASSWORD=synthetic-decoy-only",
    }
    for offset, value in records.items():
        write_record(fixture, offset, value)
    return bytes(fixture)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--version", action="version", version=GENERATOR_VERSION)
    args = parser.parse_args()
    args.output.write_bytes(build_fixture())
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(f"{args.output}: {FIXTURE_SIZE} bytes sha256={digest}")


if __name__ == "__main__":
    main()
