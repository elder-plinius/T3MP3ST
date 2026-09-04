# Synthetic memory-forensics fixture provenance

- Origin: original T3MP3ST implementation for issue #194; no artifact or code was copied from proposal #163.
- License: AGPL-3.0-or-later, matching this repository.
- Format: `T3MP3ST-SYNTH-MEM-v1`, a compact training fixture rather than an operating-system memory capture.
- Generator: `generate.py` version 1.0.0 using only the Python 3 standard library.
- Tool version: generated and verified with Python 3.12.3 on Linux x86-64; the byte construction uses specified SHA-256, ASCII, UTF-16LE, fixed offsets, and little-endian integers and is platform-independent.
- Reproduction: `python3 ctf/challenges/artifacts/memory-forensics/generate.py`; the command deterministically replaces `memdump.raw`.
- Fixture SHA-256: `848ecc439d705d06866408fbd9b99760a6f3554c4ade75431de566a2821624b7`.
- Fixture size: 32768 bytes.
- Deterministic solution: `python3 ctf/challenges/artifacts/memory-forensics/solve.py` extracts the flag from the synthetic process environment allocation.
- Sensitive-data review: every user, process, password, flag, and memory byte is deterministically generated synthetic training data. The fixture contains no acquired memory, personal data, production secret, credential, token, endpoint, or host-derived value.
- Network and container review: analysis is fully offline. The challenge has no service, listening port, container, external dependency, or host mount.
- Teardown: no persistent runtime resources are created. The smoke test removes its temporary regenerated fixture automatically.

The committed raw fixture is reviewable through its complete generator and must
not be represented as a real Windows, LSASS, or Volatility-compatible capture.
