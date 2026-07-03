# Third-Party Notices

T3MP3ST's own source (`src/`, `scripts/`) is MIT-licensed — see [`LICENSE`](LICENSE).
The `bench/` benchmark corpora are **third-party fixtures used for local evaluation
only**: they are gitignored and **not distributed** with this package, retain their
original upstream licenses, and are fetched/staged on demand by the benchmark runners.

| Corpus | Used by | Source / License | Bundled here? |
|---|---|---|---|
| **Cybench** challenge corpus | `scripts/cybench-bench.mjs` | github.com/andyzorigin/cybench (per-challenge upstream licenses) | No — gitignored (`bench/cybench/challenges/`, `corpus-stage/`); staged locally |
| **XBOW / XBEN** validation benchmarks | `scripts/xbow-bench.mjs` | github.com/xbow-engineering/validation-benchmarks (MIT) | No — gitignored (`bench/xbow/stage/`); fetched per run |
| Bundled challenge app code (WordPress / PHP / Flask samples) | challenge containers | respective upstream projects | No — part of the staged challenge sources only |

The CTF/RE/crypto tooling installed into the sandbox image
([`bench/cybench/tools/Dockerfile`](bench/cybench/tools/Dockerfile)) — radare2, gdb,
pwntools, pycryptodome, sympy, z3-solver, fpylll, numpy/scipy, UPX, etc. — is installed
from upstream package repositories at image-build time under each package's own license;
none of it is vendored into this repository.

No third-party code is bundled into the published MIT core. If you believe an attribution
is missing or incorrect, please open an issue.
