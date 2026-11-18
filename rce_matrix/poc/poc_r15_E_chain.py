#!/usr/bin/env python3
"""Lane-E two-hop chain cell: hop 1 double-decodes, hop 2 splits and executes.

The matrix driver owns this shape (``multi_hop_chain`` in the two chain rows); this shim exists so
the lane name in those cells resolves to a runnable file. Requires a run folder argument.

    timeout 300 python3 poc_r15_E_chain.py ../stage-05__cpp__20261116T022714Z__1cfd33433d25__6baf167b
"""
import sys
from pathlib import Path

import row

if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    sys.argv = [sys.argv[0], sys.argv[1], "--only", "multi_hop_chain"]
    raise SystemExit(row.main())
