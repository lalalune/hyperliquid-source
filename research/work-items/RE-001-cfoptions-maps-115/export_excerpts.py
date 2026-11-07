#!/usr/bin/env python3
"""Regenerate every disassembly excerpt in this packet, byte-for-byte.

Each excerpt is one whole function (FDE range from readelf
--debug-dump=frames-interp), emitted by
``objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-115.bin`` run from the repo root.  The nine excerpts
marked "reshipped" below were first exported for
RE-001-optiontypeinfo-maps-115 (#4237) and are regenerated here from
the same ranges, so they are byte-identical to the #4237 packet's
copies.  The fn-60ba600 / fn-60c18b0 / fn-60bfda0 / fn-60a47f0
excerpts of #4237 are NOT reshipped: no ColumnFamilyOptions-family
use of those functions was found.

Usage: python3 export_excerpts.py  (run from the repo root)
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = "work/hl-node-115.bin"

# (file name, start, stop) -- whole functions only.
EXCERPTS = [
    # The static initializer that builds all five maps.
    ("static-initializer-6089b50.objdump.txt", 0x6089B50, 0x6091E5C),
    # The .init_array[93] thunk that jumps to the initializer.
    ("thunk-6093030.objdump.txt", 0x6093030, 0x6093039),
    # The value builders used by the initializer.
    ("helper-pair-move-60842a0.objdump.txt", 0x60842A0, 0x608442E),
    ("helper-type22-6083a90.objdump.txt", 0x6083A90, 0x6083C83),
    ("helper-type19-5e32c70.objdump.txt", 0x5E32C70, 0x5E332BF),
    ("helper-nested-wrap-607f1b0.objdump.txt", 0x607F1B0, 0x607F37A),
    ("helper-factory-607ea10.objdump.txt", 0x607EA10, 0x607EB17),
    ("helper-vector-6083570.objdump.txt", 0x6083570, 0x6083A89),
    ("helper-enum18-6083c90.objdump.txt", 0x6083C90, 0x6083D74),
    ("helper-vector-6083d80.objdump.txt", 0x6083D80, 0x6084299),
    # Consumers: the six functions that reference the maps directly.
    ("consumer-section-matcher-607dd50.objdump.txt", 0x607DD50, 0x607DDAB),
    ("consumer-fifo-parser-607e560.objdump.txt", 0x607E560, 0x607E6E9),
    ("consumer-nested-bottommost-60833b0.objdump.txt", 0x60833B0, 0x6083484),
    ("consumer-nested-compression-6083490.objdump.txt", 0x6083490, 0x6083564),
    ("consumer-options-dump-6086e00.objdump.txt", 0x6086E00, 0x608818D),
    ("consumer-section-header-60c4550.objdump.txt", 0x60C4550, 0x60C46B8),
    # The shared per-section parser used by the FIFO / nested parsers.
    ("fn-60c1d50.objdump.txt", 0x60C1D50, 0x60C26D5),
    # Reshipped from #4237 (byte-identical, same ranges).
    ("pair-ctor-5d400f0.objdump.txt", 0x5D400F0, 0x5D40477),
    ("range-ctor-5d405b0.objdump.txt", 0x5D405B0, 0x5D40F32),
    ("record-dtor-5d3f950.objdump.txt", 0x5D3F950, 0x5D3F9D3),
    ("movefn-5e32b10.objdump.txt", 0x5E32B10, 0x5E32C65),
    ("movefn-5e332c0.objdump.txt", 0x5E332C0, 0x5E3354F),
    ("map-dtor-5d3f820.objdump.txt", 0x5D3F820, 0x5D3F94D),
    ("fn-60bedc0.objdump.txt", 0x60BEDC0, 0x60BF5BC),
    ("fn-60ba0b0.objdump.txt", 0x60BA0B0, 0x60BA441),
    ("fn-6099ce0.objdump.txt", 0x6099CE0, 0x6099E34),
]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        (HERE / name).write_text(out)
        print(f"wrote {name} ({start:#x}..{stop:#x})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
