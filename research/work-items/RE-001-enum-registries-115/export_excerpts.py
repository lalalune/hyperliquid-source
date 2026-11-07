#!/usr/bin/env python3
"""Regenerate every disassembly excerpt in this packet, byte-for-byte.

Each excerpt is one whole function (FDE range from readelf
--debug-dump=frames-interp), emitted by
``objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-115.bin`` run from the repo root.  Three excerpts are
re-shipped byte-identical from RE-001-optiontypeinfo-maps-115 (#4237):
the static initializer 0x60c78a0 (which builds the registries), the
per-entry apply function 0x60bedc0 (whose parse cases call the seven
parse helpers) and the serialize dispatch 0x60ba600 (whose cases do the
linear reverse scan); they are regenerated here from the same ranges,
so they are byte-identical to the #4237 packet's copies.

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
    # The static initializer that builds all twelve registries
    # (re-shipped from #4237) and its .init_array thunk.
    ("static-initializer-60c78a0.objdump.txt", 0x60C78A0, 0x60C870D),
    ("init-thunk-60c8710.objdump.txt", 0x60C8710, 0x60C8719),
    # The four std::map<unsigned char, std::string> range builders
    # (value -> name), one per enum with a reverse map.
    ("builder-map-60bd6e0.objdump.txt", 0x60BD6E0, 0x60BD97E),
    ("builder-map-60bd980.objdump.txt", 0x60BD980, 0x60BDC1E),
    ("builder-map-60bdc20.objdump.txt", 0x60BDC20, 0x60BDEBE),
    ("builder-map-60bdec0.objdump.txt", 0x60BDEC0, 0x60BE15E),
    # The eight std::unordered_map<std::string, unsigned char> range
    # builders (name -> value), one per enum with a forward map.
    ("builder-unordered-60c4950.objdump.txt", 0x60C4950, 0x60C4D52),
    ("builder-unordered-60c4ea0.objdump.txt", 0x60C4EA0, 0x60C52A2),
    ("builder-unordered-60c53f0.objdump.txt", 0x60C53F0, 0x60C57F2),
    ("builder-unordered-60c5940.objdump.txt", 0x60C5940, 0x60C5D42),
    ("builder-unordered-60c5e90.objdump.txt", 0x60C5E90, 0x60C6324),
    ("builder-unordered-60c6470.objdump.txt", 0x60C6470, 0x60C6872),
    ("builder-unordered-60c69c0.objdump.txt", 0x60C69C0, 0x60C6DC2),
    ("builder-unordered-60c6f10.objdump.txt", 0x60C6F10, 0x60C73B2),
    # The seven name -> value parse helpers, one per OptionType
    # named-enum type (11-16, 24).
    ("parse-60be160.objdump.txt", 0x60BE160, 0x60BE2AB),
    ("parse-60be2b0.objdump.txt", 0x60BE2B0, 0x60BE3FB),
    ("parse-60be400.objdump.txt", 0x60BE400, 0x60BE54B),
    ("parse-60be550.objdump.txt", 0x60BE550, 0x60BE69B),
    ("parse-60be6a0.objdump.txt", 0x60BE6A0, 0x60BE7EB),
    ("parse-60be7f0.objdump.txt", 0x60BE7F0, 0x60BE93B),
    ("parse-60be940.objdump.txt", 0x60BE940, 0x60BEA8B),
    # The dispatch functions that call the parse helpers and do the
    # reverse scan (re-shipped from #4237).
    ("fn-60bedc0.objdump.txt", 0x60BEDC0, 0x60BF5BC),
    ("fn-60ba600.objdump.txt", 0x60BA600, 0x60BB855),
    # Direct consumers: the value -> name serializer over the three
    # Compaction* maps, the CompressionType filter that lists the
    # usable compressions, and the ChecksumType value -> name
    # serializer.
    ("consumer-serialize-60b50c0.objdump.txt", 0x60B50C0, 0x60B79A6),
    ("consumer-compression-filter-5d85480.objdump.txt", 0x5D85480, 0x5D878E2),
    ("consumer-checksum-serialize-60d8b10.objdump.txt", 0x60D8B10, 0x60DA1A7),
]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d",
             f"--start-address=0x{start:x}",
             f"--stop-address=0x{stop:x}", BIN],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        (HERE / name).write_text(out)
        print(f"wrote {name} (0x{start:x}..0x{stop:x})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
