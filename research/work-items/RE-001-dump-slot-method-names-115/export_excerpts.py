#!/usr/bin/env python3
"""Regenerate every disassembly excerpt in this packet, byte-for-byte.

Each excerpt is one whole function (FDE range from readelf
--debug-dump=frames-interp), emitted by
``objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-115.bin`` run from the repo root.  The objdump command
is recorded in the work-item README, and the excerpts are the raw
objdump text exactly as emitted: instruction mnemonics such as
``endbr64`` are genuine instructions present in the target binary,
not placeholders.

Four excerpts (dump, both helpers, host) are re-shipped byte-identical
from PR #4286's packet
(research/work-items/RE-001-options-dump-115/), with credit in the
README; they regenerate to the same bytes from the same binary.

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
    # The ColumnFamilyOptions header dump itself (re-shipped from #4286).
    ("dump-60b50c0.objdump.txt", 0x60B50C0, 0x60B79A6),
    # The leveled log helper the dump calls (re-shipped from #4286).
    ("helper-5fceda0.objdump.txt", 0x5FCEDA0, 0x5FCEE93),
    # The sibling no-level helper (re-shipped from #4286).
    ("helper-nolevel-5fceea0.objdump.txt", 0x5FCEEA0, 0x5FCEF5B),
    # The sole caller of the dump (re-shipped from #4286).
    ("host-5d954b0.objdump.txt", 0x5D954B0, 0x5D96890),
    # Logger slot functions (EnvLogger unless noted).
    ("logger-logheader-5fcc200.objdump.txt", 0x5FCC200, 0x5FCC218),
    ("logger-logv-levelled-5fcd400.objdump.txt", 0x5FCD400, 0x5FCD419),
    ("logger-logv-levelled-core-5fcd2c0.objdump.txt", 0x5FCD2C0, 0x5FCD3F5),
    ("logger-getinfologlevel-5fcc220.objdump.txt", 0x5FCC220, 0x5FCC229),
    ("logger-setinfologlevel-5fcc230.objdump.txt", 0x5FCC230, 0x5FCC239),
    ("logger-close-5fcc410.objdump.txt", 0x5FCC410, 0x5FCC473),
    ("logger-closeimpl-5fceae0.objdump.txt", 0x5FCEAE0, 0x5FCEB1F),
    ("logger-logv-5fce280.objdump.txt", 0x5FCE280, 0x5FCE766),
    ("autoroll-logheader-6057000.objdump.txt", 0x6057000, 0x60571B4),
    ("autoroll-getinfologlevel-60552e0.objdump.txt", 0x60552E0, 0x6055345),
    # TableFactory slot functions.
    ("factory-bbt-getprintable-60da1f0.objdump.txt", 0x60DA1F0, 0x60DAA91),
    ("factory-cuckoo-getprintable-615aca0.objdump.txt", 0x615ACA0, 0x615AEE1),
    ("factory-plain-getprintable-6192d70.objdump.txt", 0x6192D70, 0x6193183),
    ("factory-bbt-name-60b1d90.objdump.txt", 0x60B1D90, 0x60B1D9C),
    ("configurable-getoption-609d760.objdump.txt", 0x609D760, 0x609D954),
    # Cache slot functions.
    ("cache-base-getprintable-5d3f6c0.objdump.txt", 0x5D3F6C0, 0x5D3F6DB),
    ("cache-lru-getprintable-5d3f210.objdump.txt", 0x5D3F210, 0x5D3F4AD),
    ("cache-lru-name-5d3a950.objdump.txt", 0x5D3A950, 0x5D3A95C),
    ("cache-secondary-name-5d42bb0.objdump.txt", 0x5D42BB0, 0x5D42C5A),
    ("cache-secondary-getprintable-5d42460.objdump.txt", 0x5D42460, 0x5D425A9),
    ("cache-charged-name-5db68c0.objdump.txt", 0x5DB68C0, 0x5DB68CC),
    # TablePropertiesCollectorFactory slot functions.
    ("collector-tostring-base-60b1ea0.objdump.txt", 0x60B1EA0, 0x60B1F93),
    ("collector-compactondelete-tostring-61fb370.objdump.txt", 0x61FB370, 0x61FB74F),
    ("collector-compactondelete-name-61f9880.objdump.txt", 0x61F9880, 0x61F988C),
    ("collector-compactondelete-create-61fb010.objdump.txt", 0x61FB010, 0x61FB055),
    ("customizable-inner-5d2ca00.objdump.txt", 0x5D2CA00, 0x5D2CA07),
    ("customizable-nickname-5d2ca10.objdump.txt", 0x5D2CA10, 0x5D2CA1C),
]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        (HERE / "excerpts" / name).write_text(out)
        print(f"wrote excerpts/{name} ({start:#x}..{stop:#x})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
