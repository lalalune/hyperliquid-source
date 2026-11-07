#!/usr/bin/env python3
"""Export verbatim whole-function objdump excerpts for the
RE-001-thread-local-dtor-registration-115 work item.

Each window is one FDE (extents from tools/fde_extents.py) dumped with a
single objdump invocation; the output is stored verbatim, header included,
so verify.py can regenerate it byte-for-byte. No instruction is edited,
reordered or paraphrased anywhere in this packet: instruction-level detail
lives only in these excerpts, and records.json carries semantic records.

Usage: python3 export_excerpts.py [--bin PATH] [--out DIR]
"""
import argparse
import subprocess
import sys
from pathlib import Path

BIN = Path(__file__).resolve().parents[3] / "work" / "hl-node-115.bin"
OUT = Path(__file__).resolve().parent / "excerpts"

# (file stem, start, end) — ends are FDE ends, exclusive.
WINDOWS = [
    ("register_dtor", 0x5CA0D20, 0x5CA0E1F),
    ("key_enable", 0x5CA0E20, 0x5CA0EEA),
    ("dtor_runner", 0x5CA53F0, 0x5CA5510),
    ("guard_alloc", 0x5C9D1F0, 0x5C9D323),
    ("guard_use", 0x5CA44A0, 0x5CA469D),
    ("guard_free", 0x5C98B40, 0x5C98B89),
    ("grow_one", 0x5C8B620, 0x5C8B649),
    # The 28 registered destructors, one FDE each (callers.tsv dtor set).
    ("dtor_0x15b6ca0", 0x15B6CA0, 0x15B6CBE),
    ("dtor_0x15b6cc0", 0x15B6CC0, 0x15B6D07),
    ("dtor_0x1619fe0", 0x1619FE0, 0x161A010),
    ("dtor_0x16293a0", 0x16293A0, 0x1629418),
    ("dtor_0x16f0f10", 0x16F0F10, 0x16F0F57),
    ("dtor_0x26a0570", 0x26A0570, 0x26A05CA),
    ("dtor_0x26a05d0", 0x26A05D0, 0x26A05EE),
    ("dtor_0x26a05f0", 0x26A05F0, 0x26A0637),
    ("dtor_0x2e941a0", 0x2E941A0, 0x2E941E7),
    ("dtor_0x3f11060", 0x3F11060, 0x3F110BA),
    ("dtor_0x3f110c0", 0x3F110C0, 0x3F11107),
    ("dtor_0x4752f70", 0x4752F70, 0x4752FDE),
    ("dtor_0x4752fe0", 0x4752FE0, 0x4753005),
    ("dtor_0x4780330", 0x4780330, 0x478034E),
    ("dtor_0x4e390e0", 0x4E390E0, 0x4E3913A),
    ("dtor_0x4e39140", 0x4E39140, 0x4E39187),
    ("dtor_0x4e39190", 0x4E39190, 0x4E391AE),
    ("dtor_0x5bb5200", 0x5BB5200, 0x5BB5218),
    ("dtor_0x5bb9630", 0x5BB9630, 0x5BB964B),
    ("dtor_0x5bc1830", 0x5BC1830, 0x5BC188A),
    ("dtor_0x5c7f7d0", 0x5C7F7D0, 0x5C7F7E9),
    ("dtor_0x5c7f7f0", 0x5C7F7F0, 0x5C7F84D),
    ("dtor_0x5ccc7e0", 0x5CCC7E0, 0x5CCC83A),
    ("dtor_0x5cd8510", 0x5CD8510, 0x5CD8531),
    ("dtor_0x5cdf3e0", 0x5CDF3E0, 0x5CDF40B),
    ("dtor_0x5cdf410", 0x5CDF410, 0x5CDF457),
    ("dtor_0x5cffca0", 0x5CFFCA0, 0x5CFFCD7),
    ("dtor_0x5d00840", 0x5D00840, 0x5D00877),
    # Two representative registering callers (full FDEs).
    ("caller_0x5c908b0", 0x5C908B0, 0x5C90B47),
    ("caller_0x5c9b500", 0x5C9B500, 0x5C9B5C4),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", type=Path, default=BIN)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, start, end in WINDOWS:
        cmd = ["objdump", "-d", f"--start-address=0x{start:x}",
               f"--stop-address=0x{end:x}", str(args.bin)]
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        # objdump prints a trailing blank line after the last instruction;
        # keep the output exactly as emitted.
        (args.out / f"{name}.txt").write_text(out)
        print(f"{name}: 0x{start:x}..0x{end:x} ({end - start} bytes)")
    print(f"wrote {len(WINDOWS)} excerpts to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
