#!/usr/bin/env python3
"""Export whole-function objdump excerpts for RE-001 id-configure-helpers-115.

Reads the pinned node #115 binary and emits one verbatim objdump file per
pinned function. Re-run to regenerate; verify.py diffs the output
byte-for-byte against a fresh objdump run. The 0x60c1190, 0x6099e70 and
0x6097110 excerpts are byte-identical to the ones shipped in #4320 (same
binary, same FDE ranges); they are regenerated here from the binary so the
packet is self-contained.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work" / "hl-node-115.bin"
# Pass objdump the repo-relative path so the header line reads
# "work/hl-node-115.bin: ..." (no absolute home-directory path), matching
# the excerpts shipped in #4320/#4328 byte-for-byte.
BIN_REL = "work/hl-node-115.bin"
OUT = Path(__file__).resolve().parent

# name -> (start, end) vaddrs; end is exclusive (FDE end)
FUNCTIONS = {
    "fn-609a410-id-configure-helper.objdump.txt": (0x609A410, 0x609A67C),
    "fn-6097150-configure-slot9-entry.objdump.txt": (0x6097150, 0x6097192),
    "fn-6097110-configure-slot9.objdump.txt": (0x6097110, 0x609714E),
    "fn-609d0e0-slot9.objdump.txt": (0x609D0E0, 0x609D75E),
    "fn-609a1b0-map-find.objdump.txt": (0x609A1B0, 0x609A2E7),
    "fn-609a2f0-map-erase.objdump.txt": (0x609A2F0, 0x609A3DE),
    "fn-5d5b300-map-clear.objdump.txt": (0x5D5B300, 0x5D5B39B),
    "fn-6098510-delimiter-prestep.objdump.txt": (0x6098510, 0x60985AF),
    "fn-609e2d0-nullchecked-slot9-entry.objdump.txt": (0x609E2D0, 0x609E3E2),
    "fn-60c1190-map-parse.objdump.txt": (0x60C1190, 0x60C1887),
    "fn-6099e70-set-equals.objdump.txt": (0x6099E70, 0x609A1A9),
    "fn-609c8c0-map-copy-apply.objdump.txt": (0x609C8C0, 0x609D08E),
    "fn-609bcb0-per-entry-apply.objdump.txt": (0x609BCB0, 0x609C782),
    "fn-61cf670-status-ctor.objdump.txt": (0x61CF670, 0x61CF767),
}


def main() -> int:
    for name, (start, end) in FUNCTIONS.items():
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={end:#x}", BIN_REL],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        (OUT / name).write_text(out.stdout)
        print(f"{name}: {start:#x}..{end:#x} ({len(out.stdout.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
