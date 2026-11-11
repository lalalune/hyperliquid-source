#!/usr/bin/env python3
"""Regenerate the whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-chrootfs-group-115/export_excerpts.py
Uses the repo-relative binary path so excerpt headers carry no absolute
home-directory path. The host excerpt (0x5feeab0) was first used by the
RE-002 vtable packet (RE-002-node115-rocksdb-fs-chroot-vtable) for the
vtable store only; the initializer and creator excerpts are new here.
All three are regenerated here and must match fresh objdump
byte-for-byte.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

FUNCS = {
    "fn-5feeab0-chroot-filesystem-ctor.objdump.txt": (0x5FEEAB0, 0x5FEEC0D),
    "fn-5fef080-static-initializer.objdump.txt": (0x5FEF080, 0x5FEF25F),
    "fn-5fe7870-chroot-creator-invoke.objdump.txt": (0x5FE7870, 0x5FE79AB),
}


def main() -> None:
    for name, (start, stop) in FUNCS.items():
        out = subprocess.check_output(
            ["objdump", "-d",
             f"--start-address={start:#x}", f"--stop-address={stop:#x}",
             "artifacts/node/115/hl-node"],
            cwd=ROOT, text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
        (HERE / name).write_text(out)
        print(f"wrote {name} ({start:#x}..{stop:#x})")


if __name__ == "__main__":
    main()
