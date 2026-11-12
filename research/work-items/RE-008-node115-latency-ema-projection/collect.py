#!/usr/bin/env python3
"""Regenerate instructions.tsv for the node #115 latency-EMA projection packet.

Static only: reads bytes from the pinned artifact and decodes them with
Capstone 5.0.7. The target is never loaded, executed or emulated. verify.py
re-checks every emitted row against the artifact without Capstone.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOWS = (
    ("row-closure", 0x5A327A0, 0x5A329D8),
    ("collector", 0x5B80EA0, 0x5B810CE),
    ("sort-build", 0x4D55B50, 0x4D55CB2),
    ("entry", 0x5A71D90, 0x5A71E1D),
)

sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    import capstone

    if capstone.__version__ != "5.0.7":
        raise SystemExit(f"Capstone 5.0.7 required, found {capstone.__version__}")
    data = TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise SystemExit("node #115 digest mismatch")
    sections, _ = unwind_index(data)
    text = next(section for section in sections if section["name"] == ".text")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines = ["role\tfde_start\tfde_end\tva\tbytes\tcapstone_intel"]
    for role, start, end in WINDOWS:
        offset = text["offset"] + start - text["address"]
        cursor = start
        for insn in decoder.disasm(data[offset:offset + end - start], start):
            if insn.address != cursor:
                raise SystemExit(f"decode gap at {cursor:#x}")
            cursor += insn.size
            rendered = f"{insn.mnemonic} {insn.op_str}".strip()
            lines.append(f"{role}\t{start:#x}\t{end:#x}\t{insn.address:#x}\t{insn.bytes.hex()}\t{rendered}")
        if cursor != end:
            raise SystemExit(f"decode stopped at {cursor:#x}, expected {end:#x}")
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
