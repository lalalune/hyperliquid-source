#!/usr/bin/env python3
"""Export whole-function verbatim objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-emulated-clock-options-115/export_excerpts.py

Writes one file per pinned FDE, named fn-<start>.txt, containing the
complete objdump disassembly of that FDE (plus the 9-byte .init_array
jump stub, which is its own FDE).
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

# (start, end) FDE ranges; the file is named after the start address.
EXCERPTS = [
    (0x6029D10, 0x602A25D),   # static option-map initializer
    (0x602E4C0, 0x602E4C9),   # .init_array jump stub
    (0x6025E50, 0x6025EA5),   # time_elapse_only_sleep getter
    (0x6026100, 0x6026155),   # mock_sleep getter
    (0x6026BA0, 0x6026C4B),   # time_elapse_only_sleep setter
    (0x6026AD0, 0x6026B77),   # mock_sleep setter
    (0x6025820, 0x602584D),   # time_elapse setter manager
    (0x6025850, 0x602587D),   # time_elapse getter manager
    (0x6025880, 0x60258AD),   # mock_sleep setter manager
    (0x60258B0, 0x60258DD),   # mock_sleep getter manager
    (0x6025B40, 0x6025B7F),   # SleepForMicroseconds (slot 23)
    (0x6025EB0, 0x6025FEB),   # GetCurrentTime (slot 24)
    (0x61D1480, 0x61D1504),   # bool parser
]


def disassemble(start: int, end: int) -> str:
    raw = BIN.read_bytes()[start - 0x1000:end - 0x1000]
    tmp = HERE / ".excerpt-tmp.bin"
    tmp.write_bytes(raw)
    try:
        out = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
             f"--adjust-vma={start:#x}", str(tmp)],
            capture_output=True, text=True, check=True).stdout
    finally:
        tmp.unlink(missing_ok=True)
    lines = out.splitlines()
    # Drop the objdump header (blank line, filename, blank line,
    # "Disassembly of section .data:", blank line).
    while lines and not lines[0].startswith("000000000"):
        lines.pop(0)
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    for start, end in EXCERPTS:
        path = HERE / f"fn-{start:x}.txt"
        path.write_text(disassemble(start, end))
        print(f"wrote {path.name} ({end - start:#x} bytes)")


if __name__ == "__main__":
    main()
