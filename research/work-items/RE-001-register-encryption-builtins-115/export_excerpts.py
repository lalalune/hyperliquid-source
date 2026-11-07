"""Export the whole-function objdump excerpts for the
RE-001-register-encryption-builtins-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-register-encryption-builtins-115/export_excerpts.py

Writes one verbatim objdump file per pinned routine into excerpts/.
The binary path is relative (work/hl-node-115.bin) so the objdump
header line is stable across runs.
"""

import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = "work/hl-node-115.bin"

WINDOWS = [
    ("host-5ff88c0.objdump.txt", 0x5FF88C0, 0x5FF9C50),
    ("host-cold-5ff844a.objdump.txt", 0x5FF844A, 0x5FF88B7),
    ("thunk-5ff9c50.objdump.txt", 0x5FF9C50, 0x5FF9C59),
    ("string-ctor-5ff0300.objdump.txt", 0x5FF0300, 0x5FF03E3),
    ("string-range-5fefd80.objdump.txt", 0x5FEFD80, 0x5FEFE23),
    ("vec-grow-5ff7420.objdump.txt", 0x5FF7420, 0x5FF7811),
    ("register-5ff8260.objdump.txt", 0x5FF8260, 0x5FF8449),
    ("mgr-e_-5fefa50.objdump.txt", 0x5FEFA50, 0x5FEFA7D),
    ("mgr-e0-5fefa80.objdump.txt", 0x5FEFA80, 0x5FEFAAD),
    ("mgr-cipher-5fefab0.objdump.txt", 0x5FEFAB0, 0x5FEFADD),
    ("invoke-e0-5ff6a00.objdump.txt", 0x5FF6A00, 0x5FF6C70),
    ("invoke-e_-5ff6d60.objdump.txt", 0x5FF6D60, 0x5FF70A7),
    ("invoke-cipher-5ff7120.objdump.txt", 0x5FF7120, 0x5FF7419),
    ("fe-enc-d2-5fefbc0.objdump.txt", 0x5FEFBC0, 0x5FEFC02),
    ("fe-enc-d0-5ff0060.objdump.txt", 0x5FF0060, 0x5FF00AA),
    ("fe-enc-matches-5fefca0.objdump.txt", 0x5FEFCA0, 0x5FEFCAE),
    ("fe-enc-accessor-5fefcb0.objdump.txt", 0x5FEFCB0, 0x5FEFCBE),
    ("fe-cipher-d2-5fefb70.objdump.txt", 0x5FEFB70, 0x5FEFBB2),
    ("fe-cipher-d0-5ff0010.objdump.txt", 0x5FF0010, 0x5FF005A),
    ("fe-cipher-matches-5fefc80.objdump.txt", 0x5FEFC80, 0x5FEFC8E),
    ("fe-cipher-accessor-5fefc90.objdump.txt", 0x5FEFC90, 0x5FEFC9E),
    ("libcb-dispose-5ff7900.objdump.txt", 0x5FF7900, 0x5FF7952),
    ("endswith-61d1390.objdump.txt", 0x61D1390, 0x61D13DB),
    ("cipher-jmp-61d1ef0.objdump.txt", 0x61D1EF0, 0x61D1EF9),
    ("once-a-5ffa710.objdump.txt", 0x5FFA710, 0x5FFAAD9),
    ("once-b-5ffba10.objdump.txt", 0x5FFBA10, 0x5FFBDD9),
]


def dump(name, start, stop):
    out = subprocess.run(
        [
            "objdump", "-d",
            "--start-address=%#x" % start,
            "--stop-address=%#x" % stop,
            BINARY,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    (PACKET / "excerpts" / name).write_text(out)
    return out


def main():
    (PACKET / "excerpts").mkdir(parents=True, exist_ok=True)
    for name, start, stop in WINDOWS:
        dump(name, start, stop)
        print("wrote", name, hex(start), "..", hex(stop))


if __name__ == "__main__":
    main()
