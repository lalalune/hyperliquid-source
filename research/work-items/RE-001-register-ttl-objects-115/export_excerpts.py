"""Export the whole-function objdump excerpts for the
RE-001-register-ttl-objects-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-register-ttl-objects-115/export_excerpts.py

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
    ("trigger-6205d20.objdump.txt", 0x6205D20, 0x6205E08),
    ("once-6202da0.objdump.txt", 0x6202DA0, 0x6202E78),
    ("register-62069f0.objdump.txt", 0x62069F0, 0x6206D29),
    ("regmgr-6201000.objdump.txt", 0x6201000, 0x6201035),
    ("reginvoke-6200a30.objdump.txt", 0x6200A30, 0x6200A3F),
    ("creator-6208290.objdump.txt", 0x6208290, 0x6208AFA),
    ("creator-cold-62080a4.objdump.txt", 0x62080A4, 0x620828D),
    ("mgr-mo-62009a0.objdump.txt", 0x62009A0, 0x62009CD),
    ("mgr-cff-62009d0.objdump.txt", 0x62009D0, 0x62009FD),
    ("mgr-cf-6200a00.objdump.txt", 0x6200A00, 0x6200A2D),
    ("invoke-mo-62056b0.objdump.txt", 0x62056B0, 0x620573D),
    ("invoke-mo-cold-620566b.objdump.txt", 0x620566B, 0x62056A4),
    ("invoke-cff-6205c60.objdump.txt", 0x6205C60, 0x6205CEF),
    ("invoke-cf-6202ca0.objdump.txt", 0x6202CA0, 0x6202D1A),
    ("invoke-cf-cold-6202c60.objdump.txt", 0x6202C60, 0x6202C99),
    ("ctor-mo-6205560.objdump.txt", 0x6205560, 0x620566B),
    ("ctor-cff-6205790.objdump.txt", 0x6205790, 0x62058F7),
    ("ctor-cff-cold-620573e.objdump.txt", 0x620573E, 0x6205788),
    ("ctor-cf-6202a10.objdump.txt", 0x6202A10, 0x6202B50),
    ("ctor-cf-cold-6202976.objdump.txt", 0x6202976, 0x6202A0A),
    ("string-build-6201040.objdump.txt", 0x6201040, 0x62010E3),
    ("string-assign-62010f0.objdump.txt", 0x62010F0, 0x62011D3),
    ("fe-mo-d2-61f06f0.objdump.txt", 0x61F06F0, 0x61F0732),
    ("fe-mo-d0-61f0990.objdump.txt", 0x61F0990, 0x61F09DA),
    ("fe-mo-matches-61f0770.objdump.txt", 0x61F0770, 0x61F077E),
    ("fe-mo-accessor-61f0780.objdump.txt", 0x61F0780, 0x61F078E),
    ("fe-cff-d2-6200a60.objdump.txt", 0x6200A60, 0x6200AA2),
    ("fe-cff-d0-6201240.objdump.txt", 0x6201240, 0x620128A),
    ("fe-cff-matches-6200b10.objdump.txt", 0x6200B10, 0x6200B1E),
    ("fe-cff-accessor-6200b20.objdump.txt", 0x6200B20, 0x6200B2E),
    ("fe-cf-d2-61e7cf0.objdump.txt", 0x61E7CF0, 0x61E7D32),
    ("fe-cf-d0-61e7e00.objdump.txt", 0x61E7E00, 0x61E7E4A),
    ("fe-cf-matches-61e7d70.objdump.txt", 0x61E7D70, 0x61E7D7E),
    ("fe-cf-accessor-61e7d80.objdump.txt", 0x61E7D80, 0x61E7D8E),
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
