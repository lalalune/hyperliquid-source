"""Export the whole-function objdump excerpts for the
RE-001-ttl-runtime-methods-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-ttl-runtime-methods-115/export_excerpts.py

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
    ("mo-d2-6203b80.objdump.txt", 0x6203B80, 0x6203C25),
    ("mo-d0-6203c30.objdump.txt", 0x6203C30, 0x6203CD3),
    ("mo-prepare-6200b70.objdump.txt", 0x6200B70, 0x6200BE1),
    ("mo-validate-6200e10.objdump.txt", 0x6200E10, 0x6200ED8),
    ("mo-name-6200930.objdump.txt", 0x6200930, 0x620093C),
    ("mo-isinstanceof-6202520.objdump.txt", 0x6202520, 0x62025F9),
    ("mo-slot17-6200940.objdump.txt", 0x6200940, 0x6200949),
    ("mo-fullmergev2-6206610.objdump.txt", 0x6206610, 0x6206923),
    ("mo-fullmergev2-cold-62065e6.objdump.txt", 0x62065E6, 0x620660E),
    ("mo-partialmerge-multi-6201c90.objdump.txt", 0x6201C90, 0x62022B1),
    ("mo-partialmerge-multi-cold-6201b74.objdump.txt", 0x6201B74, 0x6201C81),
    ("cf-d2-62018f0.objdump.txt", 0x62018F0, 0x6201995),
    ("cf-d0-62019a0.objdump.txt", 0x62019A0, 0x6201A43),
    ("cf-prepare-6200bf0.objdump.txt", 0x6200BF0, 0x6200C61),
    ("cf-validate-6200cf0.objdump.txt", 0x6200CF0, 0x6200D7F),
    ("cf-name-6200900.objdump.txt", 0x6200900, 0x620090C),
    ("cf-isinstanceof-6202440.objdump.txt", 0x6202440, 0x6202519),
    ("cf-slot17-62008e0.objdump.txt", 0x62008E0, 0x62008E9),
    ("cf-filter-6203520.objdump.txt", 0x6203520, 0x6203627),
    ("cf-expiry-6203400.objdump.txt", 0x6203400, 0x6203513),
    ("cf-filterv2-5d2e4a0.objdump.txt", 0x5D2E4A0, 0x5D2E53D),
    ("cf-filterv3-5d2f8a0.objdump.txt", 0x5D2F8A0, 0x5D2F999),
    ("cff-d2-6203ad0.objdump.txt", 0x6203AD0, 0x6203B75),
    ("cff-d0-6203ce0.objdump.txt", 0x6203CE0, 0x6203D83),
    ("cff-prepare-6200c70.objdump.txt", 0x6200C70, 0x6200CE1),
    ("cff-validate-6200d80.objdump.txt", 0x6200D80, 0x6200E0F),
    ("cff-name-6200910.objdump.txt", 0x6200910, 0x620091C),
    ("cff-slot17-6200920.objdump.txt", 0x6200920, 0x6200929),
    ("cff-slot19-5d2ca70.objdump.txt", 0x5D2CA70, 0x5D2CA7B),
    ("cff-create-6202ba0.objdump.txt", 0x6202BA0, 0x6202C60),
    ("cff-create-cold-6202b50.objdump.txt", 0x6202B50, 0x6202B9A),
    ("shared-empty-string-5d2ca10.objdump.txt", 0x5D2CA10, 0x5D2CA1C),
    ("shared-null-5d2ca00.objdump.txt", 0x5D2CA00, 0x5D2CA07),
    ("shared-ret0-5d2cd80.objdump.txt", 0x5D2CD80, 0x5D2CD87),
    ("shared-ret0-5d2cd90.objdump.txt", 0x5D2CD90, 0x5D2CD97),
    ("shared-ret0-5d2cda0.objdump.txt", 0x5D2CDA0, 0x5D2CDA7),
    ("shared-ret0-5d2cdb0.objdump.txt", 0x5D2CDB0, 0x5D2CDB7),
    ("shared-ret0-5d2ca30.objdump.txt", 0x5D2CA30, 0x5D2CA37),
    ("shared-ret0-5d2ca40.objdump.txt", 0x5D2CA40, 0x5D2CA47),
    ("shared-ret1-5df72f0.objdump.txt", 0x5DF72F0, 0x5DF72FA),
    ("shared-ret0-5d2ca50.objdump.txt", 0x5D2CA50, 0x5D2CA57),
    ("shared-ret8-5d2ca60.objdump.txt", 0x5D2CA60, 0x5D2CA6A),
    ("shared-isinst-default-5d2e770.objdump.txt", 0x5D2E770, 0x5D2E832),
    ("merge-error-logger-5fceda0.objdump.txt", 0x5FCEDA0, 0x5FCEE93),
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
