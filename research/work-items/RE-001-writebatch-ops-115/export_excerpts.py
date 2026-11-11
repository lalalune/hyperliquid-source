"""Regenerate the verbatim disassembly excerpts for the
RE-001-writebatch-ops-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-writebatch-ops-115/export_excerpts.py

Writes one whole-function file per pinned window (FDE range):
six wrappers, six implementations, six middle callees, six
inner record appenders, the WriteBatch constructor/destructor,
the strdup helper, the column-family resolver, and the five
timestamp-size-zero tail callees. The guard excerpt
(guard_main.txt) is NOT generated here: it is re-shipped
byte-identical from PR #3202 (RE-001-timestamp-guard-8810-115),
whose packet maps the guard, the Status builder and the
default getter in full. The excerpts are stored verbatim;
verify.py checks that a fresh run reproduces them
byte-for-byte. Instruction-level detail lives only in these
excerpt texts, not in records.json. The mnemonics in them
(endbr64 included) are genuine instructions present in the
target binary, not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("wrap_put.txt", 0x5E94540, 0x5E94656),
    ("wrap_putentity.txt", 0x5E94B20, 0x5E94C36),
    ("wrap_delete.txt", 0x5E94DA0, 0x5E94EA3),
    ("wrap_singledelete.txt", 0x5E952C0, 0x5E953C3),
    ("wrap_deleterange.txt", 0x5E95800, 0x5E95916),
    ("wrap_merge.txt", 0x5E95D70, 0x5E95EF7),
    ("impl_put.txt", 0x5E943F0, 0x5E944FF),
    ("impl_putentity.txt", 0x5E94970, 0x5E94AE1),
    ("impl_delete.txt", 0x5E94C70, 0x5E94D5E),
    ("impl_singledelete.txt", 0x5E95190, 0x5E9527E),
    ("impl_deleterange.txt", 0x5E956B0, 0x5E957B7),
    ("impl_merge.txt", 0x5E95C20, 0x5E95D27),
    ("mid_put.txt", 0x5FBF5D0, 0x5FBF795),
    ("mid_putentity.txt", 0x5FC4DB0, 0x5FC4F43),
    ("mid_delete.txt", 0x5FC0320, 0x5FC04AD),
    ("mid_singledelete.txt", 0x5FC1010, 0x5FC119D),
    ("mid_deleterange.txt", 0x5FC1E60, 0x5FC2045),
    ("mid_merge.txt", 0x5FC4020, 0x5FC41E5),
    ("inner_put.txt", 0x5FBF0B0, 0x5FBF588),
    ("inner_putentity.txt", 0x5FC46C0, 0x5FC4D78),
    ("inner_delete.txt", 0x5FBFF40, 0x5FC02E8),
    ("inner_singledelete.txt", 0x5FC0C30, 0x5FC0FD8),
    ("inner_deleterange.txt", 0x5FC1980, 0x5FC1E23),
    ("inner_merge.txt", 0x5FC3B00, 0x5FC3FD8),
    ("batch_ctor.txt", 0x5FB9F90, 0x5FBA0BE),
    ("batch_dtor.txt", 0x5FB7EE0, 0x5FB7FB7),
    ("strdup.txt", 0x61CF610, 0x61CF64F),
    ("cf_resolve.txt", 0x5FBBC90, 0x5FBBE5B),
    ("tail_put.txt", 0x5FBED30, 0x5FBF077),
    ("tail_delete.txt", 0x5FBFC20, 0x5FBFF39),
    ("tail_singledelete.txt", 0x5FC0910, 0x5FC0C29),
    ("tail_deleterange.txt", 0x5FC1600, 0x5FC1979),
    ("tail_merge.txt", 0x5FC24F0, 0x5FC27F7),
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / name).write_text(text)
        print("wrote %s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
