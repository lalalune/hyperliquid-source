"""Regenerate the verbatim disassembly excerpts for the
RE-001-ts-gate-ops-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-ts-gate-ops-115/export_excerpts.py

Writes one whole-function file per pinned window (FDE range):
the timestamp-size gate, the hex/nibble helpers, the always-OK
stub, the timestamp-size resolver, five wrappers, five
implementations and five SliceParts middles. The five inner
record appenders, the WriteBatch constructor/destructor, the
strdup helper, the Status builder and the default getter are
NOT generated here: they are re-shipped byte-identical from
PR #3209 (RE-001-writebatch-ops-115) and PR #3202
(RE-001-timestamp-guard-8810-115), whose packets map them in
full. The excerpts are stored verbatim; verify.py checks that
a fresh run reproduces them byte-for-byte. Instruction-level
detail lives only in these excerpt texts, not in records.json.
The mnemonics in them (endbr64 included) are genuine
instructions present in the target binary, not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("gate_main.txt", 0x5E882B0, 0x5E8901D),
    ("hex_helper.txt", 0x61C7E30, 0x61C7FB6),
    ("nibble.txt", 0x61C7DA0, 0x61C7DB2),
    ("ok_stub.txt", 0x5D48400, 0x5D48407),
    ("resolver.txt", 0x5FB6910, 0x5FB6A30),
    ("wrap_put.txt", 0x5E94800, 0x5E9491C),
    ("wrap_delete.txt", 0x5E95040, 0x5E95156),
    ("wrap_singledelete.txt", 0x5E95560, 0x5E95676),
    ("wrap_deleterange.txt", 0x5E95AC0, 0x5E95BE0),
    ("wrap_merge.txt", 0x5E960A0, 0x5E961BC),
    ("impl_put.txt", 0x5E94690, 0x5E947B8),
    ("impl_delete.txt", 0x5E94EE0, 0x5E94FF8),
    ("impl_singledelete.txt", 0x5E95400, 0x5E95518),
    ("impl_deleterange.txt", 0x5E95950, 0x5E95A78),
    ("impl_merge.txt", 0x5E95F30, 0x5E96058),
    ("mid_put.txt", 0x5FBF7D0, 0x5FBF92F),
    ("mid_delete.txt", 0x5FC04F0, 0x5FC062F),
    ("mid_singledelete.txt", 0x5FC11E0, 0x5FC131F),
    ("mid_deleterange.txt", 0x5FC2080, 0x5FC21F7),
    ("mid_merge.txt", 0x5FC4220, 0x5FC437F),
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
