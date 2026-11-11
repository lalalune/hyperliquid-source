"""Export the verbatim objdump excerpts for the
RE-001-tablecache-tombstone-consumers-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-tablecache-tombstone-consumers-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Re-shipped excerpt (max_covering_seqnum.txt, from
RE-001-fragmented-tombstone-iterator-115 #3900) is copied
byte-identical, not regenerated here; verify.py regenerates
every excerpt fresh from the binary and requires byte-equality,
which subsumes the re-ship check.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.
"""

import shutil
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("update_seqnums.txt", 0x5F3D4F0, 0x5F3D64A),   # TableCache::UpdateRangeTombstoneSeqnums
    ("tablecache_get.txt", 0x5F40070, 0x5F40A8D),   # TableCache::Get
    ("get_cleanup.txt", 0x5F4000E, 0x5F40070),      # Get exception-cleanup fragment FDE
    ("null_stub.txt", 0x5EBA930, 0x5EBA937),        # null-returning slot-0x18 canonical stub
    ("iterator_gate.txt", 0x5F0B050, 0x5F0B073),    # MemTable iterator gate (cited; #3674/#3900 ground)
    ("get_tail_marker.txt", 0x616FB90, 0x616FBAE),  # Get tail marker (+0x108 = 1)
]

RESHIPPED = [
    ("max_covering_seqnum.txt",
     ROOT / "research" / "work-items"
     / "RE-001-fragmented-tombstone-iterator-115"
     / "maxseq-5f32900.objdump.txt"),
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / name).write_text(text)
        print("wrote %s (%d bytes)" % (name, len(text)))
    for name, src in RESHIPPED:
        shutil.copyfile(src, PACKET / name)
        print("re-shipped %s from %s" % (name, src))


if __name__ == "__main__":
    sys.exit(main())
