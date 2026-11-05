"""Regenerate the verbatim disassembly excerpts for the
RE-001-record-write-caller-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-write-caller-115/export_excerpts.py

Writes one excerpt per window. Whole-function excerpts cover
the record-write caller 0x5fc6070..0x5fc6e8b (0x81b bytes), the
sibling record write 0x5f0f3d0..0x5f0f8c1, the validator
0x5fb9a10..0x5fb9bcb, the hashmap find-or-insert
0x5fc5e30..0x5fc5fdf with its rehash 0x5fc5cf0..0x5fc5e2d, the
map lower_bound 0x5fb7040..0x5fb70d2, the hash combine
0x5fb70e0..0x5fb7131, the Status move-assign
0x5fb71b0..0x5fb7219, the produce-request init
0x60b21f0..0x60b2262, the strdup helper 0x61cf610..0x61cf64f,
the no-op stub 0x5d54f00..0x5d54f05, the closed-path delegate
0x5fbed30..0x5fbf077 with its counter getter
0x5fbb000..0x5fbb00c (and its tail-jump alias
0x5fbb010..0x5fbb019), counter setter 0x5fbbc30..0x5fbbc3c,
vector grow 0x5fb7440..0x5fb75bb and finalizer
0x5fbebc0..0x5fbed25, and the min-register
0x5f0a1a0..0x5f0a1d0, plus the post-write hook
0x5fb6a60..0x5fb6bbf (contract-level, see README). The record-write entry 0x5f0f930..0x5f10134
is re-shipped byte-identical from #3337, and the record insert
0x5f0e890..0x5f0f37e, the varint32 encoder
0x61bd410..0x61bd4e9 and the Status builder
0x61cf670..0x61cf767 are re-shipped byte-identical from #3330
(their SHA-256s are recorded in the README); the generator
re-emits all of them from the binary, so a re-ship is verified
byte-for-byte against a fresh objdump run by verify.py.

Each excerpt is stored verbatim; verify.py checks that a fresh
run reproduces it byte-for-byte. Instruction-level detail lives
only in these excerpt text files, not in records.json. The
mnemonics in the excerpts (endbr64 included) are genuine
instructions present in the target binary, not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5FC6070, 0x5FC6E8B),
    ("sibling_write.txt", 0x5F0F3D0, 0x5F0F8C1),
    ("validator.txt", 0x5FB9A10, 0x5FB9BCB),
    ("hashmap.txt", 0x5FC5E30, 0x5FC5FDF),
    ("hashmap_rehash.txt", 0x5FC5CF0, 0x5FC5E2D),
    ("map_lookup.txt", 0x5FB7040, 0x5FB70D2),
    ("hash_combine.txt", 0x5FB70E0, 0x5FB7131),
    ("status_move.txt", 0x5FB71B0, 0x5FB7219),
    ("produce_ctor.txt", 0x60B21F0, 0x60B2262),
    ("strdup.txt", 0x61CF610, 0x61CF64F),
    ("stub.txt", 0x5D54F00, 0x5D54F05),
    ("fallback.txt", 0x5FBED30, 0x5FBF077),
    ("fallback_get.txt", 0x5FBB000, 0x5FBB00C),
    ("fallback_get_alias.txt", 0x5FBB010, 0x5FBB019),
    ("fallback_set.txt", 0x5FBBC30, 0x5FBBC3C),
    ("fallback_grow.txt", 0x5FB7440, 0x5FB75BB),
    ("fallback_final.txt", 0x5FBEBC0, 0x5FBED25),
    ("register.txt", 0x5F0A1A0, 0x5F0A1D0),
    ("post_hook.txt", 0x5FB6A60, 0x5FB6BBF),
    ("record_write.txt", 0x5F0F930, 0x5F10134),
    ("record_insert.txt", 0x5F0E890, 0x5F0F37E),
    ("varint_encode.txt", 0x61BD410, 0x61BD4E9),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
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
