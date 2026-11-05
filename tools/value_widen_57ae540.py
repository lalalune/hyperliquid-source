"""Model of the node #115 tagged-value widening conversion at
0x57ae540 (FDE 0x57ae540..0x57ae642, 258 bytes).

Evidence and derivation: research/work-items/RE-001-value-widen-
57ae540-115/ (README.md, records.json, main.txt, table.txt,
callers.tsv, census.py, verify.py, differential.py).

The body is a leaf: it reads a tag byte at [rsi], indexes a
22-entry jump table of signed 32-bit offsets at 0x931abc in
.rodata (target = table + offset), and jumps.  There is no
bounds check: tags >= 22 are outside the contract the callers
uphold (see the packet README).  Each case writes an output tag
byte at [rdi] and, for payload cases, one payload field; no
other output bytes are written.  The cases, by input tag:

  in  read (offsets from rsi)        write (offsets from rdi)   out tag
  --  ---------------------------    ------------------------   -------
   0  byte  [1]                      byte  [1]                      0
   1  u8    [1]  zero-extend         u64   [8]                      1
   2  u16   [2]  zero-extend         u64   [8]                      1
   3  u32   [4]  zero-extend         u64   [8]                      1
   4  u64   [8]                      u64   [8]                      1
   5  i8    [1]  sign-extend         i64   [8]                      2
   6  i16   [2]  sign-extend         i64   [8]                      2
   7  i32   [4]  sign-extend         i64   [8]                      2
   8  u64   [8]  bits reinterpreted  i64   [8]                      2
   9  f32   [4]  cvtss2sd            f64   [8]                      3
  10  f64   [8]                      f64   [8]                      3
  11  u32   [4]                      u32   [4]                      4
  12  16B   [16]                     16B   [8]                      5
  13  16B   [8]                      16B   [8]                      5
  14  16B   [16]                     16B   [8]                      6
  15  16B   [8]                      16B   [8]                      6
  16  -                              -                              8
  17  -                              -                              8
  18  -                              -                              7
  19  -                              -                              9
  20  -                              -                             10
  21  -                              -                             11

rax on exit is a case-dependent residue (payload cases: the
stored 64-bit value with its low byte replaced by the output
tag; cases that never reload rax keep the jump target address
with its low byte replaced by the output tag; input tag 0
returns 0).  No sampled caller reads rax; the value is modeled
anyway so the differential test can check it bit-for-bit.

widen() below is a direct transcription of the body.  The
model-only ValueError for tags >= 22 (or short buffers) is a
guard of this Python model, not a claim about the binary: the
binary performs no check.
"""

import struct

__all__ = ["widen", "OUT_TAGS", "CASE_ADDRS", "TABLE_ADDR"]

TABLE_ADDR = 0x931ABC
BODY_ADDR = 0x57AE540

# Jump-table targets in input-tag order, read from the binary
# (packet table.txt / records.json).
CASE_ADDRS = [
    0x57AE5D0, 0x57AE5DC, 0x57AE59D, 0x57AE5B7, 0x57AE570,
    0x57AE5E9, 0x57AE604, 0x57AE5C3, 0x57AE621, 0x57AE58A,
    0x57AE612, 0x57AE565, 0x57AE57D, 0x57AE5F7, 0x57AE558,
    0x57AE5AA, 0x57AE553, 0x57AE553, 0x57AE638, 0x57AE63D,
    0x57AE62E, 0x57AE633,
]

OUT_TAGS = [
    0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3,
    4, 5, 5, 6, 6, 8, 8, 7, 9, 10, 11,
]

_MASK64 = (1 << 64) - 1


def _residue(value, out_tag):
    """rax after `mov al, out_tag` on a fully loaded rax."""
    return ((value & ~0xFF) | out_tag) & _MASK64


def _dispatch_residue(case_addr, out_tag):
    """rax when a case never reloads rax after the computed jump:
    it still holds the case address from the dispatch."""
    return ((case_addr & ~0xFF) | out_tag) & _MASK64


def widen(inp, out):
    """Apply the conversion at 0x57ae540.

    inp: bytes-like, the input slot; must expose at least the
    bytes the selected case reads (32 bytes covers every case).
    out: bytearray, the output slot; must be at least 24 bytes.
    Only the case's documented write set is mutated.
    Returns the rax residue (int).
    Raises ValueError for an out-of-contract tag (model guard
    only; the binary itself performs no bounds check).
    """
    if len(inp) < 32:
        raise ValueError("input slot must expose 32 bytes")
    if len(out) < 24:
        raise ValueError("output slot must expose 24 bytes")
    tag = inp[0]
    if tag >= 22:
        raise ValueError("tag %d outside the 22-case table" % tag)

    if tag == 0:
        out[1] = inp[1]
        out[0] = 0
        return 0
    if tag == 1:
        value = inp[1]
        struct.pack_into("<Q", out, 8, value)
        out[0] = 1
        return _residue(value, 1)
    if tag == 2:
        value = struct.unpack_from("<H", inp, 2)[0]
        struct.pack_into("<Q", out, 8, value)
        out[0] = 1
        return _residue(value, 1)
    if tag == 3:
        value = struct.unpack_from("<I", inp, 4)[0]
        struct.pack_into("<Q", out, 8, value)
        out[0] = 1
        return _residue(value, 1)
    if tag == 4:
        value = struct.unpack_from("<Q", inp, 8)[0]
        struct.pack_into("<Q", out, 8, value)
        out[0] = 1
        return _residue(value, 1)
    if tag == 5:
        value = struct.unpack_from("<b", inp, 1)[0] & _MASK64
        struct.pack_into("<Q", out, 8, value)
        out[0] = 2
        return _residue(value, 2)
    if tag == 6:
        value = struct.unpack_from("<h", inp, 2)[0] & _MASK64
        struct.pack_into("<Q", out, 8, value)
        out[0] = 2
        return _residue(value, 2)
    if tag == 7:
        value = struct.unpack_from("<i", inp, 4)[0] & _MASK64
        struct.pack_into("<Q", out, 8, value)
        out[0] = 2
        return _residue(value, 2)
    if tag == 8:
        value = struct.unpack_from("<Q", inp, 8)[0]
        struct.pack_into("<Q", out, 8, value)
        out[0] = 2
        return _residue(value, 2)
    if tag == 9:
        f32 = struct.unpack_from("<f", inp, 4)[0]
        struct.pack_into("<d", out, 8, f32)
        out[0] = 3
        return _dispatch_residue(CASE_ADDRS[9], 3)
    if tag == 10:
        out[8:16] = inp[8:16]
        out[0] = 3
        return _dispatch_residue(CASE_ADDRS[10], 3)
    if tag == 11:
        value = struct.unpack_from("<I", inp, 4)[0]
        struct.pack_into("<I", out, 4, value)
        out[0] = 4
        return _residue(value, 4)
    if tag == 12:
        out[8:24] = inp[16:32]
        out[0] = 5
        return _dispatch_residue(CASE_ADDRS[12], 5)
    if tag == 13:
        out[8:24] = inp[8:24]
        out[0] = 5
        return _dispatch_residue(CASE_ADDRS[13], 5)
    if tag == 14:
        out[8:24] = inp[16:32]
        out[0] = 6
        return _dispatch_residue(CASE_ADDRS[14], 6)
    if tag == 15:
        out[8:24] = inp[8:24]
        out[0] = 6
        return _dispatch_residue(CASE_ADDRS[15], 6)
    # Unit cases: only the output tag byte is written.
    out_tag = OUT_TAGS[tag]
    out[0] = out_tag
    return _dispatch_residue(CASE_ADDRS[tag], out_tag)
