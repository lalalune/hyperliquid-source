"""Pure-model checks for tools/value_widen_57ae540.py.

Run from the repository root:
    python3 tests/test_value_widen_57ae540.py

Prints the number of checks and "checks pass" on success.

The spec below is an independent, declarative formulation of
the conversion pinned by research/work-items/RE-001-value-
widen-57ae540-115/: each input tag maps to one primitive
operation (kind, source offset, size, destination offset,
output tag).  widen() is a per-case transcription of the
binary body; the two are compared on directed edge payloads
and deterministic randomized buffers, including the exact
write set (via two different sentinel fills) and the rax
residue.  The f32 -> f64 widening is checked here against
Python's C conversion; its bit-exactness against the binary
(including NaN payloads) is pinned separately by the packet's
differential.py under Unicorn emulation.
"""

import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.value_widen_57ae540 import CASE_ADDRS, OUT_TAGS, widen  # noqa: E402

CHECKS = 0


def check(cond, msg):
    global CHECKS
    CHECKS += 1
    if not cond:
        raise AssertionError(msg)


# kind, src_off, size, dst_off, out_tag -- the semantic table.
SPEC = {
    0: ("byte", 1, 1, 1, 0),
    1: ("zext", 1, 1, 8, 1),
    2: ("zext", 2, 2, 8, 1),
    3: ("zext", 4, 4, 8, 1),
    4: ("zext", 8, 8, 8, 1),
    5: ("sext", 1, 1, 8, 2),
    6: ("sext", 2, 2, 8, 2),
    7: ("sext", 4, 4, 8, 2),
    8: ("bits", 8, 8, 8, 2),
    9: ("f32", 4, 4, 8, 3),
    10: ("f64", 8, 8, 8, 3),
    11: ("u32slot", 4, 4, 4, 4),
    12: ("copy", 16, 16, 8, 5),
    13: ("copy", 8, 16, 8, 5),
    14: ("copy", 16, 16, 8, 6),
    15: ("copy", 8, 16, 8, 6),
    16: ("unit", 0, 0, 0, 8),
    17: ("unit", 0, 0, 0, 8),
    18: ("unit", 0, 0, 0, 7),
    19: ("unit", 0, 0, 0, 9),
    20: ("unit", 0, 0, 0, 10),
    21: ("unit", 0, 0, 0, 11),
}

_MASK64 = (1 << 64) - 1


def spec_apply(tag, inp, fill):
    """Return (expected_out_bytes, expected_rax, write_offsets)."""
    kind, src, size, dst, out_tag = SPEC[tag]
    out = bytearray([fill] * 24)
    writes = {0}
    out[0] = out_tag
    if kind == "unit":
        rax = ((CASE_ADDRS[tag] & ~0xFF) | out_tag) & _MASK64
        return bytes(out), rax, writes
    if kind == "byte":
        out[dst] = inp[src]
        writes.add(dst)
        return bytes(out), 0, writes
    if kind == "copy":
        out[dst:dst + 16] = inp[src:src + 16]
        writes.update(range(dst, dst + 16))
        rax = ((CASE_ADDRS[tag] & ~0xFF) | out_tag) & _MASK64
        return bytes(out), rax, writes
    if kind == "f32":
        val = struct.unpack_from("<f", inp, src)[0]
        struct.pack_into("<d", out, dst, val)
        writes.update(range(dst, dst + 8))
        rax = ((CASE_ADDRS[tag] & ~0xFF) | out_tag) & _MASK64
        return bytes(out), rax, writes
    if kind == "f64":
        out[dst:dst + 8] = inp[src:src + 8]
        writes.update(range(dst, dst + 8))
        rax = ((CASE_ADDRS[tag] & ~0xFF) | out_tag) & _MASK64
        return bytes(out), rax, writes
    if kind == "u32slot":
        val = struct.unpack_from("<I", inp, src)[0]
        struct.pack_into("<I", out, dst, val)
        writes.update(range(dst, dst + 4))
        return bytes(out), ((val & ~0xFF) | out_tag) & _MASK64, writes
    raw = int.from_bytes(inp[src:src + size], "little")
    if kind == "sext" and size < 8 and raw >> (size * 8 - 1):
        val = (raw - (1 << (size * 8))) & _MASK64
    else:
        val = raw
    struct.pack_into("<Q", out, dst, val)
    writes.update(range(dst, dst + 8))
    return bytes(out), ((val & ~0xFF) | out_tag) & _MASK64, writes


def run_case(tag, payload, label):
    inp = bytearray(payload)
    inp[0] = tag
    before = bytes(inp)
    changed_union = set()
    for fill in (0xA5, 0x3C):
        out = bytearray([fill] * 24)
        rax = widen(bytes(inp), out)
        exp_out, exp_rax, writes = spec_apply(tag, bytes(inp), fill)
        check(bytes(out) == exp_out,
              "%s tag %d fill %#x: out mismatch" % (label, tag, fill))
        check(rax == exp_rax,
              "%s tag %d: rax %#x != spec %#x" % (label, tag, rax, exp_rax))
        changed_union |= {i for i in range(24) if out[i] != fill}
    exp_out, _, writes = spec_apply(tag, bytes(inp), 0xA5)
    check(changed_union == writes,
          "%s tag %d: write set %s != spec %s"
          % (label, tag, sorted(changed_union), sorted(writes)))
    check(bytes(inp) == before, "%s tag %d: input mutated" % (label, tag))
    check(exp_out[0] == OUT_TAGS[tag], "%s tag %d: out tag" % (label, tag))


def directed_payloads():
    """32-byte payloads stressing every read window."""
    base = bytearray(32)
    yield bytes(base)                                   # all zero
    yield bytes([0xFF] * 32)                            # all ones
    yield bytes(range(32))                              # counting
    p = bytearray(32)
    for off in (1, 2, 4, 8, 16):
        p[off] = 0x80                                   # sign bit of each window
    yield bytes(p)
    p = bytearray(32)
    struct.pack_into("<f", p, 4, float("nan"))
    struct.pack_into("<d", p, 8, float("inf"))
    yield bytes(p)
    p = bytearray(32)
    struct.pack_into("<I", p, 4, 0x7FC0BEEF)            # f32 qNaN payload
    struct.pack_into("<I", p, 24, 0x7F800001)           # f32 sNaN payload (in +16 window tail)
    yield bytes(p)
    p = bytearray(32)
    struct.pack_into("<f", p, 4, -0.0)
    struct.pack_into("<d", p, 8, -0.0)
    yield bytes(p)
    p = bytearray(32)
    struct.pack_into("<H", p, 2, 0x8000)
    struct.pack_into("<h", p, 2, -1)
    struct.pack_into("<i", p, 4, -2147483648)
    struct.pack_into("<Q", p, 8, 0xFFFFFFFFFFFFFFFF)
    yield bytes(p)


def main():
    rng = random.Random(0x57AE540)
    for tag in range(22):
        for i, payload in enumerate(directed_payloads()):
            run_case(tag, payload, "directed%d" % i)
        for i in range(300):
            payload = bytes(rng.randrange(256) for _ in range(32))
            run_case(tag, payload, "random%d" % i)
    # Out-of-contract tags: the model guard must reject them
    # (the binary performs no check; see the model docstring).
    for tag in (22, 23, 100, 255):
        try:
            widen(bytes([tag]) + bytes(31), bytearray(24))
        except ValueError:
            check(True, "guard tag %d" % tag)
        else:
            check(False, "guard tag %d did not raise" % tag)
    print("%d checks pass" % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
