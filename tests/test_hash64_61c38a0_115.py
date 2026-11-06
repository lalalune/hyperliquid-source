"""Tests for the node #115 Hash64 body model (0x61c38a0).

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_hash64_61c38a0_115.py

The golden vectors below were produced by running the original
binary bytes under Unicorn emulation (see the packet's
differential.py) and are reproduced here so the model is pinned
without the emulator. They cover every length arm the body
finishes itself: the empty input, 1..3, 4..8, 9..16, and the
four stripe bands 17..32, 33..64, 65..96, 97..128 including
both ends of each band.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from hash64_61c38a0_115 import (  # noqa: E402
    SECRET, delegation_target, hash64)


def _payload(kind, n):
    if kind == "pat":
        return bytes((i * 31 + n) & 0xFF for i in range(n))
    if kind == "zero":
        return bytes(n)
    if kind == "ff":
        return b"\xff" * n
    if kind == "incr":
        return bytes(i & 0xFF for i in range(n))
    raise ValueError(kind)


# (payload kind, length, expected) — expected values are the
# original bytes' outputs under Unicorn.
VECTORS = [
    ("pat", 0, 0x5342C3010FE1DD04),
    ("zero", 0, 0x5342C3010FE1DD04),
    ("pat", 1, 0xC913A720A2324DF4),
    ("pat", 2, 0xDB833ABC0784D793),
    ("pat", 3, 0xF9BB2B56DA901033),
    ("ff", 3, 0xF862F39F9E1F1056),
    ("pat", 4, 0xF915DDBE8AFE0C7C),
    ("incr", 5, 0x134C7FEBEFADCBD2),
    ("pat", 8, 0x6160BE29311CAF7D),
    ("pat", 9, 0xDDD9D6C2F6F5D10C),
    ("ff", 12, 0x9161A53B4DB47D54),
    ("pat", 16, 0x21502554B6C54D8A),
    ("pat", 17, 0x8E05C4F55CB6B4B7),
    ("incr", 24, 0x7B1C552A33BE577A),
    ("pat", 32, 0x37C8250880955B1C),
    ("pat", 33, 0x17E3F40B4D63F93C),
    ("ff", 48, 0x6E1469787328456A),
    ("pat", 64, 0xD89561270149CA90),
    ("pat", 65, 0x04FB17EAA6C03030),
    ("incr", 80, 0xD636E92DA962A30F),
    ("pat", 96, 0x80716FBE56FFBCC8),
    ("pat", 97, 0xFE41ACE5CC5863BD),
    ("ff", 112, 0x479E117DCE2C5D00),
    ("pat", 128, 0x3304356A081E6F8F),
    ("zero", 128, 0x69436F521EB08981),
    ("zero", 64, 0x669F1DD8884851AE),
    ("incr", 128, 0x7AA5DB2C8097080B),
]


def test_golden_vectors():
    for kind, n, want in VECTORS:
        got = hash64(_payload(kind, n))
        assert got == want, (kind, n, hex(got), hex(want))


def test_empty_input_is_the_pinned_constant():
    # The constant is loaded at 0x61c3aa6 before the zero test,
    # so every empty input returns it and no byte is read.
    assert hash64(b"") == 0x5342C3010FE1DD04


def test_secret_table_shape():
    # The 192-byte table the binary holds at VA 0x97df00; every
    # immediate baked into this body is one of its qwords.
    assert len(SECRET) == 192

    def q(off):
        return int.from_bytes(SECRET[off:off + 8], "little")

    assert q(0) == 0xBE4BA423396CFEB8
    assert q(8) == 0x1CAD21F72C81017C
    assert q(16) == 0xDB979083E96DD4DE
    assert q(24) == 0x1F67B3B7A4A44072
    assert q(32) == 0x78E5C0CC4EE679CB
    assert q(48) == 0x8E2443F7744608B8
    assert q(64) == 0xCB00C391BB52283C
    assert q(80) == 0x4EF90DA297486471
    assert q(96) == 0x3F349CE33F76FAA8
    assert q(112) == 0x3159B4CD4BE0518A
    assert q(120) == 0x647378D9C97E9FC8
    # the 1..3 arm's xor immediate is the low half of qword 0
    assert q(0) & 0xFFFFFFFF == 0x396CFEB8


def test_delegation_targets():
    # Lengths the body finishes itself have no delegation.
    assert delegation_target(0) is None
    assert delegation_target(128) is None
    # 129..240: tail jump to the delegate, seed register zeroed.
    assert delegation_target(129) == (0x61C3230, 0)
    assert delegation_target(240) == (0x61C3230, 0)
    # 241+: tail jump to the seedless body, rdx untouched.
    assert delegation_target(241) == (0x61C2890, None)
    assert delegation_target(1 << 20) == (0x61C2890, None)
    # and the model refuses those lengths rather than guessing
    for n in (129, 240, 241):
        try:
            hash64(bytes(n))
        except ValueError:
            pass
        else:
            raise AssertionError("hash64 accepted length %d" % n)


def test_every_byte_position_matters():
    # Flip one byte in each read region of a 128-byte input
    # (every stripe pair and the final pair) and in the small
    # arms; the hash must change every time.
    base = bytearray(_payload("pat", 128))
    want = hash64(bytes(base))
    for pos in (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 127):
        flipped = bytearray(base)
        flipped[pos] ^= 0x01
        assert hash64(bytes(flipped)) != want, pos
    for n in (1, 2, 3, 5, 8, 12, 16):
        base = bytearray(_payload("pat", n))
        want = hash64(bytes(base))
        for pos in range(n):
            flipped = bytearray(base)
            flipped[pos] ^= 0x80
            assert hash64(bytes(flipped)) != want, (n, pos)


def test_band_boundaries_change_the_result():
    # The same prefix at consecutive lengths across each arm
    # gate must not collide: 3/4, 8/9, 16/17, 32/33, 64/65,
    # 96/97 and the top of the inline range.
    full = _payload("pat", 129)
    seen = {}
    for n in (3, 4, 8, 9, 16, 17, 32, 33, 64, 65, 96, 97, 128):
        got = hash64(full[:n])
        assert got not in seen.values(), n
        seen[n] = got


def _run_all():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print("ok", name)
    print("%d tests passed" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
