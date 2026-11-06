"""Tests for the node #115 hash delegate model (0x61c3230).

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_hash_delegate_c3230_115.py

The golden vectors below were produced by running the original
binary bytes under Unicorn emulation (see the packet's
differential.py) and are reproduced here so the model is pinned
without the emulator. They cover the whole contract range
129..240: the no-loop lengths 129..143, the loop boundary at
143/144, every middle-loop stripe count (nbRounds - 8 = 1..7 for
lengths 144..240), and the range end 239/240, under several seeds
including the fold seeds the citing packets use.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from hash_delegate_c3230_115 import SECRET, hash_delegate  # noqa: E402


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


# (payload kind, length, seed, expected) — expected values are the
# original bytes' outputs under Unicorn.
VECTORS = [
    ("pat", 129, 0x0000000000000000, 0x60630E426FCF92D8),
    ("pat", 129, 0xD28AAD72F49BD50B, 0xE577DDDA4D0CA916),
    ("pat", 130, 0x0000000000000001, 0x6C9972A63C2EF8C9),
    ("pat", 143, 0x0000000000000000, 0x58F4A53AF95ED0C2),
    ("pat", 143, 0xFFFFFFFFFFFFFFFF, 0x43C62719A1E303D4),
    ("pat", 144, 0x0000000000000000, 0x172F6E677F49FA0A),
    ("pat", 144, 0xA5155AE5E937AA16, 0x059ACAEA27FBE92C),
    ("pat", 145, 0x0000000000000007, 0x1ABFD1C43C3DD523),
    ("pat", 159, 0x0000000000000000, 0x1414F29F1C64FBB6),
    ("pat", 160, 0x77A00858DDD37F21, 0xE09E42B3D8E53F21),
    ("pat", 161, 0x0000000000000003, 0xEA9FB3DCB5B73FC0),
    ("pat", 176, 0x0000000000000000, 0xB61CA91F0AB0F567),
    ("pat", 192, 0xD28AAD72F49BD50B, 0x3669173D335A6002),
    ("pat", 200, 0x0000000000000005, 0xB9C70AC774B1B707),
    ("pat", 224, 0x0000000000000000, 0xDAC0618C96AAB3E7),
    ("pat", 239, 0x0000000000000009, 0xC2CB112AE19A82EA),
    ("pat", 240, 0x0000000000000000, 0x66B960E005A92DE9),
    ("pat", 240, 0xFFFFFFFFFFFFFFFF, 0x4331CA01121FAC0E),
    ("zero", 129, 0x0000000000000000, 0x292D4384B39D5C58),
    ("zero", 240, 0x0000000000000000, 0x1C851CAF6823B625),
    ("ff", 144, 0xD28AAD72F49BD50B, 0x16E68AFB63882C6B),
    ("incr", 200, 0x0000000000000001, 0x504D8A34F1113253),
]


def test_golden_vectors():
    for kind, n, seed, want in VECTORS:
        got = hash_delegate(_payload(kind, n), seed)
        assert got == want, (kind, n, hex(seed), hex(got), hex(want))


def test_secret_table_shape():
    # The 192-byte table the binary holds at VA 0x97df00; its first
    # two qwords are the parent's C_A / C_B lane constants.
    assert len(SECRET) == 192
    assert SECRET[:8] == bytes.fromhex("b8fe6c3923a44bbe")
    assert int.from_bytes(SECRET[0:8], "little") == 0xBE4BA423396CFEB8
    assert int.from_bytes(SECRET[8:16], "little") == 0x1CAD21F72C81017C


def test_seed_is_taken_modulo_2_64():
    payload = _payload("pat", 200)
    assert hash_delegate(payload, 1 << 64) == hash_delegate(payload, 0)
    assert hash_delegate(payload, (1 << 64) + 5) == hash_delegate(payload, 5)


def test_every_byte_position_matters():
    # Flip one byte in each region of a 240-byte input (opening
    # stripes, middle loop stripes, final pair) and in a 129-byte
    # input; the hash must change every time.
    base = bytearray(_payload("pat", 240))
    want = hash_delegate(bytes(base), 0)
    for pos in (0, 8, 127, 128, 136, 200, 224, 239):
        flipped = bytearray(base)
        flipped[pos] ^= 0x01
        assert hash_delegate(bytes(flipped), 0) != want, pos
    base = bytearray(_payload("pat", 129))
    want = hash_delegate(bytes(base), 0)
    for pos in (0, 64, 113, 128):
        flipped = bytearray(base)
        flipped[pos] ^= 0x80
        assert hash_delegate(bytes(flipped), 0) != want, pos


def test_length_and_seed_sensitivity():
    payload = _payload("pat", 160)
    assert hash_delegate(payload, 0) != hash_delegate(payload, 1)
    assert hash_delegate(payload, 0) != hash_delegate(payload[:159], 0)
    assert hash_delegate(payload, 0) != hash_delegate(
        payload + b"\x00", 0)


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
