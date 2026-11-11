"""Tests for the node #115 seedless hash-long model (0x61c2890).

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_hash_seedless_61c2890_115.py

The golden vectors below were produced by running the original
binary bytes under Unicorn emulation (see the packet's
differential.py) and are reproduced here so the model is pinned
without the emulator. They cover the whole contract range
(lengths 241 and up): lengths with no full block, the
length % 64 == 0 cases where no final stripe runs, every
remainder-stripe count, the first full block at 1024 with its
scramble, multi-block lengths, and the block-plus-remainder
boundaries.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from hash_seedless_61c2890_115 import (  # noqa: E402
    INIT, SECRET, final_acc, hash_seedless)


def _payload(kind, n):
    if kind == "pat":
        return bytes(((i * 31 + n) & 0xFF) for i in range(n))
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
    ("pat", 241, 0xC88819340E98C88B),
    ("pat", 242, 0xA0BEC5A43DB3FCF0),
    ("pat", 255, 0x7FD353415C0EFAD4),
    ("pat", 256, 0x8FD1908CCEA8E54E),
    ("pat", 257, 0xF4C814729B329655),
    ("pat", 320, 0xFCE86A0278EEF005),
    ("pat", 384, 0x1978EB9CB767D851),
    ("pat", 500, 0x6BC492BFA43DA44E),
    ("pat", 1023, 0xD40F1AEB9CC53C57),
    ("pat", 1024, 0x2E9DA5448FAA9237),
    ("pat", 1025, 0x28F0E2B61216934B),
    ("pat", 1088, 0x280A946467A7548B),
    ("pat", 2048, 0x458CF9DC98A8A567),
    ("pat", 3000, 0x63B58556A981B25A),
    ("zero", 241, 0x77C5431D6B5B82A3),
    ("zero", 256, 0x3E44DB0019AD46EE),
    ("zero", 1024, 0x37B465FF1BC610C0),
    ("zero", 2048, 0x447E10A46C76C24B),
    ("ff", 241, 0xBB8253462A9E9C05),
    ("ff", 1088, 0x89A734C6DDC9C69E),
    ("incr", 241, 0xB78DF6016A18C222),
    ("incr", 1024, 0xA63B91FD35CA4F09),
    ("incr", 4103, 0x9AE31E5CF917249D),
]


def test_golden_vectors():
    checks = 0
    for kind, n, want in VECTORS:
        got = hash_seedless(_payload(kind, n))
        assert got == want, (kind, n, hex(got), hex(want))
        checks += 1
    return checks


def test_secret_table_shape():
    # The 192-byte table the binary holds at VA 0x97df00; its first
    # two qwords are the citing packets' C_A / C_B lane constants,
    # and the windows this body reads are pinned at offsets 121
    # (final stripe), 128..192 (scramble keys) and +11 (merge).
    assert len(SECRET) == 192
    assert SECRET[:8] == bytes.fromhex("b8fe6c3923a44bbe")
    assert int.from_bytes(SECRET[0:8], "little") == 0xBE4BA423396CFEB8
    assert int.from_bytes(SECRET[8:16], "little") == 0x1CAD21F72C81017C
    return 4


def test_init_is_the_prime_ladder():
    assert INIT == [
        0x00000000C2B2AE3D, 0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F,
        0x165667B19E3779F9, 0x85EBCA77C2B2AE63, 0x0000000085EBCA77,
        0x27D4EB2F165667C5, 0x000000009E3779B1,
    ]
    return 1


def test_every_byte_position_matters():
    # Flip one byte in each region of a 241-byte input (first
    # stripe, a middle remainder stripe, the final stripe) and of
    # a 2048-byte input (both blocks, the scramble boundary); the
    # hash must change every time.
    checks = 0
    base = bytearray(_payload("pat", 241))
    want = hash_seedless(bytes(base))
    for pos in (0, 8, 63, 64, 128, 176, 240):
        flipped = bytearray(base)
        flipped[pos] ^= 0x01
        assert hash_seedless(bytes(flipped)) != want, pos
        checks += 1
    base = bytearray(_payload("pat", 2048))
    want = hash_seedless(bytes(base))
    for pos in (0, 512, 1023, 1024, 1536, 2047):
        flipped = bytearray(base)
        flipped[pos] ^= 0x80
        assert hash_seedless(bytes(flipped)) != want, pos
        checks += 1
    return checks


def test_length_sensitivity():
    payload = _payload("pat", 300)
    assert hash_seedless(payload) != hash_seedless(payload[:299])
    assert hash_seedless(payload) != hash_seedless(payload + b"\x00")
    # a multiple-of-64 length takes no final stripe: appending a
    # zero byte is a different computation, not a no-op
    p256 = _payload("pat", 256)
    assert hash_seedless(p256) != hash_seedless(p256 + b"\x00")
    return 3


def test_accumulator_frame_shape():
    # final_acc is the array the merge call receives on the stack:
    # eight qwords, and it must differ from the init ladder for any
    # real input (the differential compares it against the native
    # stack frame directly).
    acc = final_acc(_payload("pat", 241))
    assert len(acc) == 8
    assert acc != INIT
    assert all(0 <= a < (1 << 64) for a in acc)
    return 3


def _run_all():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    total = 0
    for name, fn in tests:
        checks = fn()
        total += checks if isinstance(checks, int) else 1
        print("ok", name)
    print("%d tests passed (%d checks)" % (len(tests), total))
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
