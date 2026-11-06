"""Tests for the node #115 hash entry model (0x61c34a0).

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_hash_entry_61c34a0_115.py

The golden vectors below were produced by running the original
binary bytes under Unicorn emulation (see the packet's
differential.py) and are reproduced here so the model is pinned
without the emulator. They cover the empty input (which returns
the seed), every remainder class, the sign-extended tail bytes,
the recorded call-site seeds 0x18d and 0xbc9f1d34, and longer
inputs through the word loop.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from hash_entry_61c34a0_115 import hash_entry  # noqa: E402

# (payload, seed, expected) — expected values are the original
# bytes' outputs under Unicorn.
VECTORS = [
    (b"", 0x00000000, 0x00000000),
    (b"", 0x00000001, 0x00000001),
    (b"", 0x0000018D, 0x0000018D),
    (b"", 0xBC9F1D34, 0xBC9F1D34),
    (b"a", 0x00000000, 0xCA6C9DD6),
    (b"ab", 0x00000000, 0x589C01DD),
    (b"abc", 0x00000000, 0xAC7E1F42),
    (b"abcd", 0x00000000, 0x9E87A0D0),
    (b"abcde", 0x00000000, 0x8FA76260),
    (b"\xff", 0x00000000, 0xBF647669),
    (b"\x80\x80\x80", 0xBC9F1D34, 0xFB5CF38C),
    (b"\xff\xff\xff\xff", 0x00000007, 0x8ADBA0A5),
    (b"hello world", 0x0000018D, 0x63740019),
    (bytes(range(32)), 0xBC9F1D34, 0x3CE673AE),
    (bytes(64), 0x00000000, 0x34E34794),
    (b"\xff" * 65, 0xFFFFFFFF, 0x0EE88212),
    (b"rocksdb", 0x0000018D, 0x0700136E),
    (b"hyperliquid", 0xBC9F1D34, 0xDE0684D0),
    (b"\x00\x01\x02\x03\x04", 0xDEADBEEF, 0xE1EE4C55),
]


def test_golden_vectors():
    for payload, seed, want in VECTORS:
        got = hash_entry(payload, seed)
        assert got == want, (payload, hex(seed), hex(got), hex(want))


def test_empty_input_returns_seed():
    # h = (0 * M) ^ seed and the remainder is 0, so no mix runs.
    for seed in (0, 1, 0x18D, 0xBC9F1D34, 0xFFFFFFFF):
        assert hash_entry(b"", seed) == seed


def test_seed_is_taken_modulo_2_32():
    payload = b"some key bytes"
    assert hash_entry(payload, 1 << 32) == hash_entry(payload, 0)
    assert hash_entry(payload, (1 << 32) + 5) == hash_entry(payload, 5)


def test_tail_bytes_are_sign_extended():
    # The body uses movsbl on the tail bytes: a 0xff tail byte
    # contributes -1, not 255. A zero-extending variant of the
    # model disagrees on these inputs; the golden values pin the
    # sign-extended reading.
    def zero_ext_variant(data, seed):
        mask = 0xFFFFFFFF
        mult = 0xC6A4A793
        h = (((len(data) & mask) * mult) & mask) ^ (seed & mask)
        words = len(data) // 4
        for i in range(words):
            w = int.from_bytes(data[4 * i:4 * i + 4], "little")
            h = (h + w) & mask
            t = (h * mult) & mask
            h = t ^ (t >> 16)
        rem = len(data) - 4 * words
        if rem == 0:
            return h
        tail = data[4 * words:]
        if rem == 3:
            h = (h + (tail[2] << 16)) & mask
        if rem >= 2:
            h = (h + (tail[1] << 8)) & mask
        h = (h + tail[0]) & mask
        t = (h * mult) & mask
        return t ^ (t >> 24)

    for payload in (b"\xff", b"\x80\x80\x80", b"abcd\xff", b"\xff\xfe"):
        assert hash_entry(payload, 0) != zero_ext_variant(payload, 0), payload
    assert hash_entry(b"\x7f", 0) == zero_ext_variant(b"\x7f", 0)


def test_remainder_zero_has_no_final_mix():
    # For a multiple-of-4 length the returned value is the bare
    # accumulator after the last word step. Stepping the word
    # loop by hand for one word pins the absence of the final
    # multiply/xor-shift.
    mask = 0xFFFFFFFF
    mult = 0xC6A4A793
    h = ((4 * mult) & mask) ^ 0
    h = (h + 0x44434241) & mask  # "ABCD" little-endian
    t = (h * mult) & mask
    h = t ^ (t >> 16)
    assert hash_entry(b"ABCD", 0) == h
    # and it differs from what the final mix would give
    t2 = (h * mult) & mask
    assert hash_entry(b"ABCD", 0) != (t2 ^ (t2 >> 24))


def test_every_byte_position_matters():
    base = bytearray((i * 31 + 7) & 0xFF for i in range(64))
    want = hash_entry(bytes(base), 0x18D)
    for pos in (0, 1, 2, 3, 31, 60, 61, 62, 63):
        flipped = bytearray(base)
        flipped[pos] ^= 0x01
        assert hash_entry(bytes(flipped), 0x18D) != want, pos
    # tail positions of a remainder-3 input
    base = bytearray((i * 17 + 3) & 0xFF for i in range(11))
    want = hash_entry(bytes(base), 0)
    for pos in (8, 9, 10):
        flipped = bytearray(base)
        flipped[pos] ^= 0x40
        assert hash_entry(bytes(flipped), 0) != want, pos


def test_length_and_seed_sensitivity():
    payload = bytes((i * 13 + 1) & 0xFF for i in range(40))
    assert hash_entry(payload, 0) != hash_entry(payload, 1)
    assert hash_entry(payload, 0) != hash_entry(payload[:39], 0)
    assert hash_entry(payload, 0) != hash_entry(payload + b"\x00", 0)
    assert hash_entry(payload, 0x18D) != hash_entry(payload, 0xBC9F1D34)


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
