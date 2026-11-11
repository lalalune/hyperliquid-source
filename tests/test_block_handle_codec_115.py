"""Model tests for the node #115 BlockHandle wire codec.

Run from the repository root:
    python3 tests/test_block_handle_codec_115.py

Covers the encoder byte vectors, decoder acceptance (including
overlong forms and the 10th-byte rule), decoder failure states
(handle zeroed, slice position, corruption message), and
randomised round trips against tools/block_handle_codec_115.py.
Prints a check count and "checks pass" on success.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.block_handle_codec_115 import (  # noqa: E402
    block_handle_decode,
    block_handle_encode,
    encode_varint64,
    get_varint64,
)

CHECKS = 0


def check(cond, label):
    global CHECKS
    CHECKS += 1
    if not cond:
        raise AssertionError(label)


def expect_encode(value, hexbytes):
    got = encode_varint64(value)
    check(got == bytes.fromhex(hexbytes),
          "encode %#x: %s != %s" % (value, got.hex(), hexbytes))


def expect_decode(data, ok, offset, size, consumed):
    got = block_handle_decode(bytes(data))
    check(got["ok"] == ok, "decode %s ok flag" % bytes(data).hex())
    check(got["offset"] == offset and got["size"] == size,
          "decode %s fields %s" % (bytes(data).hex(), got))
    check(got["consumed"] == consumed,
          "decode %s consumed %s" % (bytes(data).hex(), got))
    if ok:
        check(got["status"] == "ok" and got["message"] is None,
              "decode %s status" % bytes(data).hex())
    else:
        check(got["status"] == "corruption"
              and got["message"] == "bad block handle",
              "decode %s status" % bytes(data).hex())


def main():
    # Encoder vectors (varint64: LEB128, low groups first).
    expect_encode(0, "00")
    expect_encode(1, "01")
    expect_encode(0x7F, "7f")
    expect_encode(0x80, "8001")
    expect_encode(300, "ac02")
    expect_encode(0x3FFF, "ff7f")
    expect_encode(0x4000, "808001")
    expect_encode(1 << 63, "80808080808080808001")
    expect_encode((1 << 64) - 1, "ffffffffffffffffff01")
    check(block_handle_encode(0, 0) == b"\x00\x00", "handle 0,0")
    check(block_handle_encode(0x80, 0x7F) == bytes.fromhex("80017f"),
          "handle 128,127")
    check(len(block_handle_encode((1 << 64) - 1, (1 << 64) - 1)) == 20,
          "max handle is 20 bytes")

    # Decoder: plain and round-trip forms.
    expect_decode(b"\x00\x00", True, 0, 0, 2)
    expect_decode(b"\xac\x02\x7f", True, 300, 127, 3)
    expect_decode(bytes.fromhex("ffffffffffffffffff01") * 1
                  + b"\x01", True, (1 << 64) - 1, 1, 11)
    expect_decode(block_handle_encode(123456789, 987654321),
                  True, 123456789, 987654321,
                  len(block_handle_encode(123456789, 987654321)))
    # Bytes past the handle are left in the slice.
    expect_decode(b"\x01\x02\x03\x04", True, 1, 2, 2)

    # Decoder: overlong encodings are accepted up to 10 bytes.
    expect_decode(b"\x80\x80\x00\x00", True, 0, 0, 4)
    expect_decode(b"\x81\x80\x80\x80\x80\x80\x80\x80\x80\x00\x05",
                  True, 1, 5, 11)

    # Decoder: the 10th byte contributes only its lowest bit.
    expect_decode(b"\x80" * 9 + b"\x7f\x00", True, 1 << 63, 0, 11)
    expect_decode(b"\xff" * 9 + b"\x01\x00", True, (1 << 64) - 1, 0, 11)
    expect_decode(b"\xff" * 9 + b"\x00\x00", True, (1 << 63) - 1, 0, 11)

    # Decoder failures: corruption, handle zeroed, slice position
    # pinned per varint stage.
    expect_decode(b"", False, 0, 0, 0)                # empty input
    expect_decode(b"\x80", False, 0, 0, 0)            # first varint cut
    expect_decode(b"\x80" * 9 + b"\x80", False, 0, 0, 0)   # 10th cont.
    expect_decode(b"\xff" * 10, False, 0, 0, 0)       # 10th cont. set
    expect_decode(b"\x01", False, 0, 0, 1)            # second missing
    expect_decode(b"\x01\x80", False, 0, 0, 1)        # second cut
    expect_decode(b"\x01" + b"\x80" * 9 + b"\x80",
                  False, 0, 0, 1)                     # second 10th cont.

    # Leaf rule directly: limit handling and no store on failure.
    check(get_varint64(b"", 0, 0) is None, "leaf empty")
    check(get_varint64(b"\x05", 0, 1) == (5, 1), "leaf one byte")
    check(get_varint64(b"\x85", 0, 1) is None, "leaf cut at limit")
    check(get_varint64(b"\x85\x01", 0, 2) == (133, 2), "leaf two byte")
    check(get_varint64(b"\x80" * 9 + b"\x02", 0, 10) == (0, 10),
          "leaf 10th byte bit0 clear")
    check(get_varint64(b"\x80" * 9 + b"\x03", 0, 10) == (1 << 63, 10),
          "leaf 10th byte bit0 set")

    # Randomised round trips, including boundary magnitudes.
    rng = random.Random(0xB10C)
    edges = [0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, (1 << 21) - 1, 1 << 21,
             (1 << 32) - 1, 1 << 32, (1 << 63) - 1, 1 << 63,
             (1 << 64) - 1]
    for _ in range(3000):
        off = rng.choice(edges + [rng.getrandbits(rng.choice(
            [1, 7, 8, 14, 21, 32, 56, 63, 64]))])
        size = rng.choice(edges + [rng.getrandbits(rng.choice(
            [1, 7, 8, 14, 21, 32, 56, 63, 64]))])
        blob = block_handle_encode(off, size)
        check(len(blob) <= 20, "encoded length cap")
        expect_decode(blob, True, off, size, len(blob))

    print("%d checks pass" % CHECKS)


if __name__ == "__main__":
    main()
