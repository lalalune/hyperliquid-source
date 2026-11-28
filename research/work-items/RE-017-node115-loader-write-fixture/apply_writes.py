"""Apply one selected node #115 loader store group to a pinned compact fixture."""

import argparse
from hashlib import sha256
from pathlib import Path
from struct import pack_into, unpack_from
import sys

COMPACT_SIZE = 0x42C8
U64_MAX = (1 << 64) - 1
STAGES = ("entry", "after-c-staking", "after-action-delayer")


def apply(image, expected_sha256, height, stage):
    """Apply direct stores at one boundary, leaving intervening calls to the fixture."""
    if len(image) != COMPACT_SIZE:
        raise ValueError("expected exactly 0x42c8 bytes of compact state")
    if sha256(image).hexdigest() != expected_sha256.lower():
        raise ValueError("compact state SHA-256 does not match")
    observed_height = unpack_from("<Q", image, 0x28)[0]
    if observed_height != height:
        raise ValueError(f"compact state height {observed_height} does not match {height}")
    out = bytearray(image)
    if stage == "entry":
        version, = unpack_from("<Q", image, 0x18)
        round_number, = unpack_from("<Q", image, 0x30)
        pack_into("<QQQ", out, 0x10, height, min(version + 1, U64_MAX), round_number)
        pack_into("<Q", out, 0x10E8, 0)
        pack_into("<Q", out, 0xDF0, round_number)
    elif stage == "after-c-staking":
        out[0xEF8:0xF00] = image[0x30:0x38]
    elif stage == "after-action-delayer":
        pack_into("<H", out, 0x3E28, 0)
        pack_into("<H", out, 0x3EE0, 0)
        out[0x39B0] = 2
    else:
        raise ValueError("unrecognized loader store boundary")
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compact_state", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", required=True, type=int)
    parser.add_argument("--stage", required=True, choices=STAGES)
    args = parser.parse_args()
    try:
        with args.compact_state.open("rb") as source:
            image = source.read(COMPACT_SIZE + 1)
        result = apply(image, args.sha256, args.height, args.stage)
    except (OSError, ValueError) as error:
        parser.exit(1, f"cannot apply selected loader stores: {error}\n")
    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    main()
