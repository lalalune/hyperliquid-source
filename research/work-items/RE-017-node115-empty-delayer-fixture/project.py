"""Project the selected ordinary-empty node #115 action-delayer load path."""

import argparse
from hashlib import sha256
from pathlib import Path
from struct import pack_into, unpack_from
import sys

COMPACT_SIZE = 0x42C8
DELAYER = 0x40C0


def project_empty_delayer(image, expected_sha256, height):
    """Return an updated compact fixture without resolving native pointers."""
    if len(image) != COMPACT_SIZE:
        raise ValueError("expected exactly 0x42c8 bytes of compact state")
    if sha256(image).hexdigest() != expected_sha256.lower():
        raise ValueError("compact state SHA-256 does not match")
    observed_height, = unpack_from("<Q", image, 0x28)
    if observed_height != height:
        raise ValueError(f"compact state height {observed_height} does not match {height}")

    representation, = unpack_from("<Q", image, DELAYER)
    ring_count, destination_word = unpack_from("<QQ", image, DELAYER + 0x18)
    if representation == 1 << 63:
        raise ValueError("sentinel representation is outside the selected fixture path")
    if ring_count:
        raise ValueError("nonempty ring is outside the selected fixture path")
    if destination_word:
        raise ValueError("nonzero destination word is outside the selected fixture path")

    result = bytearray(image)
    pack_into("<4Q", result, DELAYER + 0x20, 0, 8, 0, 0)
    pack_into("<Q", result, DELAYER + 0x60, 0)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compact_state", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", required=True, type=int)
    arguments = parser.parse_args()
    try:
        with arguments.compact_state.open("rb") as source:
            image = source.read(COMPACT_SIZE + 1)
        result = project_empty_delayer(image, arguments.sha256, arguments.height)
    except (ValueError, OSError) as error:
        parser.exit(1, f"cannot project selected action-delayer fixture: {error}\n")
    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    main()
