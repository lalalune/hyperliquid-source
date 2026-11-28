"""Project the selected empty #115 replay extractor on a local compact fixture."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
from struct import pack_into, unpack_from

COMPACT_SIZE = 0x42C8
DELAYER = 0x40C0
EMPTY_HEADER = (0, 8, 0, 0)
EMPTY_RESULT = (0, 8, 0)
EMPTY_CONSUMER_RANGE = (8, 8, 0, 8)


def project_empty_replay(image, expected_sha256, height):
    """Return the updated fixture, extractor qwords and four consumer range qwords."""
    if len(image) != COMPACT_SIZE:
        raise ValueError("expected exactly 0x42c8 bytes of compact state")
    if sha256(image).hexdigest() != expected_sha256.lower():
        raise ValueError("compact state SHA-256 does not match")
    if unpack_from("<Q", image, 0x28)[0] != height:
        raise ValueError("compact state height does not match")

    capacity, pointer_word, head, count = unpack_from("<4Q", image, DELAYER)
    if capacity or head or count:
        raise ValueError("input is outside the zero-capacity, zero-head, empty path")
    if not pointer_word or pointer_word % 8:
        raise ValueError("empty fixture pointer word must be nonzero and eight-byte aligned")

    out = bytearray(image)
    pack_into("<4Q", out, DELAYER, *EMPTY_HEADER)
    return bytes(out), EMPTY_RESULT, EMPTY_CONSUMER_RANGE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compact_state", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", required=True, type=int)
    arguments = parser.parse_args()
    try:
        with arguments.compact_state.open("rb") as source:
            image = source.read(COMPACT_SIZE + 1)
        out, extractor, consumer = project_empty_replay(
            image, arguments.sha256, arguments.height,
        )
    except (OSError, ValueError) as error:
        parser.exit(1, f"cannot project empty replay extractor: {error}\n")
    print(json.dumps({
        "height": arguments.height,
        "output_sha256": sha256(out).hexdigest(),
        "extractor_words": extractor,
        "consumer_range_words": consumer,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
