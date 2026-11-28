"""Apply the selected node #115 local-startup rewrite to a pinned compact fixture."""

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from struct import pack_into, unpack_from
import sys

COMPACT_SIZE = 0x42C8
U64_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class LocalStartup:
    image: bytes
    original_pair: tuple
    replay_pair: tuple
    rewritten: bool


def rewrite_local(image, image_sha256, height):
    if len(image) != COMPACT_SIZE:
        raise ValueError("expected exactly 0x42c8 bytes of compact state")
    if sha256(image).hexdigest() != image_sha256.lower():
        raise ValueError("compact state SHA-256 does not match")

    version, hardfork_round, observed_height, context_round = unpack_from("<4Q", image, 0x18)
    if observed_height != height:
        raise ValueError("compact state height does not match")
    original = version, hardfork_round
    tag, = unpack_from("<I", image, 0x10E8)
    if tag not in (0, 1):
        raise ValueError("unsupported local freeze option tag")
    if tag == 0:
        return LocalStartup(bytes(image), original, original, False)

    target, = unpack_from("<Q", image, 0x10F0)
    if target > observed_height:
        return LocalStartup(bytes(image), original, original, False)
    if target < observed_height:
        raise ValueError(f"scheduled freeze {target} is below checkpoint height {observed_height}")

    replay = min(version + 1, U64_MAX), context_round
    output = bytearray(image)
    pack_into("<QQ", output, 0x18, *replay)
    return LocalStartup(bytes(output), original, replay, True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compact_state", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", required=True, type=int)
    parser.add_argument("--image", action="store_true", help="emit the resulting compact image")
    arguments = parser.parse_args()
    try:
        with arguments.compact_state.open("rb") as source:
            image = source.read(COMPACT_SIZE + 1)
        result = rewrite_local(image, arguments.sha256, arguments.height)
    except (ValueError, OSError) as error:
        parser.exit(1, f"cannot apply selected local-startup rewrite: {error}\n")
    if arguments.image:
        sys.stdout.buffer.write(result.image)
    else:
        print(json.dumps({
            "original_pair": result.original_pair,
            "replay_pair": result.replay_pair,
            "rewritten": result.rewritten,
            "output_sha256": sha256(result.image).hexdigest(),
        }, sort_keys=True))


if __name__ == "__main__":
    main()
