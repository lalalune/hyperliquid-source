"""Apply one selected #115 replay begin-store group to pinned fixture bytes."""

import argparse
from hashlib import sha256
from pathlib import Path
from struct import pack_into, unpack_from
import sys

U64_MAX = (1 << 64) - 1
LAYOUTS = {
    "compact": (0x42C8, (0xE08, 0xF28)),
    "expanded": (0x4E38, (0x1978, 0x1A98)),
}
STAGES = ("after-clock", "before-action-initializer")


def apply(image, expected_sha256, layout, height, stage, new_round=None):
    """Project direct stores only at a selected begin boundary."""
    if layout not in LAYOUTS:
        raise ValueError("unrecognized compact or expanded layout")
    size, copies = LAYOUTS[layout]
    if len(image) != size:
        raise ValueError(f"{layout} state must be exactly {size:#x} bytes")
    if sha256(image).hexdigest() != expected_sha256.lower():
        raise ValueError("state SHA-256 does not match")
    observed_height, = unpack_from("<Q", image, 0x28)
    if observed_height != height:
        raise ValueError("fixture height does not match the selected boundary")

    result = bytearray(image)
    if stage == "after-clock":
        if type(new_round) is not int or not 0 <= new_round <= U64_MAX:
            raise ValueError("after-clock requires the admitted u64 new round")
        pack_into("<Q", result, 0x28, min(height + 1, U64_MAX))
        pack_into("<Q", result, 0x00, 0)
        for offset in (0x30, *copies):
            pack_into("<Q", result, offset, new_round)
    elif stage == "before-action-initializer":
        if new_round is not None:
            raise ValueError("before-action-initializer does not take an incoming round")
        pack_into("<QQ", result, 0, 1, 0)
    else:
        raise ValueError("unrecognized begin-store boundary")
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--layout", choices=LAYOUTS, required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--new-round", type=int)
    args = parser.parse_args()
    try:
        with args.state.open("rb") as source:
            image = source.read(LAYOUTS[args.layout][0] + 1)
        output = apply(image, args.sha256, args.layout, args.height, args.stage, args.new_round)
    except (OSError, ValueError) as error:
        parser.exit(1, f"cannot apply replay begin stores: {error}\n")
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
