"""Stage an admitted #115 tracker-delay fixture word before compact assembly."""

import argparse
from hashlib import sha256
from pathlib import Path
from struct import unpack_from
import sys

DECODED_SIZE = 0x27A8
DECODED_DELAY = 0x23B8
F64_MARKER = 0xCB
F64_SIGN = 1 << 63
F64_INF = 0x7FF0000000000000


def delay_bytes(token):
    """Convert a selected raw binary64 token, or explicit whole-tracker absence."""
    if token is None:
        return bytes(8)
    if len(token) != 9 or token[0] != F64_MARKER:
        raise ValueError("present tracker requires one complete MessagePack float64 adu token")
    bits = int.from_bytes(token[1:], "big")
    if bits != F64_SIGN and not 0 <= bits < F64_INF:
        raise ValueError("tracker delay must be finite and nonnegative")
    return bits.to_bytes(8, "little")


def project_delay(decoded, expected_sha256, height, token):
    """Produce the decoded fixture expected by the compact assembly stage."""
    if len(decoded) != DECODED_SIZE:
        raise ValueError("expected exactly 0x27a8 bytes of decoded state")
    if sha256(decoded).hexdigest() != expected_sha256.lower():
        raise ValueError("decoded state SHA-256 does not match")
    if unpack_from("<Q", decoded, 0x28)[0] != height:
        raise ValueError("decoded state height does not match")
    return decoded[:DECODED_DELAY] + delay_bytes(token) + decoded[DECODED_DELAY + 8:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_state", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", required=True, type=int)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--tracker-absent", action="store_true")
    choice.add_argument("--adu-f64-hex")
    arguments = parser.parse_args()
    try:
        with arguments.decoded_state.open("rb") as source:
            image = source.read(DECODED_SIZE + 1)
        token = (None if arguments.tracker_absent
                 else bytes.fromhex(arguments.adu_f64_hex))
        result = project_delay(image, arguments.sha256, arguments.height, token)
    except (ValueError, OSError) as error:
        parser.exit(1, f"cannot stage selected tracker delay: {error}\n")
    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    main()
