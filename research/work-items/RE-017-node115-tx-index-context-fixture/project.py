"""Stage the ordinary node #115 Context transaction-index option in a local fixture."""

import argparse
from hashlib import sha256
from pathlib import Path
from struct import pack_into, unpack_from
import sys

DECODED_SIZE = 0x27A8
INTS = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8, 0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}


def decode_tx_index(token):
    """Return selected native (tag, active payload) for omitted or supplied field."""
    if token is None:
        return 1, 0
    if token == b"\xc0":
        return 0, None
    if len(token) == 1 and token[0] < 0x80:
        return 1, token[0]
    if not token or token[0] not in INTS or len(token) != 1 + INTS[token[0]]:
        raise ValueError("expected one ordinary MessagePack integer or nil token")
    value = int.from_bytes(token[1:], "big", signed=token[0] >= 0xD0)
    if value < 0:
        raise ValueError("transaction index must be nonnegative")
    return 1, value


def stage(image, expected_sha256, height, token):
    if len(image) != DECODED_SIZE:
        raise ValueError("expected exactly 0x27a8 bytes of decoded state")
    if sha256(image).hexdigest() != expected_sha256.lower():
        raise ValueError("decoded fixture SHA-256 does not match")
    if unpack_from("<Q", image, 0x28)[0] != height:
        raise ValueError("decoded fixture height does not match")
    tag, value = decode_tx_index(token)
    output = bytearray(image)
    pack_into("<Q", output, 0x0, tag)
    if value is not None:
        pack_into("<Q", output, 0x8, value)
    return bytes(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_state", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", required=True, type=int)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--named-omitted", action="store_true")
    source.add_argument("--token-hex")
    arguments = parser.parse_args()
    try:
        token = None if arguments.named_omitted else bytes.fromhex(arguments.token_hex)
        with arguments.decoded_state.open("rb") as source:
            image = source.read(DECODED_SIZE + 1)
        output = stage(image, arguments.sha256, arguments.height, token)
    except (ValueError, OSError) as error:
        parser.exit(1, f"cannot stage selected transaction index: {error}\n")
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
