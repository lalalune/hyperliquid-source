"""Assemble an explicitly pinned node #115 pre-loader compact-state fixture."""

import argparse
import csv
from hashlib import sha256
from io import StringIO
from pathlib import Path
from struct import unpack_from
import sys

DECODED_SIZE = 0x27A8
EVM_BLOCK_SIZE = 0x1B20
COMPOSED_SIZE = 0x26D8
COMPACT_SIZE = 0x42C8
COMPOSER_INPUT_AT = 0x1108
COMPOSER_INPUT_SIZE = 0xBB8
TABLES = {
    "compose": ("RE-016-state-compose-434b9f0-115",
                "469b522f4b6d9fc1d96e57cd06035e98d2277a8cdabbc9a05e4a96ac2e78c993"),
    "materialize": ("RE-016-state-materialize-3c2e860-115",
                    "59ae79f099b09b4ca3b194e20bc7bfb526043f071c0e20eb257cff632796fc41"),
}


def table(stage):
    packet, digest = TABLES[stage]
    path = Path("research/work-items") / packet / "layout.tsv"
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != digest:
        raise ValueError(f"unexpected {stage} layout digest")
    return tuple(csv.DictReader(StringIO(raw.decode("utf-8")), delimiter="\t"))


def apply_layout(rows, sources, size, padding):
    output = bytearray()
    for row in rows:
        offset = int(row["out_offset"], 16)
        source_offset = int(row["source_offset"], 16)
        length = int(row["length"], 16)
        source = sources[row["source"]]
        if offset != len(output) or not 0 <= source_offset < source_offset + length <= len(source):
            raise ValueError("layout row has a gap, overlap, or invalid source span")
        output.extend(source[source_offset:source_offset + length])
    if len(output) + len(padding) != size:
        raise ValueError("layout output does not match the required size")
    output.extend(padding)
    return bytes(output)


def assemble(decoded, evm_block, decoded_sha256, evm_sha256, height,
             composer_tail, compact_tail):
    """Produce the materializer layout before later startup writes or replay."""
    for name, data, size, digest in (
        ("decoded state", decoded, DECODED_SIZE, decoded_sha256),
        ("EVM block", evm_block, EVM_BLOCK_SIZE, evm_sha256),
    ):
        if len(data) != size:
            raise ValueError(f"{name} must be exactly {size:#x} bytes")
        if sha256(data).hexdigest() != digest.lower():
            raise ValueError(f"{name} SHA-256 does not match")
    if len(composer_tail) != 4 or len(compact_tail) != 3:
        raise ValueError("expected four composer tail bytes and three compact tail bytes")
    observed_height = unpack_from("<Q", decoded, 0x28)[0]
    if height != observed_height:
        raise ValueError(f"decoded height {observed_height} does not match {height}")
    inner = decoded[COMPOSER_INPUT_AT:COMPOSER_INPUT_AT + COMPOSER_INPUT_SIZE]
    composed = apply_layout(table("compose"), {"in": inner, "block": evm_block},
                            COMPOSED_SIZE, composer_tail)
    return apply_layout(table("materialize"), {"in": decoded, "composed": composed},
                        COMPACT_SIZE, compact_tail)


def read_exact_candidate(path, size):
    with path.open("rb") as source:
        return source.read(size + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_state", type=Path)
    parser.add_argument("evm_block", type=Path)
    parser.add_argument("--decoded-sha256", required=True)
    parser.add_argument("--evm-sha256", required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--composer-tail", required=True, help="four supplied bytes in hex")
    parser.add_argument("--compact-tail", required=True, help="three supplied bytes in hex")
    args = parser.parse_args()
    try:
        image = assemble(
            read_exact_candidate(args.decoded_state, DECODED_SIZE),
            read_exact_candidate(args.evm_block, EVM_BLOCK_SIZE),
            args.decoded_sha256, args.evm_sha256, args.height,
            bytes.fromhex(args.composer_tail), bytes.fromhex(args.compact_tail),
        )
    except (OSError, ValueError) as error:
        parser.exit(1, f"cannot assemble compact state fixture: {error}\n")
    sys.stdout.buffer.write(image)


if __name__ == "__main__":
    main()
