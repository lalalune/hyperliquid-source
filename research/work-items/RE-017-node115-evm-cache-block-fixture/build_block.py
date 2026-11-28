"""Build the ordinary #115 EVM cache-hit aggregate from pinned local inputs."""

import argparse
from hashlib import sha256
from pathlib import Path
import sys

RECORD_SIZE = 0x810
DESCRIPTOR_SIZE = 0xF8
LANE_COUNT = 3
RECORD_FILE_SIZE = LANE_COUNT * RECORD_SIZE
DESCRIPTOR_FILE_SIZE = LANE_COUNT * DESCRIPTOR_SIZE + 8


def build_block(records, records_sha256, descriptors, descriptors_sha256):
    """Join lane pairs in account, contract and storage order, then append the tail."""
    for name, image, digest, size in (
        ("cache records", records, records_sha256, RECORD_FILE_SIZE),
        ("descriptors and tail", descriptors, descriptors_sha256, DESCRIPTOR_FILE_SIZE),
    ):
        if len(image) != size:
            raise ValueError(f"{name} must contain exactly {size:#x} bytes")
        if sha256(image).hexdigest() != digest.lower():
            raise ValueError(f"{name} SHA-256 does not match")

    block = bytearray()
    for lane in range(LANE_COUNT):
        descriptor_at = lane * DESCRIPTOR_SIZE
        record_at = lane * RECORD_SIZE
        block.extend(descriptors[descriptor_at:descriptor_at + DESCRIPTOR_SIZE])
        block.extend(records[record_at:record_at + RECORD_SIZE])
    block.extend(descriptors[-8:])
    return bytes(block)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path, help="three concatenated 0x810 cache records")
    parser.add_argument("descriptors", type=Path, help="three 0xf8 descriptors and an 8-byte tail")
    parser.add_argument("--records-sha256", required=True)
    parser.add_argument("--descriptors-sha256", required=True)
    arguments = parser.parse_args()
    try:
        with arguments.records.open("rb") as stream:
            records = stream.read(RECORD_FILE_SIZE + 1)
        with arguments.descriptors.open("rb") as stream:
            descriptors = stream.read(DESCRIPTOR_FILE_SIZE + 1)
        block = build_block(records, arguments.records_sha256,
                            descriptors, arguments.descriptors_sha256)
    except (OSError, ValueError) as error:
        parser.exit(1, f"cannot build selected EVM cache block: {error}\n")
    sys.stdout.buffer.write(block)


if __name__ == "__main__":
    main()
