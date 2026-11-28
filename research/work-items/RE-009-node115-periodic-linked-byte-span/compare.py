"""Check byte identity of a periodic RMP payload and a serializer-slice capture."""

import argparse
import hashlib
import json
from pathlib import Path
import re

SHA256 = re.compile(r"[0-9a-f]{64}")
CHUNK = 65536


def compare(payload, payload_sha, capture, capture_sha):
    if not all(SHA256.fullmatch(value) for value in (payload_sha, capture_sha)):
        raise ValueError("expected lowercase SHA-256 pins for both artifacts")
    expected, actual = hashlib.sha256(), hashlib.sha256()
    expected_size = actual_size = 0
    first_difference = None
    with payload.open("rb") as left, capture.open("rb") as right:
        while True:
            a, b = left.read(CHUNK), right.read(CHUNK)
            if not a and not b:
                break
            if first_difference is None and a != b:
                shared = next((index for index, (x, y) in enumerate(zip(a, b)) if x != y),
                              min(len(a), len(b)))
                assert expected_size == actual_size
                first_difference = expected_size + shared
            expected.update(a)
            actual.update(b)
            expected_size += len(a)
            actual_size += len(b)
    if expected.hexdigest() != payload_sha:
        raise ValueError("periodic payload SHA-256 mismatch")
    if actual.hexdigest() != capture_sha:
        raise ValueError("serializer slice SHA-256 mismatch")
    return {
        "identical": first_difference is None,
        "first_difference_offset": first_difference,
        "periodic_bytes": expected_size,
        "serializer_bytes": actual_size,
        "periodic_sha256": payload_sha,
        "serializer_sha256": capture_sha,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("payload_sha256")
    parser.add_argument("capture", type=Path)
    parser.add_argument("capture_sha256")
    args = parser.parse_args()
    try:
        result = compare(args.payload, args.payload_sha256, args.capture, args.capture_sha256)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
