"""Compare #115 compact state LtHash lanes against expected cache-record digests."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
from struct import unpack_from

COMPACT_SIZE = 0x42C8
RECORD_SIZE = 0x810
OFFSETS = {"accounts_hash": 0x1200, "contracts_hash": 0x1B08, "storage_hash": 0x2410}


def validate_digests(digests):
    if set(digests) != set(OFFSETS):
        raise ValueError("expected all three named LtHash record digests")
    for name, digest in digests.items():
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError(f"{name} must be a SHA-256 hex digest")
        if any(char not in "0123456789abcdef" for char in digest.lower()):
            raise ValueError(f"{name} must be a SHA-256 hex digest")


def compare(image, expected_image_sha256, height, expected_record_digests):
    """Compare selected complete LtHash records, including their two counters."""
    if len(image) != COMPACT_SIZE:
        raise ValueError("expected exactly 0x42c8 bytes of compact state")
    image_sha256 = sha256(image).hexdigest()
    if image_sha256 != expected_image_sha256.lower():
        raise ValueError("compact state SHA-256 does not match")
    observed_height = unpack_from("<Q", image, 0x28)[0]
    if observed_height != height:
        raise ValueError(f"compact state height {observed_height} does not match {height}")
    validate_digests(expected_record_digests)
    records = {}
    for name, offset in OFFSETS.items():
        observed = sha256(image[offset:offset + RECORD_SIZE]).hexdigest()
        expected = expected_record_digests[name].lower()
        records[name] = {
            "offset": offset,
            "record_bytes": RECORD_SIZE,
            "observed_layout_sha256": observed,
            "expected_layout_sha256": expected,
            "matches": observed == expected,
        }
    return {
        "height": observed_height,
        "compact_state_sha256": image_sha256,
        "records": records,
        "matches": all(row["matches"] for row in records.values()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compact_state", type=Path)
    parser.add_argument("--state-sha256", required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--accounts-sha256", required=True)
    parser.add_argument("--contracts-sha256", required=True)
    parser.add_argument("--storage-sha256", required=True)
    args = parser.parse_args()
    digests = {
        "accounts_hash": args.accounts_sha256,
        "contracts_hash": args.contracts_sha256,
        "storage_hash": args.storage_sha256,
    }
    try:
        with args.compact_state.open("rb") as source:
            report = compare(source.read(COMPACT_SIZE + 1), args.state_sha256, args.height, digests)
    except (OSError, ValueError) as error:
        parser.exit(2, f"invalid input to compact state LtHash comparison: {error}\n")
    print(json.dumps(report, indent=2))
    return 0 if report["matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
