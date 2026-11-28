"""Select raw ABCI references from a local node #115 abci_hashes export."""

import argparse
import json
from pathlib import Path
import re

RAW_DIGEST = re.compile(r"0x[0-9a-f]{64}")
MAX_HEIGHT = (1 << 64) - 1


def distinct_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate field: {key}")
        result[key] = value
    return result


def read_references(lines, requested):
    """Return exactly one 32-byte digest per requested height."""
    wanted = set(requested)
    if any(type(height) is not int or not 0 <= height <= MAX_HEIGHT for height in wanted):
        raise ValueError("invalid reference height")
    roots = {}
    for number, line in enumerate(lines, 1):
        try:
            row = json.loads(line, object_pairs_hook=distinct_object)
            if not isinstance(row, dict):
                raise ValueError("expected an abci_hashes object")
            height = row.get("height")
            digest = row.get("abci_digest")
            if type(height) is not int or not 0 <= height <= MAX_HEIGHT:
                raise ValueError("invalid record height")
            if not isinstance(digest, str) or RAW_DIGEST.fullmatch(digest) is None:
                raise ValueError("invalid raw abci_digest")
            if not isinstance(row.get("exchange_abci_hash"), (str, list)):
                raise ValueError("missing or invalid exchange_abci_hash")
            if height in wanted:
                if height in roots:
                    raise ValueError(f"duplicate reference for height {height}")
                roots[height] = bytes.fromhex(digest[2:])
        except ValueError as error:
            raise ValueError(f"line {number}: {error}") from error
    missing = sorted(wanted - roots.keys())
    if missing:
        raise ValueError(f"no raw ABCI reference for heights {missing}")
    return roots


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hashes_file", type=Path)
    parser.add_argument("height", type=int, nargs="+")
    args = parser.parse_args()
    try:
        with args.hashes_file.open(encoding="utf-8") as stream:
            refs = read_references(stream, args.height)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({h: "0x" + d.hex() for h, d in refs.items()}, sort_keys=True))


if __name__ == "__main__":
    main()
