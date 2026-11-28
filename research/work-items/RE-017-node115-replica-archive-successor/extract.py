"""Select and return a successor record from one pinned Dwellir replica shard."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_U64 = (1 << 64) - 1


def unsigned(value):
    return type(value) is int and 0 <= value <= MAX_U64


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f"invalid JSON constant {value}")


def successor(lines, chunk_start, checkpoint_height, expected_sha256):
    """Return native JSONL bytes after height and entire-shard pin checks."""
    if not unsigned(chunk_start) or not unsigned(checkpoint_height):
        raise ValueError("invalid shard or checkpoint coordinate")
    if checkpoint_height == MAX_U64 or checkpoint_height < chunk_start:
        raise ValueError("requested successor falls outside the shard")
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("expected a lowercase SHA-256")
    target = checkpoint_height + 1
    digest = hashlib.sha256()
    chosen = None
    for height, line in enumerate(lines, chunk_start + 1):
        digest.update(line)
        try:
            if not unsigned(height) or not line.endswith(b"\n"):
                raise ValueError("invalid archive row boundary")
            row = json.loads(line.decode("utf-8"), object_pairs_hook=unique_object,
                             parse_constant=invalid_constant)
            block = row.get("abci_block") if isinstance(row, dict) else None
            if not isinstance(block, dict) or "resps" not in row:
                raise ValueError("expected replica block and response field")
            if ("height" in row and
                    (not unsigned(row["height"]) or row["height"] != height)):
                raise ValueError("explicit height conflicts with archive coordinate")
            if not unsigned(block.get("round")) or not unsigned(block.get("parent_round")):
                raise ValueError("invalid consensus coordinate")
            if not isinstance(block.get("signed_action_bundles"), list):
                raise ValueError("expected signed action bundle array")
        except ValueError as error:
            raise ValueError(f"row at archive height {height}: {error}") from error
        if height == target:
            chosen = line
    if digest.hexdigest() != expected_sha256:
        raise ValueError("shard SHA-256 mismatch")
    if chosen is None:
        raise ValueError("requested successor is absent")
    return chosen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decompressed_shard", type=Path)
    parser.add_argument("--chunk-start", type=int, required=True)
    parser.add_argument("--checkpoint-height", type=int, required=True)
    parser.add_argument("--sha256", required=True, help="expected digest of decompressed bytes")
    args = parser.parse_args()
    try:
        with args.decompressed_shard.open("rb") as stream:
            row = successor(stream, args.chunk_start, args.checkpoint_height, args.sha256)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    sys.stdout.buffer.write(row)


if __name__ == "__main__":
    main()
