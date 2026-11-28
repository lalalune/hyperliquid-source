"""Select one offline node #115 replica export record by its explicit height."""

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class Coordinates:
    height: int
    round: int
    parent_round: int
    bundle_count: int
    responses_present: bool


def distinct_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate field: {key}")
        result[key] = value
    return result


def uint64(value, field):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError(f"{field} must be an unsigned 64-bit integer")
    return value


def parse_coordinates(line):
    row = json.loads(line, object_pairs_hook=distinct_object)
    if not isinstance(row, dict) or not isinstance(row.get("abci_block"), dict):
        raise ValueError("expected an abci_block object")
    if "resps" not in row:
        raise ValueError("missing resps")
    block = row["abci_block"]
    bundles = block.get("signed_action_bundles")
    if not isinstance(bundles, list):
        raise ValueError("expected signed_action_bundles array")
    return Coordinates(
        uint64(row.get("height"), "height"),
        uint64(block.get("round"), "round"),
        uint64(block.get("parent_round"), "parent_round"),
        len(bundles),
        row["resps"] is not None,
    )


def select_height(lines, height):
    uint64(height, "requested height")
    selected = None
    for index, line in enumerate(lines, 1):
        try:
            row = parse_coordinates(line)
        except ValueError as error:
            raise ValueError(f"line {index}: {error}") from error
        if row.height == height:
            if selected is not None:
                raise ValueError(f"ambiguous replica height {height}")
            selected = row
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("replica_file", type=Path)
    parser.add_argument("height", type=int)
    args = parser.parse_args()
    try:
        with args.replica_file.open(encoding="utf-8") as stream:
            row = select_height(stream, args.height)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if row is None:
        parser.exit(1, f"no replica row at height {args.height}\n")
    print(json.dumps(asdict(row), sort_keys=True))


if __name__ == "__main__":
    main()
