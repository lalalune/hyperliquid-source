"""Read named checkpoint height and round without materializing the rest of state."""

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path

import msgpack


@dataclass(frozen=True)
class Coordinates:
    height: int
    round: int
    round_field: str | None


def select(unpacker, readers):
    """Read one named map and skip values that are outside the selected path."""
    selected = {}
    for _ in range(unpacker.read_map_header()):
        key = unpacker.unpack()
        if not isinstance(key, str):
            raise ValueError("expected a named MessagePack map")
        reader = readers.get(key)
        if reader is None:
            unpacker.skip()
            continue
        if key in selected:
            raise ValueError(f"duplicate checkpoint key: {key}")
        selected[key] = reader(unpacker)
    return selected


def scalar(unpacker):
    value = unpacker.unpack()
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("checkpoint coordinate must be an unsigned 64-bit integer")
    return value


def context(unpacker):
    fields = select(unpacker, {"height": scalar, "round": scalar, "consensus_round": scalar})
    if "height" not in fields:
        raise ValueError("missing checkpoint height")
    aliases = set(fields) & {"round", "consensus_round"}
    if len(aliases) > 1:
        raise ValueError("round and consensus_round denote the same checkpoint field")
    field = next(iter(aliases), None)
    return Coordinates(fields["height"], fields.get(field, 0), field)


def require(unpacker, key, child):
    value = select(unpacker, {key: child})
    if key not in value:
        raise ValueError(f"missing checkpoint key: {key}")
    return value[key]


def read_coordinates(source, expected_sha256):
    with source.open("rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected_sha256:
            raise ValueError("checkpoint SHA-256 mismatch")
        stream.seek(0)
        unpacker = msgpack.Unpacker(stream, raw=False)
        try:
            result = require(unpacker, "exchange", lambda u: require(
                u, "locus", lambda locus: require(locus, "ctx", context)
            ))
        except msgpack.OutOfData as error:
            raise ValueError("incomplete checkpoint object") from error
        if unpacker.tell() != size:
            raise ValueError("trailing data after checkpoint object")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        coordinates = read_coordinates(args.checkpoint, args.sha256)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({
        "height": coordinates.height,
        "round": coordinates.round,
        "round_field": coordinates.round_field,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
