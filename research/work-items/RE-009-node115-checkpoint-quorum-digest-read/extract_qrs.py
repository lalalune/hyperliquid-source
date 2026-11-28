"""Project a digest candidate from a checksum-verified named checkpoint envelope."""

import argparse
import hashlib
import json
from pathlib import Path
import re

import msgpack


class MapPairs(list):
    """Keep map key occurrences distinct from an array of values."""


def decode_digest(payload):
    if isinstance(payload, MapPairs):
        if len(payload) != 3:
            raise ValueError("expected a three-field named quorum payload")
        values = [value for key, value in payload if key == "h"]
        if len(values) != 1:
            raise ValueError("expected exactly one quorum payload h field")
        digest = values[0]
    elif isinstance(payload, list) and len(payload) == 3:
        digest = payload[0]
    else:
        raise ValueError("unsupported quorum payload shape")
    if not isinstance(digest, str) or not re.fullmatch(r"0x[0-9a-f]{64}", digest):
        raise ValueError("expected the native 32-byte lowercase hex digest")
    return digest


def read_rows(reader, wanted_height):
    digest = None
    count = 0
    for _ in range(reader.read_array_header()):
        if reader.read_array_header() != 2:
            raise ValueError("expected a two-element quorum row")
        row_height = reader.unpack()
        if type(row_height) is not int or not 0 <= row_height < 1 << 64:
            raise ValueError("expected a quorum row height in the u64 range")
        if row_height != wanted_height:
            reader.skip()
            continue
        candidate = decode_digest(reader.unpack())
        if digest is not None and digest != candidate:
            raise ValueError("conflicting quorum digest rows at the requested height")
        digest = candidate
        count += 1
    return digest, count


def read_field(reader, name, read_value):
    found = False
    result = None
    for _ in range(reader.read_map_header()):
        if reader.unpack() == name:
            if found:
                raise ValueError(f"duplicate {name} field")
            found = True
            result = read_value()
        else:
            reader.skip()
    if not found:
        raise ValueError(f"missing {name} field")
    return result


def extract(path, sha256, height):
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ValueError("expected a lowercase SHA-256 digest")
    if type(height) is not int or not 0 <= height < 1 << 64:
        raise ValueError("requested height must be a u64")
    with path.open("rb") as source:
        size = source.seek(0, 2)
        source.seek(0)
        if hashlib.file_digest(source, "sha256").hexdigest() != sha256:
            raise ValueError("checkpoint SHA-256 mismatch")
        source.seek(0)
        reader = msgpack.Unpacker(source, raw=False, strict_map_key=False, object_pairs_hook=MapPairs)
        digest, count = read_field(
            reader, "exchange",
            lambda: read_field(
                reader, "advt", lambda: read_field(reader, "qrs", lambda: read_rows(reader, height))
            ),
        )
        if reader.tell() != size:
            raise ValueError("expected a single complete checkpoint document")
    if digest is None:
        raise ValueError("no quorum digest row at the requested height")
    return {
        "kind": "checkpoint_abci_quorum_candidate",
        "source_sha256": sha256,
        "row_height": height,
        "digest": digest,
        "agreeing_rows": count,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path, help="decompressed MessagePack checkpoint")
    parser.add_argument("--sha256", required=True, help="independently supplied SHA-256")
    parser.add_argument("--height", required=True, type=int, help="quorum row height")
    args = parser.parse_args()
    try:
        print(json.dumps(extract(args.checkpoint, args.sha256, args.height), sort_keys=True))
    except (OSError, ValueError, msgpack.UnpackException) as exc:
        parser.exit(2, f"checkpoint quorum digest: {exc}\n")


if __name__ == "__main__":
    main()
