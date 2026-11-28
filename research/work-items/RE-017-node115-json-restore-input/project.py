"""Read selected node #115 local restore inputs from a pinned named JSON file."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

MISSING = object()


class ObjectMembers(list):
    """Keep JSON object order and duplicate keys until relevant fields are read."""


def member(obj, *names, default=MISSING):
    if not isinstance(obj, ObjectMembers):
        raise ValueError(f"expected JSON object containing {names[0]}")
    matches = [value for name, value in obj if name in names]
    if len(matches) > 1:
        raise ValueError(f"duplicate field: {names[0]}")
    if matches:
        return matches[0]
    if default is MISSING:
        raise ValueError(f"missing field: {names[0]}")
    return default


def unsigned(value, name):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"{name} must be a u64")
    return value


def invalid_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def project(raw, expected_sha256, requested_height):
    """Project the selected named fields used by the offline local-restore fixture."""
    digest = sha256(raw).hexdigest()
    if digest != expected_sha256.lower():
        raise ValueError("checkpoint SHA-256 does not match")
    requested_height = unsigned(requested_height, "requested_height")
    root = json.loads(raw.decode("utf-8"), object_pairs_hook=ObjectMembers,
                      parse_constant=invalid_constant)
    exchange = member(root, "exchange")
    ctx = member(member(exchange, "locus"), "ctx")
    height = unsigned(member(ctx, "height"), "height")
    if height != requested_height:
        raise ValueError(f"decoded height {height} differs from requested height {requested_height}")
    round_number = unsigned(member(ctx, "round", "consensus_round", default=0), "round")
    hardfork = member(ctx, "hardfork", default=ObjectMembers([("version", 0), ("round", 0)]))
    freeze = member(exchange, "scheduled_freeze_height", default=None)
    return {
        "checkpoint_sha256": digest,
        "persisted_height": height,
        "persisted_round": round_number,
        "hardfork": {
            "version": unsigned(member(hardfork, "version"), "hardfork.version"),
            "round": unsigned(member(hardfork, "round"), "hardfork.round"),
        },
        "scheduled_freeze": None if freeze is None else unsigned(freeze, "scheduled_freeze"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", required=True, type=int)
    args = parser.parse_args()
    try:
        fields = project(args.checkpoint.read_bytes(), args.sha256, args.height)
    except (OSError, ValueError) as error:
        parser.exit(1, f"failed to read selected local JSON restore fields: {error}\n")
    print(json.dumps(fields, indent=2))


if __name__ == "__main__":
    main()
