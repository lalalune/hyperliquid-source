"""Project named node #115 checkpoint Context to the raw-root comparison input."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

CLOCK = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{3}|[0-9]{6}|[0-9]{9}))?")
EPOCH = datetime(1970, 1, 1)
U64_MAX = (1 << 64) - 1


class Object(list):
    """Keep named entries separate until local duplicate checks."""


def unsigned(value, label):
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise ValueError(f"{label} must be a u64")
    return value


def select(object_, fields, label):
    if not isinstance(object_, Object):
        raise ValueError(f"{label} must be a named object")
    result = {}
    for name, value in object_:
        if name in fields:
            if name in result:
                raise ValueError(f"duplicate {label}.{name}")
            result[name] = value
    return result


def required(row, name):
    if name not in row:
        raise ValueError(f"missing {name}")
    return row[name]


def clock(value):
    match = CLOCK.fullmatch(value) if type(value) is str else None
    if not match:
        raise ValueError("expected canonical checkpoint clock text")
    year, month, day, hour, minute, second = (int(piece) for piece in match.groups()[:6])
    parsed = datetime(year, month, day, hour, minute, second)
    fraction = match.group(7)
    nanos = int(fraction.ljust(9, "0")) if fraction else 0
    if fraction:
        expected_width = 3 if nanos % 1_000_000 == 0 else 6 if nanos % 1000 == 0 else 9
        if nanos == 0 or expected_width != len(fraction):
            raise ValueError("clock uses a noncanonical fractional width")
    delta = parsed - EPOCH
    return {"unix_seconds": delta.days * 86400 + delta.seconds, "subsec_nanos": nanos}


def project(data, requested_height):
    checkpoint = json.loads(data, object_pairs_hook=Object)
    outer = select(checkpoint, {"exchange"}, "checkpoint")
    exchange = select(required(outer, "exchange"), {"locus"}, "exchange")
    locus = select(required(exchange, "locus"), {"ctx"}, "locus")
    relevant = {
        "hardfork_height", "hardfork", "height", "tx_index", "round", "consensus_round",
        "time", "prev_time", "next_oid", "next_lid", "next_twap_id", "system_nonce",
        "use_system_nonce", "mac",
    }
    ctx = select(required(locus, "ctx"), relevant, "ctx")
    height = unsigned(required(ctx, "height"), "height")
    if height != unsigned(requested_height, "requested height"):
        raise ValueError(f"checkpoint height {height} differs from requested {requested_height}")
    if "round" in ctx and "consensus_round" in ctx:
        raise ValueError("both round and consensus_round present")
    if "hardfork" in ctx:
        nested = select(ctx["hardfork"], {"version", "round"}, "hardfork")
        hardfork = {key: unsigned(required(nested, key), f"hardfork.{key}") for key in ("version", "round")}
    else:
        hardfork = {"version": 0, "round": 0}
    transaction = required(ctx, "tx_index")
    if transaction is not None:
        transaction = unsigned(transaction, "tx_index")
    flag = required(ctx, "use_system_nonce")
    if type(flag) is not bool:
        raise ValueError("use_system_nonce must be a JSON boolean")
    fixed = ("hardfork_height", "next_oid", "next_lid", "system_nonce", "mac")
    return {
        **{name: unsigned(required(ctx, name), name) for name in fixed},
        "hardfork": hardfork,
        "height": height,
        "tx_index": transaction,
        "round": unsigned(ctx.get("round", ctx.get("consensus_round", 0)), "round"),
        "time": clock(required(ctx, "time")),
        "prev_time": clock(required(ctx, "prev_time")),
        "next_twap_id": unsigned(ctx.get("next_twap_id", 0), "next_twap_id"),
        "use_system_nonce": flag,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", required=True, type=int)
    args = parser.parse_args()
    try:
        raw = args.checkpoint.read_bytes()
        if hashlib.sha256(raw).hexdigest() != args.sha256:
            raise ValueError("checkpoint artifact SHA-256 mismatch")
        output = project(raw, args.height)
    except (OSError, ValueError, RecursionError) as error:
        parser.error(str(error))
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
