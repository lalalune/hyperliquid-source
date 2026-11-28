"""Compare two ordinary #115 risk settings subtrees with their raw ABCI reference."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
from types import ModuleType

COOLDOWN = "partial_liquidation_cooldown"
LIMITS = "default_hip3_limits"
LIMIT_KEYS = ("total_oi_cap2", "oi_sz_cap_per_perp", "max_transfer_ntl2",
              "max_under_initial_margin_transfer_ntl2", "daily_px_range", "max_n_users_with_positions")
SLOTS = {COOLDOWN: 37, LIMITS: 42}
DEPENDENCIES = {
    "rmp": ("RE-009-node115-msgpack-context-projection/project.py",
            "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "tree": ("RE-009-node115-context-root-isolation/isolate.py",
             "acb3c71a3c56b42d9614aeb78225cfc90f364e8468db144c0f55e22a175fc3ec"),
}


def load_helpers(folder):
    modules = {}
    for name, (relative, pin) in DEPENDENCIES.items():
        path = folder / relative
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != pin:
            raise ValueError(f"source pin mismatch for {relative}")
        module = ModuleType(f"node115_settings_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def cooldown(u):
        before = u.tell()
        value = u.unpack()
        if value is not None and (type(value) is not float or u.tell() - before != 9 or not math.isfinite(value)):
            raise ValueError("expected nil or a finite MessagePack binary64 cooldown")
        return value

    def exchange(u):
        return rmp.select(u, {
            COOLDOWN: cooldown, LIMITS: lambda limits: rmp.select(limits, dict.fromkeys(LIMIT_KEYS, rmp.read_value)),
            "locus": lambda loc: rmp.require(loc, "ctx", lambda ctx: rmp.require(ctx, "height", rmp.read_value)),
        })

    with path.open("rb") as stream:
        reader = rmp.HashingReader(stream)
        unpacker = msgpack.Unpacker(reader, raw=False)
        try:
            fields = rmp.require(unpacker, "exchange", exchange)
        except msgpack.OutOfData as error:
            raise ValueError("incomplete named checkpoint object") from error
        consumed = unpacker.tell()
        while reader.read(65536):
            pass
        if reader.digest.hexdigest() != pin:
            raise ValueError("checkpoint SHA-256 mismatch")
        if consumed != reader.count:
            raise ValueError("trailing bytes after checkpoint object")
    if type(fields.get("locus")) is not int or fields["locus"] != height:
        raise ValueError("checkpoint Context height mismatch")
    if COOLDOWN not in fields or set(fields.get(LIMITS, {})) != set(LIMIT_KEYS):
        raise ValueError("expected cooldown and all six HIP-3 limit fields")
    return fields


def compare(kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    word(height, "checkpoint height")
    fields = read_checkpoint(kit["rmp"], checkpoint, checkpoint_pin, height)
    tree = kit["tree"]
    digest, ordered = tree.read_export(reference, reference_pin, height)
    if tree.digest(helper, ordered) != digest:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(ordered) is not tuple:
        raise ValueError("expected raw Exchange branch")

    def leaf(raw):
        output = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
        value = output.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(value):
            raise ValueError("local helper returned an invalid digest")
        return bytes.fromhex(value[2:])

    duration = fields[COOLDOWN]
    option = () if duration is None else ((0, leaf(struct.pack("<d", duration))),)
    option += ((1, leaf(word(int(duration is not None), "cooldown tag"))),)
    limits = tuple((slot, leaf(word(fields[LIMITS][key], key))) for slot, key in enumerate(LIMIT_KEYS))
    actual = dict(ordered)
    limit_slot = actual.get(SLOTS[LIMITS])
    limit_children = dict(limit_slot) if type(limit_slot) is tuple else {}
    return {"height": height, "reference_raw_digest": digest,
            "cooldown_slot_matches": actual.get(SLOTS[COOLDOWN]) == option,
            "ordered_limits_slot_matches": limit_slot == limits,
            "limits": {key: limit_children.get(index) == child
                       for (index, child), key in zip(limits, LIMIT_KEYS)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helpers", type=Path)
    parser.add_argument("hash_helper", type=Path)
    parser.add_argument("height", type=int)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("checkpoint_sha256")
    parser.add_argument("reference", type=Path)
    parser.add_argument("reference_sha256")
    args = parser.parse_args()
    try:
        result = compare(load_helpers(args.helpers), args.hash_helper, args.height, args.checkpoint,
                         args.checkpoint_sha256, args.reference, args.reference_sha256)
    except (ValueError, OSError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["cooldown_slot_matches"] and result["ordered_limits_slot_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
