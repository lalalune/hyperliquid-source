"""Compare the #115 named checkpoint hil subtree with its raw ABCI reference."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
from types import ModuleType

FIELD = "hil"
SLOT = 51
KEYS = ("m", "half_life", "max_slippage", "max_n_depositors")
MODES = {"e": 0, "x": 1, "d": 2}
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
        module = ModuleType(f"node115_hil_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def binary64(unpacker, optional=False):
        before = unpacker.tell()
        value = unpacker.unpack()
        if optional and value is None:
            return None
        if type(value) is not float or unpacker.tell() - before != 9 or not math.isfinite(value):
            raise ValueError("expected a finite MessagePack binary64")
        return value

    def exchange(u):
        return rmp.select(u, {
            FIELD: lambda obj: rmp.select(obj, {
                "m": rmp.read_value,
                "half_life": lambda field: binary64(field, optional=True),
                "max_slippage": binary64,
                "max_n_depositors": rmp.read_value,
            }),
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
    values = fields.get(FIELD, {})
    if set(values) != set(KEYS):
        raise ValueError("expected all four hil fields")
    if type(values["m"]) is not str or values["m"] not in MODES:
        raise ValueError("unknown hil mode")
    return values


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

    duration = fields["half_life"]
    option = () if duration is None else ((0, leaf(struct.pack("<d", duration))),)
    option += ((1, leaf(word(int(duration is not None), "half_life tag"))),)
    expected = (
        (0, ((0, leaf(word(MODES[fields["m"]], "mode tag"))),)),
        (1, option),
        (2, leaf(struct.pack("<d", fields["max_slippage"]))),
        (3, leaf(word(fields["max_n_depositors"], "max_n_depositors"))),
    )
    actual = dict(ordered).get(SLOT)
    children = dict(actual) if type(actual) is tuple else {}
    return {"height": height, "reference_raw_digest": digest, "ordered_hil_slot_matches": actual == expected,
            "fields": {name: children.get(index) == child
                       for (index, child), name in zip(expected, KEYS)}}


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
    return 0 if result["ordered_hil_slot_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
