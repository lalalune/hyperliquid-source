"""Compare the complete #115 named Locus msc subtree against raw ABCI."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import subprocess
from types import ModuleType

FIELDS = ("apw", "ape", "tse", "mts", "nts", "uts", "scr")
ADDRESS = re.compile(r"0x[0-9a-f]{40}")
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
        module = ModuleType(f"node115_locus_misc_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def binary64(unpacker):
        start = unpacker.tell()
        value = unpacker.unpack()
        if type(value) is not float or unpacker.tell() - start != 9 or not math.isfinite(value):
            raise ValueError("expected finite MessagePack binary64 apw")
        return struct.pack("<d", value)

    def boolean(unpacker):
        value = unpacker.unpack()
        if type(value) is not bool:
            raise ValueError("expected a native Locus msc boolean")
        return bytes([value])

    def collection(unpacker):
        count = unpacker.read_array_header()
        keys, values, seen = bytearray(), bytearray(), set()
        for i in range(count):
            if unpacker.read_array_header() != 2:
                raise ValueError(f"expected two elements in uts row {i}")
            key = unpacker.unpack()
            if type(key) is str and ADDRESS.fullmatch(key):
                raw = bytes.fromhex(key[2:])
            elif type(key) is list and len(key) == 20 and all(type(v) is int and 0 <= v < 256 for v in key):
                raw = bytes(key)
            else:
                raise ValueError(f"expected a writer-shaped uts Address at row {i}")
            if raw in seen:
                raise ValueError("duplicate uts Address")
            seen.add(raw)
            keys.extend(raw)
            values.extend(word(unpacker.unpack(), "uts value"))
        return count, keys, values

    def locus(u):
        def misc(fields):
            return rmp.select(fields, {"apw": binary64, "ape": boolean, "tse": boolean,
                                       "mts": lambda v: word(v.unpack(), "mts"),
                                       "nts": lambda v: word(v.unpack(), "nts"),
                                       "uts": collection, "scr": boolean})
        return rmp.select(u, {"ctx": lambda ctx: rmp.require(ctx, "height", rmp.read_value), "msc": misc})

    def exchange(u):
        return rmp.require(u, "locus", locus)

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
    if type(fields.get("ctx")) is not int or fields["ctx"] != height:
        raise ValueError("checkpoint Context height mismatch")
    misc = fields.get("msc", {})
    if set(misc) != set(FIELDS):
        raise ValueError("expected all seven named Locus msc fields")
    return misc


def compare(kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    word(height, "checkpoint height")
    values = read_checkpoint(kit["rmp"], checkpoint, checkpoint_pin, height)
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

    def children(node, label):
        if type(node) is not tuple:
            raise ValueError(f"expected a raw {label} branch")
        return dict(node)

    locus = children(children(ordered, "Exchange").get(0), "Locus")
    context = children(locus.get(0), "Context")
    if context.get(2) != leaf(word(height, "reference Context height")):
        raise ValueError("reference inner Context height leaf mismatch")
    count, keys, words = values["uts"]
    expected_map = ((0, leaf(keys)), (1, leaf(words))) if count else ()
    expected_map += ((2, leaf(word(count, "uts count"))),)
    expected = tuple((slot, expected_map if name == "uts" else leaf(values[name]))
                     for slot, name in enumerate(FIELDS))
    actual = locus.get(15)
    parts = dict(actual) if type(actual) is tuple else {}
    matches = {name: parts.get(slot) == child for (slot, child), name in zip(expected, FIELDS)}
    return {"height": height, "reference_raw_digest": digest, "uts_row_count": count,
            "fields": matches, "ordered_locus_misc_matches": actual == expected}


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
    return 0 if result["ordered_locus_misc_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
