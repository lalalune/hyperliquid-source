"""Compare the complete named #115 Locus uaR variant sets against raw ABCI."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import ModuleType

PAYLOADS = ("Perp", "Spot", "Token", "Pdi")
UNITS = ("ActivateDexAbstraction", "ActivateUnifiedAccount", "AllBoleTokens")
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
        module = ModuleType(f"node115_locus_uar_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def collection(unpacker):
        count = unpacker.read_array_header()
        addresses, counts, tags = bytearray(), bytearray(), bytearray()
        payloads = {name: bytearray() for name in PAYLOADS}
        users = set()
        for index in range(count):
            if unpacker.read_array_header() != 2:
                raise ValueError(f"expected a user/variant set pair at row {index}")
            key = unpacker.unpack()
            if type(key) is str and ADDRESS.fullmatch(key):
                raw = bytes.fromhex(key[2:])
            elif type(key) is list and len(key) == 20 and all(type(v) is int and 0 <= v < 256 for v in key):
                raw = bytes(key)
            else:
                raise ValueError(f"expected a 20-byte uaR Address at row {index}")
            if raw in users:
                raise ValueError("duplicate uaR Address")
            users.add(raw)
            addresses.extend(raw)
            length = unpacker.read_array_header()
            counts.extend(word(length, "uaR per-user count"))
            seen = set()
            for _ in range(length):
                entry = unpacker.unpack()
                if type(entry) is dict and len(entry) == 1 and next(iter(entry)) in PAYLOADS:
                    variant, value = next(iter(entry.items()))
                    tag = PAYLOADS.index(variant)
                    data = word(value, variant)
                    payloads[variant].extend(data)
                elif type(entry) is str and entry in UNITS:
                    tag = len(PAYLOADS) + UNITS.index(entry)
                    data = b""
                else:
                    raise ValueError(f"unknown or incorrectly encoded uaR variant in row {index}")
                if (tag, data) in seen:
                    raise ValueError(f"duplicate uaR variant in row {index}")
                seen.add((tag, data))
                tags.extend(word(tag, "uaR tag"))
        return count, addresses, counts, tags, payloads

    def locus(u):
        return rmp.select(u, {"ctx": lambda ctx: rmp.require(ctx, "height", rmp.read_value),
                              "uaR": collection})

    def exchange(u):
        return rmp.require(u, "locus", locus)

    def distinct_pairs(pairs):
        values = dict(pairs)
        if len(values) != len(pairs):
            raise ValueError("duplicate uaR variant key")
        return values

    with path.open("rb") as stream:
        reader = rmp.HashingReader(stream)
        unpacker = msgpack.Unpacker(reader, raw=False, object_pairs_hook=distinct_pairs)
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
    if "uaR" not in fields:
        raise ValueError("checkpoint omits Locus uaR")
    return fields["uaR"]


def compare(kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    word(height, "checkpoint height")
    count, addresses, counts, tags, payloads = read_checkpoint(kit["rmp"], checkpoint, checkpoint_pin, height)
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
    count_child = leaf(word(count, "uaR user count"))
    expected = ((2, count_child),)
    if count:
        cases = tuple((slot, leaf(payloads[name])) for slot, name in enumerate(PAYLOADS) if payloads[name])
        enum_streams = cases + ((4, leaf(tags)),) if tags else ()
        values = ((0, enum_streams),) if enum_streams else ()
        values += ((1, leaf(counts)),)
        expected = ((0, leaf(addresses)), (1, values)) + expected
    actual = locus.get(7)
    parts = dict(actual) if type(actual) is tuple else {}
    intended = dict(expected)
    return {"height": height, "reference_raw_digest": digest, "user_count": count,
            "address_stream_matches": parts.get(0) == intended.get(0),
            "ordered_value_streams_match": parts.get(1) == intended.get(1),
            "user_count_matches": parts.get(2) == count_child, "ordered_uar_matches": actual == expected}


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
    return 0 if result["ordered_uar_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
