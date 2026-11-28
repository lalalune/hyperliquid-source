"""Check the ordered #115 display-name sequence against raw ABCI slot 19."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import ModuleType

FIELD = "user_to_display_name"
SLOT = 19
ADDRESS = re.compile(r"0x[0-9a-f]{40}")
STREAMS = ("address_bytes", "length_prefixed_utf8", "entry_count")
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
        module = ModuleType(f"node115_names_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def read_pair_streams(unpacker):
    count = unpacker.read_array_header()
    addresses, values = bytearray(), bytearray()
    seen = set()
    for _ in range(count):
        if unpacker.read_array_header() != 2:
            raise ValueError("expected two elements in every display-name pair")
        addr, text = unpacker.unpack(), unpacker.unpack()
        if type(addr) is not str or not ADDRESS.fullmatch(addr):
            raise ValueError("expected a writer-shaped 20-byte Address string")
        if type(text) is not str:
            raise ValueError("expected a MessagePack display-name string")
        key = bytes.fromhex(addr[2:])
        if key in seen:
            raise ValueError("duplicate display-name Address")
        seen.add(key)
        addresses.extend(key)
        value = text.encode("utf-8")
        values.extend(len(value).to_bytes(8, "little"))
        values.extend(value)
    return count, addresses, values


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def exchange(u):
        return rmp.select(u, {
            FIELD: read_pair_streams,
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
    if FIELD not in fields:
        raise ValueError("checkpoint omits user_to_display_name")
    return fields[FIELD]


def compare(kit, helper, height, checkpoint, checkpoint_sha, reference, reference_sha):
    if type(height) is not int or not 0 <= height < 1 << 64:
        raise ValueError("expected unsigned 64-bit checkpoint height")
    count, keys, names = read_checkpoint(kit["rmp"], checkpoint, checkpoint_sha, height)
    tree = kit["tree"]
    digest, ordered = tree.read_export(reference, reference_sha, height)
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

    expected = ((0, leaf(keys)), (1, leaf(names))) if count else ()
    expected += ((2, leaf(count.to_bytes(8, "little"))),)
    actual = dict(ordered).get(SLOT)
    children = dict(actual) if type(actual) is tuple else {}
    expected_children = dict(expected)
    return {"height": height, "reference_raw_digest": digest, "slot": SLOT, "entry_count": count,
            "ordered_subtree_matches": expected == actual,
            "streams": {name: expected_children.get(index) == children.get(index)
                        for index, name in enumerate(STREAMS)}}


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
        output = compare(load_helpers(args.helpers), args.hash_helper, args.height, args.checkpoint,
                         args.checkpoint_sha256, args.reference, args.reference_sha256)
    except (ValueError, OSError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(output, sort_keys=True))
    return 0 if output["ordered_subtree_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
