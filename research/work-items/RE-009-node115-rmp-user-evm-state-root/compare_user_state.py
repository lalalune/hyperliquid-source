"""Compare the complete #115 user_to_evm_state map against its raw root slot."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import ModuleType

FIELD = "user_to_evm_state"
SLOT = 34
DEFAULT_TIME = "1970-01-01T00:00:00"
FIELDS = ("g", "t", "b", "T")
ADDRESS = re.compile(r"0x[0-9a-f]{40}")
DEPENDENCIES = {
    "rmp": ("RE-009-node115-msgpack-context-projection/project.py",
            "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "normalize": ("RE-009-node115-checkpoint-context-projection/project.py",
                  "5b8f909500007bc23aa6ce46d0d9abf79fab081e6a35a68587d07edec95bbebd"),
    "clock": ("RE-009-node115-context-subtree-compare/compare.py",
              "9fe1de5c63e742c1974b8ecb2888e7acaca80d95a599d54178bc7f38edf15241"),
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
        module = ModuleType(f"node115_user_evm_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def address(value):
    if type(value) is str and ADDRESS.fullmatch(value):
        return bytes.fromhex(value[2:])
    if type(value) is list and len(value) == 20 and all(type(v) is int and 0 <= v < 256 for v in value):
        return bytes(value)
    raise ValueError("expected a 20-byte Address string or byte array")


def streams(kit, unpacker):
    rmp = kit["rmp"]
    row_count = unpacker.read_array_header()
    keys = bytearray()
    parts = {name: bytearray() for name in FIELDS}
    seen = set()
    for index in range(row_count):
        if unpacker.read_array_header() != 2:
            raise ValueError(f"expected two elements in user EVM row {index}")
        addr = address(unpacker.unpack())
        if addr in seen:
            raise ValueError("duplicate user EVM Address")
        seen.add(addr)
        keys.extend(addr)
        row = rmp.select(unpacker, dict.fromkeys(FIELDS, rmp.read_value))
        parts["g"].extend(word(row.get("g", 0), "g"))
        parts["t"].extend(word(row.get("t", 0), "t"))
        marker = row.get("b", False)
        if type(marker) is not bool:
            raise ValueError(f"expected a bool at row {index} field b")
        parts["b"].append(marker)
        parts["T"].extend(kit["clock"].clock(kit["normalize"].clock(row.get("T", DEFAULT_TIME))))
    return row_count, keys, parts


def read_checkpoint(kit, path, pin, height):
    import msgpack

    rmp = kit["rmp"]

    def exchange(u):
        return rmp.select(u, {
            FIELD: lambda value: streams(kit, value),
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
        raise ValueError("checkpoint omits user_to_evm_state")
    return fields[FIELD]


def project(leaf, count, keys, parts):
    count_child = (2, leaf(word(count, "row count")))
    if count == 0:
        return (count_child,)
    fields = tuple((index, leaf(parts[name])) for index, name in enumerate(FIELDS))
    return ((0, leaf(keys)), (1, fields), count_child)


def compare(kit, helper, height, checkpoint, checkpoint_sha, reference, reference_sha):
    word(height, "checkpoint height")
    count, keys, parts = read_checkpoint(kit, checkpoint, checkpoint_sha, height)
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

    expected = project(leaf, count, keys, parts)
    actual = dict(ordered).get(SLOT)
    values = dict(actual) if type(actual) is tuple else {}
    intended = dict(expected)
    return {"height": height, "slot": SLOT, "entry_count": count, "reference_raw_digest": digest,
            "ordered_subtree_matches": expected == actual,
            "address_stream_matches": intended.get(0) == values.get(0),
            "value_subtree_matches": intended.get(1) == values.get(1),
            "count_leaf_matches": intended[2] == values.get(2)}


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
