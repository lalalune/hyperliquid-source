"""Compare the persisted #115 EVM-to-L1 amount collection with raw slot 49."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import ModuleType

FIELD = "user_to_evm_to_l1_wei_remaining"
SLOT = 49
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
        module = ModuleType(f"node115_remaining_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def read_rows(unpacker):
    count = unpacker.read_array_header()
    addresses, amounts = bytearray(), bytearray()
    seen = set()
    for _ in range(count):
        if unpacker.read_array_header() != 2:
            raise ValueError("expected two elements per EVM-to-L1 amount row")
        address, amount = unpacker.unpack(), unpacker.unpack()
        if type(address) is not str or not ADDRESS.fullmatch(address):
            raise ValueError("expected a writer-shaped 20-byte Address string")
        key = bytes.fromhex(address[2:])
        if key in seen:
            raise ValueError("duplicate ledger Address")
        seen.add(key)
        addresses.extend(key)
        amounts.extend(word(amount, "remaining amount"))
    return count, addresses, amounts


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def exchange(u):
        return rmp.select(u, {
            FIELD: read_rows,
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
        raise ValueError(f"checkpoint omits {FIELD}")
    return fields[FIELD]


def compare(kit, helper, height, checkpoint, checkpoint_sha, reference, reference_sha):
    word(height, "checkpoint height")
    count, addresses, amounts = read_checkpoint(kit["rmp"], checkpoint, checkpoint_sha, height)
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

    expected = ((0, leaf(addresses)), (1, ((0, leaf(amounts)), (1, leaf(b""))))) if count else ()
    expected += ((2, leaf(word(count, "row count"))),)
    actual = dict(ordered).get(SLOT)
    wanted = dict(expected)
    children = dict(actual) if type(actual) is tuple else {}
    return {"height": height, "reference_raw_digest": digest, "slot": SLOT, "entry_count": count,
            "ordered_subtree_matches": expected == actual,
            "address_stream_matches": wanted.get(0) == children.get(0),
            "amount_subtree_matches": wanted.get(1) == children.get(1),
            "count_leaf_matches": wanted[2] == children.get(2)}


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
