"""Compare #115 named Exchange quantity wrapper subtrees with a pinned raw export."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

AMOUNT = "hlp_start_of_day_account_value"
BALANCE = "initial_usdc_evm_system_balance"
SLOTS = {AMOUNT: 26, "pvs": 27, BALANCE: 47}
DEPENDENCIES = {
    "rmp": ("RE-009-node115-msgpack-context-projection/project.py",
            "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "tree": ("RE-009-node115-context-root-isolation/isolate.py",
             "acb3c71a3c56b42d9614aeb78225cfc90f364e8468db144c0f55e22a175fc3ec"),
}


def load_helpers(folder):
    modules = {}
    for name, (relative, sha256) in DEPENDENCIES.items():
        path = folder / relative
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != sha256:
            raise ValueError(f"source pin mismatch for {relative}")
        module = ModuleType(f"node115_qty_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def exchange(unpacker):
        return rmp.select(unpacker, {
            AMOUNT: rmp.read_value, BALANCE: rmp.read_value,
            "pvs": lambda u: rmp.select(u, dict.fromkeys(("mptc", "ptc"), rmp.read_value)),
            "locus": lambda u: rmp.require(u, "ctx", lambda ctx: rmp.require(ctx, "height", rmp.read_value)),
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
    missing = set(SLOTS).difference(fields)
    if missing:
        raise ValueError(f"checkpoint omits {', '.join(sorted(missing))}")
    return fields


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def project(leaf, fields):
    empty = leaf(b"")

    def quantity(value, label):
        return ((0, leaf(word(value, label))), (1, empty))

    present = fields[AMOUNT] is not None
    amount = ((0, quantity(fields[AMOUNT], AMOUNT)),) if present else ()
    amount += ((1, leaf(word(int(present), "amount option tag"))),)
    pvs = tuple((i, quantity(fields["pvs"].get(name), "pvs." + name))
                for i, name in enumerate(("mptc", "ptc")))
    return {AMOUNT: amount, "pvs": pvs, BALANCE: quantity(fields[BALANCE], BALANCE)}


def compare(kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    word(height, "checkpoint height")
    named = read_checkpoint(kit["rmp"], checkpoint, checkpoint_pin, height)
    tree = kit["tree"]
    digest, ordered = tree.read_export(reference, reference_pin, height)
    if tree.digest(helper, ordered) != digest:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(ordered) is not tuple:
        raise ValueError("expected ordered raw Exchange branch")
    actual = dict(ordered)
    hashes = {}

    def leaf(raw):
        if raw not in hashes:
            output = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
            value = output.stdout.decode("ascii").strip()
            if not tree.DIGEST.fullmatch(value):
                raise ValueError("local helper returned an invalid digest")
            hashes[raw] = bytes.fromhex(value[2:])
        return hashes[raw]

    expected = project(leaf, named)
    results = {name: {"slot": slot, "matches": expected[name] == actual.get(slot)}
               for name, slot in SLOTS.items()}
    return {"height": height, "reference_raw_digest": digest, "fields": results,
            "all_quantity_subtrees_match": all(row["matches"] for row in results.values())}


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
    return 0 if result["all_quantity_subtrees_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
