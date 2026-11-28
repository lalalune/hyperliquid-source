"""Compare named, same-height #115 checkpoint PMI with raw root slot 54."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import ModuleType

ADDRESS = re.compile(r"0x[0-9a-f]{40}")
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
        module = ModuleType(f"node115_pmi_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def select_exchange(unpacker):
        return rmp.select(unpacker, {"pmi": rmp.read_value, "locus": lambda u: rmp.require(
            u, "ctx", lambda ctx: rmp.require(ctx, "height", rmp.read_value)
        )})

    with path.open("rb") as stream:
        reader = rmp.HashingReader(stream)
        unpacker = msgpack.Unpacker(reader, raw=False)
        try:
            fields = rmp.require(unpacker, "exchange", select_exchange)
        except msgpack.OutOfData as error:
            raise ValueError("incomplete named checkpoint object") from error
        position = unpacker.tell()
        while reader.read(65536):
            pass
        if reader.digest.hexdigest() != pin:
            raise ValueError("checkpoint SHA-256 mismatch")
        if position != reader.count:
            raise ValueError("trailing bytes after checkpoint object")
    if type(fields.get("locus")) is not int or fields["locus"] != height:
        raise ValueError("checkpoint Context height mismatch")
    if "pmi" not in fields:
        raise ValueError("checkpoint omits the named pmi field")
    pmi = fields["pmi"]
    if pmi is None:
        return None
    if type(pmi) is not str or not ADDRESS.fullmatch(pmi):
        raise ValueError("expected writer-shaped PMI nil or a lowercase 20-byte Address string")
    return bytes.fromhex(pmi[2:])


def slot_leaf(helper, tree, raw):
    result = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
    digest = result.stdout.decode("ascii").strip()
    if not tree.DIGEST.fullmatch(digest):
        raise ValueError("local helper returned an invalid digest")
    return bytes.fromhex(digest[2:])


def compare(helpers, hash_helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    if type(height) is not int or not 0 <= height < 1 << 64:
        raise ValueError("expected unsigned 64-bit checkpoint height")
    pmi = read_checkpoint(helpers["rmp"], checkpoint, checkpoint_pin, height)
    tree = helpers["tree"]
    expected = []
    if pmi is not None:
        expected.append((0, slot_leaf(hash_helper, tree, pmi)))
    expected.append((1, slot_leaf(hash_helper, tree, int(pmi is not None).to_bytes(8, "little"))))
    stated, parsed = tree.read_export(reference, reference_pin, height)
    if tree.digest(hash_helper, parsed) != stated:
        raise ValueError("reference tree does not reproduce its declared raw ABCI digest")
    if type(parsed) is not tuple:
        raise ValueError("expected raw exchange hash tree branch")
    branch = dict(parsed).get(54)
    if type(branch) is not tuple:
        raise ValueError("raw exchange tree slot 54 must be a branch")
    actual = dict(branch)
    wanted = dict(expected)
    return {
        "height": height,
        "checkpoint_pmi_present": pmi is not None,
        "reference_raw_digest": stated,
        "ordered_child_slots_match": tuple(wanted) == tuple(actual),
        "payload_leaf_matches": wanted.get(0) == actual.get(0),
        "discriminant_leaf_matches": wanted[1] == actual.get(1),
        "pmi_slot_matches": tuple(expected) == branch,
    }


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
    return 0 if result["pmi_slot_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
