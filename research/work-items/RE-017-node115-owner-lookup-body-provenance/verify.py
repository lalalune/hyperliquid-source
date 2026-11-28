"""Reproduce the opaque-store-to-body intake on both ordinary lookup paths."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from Crypto.Hash import keccak

from materialize import require, run

RING = "59dd27e2a3ff52b993ecc7f89acb7a692ef2d918"
TREE = "f310b50f8258c18ff7192d9613ef743c5c686c8d"
CUSTODY = "bd556b607be44e4f54446e5442edd1db56c41365"
RING_PACKET = "RE-017-node115-nonempty-missing-owner-ring"
TREE_PACKET = "RE-017-node115-nonempty-missing-owner-tree"
CUSTODY_PACKET = "RE-017-node115-missing-attachment-custody"


def export(repo, scratch, commit, item, names):
    result = scratch / item
    result.mkdir()
    for name in names:
        location = f"{commit}:research/work-items/{item}/{name}"
        (result / name).write_bytes(subprocess.check_output(["git", "show", location], cwd=repo))
    return result


def load(path, name):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(repo, scratch):
    ring = export(repo, scratch, RING, RING_PACKET, ("verify.py", "anchors.tsv", "probe.rs"))
    tree = export(repo, scratch, TREE, TREE_PACKET, ("verify.py", "anchors.tsv", "tree_case.py"))
    body = export(repo, scratch, CUSTODY, CUSTODY_PACKET, ("objects.py",))
    sys.path[:0] = [str(ring), str(tree), str(body)]
    ring_source = load(ring / "verify.py", "existing_ring_resolution")
    tree_source = load(tree / "verify.py", "existing_tree_resolution")
    sidecar = load(body / "objects.py", "existing_body_custody")
    ring_source.native(repo)
    tree_source.native(repo)
    rings, trees = scratch / "ring-build", scratch / "tree-build"
    rings.mkdir()
    trees.mkdir()
    return ((ring_source.measured, ring_source.build(repo, rings)),
            (tree_source.resolve, tree_source.build(repo, trees)), sidecar)


def tests(scratch, operations):
    sidecar = operations[2]

    def save(name, data):
        (scratch / name).write_bytes(data)
        return {"path": name, "sha256": sidecar.sha(data)}

    def digest(raw):
        return keccak.new(digest_bits=256, data=raw).digest()

    objects = sorted((digest(raw), ident, raw)
                     for ident, raw in ((101, b"alpha"), (201, b"beta"), (301, b"gamma")))
    key_words = [row[0] for row in objects]
    expected = [objects[i][2] for i in (2, 0, 1, 0)]

    def wire(keys):
        return (bytes(10) + bytes([0x31] * 20) + bytes([len(keys)]) + b"".join(keys)
                + bytes([0, 7, 0, 1, 2, 3, 4, 5]) + bytes([0x71] * 32) + bytes(3))

    raw = save("wire.bin", wire([key_words[i] for i in (2, 0, 1, 0)]))
    bodies = [{**save(f"object-{ident}.bin", data), "id": ident} for _, ident, data in objects]
    ring_physical = [objects[1], objects[2], (bytes(32), 0, b""), objects[0]]
    ring = save("ring.txt", ("3 3\n" + "\n".join(
        f"{key.hex()} {ident}" for key, ident, _ in ring_physical) + "\n").encode())

    def node(index, children=()):
        key, ident, _ = objects[index]
        return {"entries": [["0x" + key.hex(), ident]], "children": list(children)}

    tree = save("tree.json", json.dumps({"depth": 1, "root": node(1, [node(0), node(2)])}).encode())

    def measured(name, site, source, records, input_wire=raw):
        raw_manifest = json.dumps({"wire": input_wire, "store": {**site, "kind": source}, "bodies": records}).encode()
        entry = save(f"fixture-{name}.json", raw_manifest)
        report = run(scratch / entry["path"], entry["sha256"], scratch, scratch / name, *operations)
        print(json.dumps(report))
        return report

    for store, kind in ((ring, "ring"), (tree, "tree")):
        result = measured(kind, store, kind, bodies)
        custody = result["body_custody"]
        require(custody["source_wire_sha256"] == raw["sha256"], "wrong body-report wire parent")
        observed = [(scratch / kind / row["path"]).read_bytes() for row in custody["derived_rows"]]
        require(observed == expected, f"{kind} selected body order differs from Block key order")

    missing_wire = save("missing-store-key.bin", wire([key_words[0], digest(b"absent")]))
    missing = measured("absent-store-key", ring, "ring", bodies, missing_wire)
    require(missing["resolution"]["status"] == "missing" and missing["body_custody"] is None
            and not (scratch / "absent-store-key").exists(), "missing store should leave no body files")

    alternate = [{**bodies[1], "id": bodies[0]["id"]},
                 {**bodies[0], "id": bodies[1]["id"]}, bodies[2]]
    for label, catalog, expected_error in (
        ("wrong-catalog", alternate, "raw attachment differs from decoded key"),
        ("missing-body-id", bodies[1:], "has no body"),
    ):
        try:
            measured(label, tree, "tree", catalog)
        except ValueError as error:
            require(expected_error in str(error) and not (scratch / label).exists(), str(error))
            print(f"rejected {label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
    print("verified ring and tree selected IDs against independently pinned body bytes and source key order")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--case", type=Path)
    parser.add_argument("--case-sha")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    custom = (args.case, args.case_sha, args.output)
    if any(custom) and not all(custom):
        parser.error("--case, --case-sha and --output must be supplied together")
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        operations = prepare(args.repo.resolve(), scratch)
        if args.case:
            result = run(args.case.resolve(), args.case_sha, scratch, args.output, *operations)
            print(json.dumps(result))
            raise SystemExit(0 if result["body_custody"] is not None else 1)
        tests(scratch, operations)
