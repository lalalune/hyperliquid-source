"""Reproduce first conversion with native-style externally prepared attachments."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from Crypto.Hash import keccak

from first_conversion import require, run

PREFILTER = "1db811d9c1eb259eb0e1b910c7ab73657ccc1c2c"
LOOKUP = "3fd7579c86b20d2673078b9536c57b28c31f375c"


def load(repo, scratch, commit, name, modules):
    folder = scratch / name
    folder.mkdir()
    for filename in modules:
        location = f"{commit}:research/work-items/{name}/{filename}"
        (folder / filename).write_bytes(subprocess.check_output(["git", "show", location], cwd=repo))
    sys.path.insert(0, str(folder))
    verifier = spec_from_file_location(name, folder / "verify.py")
    module = module_from_spec(verifier)
    verifier.loader.exec_module(module)
    return module


def prepare(repo, scratch):
    lookup = load(repo, scratch, LOOKUP, "RE-017-node115-owner-lookup-body-provenance",
                  ("materialize.py", "verify.py"))
    prefilter = load(repo, scratch, PREFILTER, "RE-017-node115-prefilter-attachment-conversion",
                     ("prefilter.py", "verify.py"))
    ops, fixture = prefilter.prepare(repo, scratch)
    print(f"checking omitted owner custody from {LOOKUP}", flush=True)
    return (ops, lookup.run, lookup.prepare(repo, scratch)), fixture


def fixtures(scratch, inputs, fixture):
    runner, wire_case, kit, helper, hash_bytes = fixture
    template = runner.fixture(scratch, kit, helper, hash_bytes)
    original = (scratch / template["wire"]["path"]).read_bytes()
    require(original[30] == original[-1] == 0, "wrong empty wire fixture")
    save = lambda name, raw: wire_case.save(scratch, name, raw)
    save_json = lambda name, value: wire_case.save_json(scratch, name, value)

    objects = [(101, b"first body"), (701, b"selected body")]
    fingerprints = [keccak.new(digest_bits=256, data=raw).digest() for _, raw in objects]
    keys = ["0x" + value.hex() for value in fingerprints]
    wire = save("wire-omitted.bin", original[:30] + bytes([2]) + b"".join(fingerprints) + original[31:])
    archive = json.loads((scratch / template["archive"]["path"]).read_bytes())
    archive["abci_block"]["signed_action_bundles"] = [[keys[1], {"signed_actions": []}]]
    base = {key: template[key] for key in (
        "height", "ordered_pair", "checkpoint_rmp", "reference_h", "reference_h_plus_one",
    )}
    base.update(restored_round=40, archive=save_json("captured-archive.jsonl", archive), successful_rows=[1])
    catalog = [{"id": ident, **save(f"object-{ident}.bin", raw)} for ident, raw in objects]
    entries = sorted(zip(keys, [101, 701]))
    tree = {"depth": 0, "root": {"entries": entries, "children": []}}
    store = {"kind": "tree", **save_json("observed-tree.json", tree)}

    def measure(label, observed, **changes):
        observed_owner = save_json(f"{label}-owner.json", {"wire": wire, "store": observed, "bodies": catalog})
        scoped = dict(base, records=[{"wire": wire, "materialization": observed_owner}]) | changes
        case = save_json(f"{label}-case.json", scoped)
        output = scratch / label
        output.mkdir()
        return run(scratch / case["path"], case["sha256"], output, *inputs)

    report = measure("matched", store)
    print(json.dumps(report))
    require(report["before_filter"] == 2 and report["successful_rows"] == [1]
            and report["archive_matches"] and report["archive_keys"] == [keys[1]], "wrong attachment provenance")
    require(report["cursor"][0]["outcome"] == "converted" and report["cursor"][0]["successor"] == 41
            and report["cursor"][0]["wire_sha256"] == wire["sha256"]
            and report["selected_wire_header"]["height"] == 43
            and report["selected_root_comparison"]["selected_checks_pass"], "wrong conversion outcome")

    different_archive = json.loads(json.dumps(archive))
    different_archive["abci_block"]["signed_action_bundles"][0][0] = keys[0]
    mismatched = measure("other-archive-keys", store, archive=save_json("other-archive.jsonl", different_archive))
    require(not mismatched["archive_matches"] and mismatched["selected_root_comparison"]["selected_checks_pass"],
            "archive key mismatch must remain independent of selected Context checks")
    print("rejected alternate archive bundle key with unchanged matched same-height Context evidence")

    missing = {"depth": 0, "root": {"entries": [[keys[0], 101]], "children": []}}
    try:
        measure("missing", {"kind": "tree", **save_json("unresolved-tree.json", missing)})
    except ValueError as error:
        require(str(error) == "unresolved attachment owner at row 0", str(error))
        print(f"stopped before first conversion: {error}")
    else:
        raise ValueError("selected first conversion without prepared owner")

    ops, _, _ = inputs
    _, _, convert, wire_case, kit, *cursor = ops
    alternate = {key: value for key, value in base.items() if key != "successful_rows"}
    alternate["records"] = [{**wire, "prepared_count": 0}]
    wrong_count = save_json("bare-wire-count.json", alternate)
    try:
        convert(scratch / wrong_count["path"], wrong_count["sha256"], scratch, wire_case, kit, *cursor)
    except ValueError as error:
        require("ends before the first conversion" in str(error), str(error))
        print(f"omitting native prepared count exhausts cursor: {error}")
    else:
        raise ValueError("bare wire incorrectly supplies native prepared owner")
    print("verified omitted owner -> 2 original bodies -> first conversion round 41 -> selected archive key at H+1")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--case", type=Path)
    parser.add_argument("--case-sha")
    args = parser.parse_args()
    if bool(args.case) != bool(args.case_sha):
        parser.error("--case and --case-sha must be supplied together")
    with TemporaryDirectory() as temp:
        scratch = Path(temp)
        operations, fixture = prepare(args.repo.resolve(), scratch)
        if args.case:
            report = run(args.case.resolve(), args.case_sha, scratch, *operations)
            print(json.dumps(report))
            raise SystemExit(0 if report["archive_matches"] and report["selected_root_comparison"]["selected_checks_pass"]
                             else 1)
        fixtures(scratch, operations, fixture)
