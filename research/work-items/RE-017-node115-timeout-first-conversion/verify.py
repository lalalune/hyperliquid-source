"""Reproduce the timeout first-conversion and adjacent Context fixture."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

PACKET = Path(__file__).resolve().parent
CONVERSION = "b5c57efaa22b79029d113aa6094435cfb8dec488"
PARENT = "3f1a007af8a16d5a9d3c3d185aa7ac88d1aaab72"
CONVERSION_PACKET = "RE-017-node115-first-converted-context-fixture"
PARENT_PACKET = "RE-017-node115-replay-decoded-parent-link"


def require(condition, text):
    if not condition:
        raise ValueError(text)


def materialize(repo, scratch, commit, packet, names):
    folder = scratch / packet
    folder.mkdir()
    for name in names:
        path = f"{commit}:research/work-items/{packet}/{name}"
        (folder / name).write_bytes(subprocess.check_output(["git", "show", path], cwd=repo))
    return folder


def load(path, name):
    spec = spec_from_file_location(name, path)
    result = module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare(repo, scratch):
    parent = materialize(repo, scratch, PARENT, PARENT_PACKET, ("anchors.tsv", "verify.py"))
    subprocess.run([sys.executable, "-B", parent / "verify.py", "--repo", str(repo)], check=True)
    folder = materialize(repo, scratch, CONVERSION, CONVERSION_PACKET, ("verify.py", "sequence.py", "cursor.rs"))
    subprocess.run(["git", "apply", str(PACKET / "timeout-cursor.patch")], cwd=folder, check=True)
    sys.path.insert(0, str(folder))
    prior = load(folder / "verify.py", "existing_conversion_verifier")
    return prior.run, prior.prepare(repo, scratch)


def tests(scratch, run, prepared):
    runner, wire_case, kit, cursor, decoder, compare_case, hash_bytes, helper = prepared
    base = runner.fixture(scratch, kit, helper, hash_bytes)
    wire = (scratch / base["wire"]["path"]).read_bytes()
    require(wire[37:43] == bytes([0, 5, 40, 40, 4, 5]), "wrong clock/parent fixture boundary")
    record = json.loads((scratch / base["archive"]["path"]).read_bytes())
    record["abci_block"]["round"] = 50
    h1 = json.loads((scratch / base["reference_h_plus_one"]["path"]).read_bytes())
    tree = h1["exchange_abci_hash"]
    tree[0][1][0][1][4][1] = hash_bytes(helper, kit["tree"], (50).to_bytes(8, "little"))
    h1["abci_digest"] = kit["tree"].digest(helper, kit["tree"].decode_tree(tree))

    def qc(identity, key):
        return bytes([5, 40, identity, 4, 5]) + bytes([key] * 32) + b"\0"

    def payload(timeout, embedded_identity, optional):
        return (wire[:37] + bytes([1, timeout]) + qc(embedded_identity, 0x61) + b"\0"
                + (b"\1" + qc(40, 0x62) if optional else b"\0") + b"\0\0")

    spec = {
        "height": 42, "restored_round": 40, "ordered_pair": [5, 40],
        "archive": wire_case.save_json(scratch, "archive-round-50.jsonl", record),
        "checkpoint_rmp": base["checkpoint_rmp"], "reference_h": base["reference_h"],
        "reference_h_plus_one": wire_case.save_json(scratch, "root-round-50.jsonl", h1),
    }

    def measure(label, candidate):
        entry = wire_case.save(scratch, f"{label}.bin", candidate)
        item = wire_case.save_json(scratch, f"{label}.json", spec | {
            "records": [{**entry, "prepared_count": 0}],
        })
        return run(scratch / item["path"], item["sha256"], scratch, wire_case, kit, cursor,
                   decoder, compare_case, helper)

    for title, candidate in (
        ("optional-quorum", payload(49, 37, True)),
        ("embedded-quorum", payload(49, 40, False)),
    ):
        result = measure(title, candidate)
        event, = result["cursor"]
        require(event["identity"] == 40 and event["successor"] == 50 and event["parent_round"] == 40
                and event["outcome"] == "converted", "timeout projection did not reach first conversion")
        require(result["selected_wire_header"]["height"] == 43 and
                result["selected_root_comparison"]["selected_checks_pass"], "wrong selected Context values")
        print(f"{title} wire_sha256={hashlib.sha256(candidate).hexdigest()} {json.dumps(result)}")

    for label, candidate, expected in (
        ("different-embedded-identity", payload(49, 37, False), "identity mismatch before conversion"),
        ("below-timeout-threshold", payload(48, 37, True), "ends before the first conversion"),
    ):
        try:
            measure(label, candidate)
        except ValueError as error:
            require(expected in str(error), str(error))
            print(f"rejected {label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
    print("verified separate timeout successor, selected quorum identity and first H+1 Context comparison")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        runner, prepared = prepare(args.repo.resolve(), scratch)
        tests(scratch, runner, prepared)
