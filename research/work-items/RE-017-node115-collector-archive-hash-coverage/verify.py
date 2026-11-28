"""Verify coverage-aware collector comparison at H+1 using reconstructed hash code."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from coverage import check

COLLECTOR = "597934617f883352ca248951a9f0342720a07dee"
OUTCOMES = "5d25fbeb3ebe3394b9d746c487e970f0e5c186c6"


def load(repo, scratch, commit, packet, source, helpers=()):
    folder = scratch / packet
    folder.mkdir()
    for name in (source, *helpers):
        location = f"{commit}:research/work-items/{packet}/{name}"
        (folder / name).write_bytes(subprocess.check_output(["git", "show", location], cwd=repo))
    sys.path.insert(0, str(folder))
    identifier = packet + "-" + source
    spec = spec_from_file_location(identifier, folder / source)
    module = module_from_spec(spec)
    sys.modules[identifier] = module
    spec.loader.exec_module(module)
    return module


def prepare(repo, scratch):
    audit = load(repo, scratch, COLLECTOR, "RE-017-node115-collector-archive-outcome-audit", "audit.py")
    outcomes = load(repo, scratch, OUTCOMES, "RE-017-node115-archive-order-result-hash", "verify.py", ("order_hash.py",))
    codec = outcomes.prepare(repo, scratch)
    return (audit, outcomes.compare, codec), outcomes


def fixtures(repo, scratch, adapters, outcomes):
    audit, _, _ = adapters
    outcomes.fixtures(repo, scratch, adapters[2])
    compiled = scratch / "rust-keccak"
    key_a, key_b = "0x" + "11" * 32, "0x" + "22" * 32
    success = {"user": None, "res": {"status": "ok", "response": {"type": "default"}}}

    # The worker observes B then A even though the archive geometry books A then B.
    known = (b"\x92\x92\xd9\x42" + key_b.encode("ascii") + b"\x90\x92\xd9\x42"
             + key_a.encode("ascii") + b"\x91\x82\xa4user\xc0\xa3res"
             + b"\x82\xa6status\xa2ok\xa8response\x81\xa4type\xa7default")
    expected = "0x" + subprocess.check_output([compiled], input=known).decode("ascii").strip()
    archive = {"height": 44, "abci_block": {
        "signed_action_bundles": [[key_a, {"signed_actions": [{"action": {}}]}],
                                  [key_b, {"signed_actions": []}]],
    }, "resps": {"Hash": expected}}

    def save(name, payload):
        raw = (json.dumps(payload) + "\n").encode()
        (scratch / name).write_bytes(raw)
        return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}

    archive_file = save("archive.jsonl", archive)

    def measure(label, rows, ordinals, expected_stop):
        observed = save(f"{label}-observed.json", {"height": 44, "ordinals": ordinals,
                         "stop_position": expected_stop, "resps": {"Full": rows}})
        case = save(f"{label}-manifest.json", {"checkpoint_height": 43, "archive": archive_file,
                                            "observation": observed})
        result = check(scratch / case["path"], case["sha256"], *adapters)
        print(label, json.dumps(result))
        return result

    empty = measure("empty-prefix", [], [], 0)
    audit.require(empty["missing_archive_keys"] == [key_a, key_b] and empty["actual"] is None
                  and empty["matches"] is None, "empty prefix was compared")
    partial = measure("partial-prefix", [[key_b, []]], [4], 1)
    audit.require(partial["missing_archive_keys"] == [key_a] and partial["actual"] is None
                  and partial["matches"] is None, "partial prefix was compared")
    full = measure("complete", [[key_b, []], [key_a, [success]]], [4, 7], 2)
    audit.require(full["matches"] and full["actual"] == expected, "lost actual collector order")
    different = measure("changed-order", [[key_a, [success]], [key_b, []]], [7, 4], 2)
    audit.require(different["matches"] is False and different["actual"], "different order must compare as a mismatch")
    try:
        measure("wrong-action-count", [[key_b, []], [key_a, []]], [4, 7], 2)
    except ValueError as error:
        audit.require("action count differs" in str(error), str(error))
        print(f"rejected incompatible collector row: {error}")
    else:
        raise ValueError("incomplete row was compared")
    print("verified complete collector order, empty and partial coverage, archive permutation and action count")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--case", type=Path)
    parser.add_argument("--case-sha")
    args = parser.parse_args()
    if bool(args.case) != bool(args.case_sha):
        parser.error("--case and --case-sha must both be supplied")
    with TemporaryDirectory() as temporary:
        scratch = Path(temporary)
        repo = args.repo.resolve()
        adapters, outcomes = prepare(repo, scratch)
        if args.case:
            report = check(args.case.resolve(), args.case_sha, *adapters)
            print(json.dumps(report))
            match = report["matches"]
            raise SystemExit(2 if match is None else int(not match))
        fixtures(repo, scratch, adapters, outcomes)
