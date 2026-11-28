"""Reproduce same-batch predecessor checks through the first selected conversion."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from bridge import require, run

PACKET = Path(__file__).resolve().parent
LINKS = "3049035108cc416a3cb83fc6c8b8361fafd7f984"
CURSOR = "b5c57efaa22b79029d113aa6094435cfb8dec488"
LINK_PACKET = "RE-017-node115-retained-decoded-fingerprint"
CURSOR_PACKET = "RE-017-node115-first-converted-context-fixture"


def materialize(repo, scratch, commit, name, files):
    directory = scratch / name
    directory.mkdir()
    for filename in files:
        locator = f"{commit}:research/work-items/{name}/{filename}"
        (directory / filename).write_bytes(subprocess.check_output(["git", "show", locator], cwd=repo))
    return directory


def load(path, name):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(repo, scratch):
    links = materialize(repo, scratch, LINKS, LINK_PACKET, ("oracle.py", "probe.rs", "verify.py"))
    cursor = materialize(repo, scratch, CURSOR, CURSOR_PACKET, ("sequence.py", "cursor.rs", "verify.py"))
    sys.path[:0] = [str(links), str(cursor)]
    fingerprints = load(links / "verify.py", "existing_retained_link_verifier")
    sequence = load(cursor / "verify.py", "existing_first_conversion_verifier")
    actions = load(cursor / "sequence.py", "existing_first_conversion_case")
    oracle = load(links / "oracle.py", "independent_keccak_fixture")
    fingerprints.native(repo, links)
    link_checker = fingerprints.build(repo, links)
    runner, wire_case, kit, cursor_probe, decoder, compare_case, hash_bytes, tree_helper = (
        sequence.prepare(repo, scratch)
    )
    compare = (link_checker, actions.run, wire_case, kit, cursor_probe, decoder, compare_case, tree_helper)
    return compare, (runner, wire_case, kit, tree_helper, hash_bytes, oracle)


def fixtures(scratch, runner, wire_case, kit, tree_helper, hash_bytes, oracle):
    base = runner.fixture(scratch, kit, tree_helper, hash_bytes)
    previous = bytes([0x71] * 32)
    records = []
    for index in range(10):
        body = oracle.header(bytes([0x31] * 20), [], 0, 120_000_000,
                             (5, 40, 40 + index, 4, 5), previous)
        entry = wire_case.save(scratch, f"batch-{index}.bin", oracle.wire(body))
        records.append({**entry, "prepared_count": 0})
        previous = oracle.keccak.new(digest_bits=256, data=oracle.DOMAIN + b"\0" + body).digest()

    archive = json.loads((scratch / base["archive"]["path"]).read_bytes())
    archive["abci_block"]["round"] = 50
    h1 = json.loads((scratch / base["reference_h_plus_one"]["path"]).read_bytes())
    nodes = h1["exchange_abci_hash"]
    nodes[0][1][0][1][4][1] = hash_bytes(tree_helper, kit["tree"], (50).to_bytes(8, "little"))
    h1["abci_digest"] = kit["tree"].digest(tree_helper, kit["tree"].decode_tree(nodes))
    return {
        "height": 42, "restored_round": 40, "ordered_pair": [5, 40], "records": records,
        "archive": wire_case.save_json(scratch, "archive-round-50.jsonl", archive),
        "checkpoint_rmp": base["checkpoint_rmp"], "reference_h": base["reference_h"],
        "reference_h_plus_one": wire_case.save_json(scratch, "root-round-50.jsonl", h1),
    }


def verify(scratch, operations, fixture_args):
    spec = fixtures(scratch, *fixture_args)
    _, run_sequence, wire_case, *pipeline = operations
    case = wire_case.save_json(scratch, "same-retained-batch.json", spec)
    report = run(scratch / case["path"], case["sha256"], scratch, *operations)
    require(len(report["verified_retained_links"]) == 9, "expected every adjacent pair in the retained batch")
    require([item["expected_identity"] for item in report["verified_retained_links"]] == list(range(41, 50)),
            "retained link identity order changed")
    require([item["outcome"] for item in report["cursor"]] == ["skipped"] * 9 + ["converted"]
            and report["selected_wire_header"]["round"] == 50
            and report["selected_root_comparison"]["selected_checks_pass"], "converted Context case mismatch")
    print(json.dumps(report))

    modified = list(spec["records"])
    record = (scratch / modified[3]["path"]).read_bytes()
    replacement = record[:-35] + bytes([record[-35] ^ 1]) + record[-34:]
    modified[3] = wire_case.save(scratch, "divergent-intermediate.bin", replacement) | {"prepared_count": 0}
    divergent = wire_case.save_json(scratch, "divergent-link-case.json", spec | {"records": modified})
    unchecked = run_sequence(scratch / divergent["path"], divergent["sha256"], scratch,
                             wire_case, *pipeline)
    require(unchecked["selected_root_comparison"]["selected_checks_pass"],
            "scalar-only control should still accept the ordinary comparison inputs")
    try:
        run(scratch / divergent["path"], divergent["sha256"], scratch, *operations)
    except ValueError as error:
        require("fingerprint mismatch at positions 2 -> 3" in str(error), str(error))
        print(f"scalar cursor still reaches the same H+1 fields; audited case rejects: {error}")
    else:
        raise ValueError("unrejected intermediate predecessor divergence")
    print("verified nine retained links before conversion plus isolated divergent intermediate predecessor")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--case", type=Path)
    parser.add_argument("--case-sha")
    args = parser.parse_args()
    if bool(args.case) != bool(args.case_sha):
        parser.error("--case and --case-sha must be supplied together")
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        operations, fixture_args = prepare(args.repo.resolve(), scratch)
        if args.case:
            try:
                report = run(args.case.resolve(), args.case_sha, scratch, *operations)
            except (ValueError, KeyError, TypeError, OverflowError, OSError, subprocess.SubprocessError) as error:
                parser.error(str(error))
            print(json.dumps(report))
            raise SystemExit(0 if report["selected_root_comparison"]["selected_checks_pass"] else 1)
        verify(scratch, operations, fixture_args)
