"""Reproduce a first-converted Context case with the selected local rewrite."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
from struct import pack_into
import subprocess
import sys
from tempfile import TemporaryDirectory

import msgpack

from bridge import require, run

STARTUP = "dbef2f7057402d8355d103c2b5f1a03fecf38ace"
REWRITE = "0950325e8f3dd0a29cd2a3a6b9dd69150fb21c1c"
CONVERSION = "b5c57efaa22b79029d113aa6094435cfb8dec488"
STAGE_PACKET = "RE-017-node115-named-rmp-startup-staging"
REWRITE_PACKET = "RE-017-node115-local-startup-image-rewrite"
CONVERSION_PACKET = "RE-017-node115-first-converted-context-fixture"


def restore(repo, scratch, commit, packet, names):
    folder = scratch / packet
    folder.mkdir()
    for name in names:
        path = f"{commit}:research/work-items/{packet}/{name}"
        (folder / name).write_bytes(subprocess.check_output(["git", "show", path], cwd=repo))
    return folder


def load(path, name):
    spec = spec_from_file_location(name, path)
    code = module_from_spec(spec)
    sys.modules[name] = code
    spec.loader.exec_module(code)
    return code


def prepare(repo, scratch):
    startup = restore(repo, scratch, STARTUP, STAGE_PACKET, ("stage.py",))
    rewrite = restore(repo, scratch, REWRITE, REWRITE_PACKET, ("rewrite.py", "test_rewrite.py"))
    conversion = restore(repo, scratch, CONVERSION, CONVERSION_PACKET, ("verify.py", "sequence.py", "cursor.rs"))
    subprocess.run([sys.executable, "-B", rewrite / "test_rewrite.py"], check=True)
    subprocess.run([sys.executable, "-B", "research/work-items/RE-017-node115-local-replay-hardfork-rewrite/verify.py"],
                   cwd=repo, check=True)
    sys.path.insert(0, str(conversion))
    stage_module = load(startup / "stage.py", "named_startup_fields")
    rewrite_module = load(rewrite / "rewrite.py", "local_rewrite")
    conversion_module = load(conversion / "verify.py", "first_converted_case")
    sequence_module = load(conversion / "sequence.py", "first_converted_run")
    runner, wire_case, kit, cursor, decoder, compare_case, hash_bytes, helper = (
        conversion_module.prepare(repo, scratch)
    )
    tools = (stage_module, rewrite_module.rewrite_local, sequence_module.run, wire_case, kit,
             cursor, decoder, compare_case, hash_bytes, helper)
    return tools, (runner, wire_case, kit, hash_bytes, helper, rewrite_module.COMPACT_SIZE)


def fixtures(scratch, runner, wire_case, kit, hash_bytes, helper, compact_size):
    base = runner.fixture(scratch, kit, helper, hash_bytes)
    checkpoint = msgpack.unpackb((scratch / base["checkpoint_rmp"]["path"]).read_bytes(), raw=False)
    checkpoint["exchange"]["scheduled_freeze_height"] = 42
    checkpoint["exchange"]["locus"]["ctx"]["hardfork"]["round"] = 17
    compact = bytearray(compact_size)
    pack_into("<4Q", compact, 0x18, 5, 17, 42, 40)
    pack_into("<QQ", compact, 0x10e8, 1, 42)
    original = (scratch / base["wire"]["path"]).read_bytes()
    require(original[37:43] == bytes([0, 5, 40, 40, 4, 5]), "wrong fixture wire layout")
    records = []
    for index in range(10):
        updated = original[:38] + bytes([6, 40, 40 + index]) + original[41:]
        record = wire_case.save(scratch, f"rewritten-wire-{index}.bin", updated)
        records.append(record | {"prepared_count": 0})

    archive = json.loads((scratch / base["archive"]["path"]).read_bytes())
    archive["abci_block"]["hardfork"] = {"version": 6, "round": 40}
    archive["abci_block"]["round"] = 50

    def root(role, name, pair, consensus_round):
        reference = json.loads((scratch / base[role]["path"]).read_bytes())
        rows = reference["exchange_abci_hash"]
        context = rows[0][1][0][1]
        hardfork = context[1][1]
        for index, word in enumerate(pair):
            hardfork[index][1] = hash_bytes(helper, kit["tree"], word.to_bytes(8, "little"))
        context[4][1] = hash_bytes(helper, kit["tree"], consensus_round.to_bytes(8, "little"))
        reference["abci_digest"] = kit["tree"].digest(helper, kit["tree"].decode_tree(rows))
        return wire_case.save_json(scratch, name, reference)

    return {
        "height": 42, "records": records,
        "archive": wire_case.save_json(scratch, "rewritten-archive.jsonl", archive),
        "compact_image": wire_case.save(scratch, "original-compact.bin", compact),
        "checkpoint_rmp": wire_case.save(scratch, "original-checkpoint.rmp", msgpack.packb(checkpoint, use_bin_type=True)),
        "reference_h": root("reference_h", "original-h.jsonl", (5, 17), 40),
        "reference_h_plus_one": root("reference_h_plus_one", "rewritten-h1.jsonl", (6, 40), 50),
    }, root("reference_h_plus_one", "stale-hardfork-h1.jsonl", (5, 17), 50)


def test(scratch, tools, fixture_args):
    spec, stale_root = fixtures(scratch, *fixture_args)
    wire_case = tools[3]

    def measure(name, value):
        entry = wire_case.save_json(scratch, name, value)
        report = run(scratch / entry["path"], entry["sha256"], scratch, *tools)
        print(json.dumps({key: item for key, item in report.items() if key != "cursor"}))
        return report

    positive = measure("rewrite-success.json", spec)
    require(positive["rewritten"] and positive["original_hardfork_pair"] == (5, 17)
            and positive["materialized_replay_pair"] == (6, 40) and positive["selected_checks_pass"],
            "expected rewritten pair and selected H/H+1 match")
    negative = measure("wrong-h1-hardfork.json", spec | {"reference_h_plus_one": stale_root})
    require(negative["selected_root_comparison"]["selected_checks_pass"]
            and negative["successor_hardfork"] == {"version": False, "round": False}
            and not negative["selected_checks_pass"], "wrong original pair accepted at H+1")

    archive = json.loads((scratch / spec["archive"]["path"]).read_bytes())
    archive["abci_block"]["hardfork"] = {"version": 5, "round": 17}
    wrong = wire_case.save_json(scratch, "stale-archive.jsonl", archive)
    try:
        measure("wrong-archive.json", spec | {"archive": wrong})
    except ValueError as error:
        require("archive hardfork pair differs" in str(error), str(error))
        print(f"rejected original pair in archive: {error}")
    else:
        raise ValueError("archive used the original pair after rewrite")
    print("verified original H pair, rewritten successor and H+1 hardfork children; stale H+1/root controls rejected")


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
        tools, fixture_args = prepare(args.repo.resolve(), scratch)
        if args.case:
            try:
                report = run(args.case.resolve(), args.case_sha, scratch, *tools)
            except (ValueError, KeyError, TypeError, OverflowError, OSError, subprocess.SubprocessError) as error:
                parser.error(str(error))
            print(json.dumps(report))
            raise SystemExit(0 if report["selected_checks_pass"] else 1)
        test(scratch, tools, fixture_args)
