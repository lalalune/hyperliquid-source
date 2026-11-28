"""Verify original MessagePack checkpoint fields driving the paired Rust engine fixture."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

import msgpack

from checkpoint_case import controls, run

BASE = "2da45cb0a761cff6b478e40421699857d87a94df"
PROJECT = "28a1baad05d92cad885e8ec05dbba5ed081fbbbf"
PAIR = "67b4ebafb71af7799784d3edd701a907235336da"
HARDFORK = "85999ce63eb966749604c94420b495960b49be60"


def load(repo, scratch, commit, packet, files):
    folder = scratch / packet
    folder.mkdir()
    for filename in files:
        place = f"{commit}:research/work-items/{packet}/{filename}"
        (folder / filename).write_bytes(subprocess.check_output(["git", "show", place], cwd=repo))
    return folder


def module(folder, filename, name):
    spec = spec_from_file_location(name, folder / filename)
    result = module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare(repo, scratch):
    module_paths = [str(repo / "tools")]
    if os.environ.get("PYTHONPATH"):
        module_paths.append(os.environ["PYTHONPATH"])
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(module_paths))
    for commit, packet in ((HARDFORK, "RE-017-node115-checkpoint-hardfork-pair"),
                           (BASE, "RE-009-node115-checkpoint-root-cadence"),
                           (BASE, "RE-017-node115-positional-context-replay-key")):
        native = load(repo, scratch, commit, packet, ("verify.py", "windows.txt"))
        subprocess.run([sys.executable, "-B", native / "verify.py"], cwd=repo, env=environment, check=True)
    project = load(repo, scratch, PROJECT, "RE-017-node115-positional-context-fixture", ("project.py",))
    old = load(repo, scratch, PAIR, "RE-017-node115-engine-paired-root-parity", ("verify.py", "probe.rs"))
    positional = module(project, "project.py", "existing_positional_projection")
    paired = module(old, "verify.py", "existing_paired_engine")
    sys.path.insert(0, str(repo / "tools"))
    from abci_hash_tree_encoding_115 import enc_tree

    source = scratch / "rust-engine"
    source.mkdir()
    paired.native(repo, source)
    return positional, paired, paired.build(repo, source), enc_tree


def tests(scratch, inputs):
    positional, paired, probe, tree = inputs
    paired.tests(scratch, probe, tree)

    def save(name, raw):
        path = scratch / name
        path.write_bytes(raw)
        return {"path": name, "sha256": paired.sha(raw)}

    def block_context(height=42, round_word=40, hardfork_round=40, cadence=1):
        ctx = [500, {"version": 5, "round": hardfork_round}, height, None, round_word,
               "1969-12-31T23:59:59.999999999", "1969-12-31T23:59:58", 12, 14]
        return msgpack.packb({"exchange": {"msc": {"aci": cadence}, "locus": {"ctx": ctx}}},
                             use_bin_type=True)

    def run_case(label, payload):
        case = save(f"case-{label}.json", json.dumps(payload).encode())
        temporary = scratch / label
        temporary.mkdir()
        return run(scratch / case["path"], case["sha256"], temporary, *inputs)

    def existing(name):
        return {"path": name, "sha256": paired.sha((scratch / name).read_bytes())}

    spec = {"height": 42, "checkpoint_rmp": save("state.rmp", block_context()),
            "wire": existing("original.bin"), "reference_h": existing("raw-42-40.jsonl"),
            "reference_h_plus_one": existing("raw-43-41.jsonl"),
            "fixture_inputs": {"persisted_loader_count": 12, "auxiliary_digest": "ab" * 32}}
    result = run_case("match", spec)
    require = paired.require
    require(result["matches_h"] and result["matches_h_plus_one"], "did not get paired reconstructed roots")
    require(result["restored_checkpoint"]["hardfork_words"] == [5, 40]
            and result["restored_checkpoint"]["cadence"] == 1
            and result["restored_checkpoint"]["round"] == 40, "wrong restored Context controls")
    print(json.dumps(result))

    alt = run_case("successor-divergence", spec | {"reference_h_plus_one": existing("raw-43-42.jsonl")})
    require(alt["matches_h"] and not alt["matches_h_plus_one"], "wrong independently reference-specific divergence")
    print(f"alternate successor: matches_h={alt['matches_h']} matches_h_plus_one={alt['matches_h_plus_one']}")

    changed = save("zero-cadence.rmp", block_context(cadence=0))
    words = controls(scratch / changed["path"], changed["sha256"], 42, positional)
    require(words["cadence"] == 1000, "selected zero cadence was not defaulted")
    print("verified selected zero cadence projects the restored value 1000")
    other = save("other-height.rmp", block_context(height=43))
    try:
        run_case("wrong-height", spec | {"checkpoint_rmp": other})
    except ValueError as error:
        require("height does not match" in str(error), str(error))
        print(f"stopped before engine invocation: {error}")
    else:
        raise ValueError("matched independent reference at the wrong checkpoint height")
    changed_hardfork = save("other-hardfork.rmp", block_context(hardfork_round=39))
    try:
        run_case("hardfork-mismatch", spec | {"checkpoint_rmp": changed_hardfork})
    except subprocess.CalledProcessError:
        print("engine probe rejected restored hardfork [5,39] with source Block hardfork [5,40]")
    else:
        raise ValueError("engine probe ignored the observed checkpoint hardfork pair")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--case", type=Path)
    parser.add_argument("--case-sha")
    args = parser.parse_args()
    if bool(args.case) != bool(args.case_sha):
        parser.error("--case and --case-sha must both be supplied")
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        inputs = prepare(args.repo.resolve(), scratch)
        if args.case:
            result = run(args.case.resolve(), args.case_sha, scratch, *inputs)
            print(json.dumps(result))
            raise SystemExit(0 if result["matches_h"] and result["matches_h_plus_one"] else 1)
        tests(scratch, inputs)
