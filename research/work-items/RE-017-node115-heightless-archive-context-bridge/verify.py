"""Reproduce the source-preserving heightless archive to Context bridge."""

from argparse import ArgumentParser
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from bridge import require, run

PACKET = Path(__file__).resolve().parent
SELECTOR = "78ff506fe6f13b36d1b60f3c12de5a69c961fd8e"
WIRE_CONTEXT = "1cde76593a51988264643cf60747e48e493339a5"
SELECTOR_PACKET = "RE-017-node115-replica-archive-successor"
WIRE_PACKET = "RE-017-node115-wire-adjacent-context-fixture"
SHARD_SHA = "bc40439724fe15c884f2aae0b41d6088b63c51dd8ba196ea0c1760054e938885"
ROW_SHA = "862925e067aa60c9ea63e5be52d15a83010c3710d8256f0d953e839658c567dd"


def checkout_packet(repo, scratch, commit, name, files):
    folder = scratch / name
    folder.mkdir()
    for name in files:
        path = f"research/work-items/{folder.name}/{name}"
        (folder / name).write_bytes(subprocess.check_output(
            ["git", "show", f"{commit}:{path}"], cwd=repo,
        ))
    return folder


def pinned_module(path, name):
    spec = spec_from_file_location(name, path)
    result = module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare(repo, scratch):
    selector_folder = checkout_packet(repo, scratch, SELECTOR, SELECTOR_PACKET, (
        "extract.py", "verify.py",
    ))
    subprocess.run([sys.executable, "-B", str(selector_folder / "verify.py"), "--repo", str(repo)],
                   cwd=repo, check=True)
    selector = pinned_module(selector_folder / "extract.py", "pinned_provider_selector")
    wire_folder = checkout_packet(repo, scratch, WIRE_CONTEXT, WIRE_PACKET, (
        "wire_case.py", "verify.py", "probe.rs", "wire.bin", "archive.jsonl",
    ))
    sys.path.insert(0, str(wire_folder))
    runner = pinned_module(wire_folder / "verify.py", "pinned_wire_context_runner")
    wire_case = pinned_module(wire_folder / "wire_case.py", "pinned_wire_case")
    kit, compare_case, hash_bytes, helper = runner.toolkit(repo, scratch)
    probe = runner.decoder(repo, scratch)
    return selector, runner, wire_case, kit, probe, compare_case, hash_bytes, helper


def compare(scratch, manifest, sha256, selector, wire_case, kit, probe, compare_case, helper):
    report = run(manifest, sha256, scratch, selector, wire_case, kit, probe, compare_case, helper)
    print(json.dumps(report), flush=True)
    return report


def test(scratch, selector, runner, wire_case, kit, probe, compare_case, hash_bytes, helper):
    spec = runner.fixture(scratch, kit, helper, hash_bytes)
    del spec["archive"]
    del spec["clock_control"]
    shard = (PACKET / "shard.jsonl").read_bytes()
    source = {"path": "shard.jsonl", "sha256": SHARD_SHA, "chunk_start": 0, "row_sha256": ROW_SHA}
    (scratch / source["path"]).write_bytes(shard)
    spec["archive_shard"] = source

    def run_case(label, archive_source):
        entry = wire_case.save_json(scratch, f"case-{label}.json", spec | {"archive_shard": archive_source})
        return compare(scratch, scratch / entry["path"], entry["sha256"], selector,
                       wire_case, kit, probe, compare_case, helper)

    good = run_case("good", source)
    origin = good["source_archive"]
    require(origin["height"] == 43 and origin["line_number"] == 43
            and origin["source_row_has_explicit_height"] is False, "wrong source coordinates")
    segment = shard[origin["byte_offset"]:origin["byte_offset"] + origin["byte_length"]]
    require(segment.startswith(b"   {") and hashlib.sha256(segment).hexdigest() == ROW_SHA,
            "original row byte boundaries differ")
    require(good["projected_archive_header_sha256"] != ROW_SHA, "derived projection mislabeled as source")
    require(good["wire_derived_successor"]["round"] == 41
            and good["selected_root_comparison"]["selected_checks_pass"], "wire Context comparison failed")

    tail_changed = shard[:-1] + b" \n"
    (scratch / "changed-tail.jsonl").write_bytes(tail_changed)
    lines = shard.splitlines(keepends=True)
    conflicting = json.loads(lines[42])
    conflicting["height"] = 42
    lines[42] = (json.dumps(conflicting) + "\n").encode()
    bad_height = b"".join(lines)
    conflicting_entry = wire_case.save(scratch, "conflicting-height.jsonl", bad_height) | {
        "chunk_start": 0, "row_sha256": hashlib.sha256(lines[42]).hexdigest(),
    }
    for label, artifact, expected in (
        ("shifted-chunk", source | {"chunk_start": 1}, "selected archive row SHA-256 mismatch"),
        ("unselected-tail", source | {"path": "changed-tail.jsonl"}, "shard SHA-256 mismatch"),
        ("conflicting-height", conflicting_entry, "explicit height conflicts with archive coordinate"),
    ):
        try:
            run_case(label, artifact)
        except ValueError as error:
            require(expected in str(error), str(error))
            print(f"rejected {label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
    print("verified unchanged source bytes, physical H+1 coordinates, independently pinned derived header and selected roots")


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
        selector, runner, wire_case, kit, probe, compare_case, hash_bytes, helper = prepare(
            args.repo.resolve(), scratch,
        )
        if args.case:
            try:
                result = compare(scratch, args.case.resolve(), args.case_sha, selector,
                                 wire_case, kit, probe, compare_case, helper)
            except (ValueError, KeyError, TypeError, OverflowError, OSError, subprocess.SubprocessError) as error:
                parser.error(str(error))
            raise SystemExit(0 if result["selected_root_comparison"]["selected_checks_pass"] else 1)
        test(scratch, selector, runner, wire_case, kit, probe, compare_case, hash_bytes, helper)
