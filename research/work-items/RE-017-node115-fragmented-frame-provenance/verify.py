"""Reproduce cross-file frame provenance through the first-converted fixture."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from fragments import require, run

CAPTURE = "636ef31537fff58b0122108c31df4b52073781eb"
CAPTURE_PACKET = "RE-017-node115-frame-capture-custody"


def load(path, name):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(repo, scratch):
    runner = scratch / "frame-packet"
    runner.mkdir()
    for name in ("verify.py", "capture_case.py", "probe.rs"):
        location = f"{CAPTURE}:research/work-items/{CAPTURE_PACKET}/{name}"
        (runner / name).write_bytes(subprocess.check_output(["git", "show", location], cwd=repo))
    sys.path.insert(0, str(runner))
    old = load(runner / "verify.py", "pinned_frame_provenance_verifier")
    frame_case = load(runner / "capture_case.py", "pinned_frame_provenance_case")
    operations, fixture = old.prepare(repo, scratch)
    return (frame_case.run, operations), (fixture, old.framed)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def tests(scratch, operations, original):
    _, ops = operations
    wire_case = ops[2][2]
    (fixtures, params), framed = original
    spec = fixtures(scratch, *params)
    frames = []
    meta = []
    for index, entry in enumerate(spec.pop("records")):
        raw = (scratch / entry["path"]).read_bytes()
        frame = framed(raw, index % 2)
        frames.append(frame)
        meta.append({"frame_sha256": sha(frame), "payload_sha256": entry["sha256"], "prepared_count": 0})
    capture = b"".join(frames)
    boundaries = (0, 2, 4, len(frames[0]) + 7, len(capture))
    fragments = [capture[start:end] for start, end in zip(boundaries, boundaries[1:])]
    entries = [wire_case.save(scratch, f"capture-source-{index}.bin", raw)
               for index, raw in enumerate(fragments)]
    source = {"fragments": entries, "sha256": sha(capture), "frames": meta}

    def measured(label, value):
        item = wire_case.save_json(scratch, f"case-{label}.json", spec | {"framed_capture": value})
        return run(scratch / item["path"], item["sha256"], scratch, *operations)

    actual = measured("exact-fragments", source)
    coordinates = actual["frame_source_ranges"]
    require(len(coordinates[0]["parts"]) == 3 and len(coordinates[1]["parts"]) == 2,
            "expected first header and second compressed body to straddle fragments")
    for record, original in zip(coordinates, frames):
        rebuilt = b"".join(fragments[part["fragment"]][part["offset"]:part["offset"] + part["size"]]
                           for part in record["parts"])
        require(rebuilt == original, f"wrong physical fragment bytes for frame {record['frame']}")
    require(len(actual["verified_retained_links"]) == 9
            and actual["selected_root_comparison"]["selected_checks_pass"], "failed replay of reconstructed frames")
    print(json.dumps({key: actual[key] for key in (
        "capture_sha256", "source_fragments", "frame_source_ranges",
        "selected_wire_header", "selected_root_comparison",
    )}))
    for label, manifest, expected in (
        ("wrong-order", source | {"fragments": [entries[1], entries[0], *entries[2:]]},
         "wrong joined frame-stream SHA-256"),
        ("wrong-fragment", source | {"fragments": [entries[0] | {"sha256": "0" * 64}, *entries[1:]]},
         "wrong capture-fragment SHA-256 at 0"),
    ):
        try:
            measured(label, manifest)
        except ValueError as error:
            require(expected in str(error), str(error))
            print(f"rejected {label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
    print("verified cross-fragment header/body spans and byte-preserving first-converted replay checks")


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
        operations, fixture = prepare(args.repo.resolve(), scratch)
        if args.case:
            try:
                result = run(args.case.resolve(), args.case_sha, scratch, *operations)
            except (ValueError, KeyError, TypeError, OverflowError, OSError, subprocess.SubprocessError) as error:
                parser.error(str(error))
            print(json.dumps(result))
            raise SystemExit(0 if result["selected_root_comparison"]["selected_checks_pass"] else 1)
        tests(scratch, operations, fixture)
