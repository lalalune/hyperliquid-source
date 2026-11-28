"""Reproduce mixed transport inventory through the pinned Block fixture."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from mixed import digest, require, run

PACKET = Path(__file__).resolve().parent
CAPTURE = "636ef31537fff58b0122108c31df4b52073781eb"
CAPTURE_PACKET = "RE-017-node115-frame-capture-custody"


def load(path, name):
    spec = spec_from_file_location(name, path)
    result = module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare(repo, scratch):
    existing = scratch / "existing-frame-custody"
    existing.mkdir()
    for name in ("verify.py", "capture_case.py", "probe.rs"):
        source = f"{CAPTURE}:research/work-items/{CAPTURE_PACKET}/{name}"
        (existing / name).write_bytes(subprocess.check_output(["git", "show", source], cwd=repo))
    sys.path.insert(0, str(existing))
    old = load(existing / "verify.py", "pinned_frame_custody_verifier")
    core = load(existing / "capture_case.py", "pinned_frame_custody_case")
    ordinary_ops, fixture = old.prepare(repo, scratch)
    old.PACKET = PACKET
    mixed_probe = old.build(repo, scratch / "mixed-build")
    return (mixed_probe, core.run, ordinary_ops), (fixture, old.framed)


def test(scratch, bridge_args, known_fixture):
    _, _, ordinary_ops = bridge_args
    wire_case = ordinary_ops[2][2]
    (fixture, fixture_args), encode = known_fixture
    case = fixture(scratch, *fixture_args)
    blocks = case.pop("records")
    source_frames = []
    declared = []

    def store(payload, flag, kind, prepared_count):
        frame = encode(payload, flag)
        source_frames.append(frame)
        declared.append({"kind": kind, "frame_sha256": digest(frame),
                         "payload_sha256": digest(payload), "prepared_count": prepared_count})

    opaque = b"offline fixture Tx sample"
    for number, entry in enumerate(blocks):
        if number in (0, 4, 9):
            store(bytes([1, len(opaque)]) + opaque, int(number == 4), "Tx", None)
        store((scratch / entry["path"]).read_bytes(), number % 2, "Block", 0)
    source = wire_case.save(scratch, "mixed-capture.bin", b"".join(source_frames))
    source["frames"] = declared

    def measured(name, framed_capture):
        entry = wire_case.save_json(scratch, f"case-{name}.json", case | {"framed_capture": framed_capture})
        return run(scratch / entry["path"], entry["sha256"], scratch, *bridge_args)

    result = measured("mixed", source)
    receipt = result["source_frame_receipts"]
    require([row["index"] for row in receipt if row["kind"] == "Tx"] == [0, 5, 11],
            "wrong Tx positions in original capture")
    require([row["block_view_index"] for row in receipt if row["kind"] == "Block"] == list(range(10)),
            "Block view lost original logical order")
    derived = result["derived_block_view"]
    require(len(derived["verified_retained_links"]) == 9 and
            derived["selected_root_comparison"]["selected_checks_pass"], "failed Block view replay")
    for original, carried in zip((row for row in receipt if row["kind"] == "Block"), derived["frame_receipts"]):
        require(original["frame_sha256"] == carried["frame_sha256"]
                and original["payload_sha256"] == carried["payload_sha256"], "source Block bytes changed")
    print(json.dumps({"mixed_capture_sha256": result["mixed_capture_sha256"],
                     "source_frame_receipts": receipt,
                     "block_view_sha256": derived["capture_sha256"],
                     "selected_wire_header": derived["selected_wire_header"],
                     "selected_root_comparison": derived["selected_root_comparison"]}))
    for label, wrong, expected in (
        ("wrong-kind", declared[0] | {"kind": "Block"}, "wrong decoded frame kind at 0"),
        ("wrong-tx-count", declared[0] | {"prepared_count": 0}, "Tx frame 0 has no prepared Block count"),
    ):
        try:
            measured(label, source | {"frames": [wrong, *declared[1:]]})
        except ValueError as error:
            require(expected in str(error), str(error))
            print(f"rejected {label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
    print("verified three opaque Tx frames, ten unchanged Block frames, and the retained H+1 Context fixture")


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
        bridge_args, fixture = prepare(args.repo.resolve(), scratch)
        if args.case:
            result = run(args.case.resolve(), args.case_sha, scratch, *bridge_args)
            print(json.dumps(result))
            raise SystemExit(0 if result["derived_block_view"]["selected_root_comparison"]["selected_checks_pass"] else 1)
        test(scratch, bridge_args, fixture)
