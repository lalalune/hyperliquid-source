"""Reproduce frame positions and derived payload pins through retained replay."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from capture_case import require, run, sha

PACKET = Path(__file__).resolve().parent
FRAME = "df2e8596a9af828dde559c98d083af882fc14102"
LINKED = "a56e64a7bd8b78323f9c91224149ee16d8b4d356"
FRAME_PACKET = "RE-017-node115-framed-replay-fixture"
LINKED_PACKET = "RE-017-node115-linked-first-converted-fixture"
CRATES = (
    "replay-completed-payload", "client-block-success", "lz4-decode", "lz4-literal-encoder",
    "daycount-date", "gossip-response-record", "signed-scalar", "u32-varint",
    "tcp-stream-frame-lz4", "tcp-frame-plan",
)
READER = "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs"


def export(repo, scratch, commit, item, names):
    result = scratch / item
    result.mkdir()
    for name in names:
        path = f"{commit}:research/work-items/{item}/{name}"
        (result / name).write_bytes(subprocess.check_output(["git", "show", path], cwd=repo))
    return result


def load(path, name):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(repo, source):
    source.mkdir()
    raw = subprocess.check_output(["git", "archive", FRAME, READER, *(
        f"src/node115-{name}" for name in CRATES
    )], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for item in archive.getmembers():
            path = Path(item.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    (item.isdir() or item.isfile()), "unexpected Git archive member")
        archive.extractall(source)
    (source / "probe.rs").write_bytes((PACKET / "probe.rs").read_bytes())
    (source / "Cargo.toml").write_text("""
[package]
name = "offline-frame-capture-probe"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-tcp-stream-frame-lz4 = { path = "src/node115-tcp-stream-frame-lz4" }
node115-replay-completed-payload = { path = "src/node115-replay-completed-payload" }

[[bin]]
name = "offline-frame-capture-probe"
path = "probe.rs"
""")
    print(f"compile exact frame reader/decoder {FRAME} offline", flush=True)
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=source, check=True)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--target-dir", source / "target"],
                   cwd=source, check=True)
    return source / "target/debug/offline-frame-capture-probe"


def prepare(repo, scratch):
    native = export(repo, scratch, FRAME, FRAME_PACKET, ("verify.py", "anchors.tsv"))
    subprocess.run([sys.executable, "-B", native / "verify.py", "--repo", str(repo)], check=True)
    frame_probe = build(repo, scratch / "frame-build")
    linked = export(repo, scratch, LINKED, LINKED_PACKET, ("verify.py", "bridge.py"))
    sys.path.insert(0, str(linked))
    linked_tests = load(linked / "verify.py", "existing_linked_batch_case")
    linked_bridge = load(linked / "bridge.py", "existing_linked_batch_bridge")
    operations, fixture = linked_tests.prepare(repo, scratch)
    return (frame_probe, linked_bridge.run, operations), (linked_tests.fixtures, fixture)


def framed(raw, flag):
    if flag == 1:
        require(15 <= len(raw) < 270, "synthetic one-run literal size")
        # Independent synthetic LZ4 literal run, with capacity above actual output length.
        raw = (128).to_bytes(4, "little") + bytes([0xf0, len(raw) - 15]) + raw
    return len(raw).to_bytes(4, "big") + bytes([flag]) + raw


def tests(scratch, inputs, fixture):
    frame_probe, linked, operations = inputs
    wire_case = operations[2]
    previous, args = fixture
    spec = previous(scratch, *args)
    records = spec.pop("records")
    source, declared = [], []
    flags = [0, 1, 2, 1, 0, 1, 0, 1, 2, 1]
    for record, flag in zip(records, flags):
        plain = (scratch / record["path"]).read_bytes()
        wire = framed(plain, flag)
        source.append(wire)
        declared.append({"frame_sha256": sha(wire), "payload_sha256": record["sha256"],
                         "prepared_count": record["prepared_count"]})
    capture = b"".join(source)
    archived = wire_case.save(scratch, "captured-frames.bin", capture)
    meta = {**archived, "frames": declared}

    def measured(label, item):
        bind = wire_case.save_json(scratch, f"case-{label}.json", spec | {"framed_capture": item})
        return run(scratch / bind["path"], bind["sha256"], scratch, frame_probe, linked, operations)

    result = measured("match", meta)
    receipts = result["frame_receipts"]
    require([row["compressed"] for row in receipts] == [flag == 1 for flag in flags],
            "frame flag-mode selection mismatch")
    require([row["frame_size"] for row in receipts] == [len(wire) for wire in source],
            "frame receipt length mismatch")
    require(len(result["verified_retained_links"]) == 9 and result["selected_wire_header"]["round"] == 50
            and result["selected_root_comparison"]["selected_checks_pass"], "offline replay result failed")
    print(json.dumps({"capture_sha256": result["capture_sha256"], "frame_receipts": receipts,
                      "retained_links_checked": len(result["verified_retained_links"]),
                      "selected_wire_header": result["selected_wire_header"],
                      "selected_root_comparison": result["selected_root_comparison"]}))
    bad_pin = [*declared]
    bad_pin[1] = bad_pin[1] | {"payload_sha256": bad_pin[0]["payload_sha256"]}
    altered_pin = [*declared]
    altered_pin[1] = altered_pin[1] | {"frame_sha256": altered_pin[0]["frame_sha256"]}
    for label, supplied, message in (
        ("wrong-stream-pin", meta | {"sha256": "0" * 64}, "wrong original frame-stream SHA-256"),
        ("wrong-body-pin", meta | {"frames": bad_pin}, "wrong decoded payload SHA-256 at 1"),
        ("wrong-frame-pin", meta | {"frames": altered_pin}, "wrong source frame SHA-256 at 1"),
    ):
        try:
            measured(label, supplied)
        except ValueError as error:
            require(message in str(error), str(error))
            print(f"rejected {label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
    print("verified plain and LZ4 frame custody, retained links and selected H/H+1 Context checks")


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
        inputs, fixture = prepare(args.repo.resolve(), scratch)
        if args.case:
            try:
                result = run(args.case.resolve(), args.case_sha, scratch, *inputs)
            except (ValueError, KeyError, TypeError, OverflowError, OSError, subprocess.SubprocessError) as error:
                parser.error(str(error))
            print(json.dumps(result))
            raise SystemExit(0 if result["selected_root_comparison"]["selected_checks_pass"] else 1)
        tests(scratch, inputs, fixture)
