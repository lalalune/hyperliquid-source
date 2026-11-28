"""Check missing-owner input, exact content keys and local object custody."""

from argparse import ArgumentParser
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from Crypto.Hash import keccak

from objects import require, sha, stage

PACKET = Path(__file__).resolve().parent
BASE = "2da45cb0a761cff6b478e40421699857d87a94df"
HANDOFF = "f71c6add4d11c278d7b3bdccc86e64ebabcc833c"
ATTACH = "af37f6a7a2f28278dcea1f03d94e53ef4b7cc143"
HANDOFF_PACKET = "RE-017-node115-replay-attachment-owner-handoff"
ATTACH_PACKET = "RE-017-node115-replay-attachment-fixture"
READER = "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs"
CRATES = (
    "client-block-success", "daycount-date", "gossip-response-record", "signed-scalar", "u32-varint",
)


def static(repo, scratch):
    for commit, name, files, args in (
        (HANDOFF, HANDOFF_PACKET, ("verify.py", "windows.txt"), ()),
        (ATTACH, ATTACH_PACKET, ("verify.py", "anchors.tsv"), ("--repo", str(repo))),
    ):
        target = scratch / name
        target.mkdir()
        for filename in files:
            path = f"{commit}:research/work-items/{name}/{filename}"
            (target / filename).write_bytes(subprocess.check_output(["git", "show", path], cwd=repo))
        subprocess.run([sys.executable, "-B", target / "verify.py", *args], cwd=repo, check=True)


def build(repo, scratch):
    raw = subprocess.check_output(["git", "archive", BASE, READER, *(
        f"src/node115-{name}" for name in CRATES
    )], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    (member.isfile() or member.isdir()), "unexpected Git archive path")
        archive.extractall(scratch)
    (scratch / "probe.rs").write_bytes((PACKET / "probe.rs").read_bytes())
    (scratch / "Cargo.toml").write_text("""
[package]
name = "offline-missing-attachment-probe"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-client-block-success = { path = "src/node115-client-block-success" }

[[bin]]
name = "offline-missing-attachment-probe"
path = "probe.rs"
""")
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=scratch, check=True)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--target-dir", scratch / "target"],
                   cwd=scratch, check=True)
    return scratch / "target/debug/offline-missing-attachment-probe"


def test(scratch, probe):
    def save(name, data):
        (scratch / name).write_bytes(data)
        return {"path": name, "sha256": sha(data)}

    contents = [b"abc", b""]
    keys = [keccak.new(digest_bits=256, data=raw).digest() for raw in contents]
    source = (bytes(10) + bytes([0x31] * 20) + b"\3" + keys[0] + keys[1] + keys[0]
              + bytes([0, 7, 0, 1, 2, 3, 4, 5]) + bytes([0x71] * 32) + bytes([0, 0, 0]))
    wire = save("wire.bin", source)
    objects = [
        {**save(f"raw-{index}.bin", contents[index]), "keccak256": "0x" + keys[index].hex()}
        for index in (1, 0)
    ]
    case = {"wire": wire, "objects": objects}

    def measured(label, values):
        entry = save(f"{label}.json", json.dumps(values).encode())
        return stage(scratch / entry["path"], entry["sha256"], probe, scratch / label)

    result = measured("pinned-order", case)
    require(result["wire_attachment_owner"] == "absent" and result["source_wire_sha256"] == wire["sha256"],
            "original missing-owner wire provenance lost")
    rows = result["derived_rows"]
    require([row["content_key"] for row in rows] == ["0x" + keys[i].hex() for i in (0, 1, 0)]
            and [(scratch / "pinned-order" / row["path"]).read_bytes() for row in rows] == [b"abc", b"", b"abc"],
            "lost repeated or zero-length content")
    print(json.dumps(result))
    changed = save("changed.bin", b"other ordinary body")
    present = save("already-present.bin", source[:-1] + bytes([1, 0]))
    for label, edited, expected in (
        ("missing-body", case | {"objects": objects[:1]}, "missing independently supplied attachment"),
        ("repinned-wrong-body", case | {"objects": [objects[0], objects[1] | changed]}, "differs from decoded key"),
        ("present-owner", case | {"wire": present}, "already carries an attachment owner"),
    ):
        try:
            measured(label, edited)
        except ValueError as error:
            require(expected in str(error), str(error))
            print(f"rejected {label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
    require((scratch / wire["path"]).read_bytes() == source, "original captured wire changed")
    print("verified separately pinned raw objects, empty and repeated bodies, exact header order and unchanged wire")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--case", type=Path)
    parser.add_argument("--case-sha")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    supplied = (args.case, args.case_sha, args.output)
    if any(supplied) and not all(supplied):
        parser.error("--case, --case-sha and --output must be supplied together")
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        static(args.repo.resolve(), scratch)
        decoder = build(args.repo.resolve(), scratch)
        if args.case:
            print(json.dumps(stage(args.case.resolve(), args.case_sha, decoder, args.output)))
        else:
            test(scratch, decoder)
