"""Verify the selected node #115 wire to archive audit."""

from argparse import ArgumentParser
import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_native(repo):
    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

    image = (repo / TARGET).read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET_SHA256, "wrong target")
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, va, n):
        section = sections[name]
        position = va - section["va"]
        require(0 <= position <= position + n <= section["size"], "outside ELF section")
        offset = section["offset"] + position
        return image[offset:offset + n]

    eh = sections[".eh_frame"]
    _, rows = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    bounds = {(row["entry"], row["end"]) for row in rows}
    spans = {}
    with (PACKET / "anchors.tsv").open() as file:
        for row in csv.DictReader(file, delimiter="\t"):
            start, end, address = (int(row[key], 16) for key in ("start", "end", "address"))
            raw = bytes.fromhex(row["bytes"])
            require((start, end) in bounds and start <= address < address + len(raw) <= end,
                    f"wrong FDE for {address:#x}")
            require(address not in spans and read(".text", address, len(raw)) == raw,
                    f"wrong instruction bytes at {address:#x}")
            spans[address] = raw
            print(f"{start:#x}..{end:#x} {address:#x} {raw.hex()} {row['instruction']}")

    def target(site):
        raw = spans[site]
        return site + len(raw) + struct.unpack("<i", raw[-4:])[0]

    for site, label in {
        0x4d6d777: b"abci_block", 0x4d6d7ca: b"height", 0x4d6d5fb: b"time",
        0x4d6d656: b"round", 0x4d6d680: b"parent_round", 0x4e0b078: b"hardfork",
        0x4e0a658: b"proposer", 0x4d6de67: b"version", 0x4d6de90: b"round",
    }.items():
        require(read(".rodata", target(site), len(label)) == label, f"wrong archive field {label!r}")
    require(spans[0x4d6d5f7][-1] == spans[0x4fad64b][-1] == 0x38, "wrong time base")
    require(spans[0x4fad67e][-1] == 0x18 and spans[0x4fad687][-1] == 0x20,
            "wrong independent round members")
    require(spans[0x4fad690][-1] == 0x28 and spans[0x4fad675][-1] == 0x44,
            "wrong hardfork or proposer members")
    require(spans[0x57a6f34][-4:] == b"T\0\0\0", "wrong time separator")
    print(f"verified {len(spans)} native archive header instruction spans")


def compile_probe(repo, scratch, commit, header):
    crates = [
        "node115-replay-completed-payload", "node115-client-block-success",
        "node115-lz4-decode", "node115-lz4-literal-encoder", "node115-daycount-date",
        "node115-gossip-response-record", "node115-signed-scalar", "node115-u32-varint",
    ]
    if not header:
        crates += ["node115-date-time-display", "node115-checkpoint-clock-text"]
    reader = "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs"
    encoded = subprocess.check_output(
        ["git", "archive", commit, reader, *(f"src/{name}" for name in crates)], cwd=repo
    )
    with tarfile.open(fileobj=io.BytesIO(encoded)) as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts
            expected = parts and (parts[0] == "src" or member.name == reader)
            expected_dir = member.isdir() and reader.startswith(member.name.rstrip("/") + "/")
            require((expected or expected_dir) and ".." not in parts
                    and (member.isfile() or member.isdir()), "unexpected source archive member")
        archive.extractall(scratch)
    shutil.copyfile(PACKET / "probe.rs", scratch / "probe.rs")
    (scratch / "Cargo.toml").write_text("""
[package]
name = "offline-wire-archive-probe"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-replay-completed-payload = { path = "src/node115-replay-completed-payload" }

[[bin]]
name = "offline-wire-archive-probe"
path = "probe.rs"

[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(project_header)'] }
""")
    env = os.environ.copy()
    env.pop("RUSTFLAGS", None)
    if header:
        env["RUSTFLAGS"] = "--cfg project_header"
    print(f"build and run existing projection commit {commit} offline", flush=True)
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=scratch, env=env, check=True)
    return subprocess.check_output([
        "cargo", "run", "--locked", "--offline", "--quiet", "--",
        str(PACKET / "wire.bin"), "40",
    ], cwd=scratch, env=env, text=True).strip()


def verify_fixture(repo, compile_sources):
    from audit import audit, load

    root = PACKET / "fixture.json"
    recorded = load((PACKET / "observed.json").read_bytes())
    if compile_sources:
        with tempfile.TemporaryDirectory() as scratch:
            scratch = Path(scratch)
            header = json.loads(compile_probe(
                repo, scratch / "header", "e86354ccddec0b517ac5d239280d70adf520f355", True,
            ))
            header["time"] = compile_probe(
                repo, scratch / "clock", "7dbf442417093a79ece6aae5c2d6e560ab1c7b2d", False,
            )
        observations = {
            "wire_sha256": hashlib.sha256((PACKET / "wire.bin").read_bytes()).hexdigest(),
            "abci_block": header,
        }
        require(observations == recorded, "fresh probe observations differ from the recorded fixture")
        print(json.dumps(observations))
    matched = audit(root, recorded)
    require(matched["height"] == 43 and not matched["differences"], "native fixture header mismatch")

    other = {**recorded, "abci_block": {**recorded["abci_block"], "parent_round": 41}}
    mismatch = audit(root, other)
    require(mismatch["differences"] == {"parent_round": {"archive": 40, "decoded": 41}},
            "wrong isolated mismatch")
    def rejects(manifest_path, observation, expected):
        try:
            audit(manifest_path, observation)
        except ValueError as error:
            require(expected in str(error), str(error))
        else:
            raise ValueError(f"missing rejection for {expected}")

    rejects(root, {**recorded, "wire_sha256": "0" * 64}, "different wire input")
    with tempfile.TemporaryDirectory() as scratch:
        scratch = Path(scratch)
        shutil.copyfile(PACKET / "wire.bin", scratch / "wire.bin")
        archive = load((PACKET / "archive.jsonl").read_bytes())
        archive["height"] = 42
        raw = (json.dumps(archive) + "\n").encode()
        (scratch / "archive.jsonl").write_bytes(raw)
        manifest = load(root.read_bytes())
        manifest_path = scratch / "fixture.json"
        manifest_path.write_text(json.dumps(manifest))
        rejects(manifest_path, recorded, "wrong artifact SHA-256")
        manifest["archive"]["sha256"] = hashlib.sha256(raw).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        rejects(manifest_path, recorded, "differs from H+1")
    print(json.dumps(matched))
    print("verified six equal header fields, cutoff mismatch, artifact pins and distinct H+1 coordinate")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--compile-probes", action="store_true")
    args = parser.parse_args()
    verify_native(args.repo)
    verify_fixture(args.repo, args.compile_probes)
