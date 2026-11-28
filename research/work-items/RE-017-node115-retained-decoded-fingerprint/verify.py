"""Reproduce the native helper link and offline canonical replay comparison."""

from argparse import ArgumentParser
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from oracle import DOMAIN, fixture

PACKET = Path(__file__).resolve().parent
BASE = "2da45cb0a761cff6b478e40421699857d87a94df"
RETAINED = "2b54931ef56fc4dc97814f1b9e4d77616fb9f5ed"
DECODER = "3f1a007af8a16d5a9d3c3d185aa7ac88d1aaab72"
RETAINED_PACKET = "research/work-items/RE-017-node115-retained-batch-parent-link"
READER = "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs"
CODEC = ("certificate-caller", "nested-certificate-decision", "certificate-long-sort",
         "stake-predicate", "varint-buffer-writer")
WIRE = ("client-block-success", "gossip-response-record", "signed-scalar", "u32-varint", "daycount-date")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def native(repo, scratch):
    evidence = scratch / "native"
    evidence.mkdir()
    for name in ("verify.py", "windows.txt"):
        data = subprocess.check_output(["git", "show", f"{RETAINED}:{RETAINED_PACKET}/{name}"], cwd=repo)
        (evidence / name).write_bytes(data)
    subprocess.run([sys.executable, "-B", str(evidence / "verify.py")], cwd=repo, check=True)

    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

    image = (repo / TARGET).read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET_SHA256, "wrong node artifact")
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, va, length):
        section = sections[name]
        relative = va - section["va"]
        require(0 <= relative <= relative + length <= section["size"], "outside ELF section")
        offset = section["offset"] + relative
        return image[offset:offset + length]

    eh = sections[".eh_frame"]
    _, rows = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    for entry, spans in {
        0x4facd10: {0x4face6f: "e8ccbe8300"},
        0x57e8d40: {
            0x57e8d59: "bf1d000000", 0x57e8d70: "0f1005a9d514fb",
            0x57e8d77: "0f11400d", 0x57e8d7b: "0f100591d514fb",
            0x57e8d82: "0f1100", 0x57e8da1: "31d2", 0x57e8da3: "e808b00300",
            0x57e8ef6: "48c784244001000088000000", 0x57e8f02: "66c78424480100000100",
            0x57e8f42: "ba20000000",
        },
        0x5823db0: {0x5823f8d: "c6040800"},
    }.items():
        end, = (row["end"] for row in rows if row["entry"] == entry)
        for address, expected in spans.items():
            raw = bytes.fromhex(expected)
            require(entry <= address < address + len(raw) <= end and read(".text", address, len(raw)) == raw,
                    f"instruction {address:#x} changed")
            print(f"{entry:#x}..{end:#x} {address:#x} {expected}")

    def target(address, length):
        raw = read(".text", address, length)
        return address + length + struct.unpack("<i", raw[-4:])[0]

    require(target(0x4face6f, 5) == 0x57e8d40 and target(0x57e8da3, 5) == 0x5823db0,
            "retained helper and variant serializer edge mismatch")
    require(target(0x57e8d7b, 7) + 13 == target(0x57e8d70, 7), "domain split mismatch")
    require(read(".rodata", target(0x57e8d7b, 7), 29) == DOMAIN, "domain bytes changed")
    print("retained previous owner -> 0x57e8d40 -> variant zero, 29-byte domain and 32-byte Keccak")


def archive(repo, scratch, commit, names, include=()):
    payload = subprocess.check_output(["git", "archive", commit, *include, *(
        f"src/node115-{name}" for name in names
    )], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(payload)) as source:
        for member in source.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    (member.isfile() or member.isdir()), "unexpected Git archive member")
        source.extractall(scratch)


def build(repo, scratch):
    archive(repo, scratch, BASE, CODEC)
    archive(repo, scratch, DECODER, WIRE, (READER,))
    (scratch / "probe.rs").write_bytes((PACKET / "probe.rs").read_bytes())
    (scratch / "Cargo.toml").write_text("""
[package]
name = "retained-fingerprint-probe"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-certificate-caller = { path = "src/node115-certificate-caller" }
node115-client-block-success = { path = "src/node115-client-block-success" }
node115-nested-certificate-decision = { path = "src/node115-nested-certificate-decision" }

[[bin]]
name = "retained-fingerprint-probe"
path = "probe.rs"
""")
    print(f"compiling exact certificate codec {BASE} and decoded retained link {DECODER} offline")
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=scratch, check=True)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--target-dir", scratch / "target"],
                   cwd=scratch, check=True)
    return scratch / "target/debug/retained-fingerprint-probe"


def test(probe):
    artifacts, canonical, expected = fixture()
    for name, data in artifacts.items():
        require((PACKET / name).read_bytes() == data, f"fixture byte mismatch for {name}")
        print(f"{hashlib.sha256(data).hexdigest()}  {name}")
    for name in ("next.bin", "changed-digest.bin", "changed-identity.bin"):
        result = json.loads(subprocess.check_output(
            [probe, PACKET / "previous.bin", PACKET / name],
        ))
        require(result["previous_variant_zero"] == canonical.hex() and
                result["expected_predecessor"] == expected.hex(), "canonical projection or Keccak differs")
        require(result["expected_identity"] == 41 and
                result["observed_identity"] == (42 if name == "changed-identity.bin" else 41),
                "wrong selected identity coordinates")
        require((result["observed_predecessor"] == expected.hex()) == (name != "changed-digest.bin"),
                "wrong selected predecessor hash")
        require(result["link_matches"] == (name == "next.bin"), "wrong continuity comparison result")
        print(f"{name}: {json.dumps(result)}")
    print("verified exact variant-zero bytes and independent Keccak, linked pair and isolated identity/digest controls")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    with TemporaryDirectory() as folder:
        root = Path(folder)
        native(args.repo.resolve(), root)
        test(build(args.repo.resolve(), root))
