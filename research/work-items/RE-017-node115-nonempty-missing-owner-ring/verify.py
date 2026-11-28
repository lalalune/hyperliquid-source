"""Reproduce the selected nonempty missing-owner flat ring lookup."""

from argparse import ArgumentParser
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

PACKET = Path(__file__).resolve().parent
BASE = "2da45cb0a761cff6b478e40421699857d87a94df"
READER = "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs"
CRATES = (
    "client-block-success", "daycount-date", "gossip-response-record", "signed-scalar",
    "u32-varint", "rpc-flat-materializer",
)


def require(condition, text):
    if not condition:
        raise ValueError(text)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def native(repo):
    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame
    image = (repo / TARGET).read_bytes()
    require(sha(image) == TARGET_SHA256, "wrong captured target")
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, va, size):
        region = sections[name]
        delta = va - region["va"]
        require(0 <= delta <= delta + size <= region["size"], "outside ELF section")
        start = region["offset"] + delta
        return image[start:start + size]

    eh = sections[".eh_frame"]
    _, rows = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    extents = {(row["entry"], row["end"]) for row in rows}
    observed = {}
    with (PACKET / "anchors.tsv").open() as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            start, end, va = (int(row[key], 16) for key in ("start", "end", "address"))
            raw = bytes.fromhex(row["bytes"])
            require((start, end) in extents and start <= va < va + len(raw) <= end,
                    f"wrong FDE for {va:#x}")
            require(read(".text", va, len(raw)) == raw, f"wrong native bytes at {va:#x}")
            observed[va] = raw
            print(f"{start:#x}..{end:#x} {va:#x} {raw.hex()} {row['instruction']}")

    def direct(address, width=4):
        raw = observed[address]
        return address + len(raw) + int.from_bytes(raw[-width:], "little", signed=True)

    for address, destination in {
        0x5a87666: 0x5a87a52, 0x4fad7ff: 0x4fad964, 0x4fad9e5: 0x57f5ee0,
        0x4fad9ec: 0x4fadae4, 0x4fad9fa: 0x4fadae4, 0x4fadaee: 0x4fadb12,
        0x4fadadf: 0x4fad733, 0x4fad9bd: 0x4fada64,
    }.items():
        width = 1 if address == 0x4fadaee else 4
        require(direct(address, width) == destination, f"wrong selected edge at {address:#x}")
    rel = sections[".rela.dyn"]
    relocs = {slot: value for slot, meta, value in
              struct.iter_unpack("<QQq", read(".rela.dyn", rel["va"], rel["size"])) if meta == 8}
    require(relocs[direct(0x5a87a64)] == 0x4fad710, "wrong owner-handoff binding")
    require(observed[0x5a8750c][-4:] == b"\x28\x01\0\0"
            and observed[0x4fad7dd][-1] == 0x20 and observed[0x4fad964][-1] == 0x38
            and observed[0x4fad9ae][-1] == 0x20 and observed[0x4fadb3e][-1] == 0x1c,
            "wrong store location, ring layout, row stride or missing tag")
    print(f"verified {len(observed)} exact caller/flat lookup/append and missing-key instruction spans")


def build(repo, scratch):
    data = subprocess.check_output(["git", "archive", BASE, READER, *(
        f"src/node115-{name}" for name in CRATES
    )], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    (member.isfile() or member.isdir()), "unexpected source path")
        archive.extractall(scratch)
    (scratch / "probe.rs").write_bytes((PACKET / "probe.rs").read_bytes())
    (scratch / "Cargo.toml").write_text("""
[package]
name = "nonempty-owner-ring-probe"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-client-block-success = { path = "src/node115-client-block-success" }
node115-rpc-flat-materializer = { path = "src/node115-rpc-flat-materializer" }

[[bin]]
name = "nonempty-owner-ring-probe"
path = "probe.rs"
""")
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=scratch, check=True)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--target-dir", scratch / "target"],
                   cwd=scratch, check=True)
    return scratch / "target/debug/nonempty-owner-ring-probe"


def measured(probe, scratch, wire, wire_sha, ring, ring_sha):
    inputs = []
    for name, source, expected in (("captured-block.bin", wire, wire_sha), ("supplied-ring.txt", ring, ring_sha)):
        data = source.read_bytes()
        require(sha(data) == expected, f"wrong {name} SHA-256")
        target = scratch / name
        target.write_bytes(data)
        inputs.append(target)
    result = json.loads(subprocess.check_output([probe, *inputs]))
    return {"wire_sha256": wire_sha, "ring_sha256": ring_sha, **result}


def tests(scratch, probe):
    keys = {letter: bytes([value] * 32) for letter, value in zip("ABCD", (40, 60, 80, 100))}
    ring = scratch / "independent-ring.txt"
    ring.write_text(
        "3 3\n" + "\n".join(f"{keys[letter].hex()} {value}"
                             for letter, value in zip("BCDA", (201, 301, 0, 101))) + "\n"
    )

    def observe(order):
        wire = scratch / "source.bin"
        raw = (bytes(10) + bytes([0x31] * 20) + bytes([len(order)]) + b"".join(keys[k] for k in order)
               + bytes([0, 7, 0, 1, 2, 3, 4, 5]) + bytes([0x71] * 32) + bytes(3))
        wire.write_bytes(raw)
        result = measured(probe, scratch, wire, sha(raw), ring, sha(ring.read_bytes()))
        print(json.dumps(result))
        return result

    matched = observe("CABA")
    require(matched["status"] == "materialized"
            and [row["physical_index"] for row in matched["rows"]] == [1, 3, 0, 3]
            and [row["opaque_value"] for row in matched["rows"]] == [301, 101, 201, 101],
            "wrapped ring failed source key order or repeat")
    missing = observe("CDA")
    require(missing["status"] == "missing" and missing["position"] == 1
            and missing["key"] == keys["D"].hex() and "rows" not in missing,
            "missing key did not close completed-owner result")
    print("verified wrapped ring source lookup, repeated row order and first missing key")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--wire", type=Path)
    parser.add_argument("--wire-sha")
    parser.add_argument("--ring", type=Path)
    parser.add_argument("--ring-sha")
    args = parser.parse_args()
    custom = (args.wire, args.wire_sha, args.ring, args.ring_sha)
    if any(custom) and not all(custom):
        parser.error("supply wire and ring files with their respective SHA-256 pins")
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        native(args.repo.resolve())
        probe = build(args.repo.resolve(), scratch)
        if args.wire:
            result = measured(probe, scratch, *custom)
            print(json.dumps(result))
            raise SystemExit(0 if result["status"] == "materialized" else 1)
        tests(scratch, probe)
