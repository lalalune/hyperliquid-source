"""Verify the selected retained attachment key route and offline comparison."""

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

from compare import compare, require

PACKET = Path(__file__).resolve().parent
DECODER = "af37f6a7a2f28278dcea1f03d94e53ef4b7cc143"
CRATES = ("replay-completed-payload", "client-block-success", "lz4-decode", "lz4-literal-encoder",
          "daycount-date", "gossip-response-record", "signed-scalar", "u32-varint", "agent-erase-state")
READER = "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs"


def native(repo):
    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame
    image = (repo / TARGET).read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET_SHA256, "wrong target")
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, va, length):
        where = sections[name]
        relative = va - where["va"]
        require(0 <= relative <= relative + length <= where["size"], "outside ELF section")
        start = where["offset"] + relative
        return image[start:start + length]

    eh = sections[".eh_frame"]
    _, rows = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    bounds = {(row["entry"], row["end"]) for row in rows}
    spans = {}
    with (PACKET / "anchors.tsv").open() as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            start, end, va = (int(row[key], 16) for key in ("start", "end", "address"))
            raw = bytes.fromhex(row["bytes"])
            require((start, end) in bounds and start <= va < va + len(raw) <= end,
                    f"wrong FDE at {va:#x}")
            require(read(".text", va, len(raw)) == raw, f"wrong bytes at {va:#x}")
            spans[va] = raw
            print(f"{start:#x}..{end:#x} {va:#x} {raw.hex()} {row['instruction']}")

    def target(va):
        op = spans[va]
        return va + len(op) + struct.unpack("<i", op[-4:])[0]

    def offset(va):
        return struct.unpack("<I", spans[va][-4:])[0]

    for address, destination in {
        0x4fad4b0: 0x4fad3f0, 0x5a6ece8: 0x5a6ee67, 0x5a6f991: 0x595a6b0,
        0x595ab43: 0x50e2f80, 0x50e2fce: 0x4d6d740, 0x4d6d78b: 0x50818f0,
        0x50819aa: 0x4d6d5c0, 0x4d6d639: 0x5075db0,
        0x5075ed1: 0x4e1c250, 0x5075ff6: 0x4e1c250,
    }.items():
        require(target(address) == destination, f"wrong selected branch/call {address:#x}")
    rel = sections[".rela.dyn"]
    relocs = {slot: value for slot, meta, value in
              struct.iter_unpack("<QQq", read(".rela.dyn", rel["va"], rel["size"])) if meta == 8}
    require(relocs[target(0x5a6e48d)] == 0x4fad300, "wrong converter relocation")
    require(spans[0x4fad4a6][-2:] == b"\xa2\x01", "wrong converter append result")
    require(offset(0x5a6e47a) == offset(0x5a6e600)
            and offset(0x5a6e609) == offset(0x5a6e600) + 16
            and offset(0x5a6e63f) == 0x320 and offset(0x5a6e636) == 0x330
            and offset(0x5a6eb49) == 0x328 and offset(0x5a6eb19) == 0x330,
            "wrong retained descriptor movement")
    require(offset(0x5a6ec02) == 0x1b0 and offset(0x5a6ec0a) == 0x1b8 and
            offset(0x5a6ec12) == 0x1c0 and offset(0x5a6eeBD) == offset(0x5a6f989) == 0x290,
            "wrong archive descriptor placement")
    require(spans[0x4fad46d][-1] == spans[0x5a6eb91][-1] == spans[0x5a6eba5][-1] == 40
            and offset(0x5075ec6) == offset(0x5075fe8) == 32, "wrong copy or printable key width")
    require(read(".rodata", target(0x4d6d625), 21) == b"signed_action_bundles", "wrong archive member")
    print(f"verified {len(spans)} selected converter/clone/serializer instruction spans")


def build(repo, scratch):
    source = subprocess.check_output(["git", "archive", DECODER, "src/l1-shared", READER, *(
        f"src/node115-{crate}" for crate in CRATES
    )], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(source)) as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    (member.isfile() or member.isdir()), "unexpected source archive path")
        archive.extractall(scratch)
    (scratch / "probe.rs").write_bytes((PACKET / "probe.rs").read_bytes())
    (scratch / "Cargo.toml").write_text("""
[package]
name = "attachment-key-probe"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-replay-completed-payload = { path = "src/node115-replay-completed-payload" }

[[bin]]
name = "attachment-key-probe"
path = "probe.rs"
""")
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=scratch, check=True)
    subprocess.run(["cargo", "build", "--locked", "--offline", "--quiet", "--target-dir", scratch / "target"],
                   cwd=scratch, check=True)
    return scratch / "target/debug/attachment-key-probe"


def tests(scratch, probe):
    from Crypto.Hash import keccak
    keys = [(keccak.new(digest_bits=256, data=raw).digest(), raw) for raw in (b"abc", b"", b"xyz")]
    wire = bytearray(bytes(10) + bytes([0x31] * 20) + b"\3")
    for key, _ in keys:
        wire.extend(key)
    wire.extend(bytes([0, 7, 0, 1, 2, 3, 4, 5]) + bytes([0x71] * 32) + bytes([0, 0, 1, 3]))
    for key, payload in keys:
        wire.extend(key + bytes([len(payload)]) + payload)

    def save(name, raw):
        (scratch / name).write_bytes(raw)
        return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}

    def archive(order):
        block = {"signed_action_bundles": [["0x" + keys[i][0].hex(), {"signed_actions": []}] for i in order]}
        return save("archive.jsonl", (json.dumps({"height": 43, "abci_block": block, "resps": None}) + "\n").encode())

    def measured(observations, archived):
        spec = {"height": 43, "wire": save("wire.bin", wire), "archive": archive(archived),
                "successful_rows": observations}
        case = save("case.json", json.dumps(spec).encode())
        result = compare(scratch / case["path"], case["sha256"], probe)
        print(json.dumps(result))
        return result

    positive = measured([0, 2], [0, 2])
    require(positive["matched"] and positive["verified_source_count"] == 3, "wrong sparse success fixture")
    require(not measured([0, 2], [2, 0])["matched"], "wrong archive order accepted")
    require(not measured([0, 2], [0, 1, 2])["matched"], "unselected original row inserted")
    require(measured([], [])["matched"], "empty successful selection failed")
    print("verified content-pinned source rows, two selected archive keys and rejected order/count changes")


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
        native(args.repo.resolve())
        probe = build(args.repo.resolve(), scratch)
        if args.case:
            result = compare(args.case, args.case_sha, probe)
            print(json.dumps(result))
            raise SystemExit(0 if result["matched"] else 1)
        tests(scratch, probe)
