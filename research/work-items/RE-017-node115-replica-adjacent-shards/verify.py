"""Verify the selected native node #115 replica row and roll coordinates."""

from argparse import ArgumentParser
import csv
import hashlib
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

    for site, destination in {
        0x595ab43: 0x50e2f80, 0x50e2fce: 0x4d6d740,
        0x4d6d7de: 0x5077210, 0x5a6f991: 0x595a6b0,
    }.items():
        require(target(site) == destination, f"wrong replica boundary at {site:#x}")
    for site, label in {
        0x4d6d777: b"abci_block", 0x4d6d7a4: b"resps", 0x4d6d7ca: b"height",
        0x4d6d625: b"signed_action_bundles", 0x4d6d656: b"round", 0x4d6d680: b"parent_round",
    }.items():
        require(read(".rodata", target(site), len(label)) == label, f"wrong native field {label!r}")
    require(spans[0x50e307b][-1] == 10, "wrong line boundary")
    require(spans[0x595a6d9][-1] == 1 and spans[0x595a6dd][-1] == 0xff,
            "wrong saturating subtraction")
    require(spans[0x4d6d7c6][-1] == 0x80, "wrong direct height field")
    require(struct.unpack("<I", spans[0x5a6ef02][-4:])[0]
            - struct.unpack("<I", spans[0x5a6f989][-4:])[0] == 0x80,
            "record height does not reach the explicit JSON field")

    reciprocal = struct.unpack("<Q", spans[0x595a6e1][-8:])[0]
    shift = 64 + spans[0x595a6f1][-1]
    bucket_width = struct.unpack("<I", spans[0x595a6f5][-4:])[0]
    for height in (0, 1, 9_999, 10_000, 10_001, 20_000, 20_001, (1 << 64) - 1):
        one_less = max(height - 1, 0)
        native = ((one_less * reciprocal) >> shift) * bucket_width
        require(native == (one_less // 10_000) * 10_000, "wrong derived bucket coordinate")
        print(f"height {height} native rotation bucket {native}")
    print(f"verified {len(spans)} native replica rotation and explicit-height spans")


def verify_fixtures():
    from tempfile import TemporaryDirectory
    from select_pair import parse_json, select_pair

    manifest = parse_json((PACKET / "manifest.json").read_text())
    selected = select_pair(PACKET, manifest, 10_000)
    literal = [
        (10_000, "archive/20261030/0", 2, 179),
        (10_001, "archive/20261031/10000", 1, 0),
    ]
    observed = [(row.height, row.shard, row.line, row.offset) for row in selected]
    require(observed == literal, f"wrong cross-shard coordinates {observed}")
    for row in selected:
        raw = row.raw.encode("utf-8")
        blob = (PACKET / row.shard).read_bytes()
        require(blob[row.offset:row.offset + len(raw)] == raw, "selected row bytes changed")
        require(hashlib.sha256(raw).hexdigest() == row.row_sha256, "wrong row digest")
        print(f"height={row.height} shard={row.shard} line={row.line} offset={row.offset} sha256={row.row_sha256}")

    def rejects(root, shards, fragment):
        try:
            select_pair(root, shards, 10_000)
        except ValueError as error:
            require(fragment in str(error), str(error))
        else:
            raise ValueError(f"failed to reject {fragment}")

    rejects(PACKET, manifest[1:], "missing native height 10001")
    wrong = [{**item, "sha256": "0" * 64} for item in manifest]
    rejects(PACKET, wrong, "shard SHA-256 mismatch")
    with TemporaryDirectory() as scratch:
        root = Path(scratch)
        file = root / "first"
        other = root / "second"
        for path in (file, other):
            path.write_bytes(selected[0].raw.encode("utf-8"))
        records = [
            {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in (file, other)
        ]
        rejects(root, records, "height 10000 is ambiguous")
    print("verified two exact adjacent raw rows and missing/ambiguous/pin controls")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
    verify_fixtures()
