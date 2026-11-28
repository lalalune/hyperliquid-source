"""Verify the replica header field routes and distinct preflight comparands."""

from argparse import ArgumentParser
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from project import Hardfork, load_header

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

    for site, expected in {
        0x4d6d5fb: b"time", 0x4d6d656: b"round", 0x4d6d680: b"parent_round",
        0x4d6d7ca: b"height", 0x4e0b078: b"hardfork", 0x4d6de67: b"version",
        0x4d6de90: b"round", 0x4e0a658: b"proposer",
    }.items():
        require(read(".rodata", target(site), len(expected)) == expected, "changed field name")
    for site, expected in {
        0x4d6d60c: 0x5076270, 0x5076330: 0x4fcd860, 0x4fcd8b0: 0x57a6f10,
        0x4d6d667: 0x50783d0, 0x4d6d691: 0x50783d0, 0x4d6d7de: 0x5077210,
        0x4d6d6a4: 0x4e0b070, 0x4e0b084: 0x50878e0, 0x508799a: 0x4d6de30,
        0x4d6de7b: 0x5077210, 0x4d6dea4: 0x50783d0,
        0x5078482: 0x54282a0, 0x50772c2: 0x50fc010,
        0x4d6d6ba: 0x4e0a650, 0x4e0a664: 0x506d150, 0x506d21d: 0x4e1c250,
        0x5a04eed: 0x5a0621d, 0x5a04eff: 0x5a0624a,
        0x5a04f1a: 0x5a0626d, 0x5a04f23: 0x5a0626d,
    }.items():
        require(target(site) == expected, f"wrong edge at {site:#x}")

    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    for site, expected in {0x4fcd8d2: 0x1680500, 0x57a6f23: 0x1628bc0, 0x57a6f5b: 0x162a760}.items():
        require(relocations.get(target(site)) == (8, expected), f"wrong slot at {site:#x}")
    print(f"Pinned #115 digest {TARGET_SHA256}; {len(spans)} instruction witnesses")
    print("Preflight operands: hardfork.version, hardfork.round; archive time follows a distinct formatter")


def verify_fixture():
    block = {
        "round": 120, "parent_round": 116, "time": "2026-10-21T03:04:05.123456789",
        "hardfork": {"version": 69, "round": 1091072071},
        "proposer": "0x" + "00" * 19 + "ab",
        "signed_action_bundles": [],
    }
    record = {"height": 7001, "abci_block": block, "resps": None}

    def encoded():
        return json.dumps(record, separators=(",", ":")).encode() + b"\n"

    raw = encoded()
    header = load_header(raw, expected_height=7001)
    hardfork = Hardfork(69, 1091072071)
    expected = {"state_time": hardfork.words, "block_parent_time": hardfork.words}
    require(header.pipeline_comparands(hardfork) == expected, "incorrect legacy field mapping")
    require((header.height, header.prev_round, header.new_round) == (7001, 116, 120), "round/height conflation")
    require(header.time == block["time"] and header.proposer == bytes(19) + b"\xab", "other header fields")
    block["time"] = "2026-10-21T03:04:06.000000001"
    require(load_header(encoded()).pipeline_comparands(hardfork) == expected, "timestamp leaked into guard")
    block["hardfork"]["version"] = 70
    projected = load_header(encoded()).pipeline_comparands(hardfork)
    require(projected["state_time"] != projected["block_parent_time"], "version mismatch was hidden")
    block["hardfork"] = {"version": 69, "round": 1091072072}
    projected = load_header(encoded()).pipeline_comparands(hardfork)
    require(projected["state_time"] != projected["block_parent_time"], "hardfork-round mismatch was hidden")
    del record["height"]
    require(load_header(encoded(), expected_height=7001).height == 7001, "external coordinate was lost")

    for label, line, height, message in (
        ("height versus round", raw, 120, "record height disagrees"),
        ("unlocated heightless row", encoded(), None, "missing external height"),
        ("unsigned hardfork scalar", raw.replace(b'"version":69', b'"version":-1'), 7001, "unsigned 64-bit"),
        ("duplicate header key", raw.replace(b'"parent_round":116', b'"parent_round":116,"parent_round":117'),
         7001, "duplicate JSON key"),
        ("redacted proposer", raw.replace(b'"0x' + b"00" * 19 + b'ab"', b'"<redacted>"'), 7001, "fixed 20-byte"),
    ):
        try:
            load_header(line, expected_height=height)
        except ValueError as error:
            require(message in str(error), f"{label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
        print(f"Rejected control: {label}")
    print(f"Synthetic fixture SHA-256 {hashlib.sha256(raw).hexdigest()}")
    print("Timestamp replacement leaves the guard inputs equal; changing either hardfork word breaks equality")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    verify_native(args.repo.resolve())
    verify_fixture()


if __name__ == "__main__":
    main()
