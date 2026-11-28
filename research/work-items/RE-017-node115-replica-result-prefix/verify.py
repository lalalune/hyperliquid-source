"""Verify the selected node #115 result collector prefix."""

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
        0x5b7865e: 0x51e62a0, 0x5b786c1: 0x5b787ea,
        0x5b78a25: 0x5b78c25, 0x5b78a9d: 0x51e62a0,
        0x5b78b09: 0x5b78c1d, 0x5b78bc9: 0x5b789d0,
        0x5b78c2a: 0x5859480, 0x5b78c53: 0x5b78ced, 0x5b78c62: 0x51e62a0,
    }.items():
        require(target(site) == destination, f"wrong collector edge at {site:#x}")

    def displacement(site):
        return struct.unpack("<I", spans[site][-4:])[0]

    require(spans[0x5b78afc][-8:] == bytes.fromhex("0000000000000080"),
            "wrong collector end marker")
    require(spans[0x5b786cb][-4:] == spans[0x5b786df][-4:] == bytes(4),
            "wrong initial empty capacity or count")
    require(spans[0x5b786d2][-4:] == bytes.fromhex("08000000"), "wrong initial empty pointer")
    require(spans[0x5b7896a][-4:] == bytes.fromhex("01000000"), "wrong first ordinary result length")
    require(spans[0x5b78a11][-1] == 0x38 and spans[0x5b78a61][-1] == 6,
            "wrong output and input stride")
    require(spans[0x5b78933][-1] == spans[0x5b789d8][-1] == 0x30,
            "wrong first and subsequent inner count position")
    count_slot = struct.unpack("<I", spans[0x5b7896a][-8:-4])[0]
    require(count_slot == displacement(0x5b78a09) == displacement(0x5b78ced) == 0xc8,
            "wrong collected prefix count publication")
    require(displacement(0x5b78cf9) + 16 == count_slot and spans[0x5b78cf5][-1] == 0x10,
            "wrong vector descriptor return")

    print(f"verified {len(spans)} pinned result collector spans")
    print("initial end returns the empty descriptor; later end returns the accumulated prefix")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
