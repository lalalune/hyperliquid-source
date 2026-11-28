"""Verify the selected node #115 replay conversion cursor anchors."""

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
        0x5a6e3ea: 0x5a700f8,
        0x5a6e4a5: 0x5a6e5e0,
        0x5a6e5b9: 0x5a6e300,
        0x5a6e5cd: 0x5a6e300,
        0x5a6ff8f: 0x5a6e4cb,
        0x4fad398: 0x4fad5d7,
    }.items():
        require(target(site) == destination, f"wrong conversion edge at {site:#x}")
    branch = spans[0x4fad5f5]
    require(branch[0] == 0x73 and 0x4fad5f5 + len(branch) + branch[1] == 0x4fad607,
            "wrong inclusive empty gate branch")

    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    require(relocations.get(target(0x5a6e48d)) == (8, 0x4fad300), "wrong converter slot")

    def stack_offset(site):
        return struct.unpack("<I", spans[site][-4:])[0]

    require(stack_offset(0x5a6e2d6) == stack_offset(0x5a6e3e2) == stack_offset(0x5a6e46f),
            "wrong expected identity slot")
    require(spans[0x5a6e48a] == bytes.fromhex("4c89fa"), "wrong cutoff argument register")
    require(spans[0x4fad38c][-1] == 0x20, "wrong prepared owner count")
    require(spans[0x4fad5e3][-1] == 10, "wrong saturating age distance")
    require(spans[0x4fad67e][-1] == 0x18, "wrong converted successor store")
    require(stack_offset(0x5a6e609) + 8 == stack_offset(0x5a6e49d) + 0x18,
            "wrong source of the successor copy")
    require(stack_offset(0x5a6e636) + 8 == stack_offset(0x5a6fd24),
            "wrong retained successor reload")
    print(f"verified {len(spans)} replay conversion cursor instruction spans and selected edges")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
