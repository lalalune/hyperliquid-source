"""Verify the selected node #115 first Block fixture."""

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
        0x4eff60c: 0x5821150, 0x4eff624: 0x4eff6d0,
        0x4eff642: 0x5824b60, 0x4eff69a: 0x4eff848,
        0x4eff6db: 0x4fb7760, 0x5a8729e: 0x5a8869d,
        0x5a874c0: 0x5a88aff, 0x5a874cd: 0x5a88aff,
        0x5a6e328: 0x5ab6df0, 0x5a6e39c: 0x5a63100,
        0x5a6e3a6: 0x5a6e318, 0x5a6e3b7: 0x5a6e318,
    }.items():
        require(target(site) == destination, f"wrong selected replay path at {site:#x}")
    require(spans[0x4eff62a][-1] == 1, "wrong Tx discriminator")
    require(spans[0x4eff692] == bytes.fromhex("48c7430800000000"), "wrong Tx first owner")
    require(spans[0x5a6e34e] == bytes.fromhex("7430"), "wrong null-first worker path")
    require(spans[0x5a874b9][-4:] == bytes.fromhex("00010000")
            and spans[0x5a874c6][-4:] == bytes.fromhex("08010000"), "wrong startup pair slots")
    print(f"verified {len(spans)} decoder, consumer and replay worker instruction spans")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
