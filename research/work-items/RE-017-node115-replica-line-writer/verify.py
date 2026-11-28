"""Verify the selected native node #115 replica line writer."""

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

    for site, label in (
        (0x4d6d777, b"abci_block"), (0x4d6d7a4, b"resps"), (0x4d6d7ca, b"height"),
        (0x4d6d5fb, b"time"), (0x4d6d625, b"signed_action_bundles"), (0x4d6d656, b"round"),
        (0x4d6d680, b"parent_round"), (0x4e0b078, b"hardfork"), (0x4e0a658, b"proposer"),
        (0x4d6de67, b"version"), (0x4d6de90, b"round"),
        (0x53caf47, b"signed_actions"), (0x53caf74, b"broadcaster"), (0x53caf9a, b"broadcaster_nonce"),
    ):
        at = target(site)
        require(read(".rodata", at, len(label)) == label, f"wrong record field {label!r}")
    for site, destination in {
        0x595ab43: 0x50e2f80, 0x50e2fce: 0x4d6d740,
        0x4d6d78b: 0x50818f0, 0x50819aa: 0x4d6d5c0,
        0x4d6d7b5: 0x506e230, 0x4d6d7de: 0x5077210,
        0x4d6d639: 0x5075db0, 0x4d6d667: 0x50783d0,
        0x4d6d691: 0x50783d0, 0x4d6d6a4: 0x4e0b070, 0x4d6d6ba: 0x4e0a650,
        0x4e0b084: 0x50878e0, 0x4e0a664: 0x506d150,
        0x5075ed1: 0x4e1c250, 0x5075f05: 0x53caf10, 0x5076032: 0x53caf10,
        0x53caf5b: 0x5090810, 0x53caf85: 0x506d150, 0x53cafae: 0x5079ee0,
    }.items():
        require(target(site) == destination, f"wrong record writer edge at {site:#x}")
    require(spans[0x50e307b][-1] == 10, "wrong record terminator")
    require(spans[0x5075e96][-1] == ord("[") and spans[0x5075f23][-1] == ord("]"),
            "wrong bundle pair delimiters")
    require(spans[0x5075f6c][-1] == 40, "wrong bundle order stride")
    require(spans[0x5075ec1][-4:] == bytes.fromhex("42000000")
            and spans[0x5075ec6][-4:] == bytes.fromhex("20000000"), "wrong bundle reference width")

    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    require(spans[0x4e1c25d] == bytes.fromhex("4531c0")
            and relocations.get(target(0x4e1c260)) == (8, 0x2eabb50),
            "wrong untrimmed fixed-width JSON hex helper")
    print(f"verified {len(spans)} native replica writer spans and ordered outer, block and bundle fields")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
