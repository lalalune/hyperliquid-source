"""Verify the selected node #115 framed replay reader."""

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
        0x5a80cb9: 0x5ab4390,
        0x5a80de7: 0x5860bb0,
        0x5ab4746: 0x5ab3a50,
        0x5ab474e: 0x5ab4819,
        0x5ab4831: 0x5ab4bf7,
        0x5ab4a42: 0x5ab3a50,
        0x5ab4c02: 0x5ab4d9d,
        0x5ab57ab: 0x5ab586c,
    }.items():
        require(target(site) == destination, f"wrong selected reader edge at {site:#x}")

    def u32tail(site):
        return struct.unpack("<I", spans[site][-4:])[0]

    for size, length, swap, flag in (
        (0x5ab4732, 0x5ab4819, 0x5ab4820, 0x5ab4823),
        (0x5ab4a24, 0x5ab4a56, 0x5ab4a5d, 0x5ab4a60),
    ):
        require(u32tail(size) == 5, "wrong header size")
        require(spans[swap] == bytes.fromhex("410fce"), "wrong length byte swap")
        require(u32tail(length) + 4 == u32tail(flag), "wrong flag coordinate")

    require(spans[0x5ab4c02][:2] == bytes.fromhex("0f83"), "wrong unsigned frame gate")
    require(spans[0x5ab4d9d][-1] == 1, "wrong compressed flag value")
    require(spans[0x5ab4da1][-1] == spans[0x5ab57a7][-2] == 0x50,
            "wrong compressed flag handoff")
    require(u32tail(0x5a80918) == 10_000_000, "wrong initial reader budget")
    require(u32tail(0x5a80c48) == u32tail(0x5a80db8), "wrong decoder budget handoff")
    require(u32tail(0x5a80c94) - u32tail(0x5a80ca2) == spans[0x5ab43db][-1],
            "wrong reader input budget handoff")
    require(spans[0x5ab43df][-1] == spans[0x5ab4bfe][-1] == spans[0x5ab57c1][-1],
            "frame and LZ4 limits do not share the reader slot")

    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    require(relocations.get(target(0x5ab57d5)) == (8, 0x477f8c0), "wrong LZ4 adapter slot")
    print(f"verified {len(spans)} replay-specific framing spans, budgets and decoder handoffs")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
