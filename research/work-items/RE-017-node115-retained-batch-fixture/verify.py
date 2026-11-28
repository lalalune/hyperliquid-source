"""Verify the selected node #115 retained replay continuity inputs."""

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
        0x5a818ca: 0x4facd10,
        0x4facdd8: 0x5b2b500,
        0x4fad00c: 0x5b2b500,
        0x5b2b529: 0x4fadcc0,
    }.items():
        require(target(site) == destination, f"wrong retained batch call at {site:#x}")

    def disp(site):
        return struct.unpack("<I", spans[site][-4:])[0]

    primary = disp(0x4facdd0)
    following = disp(0x4fad004)
    require(primary == following == disp(0x4facda3) == disp(0x4facfb8), "wrong identity slot")
    require(spans[0x4facdab][-1] == 0 and spans[0x4facfc0][-1] == 1,
            "wrong initial/following link tag")
    tag = struct.unpack("<I", spans[0x4facfc0][-5:-1])[0]
    require(tag - following == spans[0x4fadd31][-2] == 0x10, "wrong link tag slot")
    require(disp(0x4facfd8) - following == spans[0x4fadd37][-1] == 0x11,
            "wrong link byte window")
    require(disp(0x4face46) == disp(0x4facfb0), "wrong successor handoff")
    require(disp(0x4face86) == disp(0x4facfc8) and disp(0x4face8e) == disp(0x4facfd0),
            "wrong retained two-lane fingerprint copy")
    require(spans[0x4facfe0][-1] == 16 and spans[0x4fadd40][-1] - spans[0x4fadd3b][-1] == 16,
            "wrong second fingerprint lane")
    require(spans[0x4fadd5e][-4:] == bytes.fromhex("ffff0000"), "wrong lane equality mask")
    print(f"verified {len(spans)} retained continuity spans, first-row seed and both link halves")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
