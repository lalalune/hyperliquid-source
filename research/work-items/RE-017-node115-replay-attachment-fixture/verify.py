"""Verify the selected node #115 replay attachment fixture anchors."""

from argparse import ArgumentParser
import csv
import hashlib
from pathlib import Path
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

    require(spans[0x4faded0][-4:] == bytes.fromhex("88000000"), "wrong hash rate")
    require(spans[0x4fadedc][-2:] == bytes.fromhex("0100"), "wrong hash delimiter")
    for site, expected in {
        0x4fade4e: 0x20, 0x4fade53: 0x18, 0x4fade57: 0x20,
        0x4fadfc2: 0x20, 0x4fadfc6: 0x20, 0x4fadfde: 0x18, 0x4fadfe2: 0x18,
        0x4fadf3c: 0x28, 0x4fae013: 0x28, 0x4fae024: 0x20,
    }.items():
        require(spans[site][-1] == expected, f"wrong fixture comparison offset at {site:#x}")

    from re11_selfdestruct_keccak115 import keccak256

    for payload, digest in {
        b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    }.items():
        observed = keccak256(payload).hex()
        require(observed == digest, f"fixture digest differs for {payload.hex()}")
        print(f"fixture payload {payload.hex() or 'empty'} keccak256 {observed}")
    print(f"verified {len(spans)} attachment instruction spans and both content vectors")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
