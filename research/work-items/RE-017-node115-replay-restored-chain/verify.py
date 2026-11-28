"""Verify restored Locus chain provenance for node #115 replay preflight."""

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

    table = target(0x332c7d9)
    chn_arm = table + struct.unpack("<i", read(".rodata", table + 5 * 4, 4))[0]
    require(chn_arm == 0x332d17f, "wrong Locus chn arm")
    require(read(".rodata", target(0x333048e), 3) == b"chn", "wrong Locus field name")
    for site, destination in {
        0x332d184: 0x333048e, 0x332d195: 0x2f35c20, 0x2f35cee: 0x3183e50,
        0x31842fb: 0x4682470, 0x3184326: 0x4682610,
        0x3330c4e: 0x332e013, 0x5a04f59: 0x5a062b6, 0x5a06721: 0x5a07b1d,
    }.items():
        require(target(site) == destination, f"wrong edge at {site:#x}")

    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    names = []
    for index, char_site in enumerate((0x46824b1, 0x468250e, 0x468253f, 0x4682570)):
        slot = target(0x4682593) + 16 * index
        info, address = relocations[slot]
        length = struct.unpack("<Q", read(".data.rel.ro", slot + 8, 8))[0]
        require(info == 8 and length in (5, 7), "wrong chain-name metadata")
        require(spans[char_site][-2:] == bytes((9, index)), "wrong named visitor success tag")
        names.append(read(".rodata", address, length))
    require(names == [b"Local", b"Sandbox", b"Testnet", b"Mainnet"], "wrong chain enum order")
    raw_tag_sites = (0x468262e, 0x4682694, 0x468269d, 0x4682670)
    for index, site in enumerate(raw_tag_sites):
        require(spans[site][-2:] == bytes((9, index)), "wrong alternate success tag")

    staging = struct.unpack("<I", spans[0x3330c3e][-4:])[0]
    aggregate = struct.unpack("<I", spans[0x332e01a][-4:])[0]
    extent = struct.unpack("<I", spans[0x332e022][-4:])[0]
    compact_offset = struct.unpack("<I", spans[0x5a04f52][2:6])[0]
    expanded_offset = struct.unpack("<I", spans[0x5a0671a][2:6])[0]
    require(0 <= staging - aggregate < extent and staging - aggregate == compact_offset == 0xb9a,
            "Locus byte does not reach the compact state operand")
    require(expanded_offset == 0x170a, "wrong expanded preflight offset")
    require(target(0x5a062b6) == target(0x5a07b1d), "guards disagree on the diagnostic")
    require(spans[0x5a04f52][-1] == spans[0x5a0671a][-1] == names.index(b"Mainnet"),
            "replay guards disagree with the restored chain tag")

    import_info, _ = relocations[target(0x332e02a)]
    table_type = import_info & 0xffffffff
    symbol = import_info >> 32
    dynsym = sections[".dynsym"]
    dynstr = sections[".dynstr"]
    offset = struct.unpack("<I", read(".dynsym", dynsym["va"] + symbol * 24, 4))[0]
    require(table_type == 6 and read(".dynstr", dynstr["va"] + offset, 7) == b"memcpy\0",
            "wrong aggregate copy binding")
    print(f"Pinned #115 SHA-256 {TARGET_SHA256}; {len(spans)} selected witnesses")
    print("Named Locus chn reaches state +0xb9a; compact and expanded guards both require Mainnet tag 3")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    verify_native(args.repo.resolve())


if __name__ == "__main__":
    main()
