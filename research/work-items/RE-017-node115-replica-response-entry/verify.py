"""Verify the selected native node #115 Full response entries."""

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
        0x502d1f9: 0x54834d0, 0x502d247: 0x54834d0,
        0x548351c: 0x5072c50, 0x5483541: 0x507ac50, 0x507ad0a: 0x59227c0,
        0x5072d25: 0x4e1c250, 0x5922849: 0x509a4c0, 0x509a590: 0x50a3510,
        0x59228c1: 0x5086930, 0x50869ea: 0x4d8e0a0, 0x5079f92: 0x4dfe400,
    }.items():
        require(target(site) == destination, f"wrong response writer edge at {site:#x}")
    for site, name in {
        0x548350b: b"user", 0x548352d: b"res", 0x5922800: b"status", 0x5922835: b"response",
        0x4d8e387: b"data", 0x4d8e774: b"data", 0x4d8e7e7: b"data",
    }.items():
        require(read(".rodata", target(site), len(name)) == name, f"wrong field at {site:#x}")

    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}

    def check_label(site, label):
        slot = target(site) + 16
        info, address = relocations[slot]
        size = struct.unpack("<Q", read(".data.rel.ro", slot + 8, 8))[0]
        require(info == 8 and size == len(label) and read(".rodata", address, size) == label,
                f"wrong result label at {site:#x}")

    for site, label in {0x5922807: b"err", 0x592288b: b"ok"}.items():
        check_label(site, label)
    table = target(0x4d8e0af)
    for tag, arm, site, label, call, writer in (
        (8, 0x4d8e78f, 0x4d8e7c1, b"token", 0x4d8e7fb, 0x5079ee0),
        (9, 0x4d8e327, 0x4d8e359, b"spot", 0x4d8e39b, 0x5079ee0),
        (10, 0x4d8e715, 0x4d8e747, b"validatorVote", 0x4d8e788, 0x5079cc0),
        (14, 0x4d8e13d, 0x4d8e16f, b"default", 0, 0),
    ):
        displacement = struct.unpack("<i", read(".rodata", table + tag * 4, 4))[0]
        require(table + displacement == arm, f"wrong arm for tag {tag}")
        check_label(site, label)
        if call:
            require(target(call) == writer, f"wrong data writer for tag {tag}")

    require(spans[0x59227cc][-1] == 15, "wrong error tag")
    require(spans[0x5072cf9][-1] == 0, "wrong null-user predicate")
    require(spans[0x5072d4c][-4:] == b"null", "wrong null-user output")
    require(spans[0x5072d15][-4:] == bytes.fromhex("2a000000"), "wrong address text length")
    require(spans[0x5072d1a][-4:] == bytes.fromhex("14000000"), "wrong address byte length")
    require(spans[0x5079d6c][-1] == 1 and spans[0x5079d8a][-4:] == b"true", "wrong true writer")
    require(spans[0x5079db4][-4:] + spans[0x5079daf][-1:] == b"false", "wrong false writer")

    def table_bytes(site, size):
        info, address = relocations[target(site)]
        require(info == 8, f"wrong table relocation at {site:#x}")
        return read(".rodata", address, size)

    expected = bytearray(b"u" * 32 + bytes(224))
    for byte, char in {8: b"b", 9: b"t", 10: b"n", 12: b"f", 13: b"r", 34: b'"', 92: b"\\"}.items():
        expected[byte] = char[0]
    require(table_bytes(0x50a3521, 256) == expected, "wrong 256-byte escape table")
    require(table_bytes(0x50a3528, 16) == b"0123456789abcdef", "wrong escape hex alphabet")
    print(f"verified {len(spans)} native entry-writer spans, variant labels and all 256 escape bytes")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
