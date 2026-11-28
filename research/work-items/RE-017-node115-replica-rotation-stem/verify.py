#!/usr/bin/env python3
"""Verify the #115 replica file roll stem and liner replacement."""
from argparse import ArgumentParser
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
FRAMES = (0x595A6B0, 0x595AC30, 0x5951600, 0x1533E80, 0x50E2F80)
CALLS = {
    0x595AAF6: 0x5951600,
    0x595AB43: 0x50E2F80,
    0x595AB4B: 0x14C3950,
    0x595AB53: 0x1533E80,
    0x595AB67: 0x14C4D00,
    0x595160C: 0x14C3950,
    0x5951614: 0x1533E80,
    0x5951628: 0x14C4D00,
    0x50E3090: 0x14C37F0,
}
OPERANDS = {
    # prior bucket arithmetic and roll gate.
    0x0595a6d9: "4883fe01",
    0x0595a6dd: "4883d6ff",
    0x0595a6e1: "48b94b598638d6c56d34",
    0x0595a6ee: "48f7e1",
    0x0595a6f1: "48c1ea0b",
    0x0595a6f5: "4c69f210270000",
    0x0595a6fc: "4c3b7768",
    # bind prefix, clock date and bucket separately.
    0x0595a709: "0f104708",
    0x0595a70d: "0f118424c0000000",
    0x0595a715: "4c89742458",
    0x0595a73b: "8b442468",
    0x0595a74b: "488d8424c0000000",
    0x0595a753: "4889442408",
    0x0595a764: "4c897c2418",
    0x0595a775: "488d442458",
    0x0595a77a: "4889442428",
    0x0595a792: "488dbc2490000000",
    0x0595a79a: "488d542408",
    0x0595a7a5: "4d897568",
    # consume path, replace liner, then serialize original row.
    0x0595aac0: "488b8424a0000000",
    0x0595aac8: "48898424d0000000",
    0x0595aad0: "0f10842490000000",
    0x0595aad8: "0f298424c0000000",
    0x0595aae5: "488db424c0000000",
    0x0595ab18: "0f115b30",
    0x0595ab1c: "0f115320",
    0x0595ab20: "0f114b10",
    0x0595ab24: "0f1103",
    0x0595ab35: "4889df",
    0x0595ab3b: "488b9424b0000000",
    # initial filename argument for comparison.
    0x0595ac41: "4c894c2458",
    0x0595ae0d: "488b442458",
    0x0595ae12: "48898424a8000000",
    0x0595ae65: "4c89642428",
    # normal descriptor arguments and JSON newline.
    0x05951655: "8b7b34",
    0x01533e93: "488b5710",
    0x01533ee8: "488b7308",
    0x01533eec: "4c01f6",
    0x01533eef: "8b7b1c",
    0x01533ef2: "4889c2",
    0x01533ef5: "41ffd4",
    0x050e307b: "c604030a",
}

def require(ok, message):
    if not ok:
        raise ValueError(message)


def edge(raw, address, opcode, destination):
    displacement = int.from_bytes(raw[len(bytes.fromhex(opcode)):], "little", signed=True)
    require(raw.startswith(bytes.fromhex(opcode)) and address + len(raw) + displacement == destination,
            f"Edge {address:#x} must reach {destination:#x}")


def semantics(instructions):
    for address, destination in CALLS.items():
        edge(instructions[address], address, "e8", destination)
    for address, opcode, destination in (
        (0x595A700, "0f86", 0x595AB27),
        (0x595A722, "ff15", 0x64E0990),
        (0x595A735, "ff15", 0x64E0AB8),
        (0x595A769, "488b05", 0x64E0B68),
        (0x595A77F, "488b05", 0x64E0A98),
        (0x595A78B, "488d35", 0x440E47),
        (0x595A79F, "ff15", 0x64DF6E8),
        (0x595A7AE, "0f85", 0x595AAC0),
        (0x595AAED, "ff15", 0x64E0020),
        (0x595AE76, "488d35", 0x440E47),
        (0x595AE97, "ff15", 0x64E0020),
        (0x5951658, "ff15", 0x64DFE78),
        (0x1533EA8, "4c8b25", 0x64DFFC0),
    ):
        edge(instructions[address], address, opcode, destination)
    for address, expected in OPERANDS.items():
        require(instructions[address] == bytes.fromhex(expected), f"Changed operand at {address:#x}")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    sys.path.insert(0, str(args.repo.resolve() / "tools"))
    from struct import iter_unpack

    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

    image = (args.repo / TARGET).read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET_SHA256, "Wrong #115 image")
    sections = {row["name"]: row for row in parse_sections(image)}

    def at(name, address, length):
        section = sections[name]
        delta = address - section["va"]
        require(0 <= delta <= delta + length <= section["size"], "Out-of-section witness")
        offset = section["offset"] + delta
        return image[offset:offset + length]

    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", eh["va"], eh["size"]), eh["va"])
    ends = {row["entry"]: row["end"] for row in fdes}
    bounds = tuple((start, ends[start]) for start in FRAMES)
    print(f"target={TARGET} sha256={TARGET_SHA256} bytes={len(image)}")
    print(f"Python {sys.version.split()[0]}")
    for start, end in bounds:
        print(f"FDE {start:#x}..{end:#x}")
    require(at(".rodata", 0x440E47, 8) == bytes.fromhex("c0012fc0012fc000"),
            "Wrong formatted path template")
    records = sections[".rela.dyn"]
    relocations = {
        slot: (info, addend)
        for slot, info, addend in iter_unpack("<QQq", at(".rela.dyn", records["va"], records["size"]))
    }
    targets = {
        0x64E0990: 0x1629690,
        0x64E0AB8: 0x1629FB0,
        0x64E0B68: 0x150CE90,
        0x64E0A98: 0x1689420,
        0x64DF6E8: 0x141E3A0,
        0x64E0020: 0x14C3B30,
    }
    for slot, target in targets.items():
        require(relocations[slot] == (8, target), f"Wrong RELATIVE slot {slot:#x}")
        print(f"R_X86_64_RELATIVE {slot:#x} -> {target:#x}")
    symbols = sections[".dynsym"]
    strings = sections[".dynstr"]
    string_table = at(".dynstr", strings["va"], strings["size"])
    for slot, symbol in ((0x64DFE78, b"close"), (0x64DFFC0, b"write")):
        info, _ = relocations[slot]
        require(info & 0xffffffff == 6, "Expected a GLOB_DAT import")
        index = info >> 32
        string_offset = int.from_bytes(at(".dynsym", symbols["va"] + 24 * index, 4), "little")
        end = string_table.index(b"\0", string_offset)
        require(string_table[string_offset:end] == symbol, f"Wrong imported symbol for {slot:#x}")
        print(f"R_X86_64_GLOB_DAT {slot:#x} -> {symbol.decode()}")

    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        if line.startswith("#"):
            continue
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        require(address not in windows and
                any(start <= address < address + len(raw) <= end for start, end in bounds),
                f"Invalid selected instruction {address:#x}")
        windows[address] = at(".text", address, len(raw))
        require(windows[address] == raw, f"Wrong instruction at {address:#x}")
    semantics(windows)
    for name, address, index, operand in (
        ("different rotation threshold", 0x595A700, 1, 0x87),
        ("different stem input", 0x595A775, 4, 0x68),
        ("redirect old liner cleanup", 0x595AAF6, 1, 0x00),
        ("change record terminator", 0x50E307B, 3, 0x00),
    ):
        bad = bytearray(windows[address])
        bad[index] = operand
        try:
            semantics(windows | {address: bytes(bad)})
        except ValueError:
            print(f"PASS control: {name} rejected")
        else:
            raise ValueError(f"Control escaped: {name}")
    print(f"PASS: {len(windows)} instruction anchors across {len(bounds)} FDEs")
    print("PASS: rotated filename receives the bucket marker; the old-liner path attempts flush and close before encoding the incoming row")


if __name__ == "__main__":
    main()
