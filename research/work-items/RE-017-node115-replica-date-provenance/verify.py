#!/usr/bin/env python3
"""Verify where #115 replica rows get their path date and record time."""
from argparse import ArgumentParser
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
FRAMES = (
    0x595A6B0, 0x1629690, 0x5C842E0, 0x1629FB0, 0x150CE90,
    0x50E2F80, 0x4D6D5C0, 0x4D6D740, 0x50818F0,
)
CALLS = {
    0x162969F: 0x5C842E0,
    0x16296CB: 0x5C84210,
    0x595AB43: 0x50E2F80,
    0x50E2FCE: 0x4D6D740,
    0x4D6D78B: 0x50818F0,
    0x4D6D60C: 0x5076270,
    0x50E3090: 0x14C37F0,
}
OPERANDS = {
    # bucket-only rotation and distinct clock/record operands.
    0x0595a6cd: "48899424b0000000",
    0x0595a6fc: "4c3b7768",
    0x0595a733: "31d2",
    0x0595a764: "4c897c2418",
    0x0595ab27: "4c8d7c2408",
    0x0595ab2c: "4c89ff",
    0x0595ab38: "4c89fe",
    0x0595ab3b: "488b9424b0000000",
    # realtime UTC decomposition.
    0x0162969d: "31ff",
    0x016296a4: "4889442418",
    0x016296a9: "89542420",
    0x016296ad: "48c744242800000000",
    0x016296b6: "c744243000000000",
    0x016296d0: "4c8b742408",
    0x016296fd: "4869c280510100",
    0x01629704: "4929c6",
    0x0162970a: "49c1ff3f",
    0x01629727: "4c01fa",
    0x0162972a: "81c23bf90a00",
    0x0162973c: "4181e780510100",
    0x01629743: "4501f7",
    0x01629746: "8903",
    0x01629748: "44897b04",
    0x0162974c: "896b08",
    # zero adjustment preserves valid day/time.
    0x01629fb0: "035604",
    0x01629fbc: "4c69c807452ec2",
    0x01629fc3: "49c1e920",
    0x01629fc7: "4101c1",
    0x01629fcd: "c1e91f",
    0x01629fd0: "41c1f910",
    0x01629fd4: "4101c9",
    0x01629fd7: "4169c980510100",
    0x01629fde: "29c8",
    0x01629fe2: "c1f91f",
    0x01629fe5: "4101c9",
    0x01629fe8: "448b06",
    0x01629feb: "8b5608",
    0x01629fee: "4183f901",
    0x01629ff4: "4183f9ff",
    0x0162a139: "81e180510100",
    0x0162a13f: "01c1",
    0x0162a141: "448907",
    0x0162a144: "894f04",
    0x0162a147: "895708",
    # date and JSON time consume separate sources.
    0x0150ce9f: "8b07",
    0x0150cebe: "48c744243806000000",
    0x050e2f8b: "4889d3",
    0x050e2f8e: "4989f4",
    0x050e2fcb: "4889df",
    0x050e306a: "498b0424",
    0x050e306e: "4889442418",
    0x050e3082: "488d742418",
    0x04d6d5f7: "488d4b38",
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
        (0x595AB2F, "ff15", 0x64E0990),
        (0x595A735, "ff15", 0x64E0AB8),
        (0x595A769, "488b05", 0x64E0B68),
        (0x1629732, "ff15", 0x64DFFF0),
        (0x1629FF8, "0f85", 0x162A139),
        (0x5C842ED, "ff15", 0x64E1248),
        (0x150CEB2, "488d05", 0x465BC9),
        (0x4D6D777, "488d35", 0x916931),
        (0x50819AA, "e9", 0x4D6D5C0),
        (0x4D6D5FB, "488d35", 0x459E8C),
    ):
        edge(instructions[address], address, opcode, destination)
    for address, expected in OPERANDS.items():
        require(instructions[address] == bytes.fromhex(expected), f"Changed operand at {address:#x}")


def date_controls(instructions):
    day_size = int.from_bytes(instructions[0x1629FD7][-4:], "little")
    multiplier = int.from_bytes(instructions[0x1629FBC][-4:], "little", signed=True)
    divisor = 1 << 32
    require(-divisor < multiplier < 0, "Expected carry form for normal seconds")
    # x + floor(m*x / 2**32) is non-decreasing on nonnegative integral x,
    # since each new x contributes +1 while the floor can fall by at most 1.
    largest = day_size - 1
    upper = largest + multiplier * largest // divisor
    require(0 <= upper < (1 << 16), "On valid seconds of day the offset quotient must stay zero")
    print(f"zero offset: valid 0..{largest} bounds fold to 0..{upper}, so the day adjustment is zero")


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
    require(at(".rodata", 0x465BC9, 6) == b"%Y%m%d", "Wrong path date formatter")
    require(at(".rodata", 0x916931, 10) == b"abci_block", "Wrong outer Block field")
    require(at(".rodata", 0x459E8C, 4) == b"time", "Wrong block timestamp field")
    records = sections[".rela.dyn"]
    relocations = {
        slot: (info, addend)
        for slot, info, addend in iter_unpack("<QQq", at(".rela.dyn", records["va"], records["size"]))
    }
    targets = {
        0x64E0990: 0x1629690,
        0x64E0AB8: 0x1629FB0,
        0x64E0B68: 0x150CE90,
        0x64DFFF0: 0x1628F50,
    }
    for slot, target in targets.items():
        require(relocations[slot] == (8, target), f"Wrong RELATIVE slot {slot:#x}")
        print(f"R_X86_64_RELATIVE {slot:#x} -> {target:#x}")
    symbols = sections[".dynsym"]
    strings = sections[".dynstr"]
    string_table = at(".dynstr", strings["va"], strings["size"])
    for slot, symbol in ((0x64E1248, b"clock_gettime"),):
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
    date_controls(windows)
    for name, address, index, operand in (
        ("change the reuse threshold", 0x595A700, 1, 0x87),
        ("change realtime clock selector", 0x162969D, 1, 0xc9),
        ("change validated seconds-of-day divisor", 0x1629FD7, 3, 0x81),
        ("substitute a record time offset", 0x4D6D5F7, 3, 0x40),
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
    print("PASS: path date is UTC realtime on roll; a reused liner still serializes the original record time")


if __name__ == "__main__":
    main()
