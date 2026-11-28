#!/usr/bin/env python3
"""Check the #115 ClientBlockWireOrTx count, write and read boundaries."""
from argparse import ArgumentParser
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
FRAMES = (0x4FB5AE0, 0x4FB5CE0, 0x5823480, 0x4EFF5F0, 0x4E052F0)

CALLS = {
    0x58234BB: 0x4FB5AE0,
    0x582353A: 0x4FB5CE0,
    0x4FB5B0E: 0x58220E0,
    0x4FB5B27: 0x58292C0,
    0x4FB5B8B: 0x5B56F70,
    0x4FB5BB0: 0x58220E0,
    0x4FB5BD1: 0x5822B90,
    0x4FB5D15: 0x5821F30,
    0x4FB5D72: 0x59681D0,
    0x4FB5D92: 0x5967060,
    0x4FB5DB4: 0x4E055D0,
    0x4FB5DFB: 0x5B56E10,
    0x4FB5E32: 0x5821F30,
    0x4FB5E56: 0x5822910,
    0x4EFF60C: 0x5821150,
    0x4EFF642: 0x5824B60,
    0x4EFF6DB: 0x4FB7760,
    0x4EFF82F: 0x4E052F0,
    0x4E05366: 0x5824840,
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def edge(raw, address, opcode, destination):
    displacement = int.from_bytes(raw[len(bytes.fromhex(opcode)):], "little", signed=True)
    require(raw.startswith(bytes.fromhex(opcode)) and address + len(raw) + displacement == destination,
            f"Edge {address:#x} must reach {destination:#x}")


def semantics(instructions):
    for address, target in CALLS.items():
        edge(instructions[address], address, "e8", target)
    for address, opcode, target in (
        (0x4FB5AFB, "0f84", 0x4FB5BA3),
        (0x4FB5B01, "488d35", 0x459E6C),
        (0x4FB5B66, "0f84", 0x4FB5C9F),
        (0x4FB5BA3, "488d35", 0x45A05C),
        (0x4FB5D00, "0f84", 0x4FB5E23),
        (0x4FB5D06, "488d35", 0x459E6C),
        (0x4FB5DCC, "0f84", 0x4FB5F0C),
        (0x4FB5E23, "488d35", 0x45A05C),
        (0x4FB5E8A, "ff15", 0x64DF508),
        (0x4FB5F25, "e9", 0x4FB5E9B),
        (0x58234DA, "ff15", 0x64DF480),
    ):
        edge(instructions[address], address, opcode, target)
    for address, raw in {
        0x5823499: "48c744244800000000", # initial count zero
        0x58234C7: "4c8b642448",         # count carried to allocation
        0x58234D7: "4c89e7",
        0x582350E: "4c89642420",         # writer's capacity
        0x5823518: "48c744243000000000", # writer's initial cursor
        0x4FB5AF8: "4d85ff",             # count selector
        0x4FB5B7A: "48ffc0",             # present option width
        0x4FB5CA9: "48ffc0",             # absent option width
        0x4FB5CF9: "4d8b3c24",       # primary owner from entry
        0x4FB5CFD: "4d85ff",             # write selector
        0x4FB5DC4: "498b742408",         # second owner from entry
        0x4FB5DC9: "4885f6",
        0x4FB5DE4: "c6040101",           # Some raw byte
        0x4FB5DE8: "48ffc0",
        0x4FB5DEB: "49894620",
        0x4FB5DEF: "4883c610",
        0x4FB5F1A: "c6043000",           # None raw byte
        0x4FB5F1E: "48ffc6",
        0x4FB5F21: "49897620",
        0x4FB5E43: "4d8b7d20",           # Tx length
        0x4FB5E66: "498b7518",           # Tx data pointer
        0x4FB5E87: "4c89fa",             # raw copy length
        0x4FB5E94: "4c01ff",             # Tx advances by length
        0x4EFF62A: "83f801",
        0x4E05335: "0fb602",             # decoder reads raw byte
        0x4E0534E: "83f801",
    }.items():
        require(instructions[address] == bytes.fromhex(raw), f"Operand changed at {address:#x}")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    sys.path.insert(0, str(args.repo.resolve() / "tools"))
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
    for address, expected in ((0x459E6C, bytes(4)), (0x45A05C, bytes.fromhex("01000000"))):
        data = at(".rodata", address, 4)
        require(data == expected, "Bad compact-u32 tag constant")
        print(f".rodata {address:#x} {data.hex(' ')}")

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
        ("swap Block and Tx selection", 0x4FB5D00, 1, 0x85),
        ("change raw Some tag", 0x4FB5DE4, 3, 0x00),
        ("use wrong Tx length slot", 0x4FB5E43, 3, 0x18),
        ("alter count writer call", 0x58234BB, 1, 0x21),
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
    print("PASS: count pass and VecWriter pair match the existing replay reader's Block, Option and Tx boundaries")


if __name__ == "__main__":
    main()
