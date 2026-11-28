#!/usr/bin/env python3
"""Verify Node #115 replay owner provenance into a connection queue."""
from argparse import ArgumentParser
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
FRAMES = (0x4E45C50, 0x5861530, 0x4FBA210, 0x5A63100, 0x581A8B0, 0x5A6E1E0)
CALLS = {
    0x4E45CE3: 0x5823480,
    0x4E45D85: 0x5823480,
    0x5861560: 0x4E45C50,
    0x4FBA243: 0x5861530,
    0x5A63138: 0x5861530,
    0x5A63CF7: 0x581A8B0,
    0x5A6E42D: 0x5A63100,
    0x5A6E43D: 0x5A63100,
}

OPERANDS = {
    # block-only input selection and clearing.
    0x04fba215: "488b07",
    0x04fba218: "4885c0",
    0x04fba227: "4889442408",
    0x04fba22c: "48c744241000000000",
    0x04fba29a: "31db",
    # copy successful vector out.
    0x058615b3: "4883f908",
    0x058615b9: "488b442418",
    0x058615be: "48894310",
    0x058615c2: "0f10442408",
    0x058615c7: "0f1103",
    # block-only owner build.
    0x04fba248: "48c744241801000000",
    0x04fba251: "48c744242001000000",
    0x04fba25a: "bf28000000",
    0x04fba26d: "488b442438",
    0x04fba272: "48894320",
    0x04fba280: "0f114b10",
    0x04fba284: "0f1103",
    # full owner build.
    0x05a63155: "bf28000000",
    0x05a63169: "488b8c2450010000",
    0x05a63171: "48894820",
    0x05a63187: "660f114810",
    0x05a6318c: "660f1100",
    0x05a63190: "4889442410",
    # prefer conditional block-only owner.
    0x05a631a6: "4889842480000000",
    0x05a634a4: "4c8b742410",
    0x05a63606: "488b842480000000",
    0x05a6360e: "4885c0",
    0x05a63611: "4c89f2",
    0x05a63614: "480f45d0",
    0x05a63618: "48899424f0000000",
    # selected reference clones.
    0x05a63820: "f0",
    0x05a63821: "49ff06",
    0x05a63824: "4c89f3",
    0x05a63849: "488b9c24f0000000",
    0x05a63935: "f0",
    0x05a63936: "48ff03",
    # stage chosen owner for ring.
    0x05a63c9d: "4c8b7050",
    0x05a63ce0: "48899c2440010000",
    0x05a63ce8: "498dbe80000000",
    0x05a63cef: "488db42430010000",
    # publish 24-byte row.
    0x0581a8c1: "f0",
    0x0581a8c2: "4c0fc17708",
    0x0581a8ca: "4983e5e0",
    0x0581a8dd: "4183e61f",
    0x0581aa2e: "4b8d0476",
    0x0581aa32: "488b4e10",
    0x0581aa36: "48894cc210",
    0x0581aa49: "0f1104c2",
    0x0581aa4d: "f0",
    0x0581aa4e: "4809b210030000",
    # worker passes selectors 0 and 1.
    0x05a6e42b: "31d2",
    0x05a6e438: "ba01000000",
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
        (0x4FBA21B, "74", 0x4FBA29A),
        (0x5A631A0, "ff15", 0x64EBBA0),
        (0x5A631BE, "488d05", 0x445DB6),
        (0x5A6367A, "0f84", 0x5A63820),
        (0x5A63695, "0f84", 0x5A63849),
        (0x5A63827, "0f8f", 0x5A6393F),
        (0x5A63851, "e9", 0x5A63935),
        (0x581A8E1, "e9", 0x581AA2E),
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
    source = at(".rodata", 0x445DB6, 0x17)
    require(source == b"node/src/connections.rs", "Bad callback source label")
    records = sections[".rela.dyn"]
    relocations = iter_unpack("<QQq", at(".rela.dyn", records["va"], records["size"]))
    alternate = [(kind, addend) for slot, kind, addend in relocations if slot == 0x64EBBA0]
    require(alternate == [(8, 0x4FBA210)], "Wrong RELATIVE alternate carrier target")
    print(f"source={source.decode()} alternate slot=0x64ebba0 target={alternate[0][1]:#x}")

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
        ("change cleared attachment word", 0x4FBA22C, 5, 0x01),
        ("reverse zero-selector path", 0x5A6367A, 1, 0x85),
        ("alter chosen owner record slot", 0x5A63CE0, 4, 0x48),
        ("alter queue row stride", 0x581AA2E, 3, 0x77),
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
    print("PASS: selected callback carries the full or Block-only wire owner to a 24-byte queue row")


if __name__ == "__main__":
    main()
