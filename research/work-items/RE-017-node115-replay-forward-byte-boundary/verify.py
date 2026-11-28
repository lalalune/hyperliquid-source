#!/usr/bin/env python3
"""Verify the #115 forwarded wire owner and selected outer byte boundary."""
from argparse import ArgumentParser
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
FRAMES = (
    0x5A7C7D0, 0x5A71040, 0x581B4B0, 0x5819960, 0x5A7DCE0,
    0x58610B0, 0x4E48CC0, 0x5823750, 0x581F160,
)
CALLS = {
    0x5A7D062: 0x15D6730,
    0x5A71208: 0x581B4B0,
    0x5A7DE90: 0x5819960,
    0x5A7DFB4: 0x58610B0,
    0x58610E0: 0x4E48CC0,
    0x4E48D53: 0x5823750,
    0x4E48DF5: 0x5823750,
    0x5823786: 0x581EC90,
    0x5823803: 0x581F160,
    0x581F210: 0x5822910,
}
OPERANDS = {
    # one queue in both future captures.
    0x05a7c99c: "bf20010000",
    0x05a7c9b3: "0f118010010000",
    0x05a7c9ba: "0f118000010000",
    0x05a7ca76: "4989c6",
    0x05a7caa1: "4c89b42480010000",
    0x05a7cb2a: "4c89b42438010000",
    0x05a7cbf0: "4c89b424b8010000",
    0x05a7ccec: "0f10942438010000",
    0x05a7ccfc: "0f299424d0010000",
    0x05a7cdec: "0f288424d0010000",
    0x05a7cdf4: "0f298424b0000000",
    0x05a7cf98: "0f288424b0000000",
    0x05a7cfb0: "0f29842480010000",
    0x05a7d023: "488db42480010000",
    0x05a7d02b: "ba98000000",
    # send and receive the owner qword.
    0x05a711cb: "4c8b7338",
    0x05a71201: "498dbe80000000",
    0x0581b64a: "4a8934f2",
    0x0581b64e: "f0",
    0x0581b64f: "48098210010000",
    0x05819acf: "488b8210010000",
    0x05819ad6: "0fa3c8",
    0x05819add: "83e01f",
    0x05819ae0: "488b14c2",
    0x05819aeb: "b801000000",
    0x05a7de7a: "4d8b27",
    0x05a7de7d: "498dbc24a0010000",
    0x05a7de85: "498dac2480000000",
    0x05a7de95: "4883f801",
    0x05a7de9b: "4989d7",
    # encoder owns the received byte span and gets the 20-byte origin.
    0x05a7dcf9: "49bd0100000000000080",
    0x05a7df55: "8b8590000000",
    0x05a7df5f: "0f108580000000",
    0x05a7df79: "898424f0010000",
    0x05a7df85: "0f118424e0010000",
    0x05a7df8d: "498d45ff",
    0x05a7df91: "4889442468",
    0x05a7df96: "4c897c2470",
    0x05a7dfa7: "488d742468",
    # copy 20-byte origin then select encoder branch.
    0x058237e3: "48c744242800000000",
    0x0581f17a: "488dae78010000",
    0x0581f1a8: "8b4d10",
    0x0581f1ab: "894c3010",
    0x0581f1af: "0f104500",
    0x0581f1b3: "0f110430",
    0x0581f1b7: "4883c614",
    0x0581f1bb: "498b07",
    0x0581f1c1: "4c31e9",
    0x0581f1c4: "4885c0",
    0x0581f1cc: "480f48c1",
    0x0581f1db: "48630481",
    # emit discriminant, blob width and raw bytes.
    0x0581f1f2: "c6043000",
    0x0581f1f6: "48ffc6",
    0x0581f1fd: "4d8b6f08",
    0x0581f201: "4d8b7d20",
    0x0581f20d: "4c89fa",
    0x0581f224: "498b7518",
    0x0581f248: "4c89fa",
    0x0581f251: "4d01fd",
    0x0581f254: "4d896e20",
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
        (0x5A7CC5C, "488d0d", 0x64B8C40),
        (0x5A7D04E, "4c8d05", 0x64B8F20),
        (0x5A7DFA0, "488d0d", 0x93B75A),
        (0x581F1D4, "488d0d", 0x935B40),
        (0x581F24B, "ff15", 0x64DF508),
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
    table = 0x935B40
    row = table + int.from_bytes(at(".rodata", table, 4), "little", signed=True)
    require(row == 0x581F1E4, "Variant 0 doesn't reach the length-prefixed byte writer")
    require(at(".rodata", 0x93B75A, 29) == b"consensus forward external tx",
            "Wrong forward operation label")
    print(f"selected writer table {table:#x}, entry 0 -> {row:#x}")
    records = sections[".rela.dyn"]
    relocations = iter_unpack("<QQq", at(".rela.dyn", records["va"], records["size"]))
    targets = {0x64B8C58: 0x5A71040, 0x64B8F38: 0x5A7DCE0}
    observed = {slot: addend for slot, info, addend in relocations if slot in targets and info == 8}
    require(observed == targets, "Wrong future poll targets")
    for slot, target in observed.items():
        print(f"R_X86_64_RELATIVE {slot:#x} -> {target:#x}")

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
        ("different downstream future capture", 0x5A7CB2A, 4, 0x40),
        ("different origin width", 0x581F1B7, 3, 0x10),
        ("different outer variant byte", 0x581F1F2, 3, 0x01),
        ("different owner byte-length field", 0x581F201, 3, 0x18),
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
    print("PASS: selected record wraps the same owner span in origin20, byte 0, and compact U64 length")


if __name__ == "__main__":
    main()
