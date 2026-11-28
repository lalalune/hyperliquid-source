#!/usr/bin/env python3
"""Verify transfer of the #115 wire owner through a scheduled queue."""
from argparse import ArgumentParser
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
FRAMES = (0x5819B20, 0x5A71040, 0x581B4B0, 0x5A3EDE0, 0x5A7C7D0)
CALLS = {
    0x5A7115A: 0x5A2F550,
    0x5A71330: 0x5819B20,
    0x5A71362: 0x5819B20,
    0x5A71208: 0x581B4B0,
}
OPERANDS = {
    # ready row and dequeue projection.
    0x05819c8f: "488b9010030000",
    0x05819c96: "0fa3ca",
    0x05819c9d: "83e21f",
    0x05819ca0: "488d1452",
    0x05819ca4: "0f1004d0",
    0x05819ca8: "0f114708",
    0x05819cac: "488b44d010",
    0x05819cb1: "48894718",
    0x05819cb9: "48c70701000000",
    # receive arguments and ready result.
    0x05a71318: "498db424a0010000",
    0x05a71320: "4d8dac2480000000",
    0x05a71328: "488d7c2410",
    0x05a7132d: "4c89ea",
    0x05a71335: "837c241001",
    0x05a71372: "8b442418",
    # exact owner preservation through packed copies.
    0x05a7138a: "8b4c242c",
    0x05a7138e: "898c24a0000000",
    0x05a71395: "0f1044241c",
    0x05a7139a: "0f29842490000000",
    0x05a713aa: "8b8c24a0000000",
    0x05a713b1: "898c2480000000",
    0x05a713b8: "0f28842490000000",
    0x05a713c0: "0f29442470",
    0x05a713da: "8b8c2480000000",
    0x05a713e1: "894c2460",
    0x05a713e5: "0f28442470",
    0x05a713ea: "0f29442450",
    0x05a713f9: "660f28442450",
    0x05a713ff: "660f114324",
    0x05a71404: "8b442460",
    0x05a71408: "894334",
    0x05a7141f: "488b4330",
    0x05a71423: "48894368",
    # pending outer state.
    0x05a71531: "b001",
    0x05a71533: "b104",
    0x05a7151c: "884b61",
    # forward owner by value into single-word row.
    0x05a711bd: "488b7368",
    0x05a711cb: "4c8b7338",
    0x05a71201: "498dbe80000000",
    0x05a71265: "48895b68",
    0x0581b64a: "4a8934f2",
    0x0581b64e: "f0",
    0x0581b64f: "48098210010000",
    # release on closed or dropped pending state.
    0x05a714d4: "4889742410",
    0x05a714d9: "f0",
    0x05a714da: "48ff0e",
    0x05a3edf4: "83f804",
    0x05a3ee59: "488b4368",
    0x05a3ee5d: "f0",
    0x05a3ee5e: "48ff08",
    0x05a3ee63: "488d7b68",
    0x05a3ee6d: "c6436000",
    # two queue shapes and registered future capture.
    0x05a7c806: "bf20030000",
    0x05a7c81d: "0f118010030000",
    0x05a7c824: "0f118000030000",
    0x05a7c82b: "4889842400020000",
    0x05a7c83f: "4889842420030000",
    0x05a7c847: "4889842428030000",
    0x05a7c99c: "bf20010000",
    0x05a7c9b3: "0f118010010000",
    0x05a7c9ba: "0f118000010000",
    0x05a7cbe8: "0f29842480010000",
    0x05a7cbf0: "4c89b424b8010000",
    0x05a7cc46: "488db42480010000",
    0x05a7cc4e: "ba08010000",
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
        (0x5819C99, "73", 0x5819CCB),
        (0x5A7105D, "488d0d", 0x93970C),
        (0x5A71161, "0f85", 0x5A71531),
        (0x5A711E2, "0f85", 0x5A714D4),
        (0x5A714E4, "ff15", 0x64E4CB8),
        (0x5A3EE67, "ff15", 0x64E4CB8),
        (0x5A7CC5C, "488d0d", 0x64B8C40),
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
    table = 0x93970C
    state_four = table + int.from_bytes(at(".rodata", table + 4 * 4, 4), "little", signed=True)
    require(state_four == 0x5A7114E, "Pending state must resume at sleep poll")
    print(f"state table {table:#x}, state 4 -> {state_four:#x}")
    records = sections[".rela.dyn"]
    relocations = iter_unpack("<QQq", at(".rela.dyn", records["va"], records["size"]))
    targets = {0x64B8C40: 0x5A3EDE0, 0x64B8C58: 0x5A71040, 0x64E4CB8: 0x5A8E7C0}
    observed = {slot: addend for slot, info, addend in relocations if slot in targets and info == 8}
    require(observed == targets, "Wrong RELATIVE future or drop slots")
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
        ("wrong owner position in dequeue result", 0x5819CB1, 3, 0x10),
        ("wrong retained future owner slot", 0x5A71423, 3, 0x60),
        ("wrong outbound owner load", 0x5A711BD, 3, 0x60),
        ("wrong destructor owner slot", 0x5A3EE59, 3, 0x60),
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
    print("PASS: timed consumer preserves the owner through pending sleep, then transfers or releases it")


if __name__ == "__main__":
    main()
