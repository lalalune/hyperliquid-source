"""Recheck the linked-VA windows and control-flow operands on node #115."""
from hashlib import sha256
from pathlib import Path
from struct import unpack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.re010_action_type_matcher_115 import BINARY, Image

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = (
    (0x4d40a0e, "41bc92000000"),
    (0x54a33eb, "4983c7084889e74c89ee4c89e24c89f9"),
    (0x54f4b98, "418b463848c74424480000000048c74424500100000089442458"),
    (0x54f4bc6, "0fb74424603da2010000"),
    (0x54f4c0d, "66817c2460a201"),
    (0x54f4c50, "66817c2460a201"),
    (0x54f4c73, "450fb64e504d8d4618488d7c2460488d5424404889ee4c89f1"),
    (0x54f4c91, "0fb74424603da2010000"),
    (0x54f4ca1, "b00e488b4c24208801"),
)

EDGES = (
    (0x4d409c5, "e8", 4, 0x56c1dd0),
    (0x54a33fb, "e8", 4, 0x54f45e0),
    (0x54f4bc1, "e8", 4, 0x50f9720),
    (0x54f4bd0, "0f85", 4, 0x54f4caf),
    (0x54f4c08, "e8", 4, 0x5551140),
    (0x54f4c14, "0f85", 4, 0x54f4d42),
    (0x54f4c4b, "e8", 4, 0x5551920),
    (0x54f4c57, "0f85", 4, 0x54f4df5),
    (0x54f4c8c, "e8", 4, 0x555f0d0),
    (0x54f4c9b, "0f85", 4, 0x54f4ea5),
)

CELLS = (
    (0x9136b8, 12, 0x4d409a1),
    (0x92671c, 12, 0x54a33eb),
)


def check(image):
    for address, expected in WINDOWS:
        expected = bytes.fromhex(expected)
        if image.read(address, len(expected)) != expected:
            raise ValueError(f"instruction window mismatch at {address:#x}")

    for site, opcode, displacement_size, target in EDGES:
        opcode = bytes.fromhex(opcode)
        if image.read(site, len(opcode)) != opcode:
            raise ValueError(f"wrong opcode at {site:#x}")
        operand = site + len(opcode)
        displacement = int.from_bytes(image.read(operand, displacement_size), "little", signed=True)
        if operand + displacement_size + displacement != target:
            raise ValueError(f"wrong edge target at {site:#x}")

    for table, index, target in CELLS:
        displacement, = unpack("<i", image.read(table + 4 * index, 4))
        if table + displacement != target:
            raise ValueError(f"wrong dispatch arm for cell {table:#x}[{index}]")


def main():
    data = BINARY.read_bytes()
    if sha256(data).hexdigest() != DIGEST:
        raise ValueError("unexpected node #115 digest")
    check(Image(data))
    changed = bytearray(data)
    mutant = Image(changed)
    controls = (0x54f4c77, 0x54f4c79, 0x54f4c9c)
    for address in controls:
        offset = mutant.off(address)
        changed[offset] ^= 1
        try:
            check(mutant)
        except ValueError:
            changed[offset] ^= 1
        else:
            raise ValueError(f"mutant accepted at {address:#x}")
    print(f"{len(WINDOWS)} linked-VA windows, {len(EDGES)} edges, "
          f"{len(CELLS)} dispatch cells, {len(controls)} rejected mutations")


if __name__ == "__main__":
    main()
