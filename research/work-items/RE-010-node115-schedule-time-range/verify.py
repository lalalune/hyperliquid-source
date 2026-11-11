"""Recheck the linked-VA windows and control-flow operands on node #115."""
from hashlib import sha256
from pathlib import Path
from struct import unpack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.re010_action_type_matcher_115 import BINARY, Image

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = (
    (0x54a3616, "498b4f084d8b47104889e74c89ee4c89e2"),
    (0x4d41315, "41bc98000000"),
    (0x55052dc, "4c898424f000000048898c24e8000000"),
    (0x55056f7, "66817c2460a201"),
    (0x5505736, "66817c2460a201"),
    (0x5505757, "48b8cbcccccccccccc0c4c8b8424f00000004939c00f97c0488b8c24e800000020c83c01"),
    (0x5505786, "66c741160000c741120000000066c74110540148c7411801000000"),
    (0x55058a4, "488d7c2460488d5424204c89fe"),
    (0x55058b6, "66817c2460a201"),
    (0x55058bf, "b00e488b4c2408"),
    (0x550591f, "b00f8801"),
)

EDGES = (
    (0x4d412fc, "e8", 4, 0x57389f0),
    (0x54a3627, "e8", 4, 0x55052a0),
    (0x55056f2, "e8", 4, 0x5551140),
    (0x55056fe, "0f85", 4, 0x55057a6),
    (0x5505731, "e8", 4, 0x5551920),
    (0x550573d, "0f85", 4, 0x5505848),
    (0x550577b, "0f85", 4, 0x55058a4),
    (0x55057a1, "e9", 4, 0x550591f),
    (0x55058b1, "e8", 4, 0x5569c10),
    (0x55058bd, "75", 1, 0x55058c8),
)

CELLS = (
    (0x9136b8, 18, 0x4d412d8),
    (0x92671c, 18, 0x54a3616),
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
    controls = (0x5505759, 0x550577c, 0x55058b2)
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
