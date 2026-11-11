"""Recheck the linked-VA windows and control-flow operands on node #115."""
from hashlib import sha256
from pathlib import Path
from struct import unpack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.re010_action_type_matcher_115 import BINARY, Image

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = (
    (0x4d40bf1, "41bc88000000"),
    (0x54a3453, "4983c7084889e74c89ee4c89e24c89f9"),
    (0x54ff5a4, "498b4610483d11270000"),
    (0x54ff5b0, "66c74424605801"),
    (0x54ff60e, "498b4610483d11270000"),
    (0x54ff61a, "498b560848c1e004488d0c80488d340a"),
    (0x54ff630, "4889cd4885c9"),
    (0x54ff63c, "80784e00488d4050488d4db0"),
    (0x54ff64f, "4c8ba0e81600004d85e4"),
    (0x54ff7e5, "0fb74424603da2010000"),
    (0x54ff82c, "66817c2460a201"),
    (0x54ff87a, "66817c2460a201"),
)

EDGES = (
    (0x4d40bc0, "e8", 4, 0x5717bf0),
    (0x54a3463, "e8", 4, 0x54ff1a0),
    (0x54ff5ae, "72", 1, 0x54ff61a),
    (0x54ff618, "73", 1, 0x54ff5b0),
    (0x54ff636, "0f84", 4, 0x54ff7b6),
    (0x54ff648, "75", 1, 0x54ff630),
    (0x54ff659, "0f84", 4, 0x54ff7b6),
    (0x54ff7e0, "e8", 4, 0x50fa240),
    (0x54ff7ef, "0f85", 4, 0x54ff8b7),
    (0x54ff827, "e8", 4, 0x5551140),
    (0x54ff833, "0f85", 4, 0x54ff971),
    (0x54ff875, "e8", 4, 0x5551920),
    (0x54ff881, "0f85", 4, 0x54ffa24),
    (0x54ff8ad, "e8", 4, 0x5132ab0),
)

CELLS = (
    (0x9136b8, 2, 0x4d40b9c),
    (0x92671c, 2, 0x54a3453),
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
    controls = (0x54ff5aa, 0x54ff63e, 0x54ff8ae)
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
