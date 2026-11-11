"""Recheck the linked-VA windows and control-flow operands on node #115."""
from hashlib import sha256
from pathlib import Path
from struct import unpack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.re010_action_type_matcher_115 import BINARY, Image

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = (
    (0x59d6671, "4c8b76104d6be63848b849922449922449024939c6"),
    (0x59d66a0, "4d85e4"),
    (0x59d66a8, "498b5d084c89e7"),
    (0x59d66d5, "8b73200fb77b350f10030f104b10410f110407410f114c071041897407200f104324410f114407240fb673344883c33841887407346641897c07354883c03848ffc9"),
    (0x59d671b, "41bf0800000048bb0000000000000080f2410f10455031c0493b4518"),
    (0x59d673e, "498b7d284889fd48c1e5054889f848c1e83b0f95c04883c3f84839dd0f97c108c1"),
    (0x59d6776, "498b7520410f104d284885ed488914240f294c2440"),
    (0x59d67f6, "4c897424584c897c24604c89742468"),
    (0x59d6837, "488dbc24c0000000488d4c2458488b742410"),
    (0x59d6868, "488b442418c600000f10442458488b542467488b4c246f0f1140014889501048894818"),
)

EDGES = (
    (0x59d6686, "76", 1, 0x59d6693),
    (0x59d66a3, "74", 1, 0x59d671b),
    (0x59d66af, "ff15", 4, 0x64df480),
    (0x59d66b8, "0f84", 4, 0x59d68b2),
    (0x59d6717, "75", 1, 0x59d66d0),
    (0x59d6737, "71", 1, 0x59d673e),
    (0x59d678b, "0f84", 4, 0x59d689d),
    (0x59d679c, "ff15", 4, 0x64df480),
    (0x59d67ca, "ff15", 4, 0x64df508),
    (0x59d6849, "e8", 4, 0x55650b0),
)

CELLS = (

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
    controls = (0x59d6678, 0x59d670d, 0x59d684a)
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
