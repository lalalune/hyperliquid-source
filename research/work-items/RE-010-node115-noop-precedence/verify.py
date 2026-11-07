"""Check the noop wrapper's short circuits against the authenticated node ELF."""
from hashlib import sha256
from pathlib import Path
from struct import unpack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.re010_action_type_matcher_115 import BINARY, Image

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def check(image, site, hex_bytes):
    expected = bytes.fromhex(hex_bytes)
    actual = image.read(site, len(expected))
    if actual != expected:
        raise ValueError(f"{site:#x}: expected {hex_bytes}, got {actual.hex()}")


def edge(image, site, opcode, destination, base=None):
    opcode = bytes.fromhex(opcode)
    if image.read(site, len(opcode)) != opcode:
        raise ValueError(f"wrong opcode at {site:#x}")
    end = site + len(opcode) + 4
    displacement, = unpack("<i", image.read(end - 4, 4))
    if (end if base is None else base) + displacement != destination:
        raise ValueError(f"wrong target at {site:#x}")


def check_execute_cell(image):
    edge(image, 0x92671C, "", 0x54A301C, base=0x92671C)


def check_first_result(image):
    check(image, 0x5520AE7, "66817c2470a201754b")


def verify(image):
    edge(image, 0x9136B8, "", 0x4D3FA15, base=0x9136B8)
    edge(image, 0x4D3FA2C, "e8", 0x573D550)
    check(image, 0x4D3FA31, "803c24090f853824000041bc86000000")
    check(image, 0x54A2FFD, "482d86000000b914000000480f43c8")
    check_execute_cell(image)
    check(image, 0x54A301C, "4889e74c89ee4c89e2")
    edge(image, 0x54A3025, "e8", 0x5520580)
    check(image, 0x5520591, "8b4210")
    check(image, 0x55205A0, "f30f6f02")
    check(image, 0x5520902, "488babe81600004885ed")
    edge(image, 0x552090C, "0f84", 0x5520AB5)
    check(image, 0x5520984, "85c0")
    edge(image, 0x5520986, "0f84", 0x5520AA2)
    check(image, 0x5520AA7, "66c740102001c6000f")
    edge(image, 0x5520AB0, "e9", 0x5520BE3)
    check(image, 0x5520AB5, "48c78424f00000000000000048c784240001000000000000")
    edge(image, 0x5520AE2, "e8", 0x5551140)
    check_first_result(image)
    check(image, 0x5520B19, "4531c0")
    edge(image, 0x5520B1C, "e8", 0x5551920)
    check(image, 0x5520B21, "66817c2470a201")
    edge(image, 0x5520B28, "0f85", 0x5520BF5)
    check(image, 0x5520B33, "c6000e")
    edge(image, 0x5520B36, "e9", 0x5520BE3)
    check(image, 0x5520B92, "660f7f4010c6000f")
    check(image, 0x5520C4C, "660f7f4010")
    edge(image, 0x5520C51, "e9", 0x5520AAD)


def main():
    data = BINARY.read_bytes()
    if sha256(data).hexdigest() != DIGEST:
        raise ValueError("unexpected node #115 digest")
    verify(Image(data))
    changed = bytearray(data)
    mutant = Image(changed)
    for address, test in ((0x92671C, check_execute_cell), (0x5520AEE, check_first_result)):
        offset = mutant.off(address)
        changed[offset] ^= 1
        try:
            test(mutant)
        except ValueError:
            changed[offset] ^= 1
        else:
            raise ValueError(f"mutant accepted at {address:#x}")
    print("noop: selected decoder and execute cells, two ordered checks, two rejected mutations")


if __name__ == "__main__":
    main()
