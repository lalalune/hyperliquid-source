"""Verify the node #115 order layout and wrapper branches against the pinned ELF."""
from hashlib import sha256
from pathlib import Path
from struct import unpack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.re010_action_type_matcher_115 import BINARY, Image

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

CALLS = {
    0x4D4048C: 0x571E250,
    0x571E7F1: 0x56952C0,
    0x571ECA5: 0x4892290,
    0x54A32CA: 0x550DE20,
    0x550E3E7: 0x50F9E10,
    0x550E437: 0x5551140,
    0x550E480: 0x5551920,
    0x550E4C9: 0x59D6660,
}


def equal(actual, expected, where):
    if actual != expected:
        raise ValueError(f"{where}: expected {expected!r}, found {actual!r}")


def target(raw, base):
    return base + unpack("<i", raw)[0]


def check_call(image, site, expected):
    equal(image.read(site, 1), b"\xe8", hex(site))
    equal(target(image.read(site + 1, 4), site + 5), expected, hex(site))


def check_window(image, address, expected):
    expected = bytes.fromhex(expected)
    equal(image.read(address, len(expected)), expected, hex(address))


def verify(image):
    for base, arm in [(0x9136B8, 0x4D40468), (0x92671C, 0x54A32BA)]:
        equal(target(image.read(base + 14 * 4, 4), base), arm, hex(base))
    for index, name in enumerate([b"orders", b"grouping", b"builder"]):
        slot = 0x64B5BD0 + 16 * index
        size, = unpack("<Q", image.read(slot + 8, 8))
        equal(image.read(image.relative[slot], size), name, hex(slot))
    for site, callee in CALLS.items():
        check_call(image, site, callee)

    # Child success stores three words and the map finalizer writes them out.
    check_window(image, 0x571E7F6, "0fb64424203c090f85a0080000")
    check_window(image, 0x571E803, "488b4424284889442408488b4424304889842428010000"
                 "488b4424384889842468020000")
    check_window(image, 0x571EC59, "488bbc2468020000")
    check_window(image, 0x571ED2B, "488b742408498936488b9424280100004989560849897e10")
    equal(image.read(0x931D50, 6), b"orders", "missing-field literal")
    check_window(image, 0x4D40491, "4c8b34244c8b7c24084c89f048f7d80f808a1a0000")
    check_window(image, 0x4D404AB, "f30f6f4c2410")
    check_window(image, 0x4D404D7, "41bc94000000e9e11d0000")
    check_window(image, 0x4D422DA, "66480f7ecf660f70c1ee66490f7ec04181fce20000007530")
    check_window(image, 0x4D42322, "4c89a424d8010000")
    check_window(image, 0x4D42335, "4c898c24e0010000")
    check_window(image, 0x4D4234E, "48898424e80100004889bc24f0010000")
    check_window(image, 0x4D423C2, "488db424d8010000baf0000000")
    check_window(image, 0x54A32BA, "4983c7084889e74c89ee4c89e24c89f9")

    # The scan bound, stride and zero-row branch use the forwarded array.
    check_window(image, 0x550E240, "488b8424f8000000488b5008486b481038488d340a")
    check_window(image, 0x550E260, "4889cd4885c90f845301000080783600488d4038"
                 "488d4dc875e64d8ba7e81600004d85e40f8435010000")
    check_window(image, 0x550E3EC, "0fb78424800000003da20100000f85d4000000")
    check_window(image, 0x550E43C, "6681bc2480000000a2010f8514010000")
    check_window(image, 0x550E485, "6681bc2480000000a2010f858d010000")


def main():
    data = BINARY.read_bytes()
    equal(sha256(data).hexdigest(), DIGEST, "artifact digest")
    image = Image(data)
    verify(image)
    mutant = bytearray(data)
    mutated_image = Image(mutant)
    for site in (0x4D4048C, 0x54A32CA, 0x550E4C9):
        offset = mutated_image.off(site + 1)
        mutant[offset] ^= 1
        try:
            check_call(mutated_image, site, CALLS[site])
        except ValueError:
            mutant[offset] ^= 1
        else:
            raise ValueError(f"mutant accepted at {site:#x}")
    print("order: 2 dispatch cells, 3 relocated fields, 8 calls, 3 rejected mutations")


if __name__ == "__main__":
    main()
