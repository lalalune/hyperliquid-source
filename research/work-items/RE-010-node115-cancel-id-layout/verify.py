"""Verify the selected cancel and cancelByCloid wrapper contracts."""
from hashlib import sha256
from pathlib import Path
from struct import unpack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.re010_action_type_matcher_115 import BINARY, Image

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def expect(actual, expected, label):
    if actual != expected:
        raise ValueError(f"{label}: expected {expected!r}, got {actual!r}")


def window(image, address, code):
    code = bytes.fromhex(code)
    expect(image.read(address, len(code)), code, hex(address))


def relative(image, address, base, expected):
    displacement, = unpack("<i", image.read(address, 4))
    expect(base + displacement, expected, hex(address))


def call(image, site, destination):
    window(image, site, "e8")
    relative(image, site + 1, site + 5, destination)


def bounds(image, site, rejected):
    window(image, site, "488b4310483d112700000f83")
    relative(image, site + 12, site + 16, rejected)


def numeric_range(image):
    window(image, 0x5514255, "488b4b0848c1e0044801c8")


def client_range(image):
    window(image, 0x5539475, "488b4b08488d0480488d0481")


def verify(image):
    for index, name in enumerate([b"cancels", b"f"]):
        slot = 0x64A2D88 + index * 16
        length, = unpack("<Q", image.read(slot + 8, 8))
        expect(image.read(image.relative[slot], length), name, hex(slot))

    variants = [
        (3, 0x4D40C9B, 0x4D40CA2, 0x4D40CBF, 0x56F1F20, 0x4D40CF0, 0x54A34A1, 0x5513DF0),
        (4, 0x4D4082C, 0x4D40833, 0x4D40850, 0x56E01B0, 0x4D40881, 0x54A338A, 0x5539010),
    ]
    for index, decode_arm, fields, decode_site, decoder, tag, arm, handler in variants:
        relative(image, 0x9136B8 + 4 * index, 0x9136B8, decode_arm)
        window(image, fields, "4c8d05")
        relative(image, fields + 3, fields + 7, 0x64A2D88)
        call(image, decode_site, decoder)
        window(image, tag, f"41bc{0x86 + index:02x}000000")
        relative(image, 0x92671C + 4 * index, 0x92671C, arm)
        window(image, arm, "4983c7084889e74c89ee4c89e24c89f9")
        call(image, arm + 16, handler)

    for site, rejected in [(0x5514245, 0x55141A9), (0x5539465, 0x55393C9)]:
        bounds(image, site, rejected)
        window(image, rejected + 5, "66b85801")
    numeric_range(image)
    client_range(image)

    wrappers = [
        (0x5514285, 0x50F9480, 0x55142CC, 0x551430E, 0x5514347, 0x5208370,
         [0x5514351, 0x55143FE, 0x55144A0], [0x55143E9, 0x551444F, 0x55144F1]),
        (0x55394A6, 0x50FB250, 0x55394ED, 0x553952F, 0x5539568, 0x5133120,
         [0x5539572, 0x553961F, 0x55396C1], [0x553960A, 0x5539670, 0x5539712]),
    ]
    for prep, prep_fn, first, second, finish, finish_fn, error_edges, result_tags in wrappers:
        call(image, prep, prep_fn)
        call(image, first, 0x5551140)
        call(image, second, 0x5551920)
        call(image, finish, finish_fn)
        window(image, prep + 5, "0fb74424403da20100000f85")
        relative(image, prep + 17, prep + 21, error_edges[0])
        for site, target in zip([first, second], error_edges[1:]):
            window(image, site + 5, "66817c2440a2010f85")
            relative(image, site + 14, site + 18, target)
        window(image, result_tags[0], "c6020f")
        for site in result_tags[1:]:
            window(image, site, "c6000f")


def main():
    data = BINARY.read_bytes()
    expect(sha256(data).hexdigest(), DIGEST, "artifact digest")
    verify(Image(data))
    changed = bytearray(data)
    mutant = Image(changed)
    controls = [
        (0x551424B, lambda: bounds(mutant, 0x5514245, 0x55141A9)),
        (0x5539480, lambda: client_range(mutant)),
    ]
    for address, verify_control in controls:
        offset = mutant.off(address)
        changed[offset] ^= 1
        try:
            verify_control()
        except ValueError:
            changed[offset] ^= 1
        else:
            raise ValueError(f"mutant accepted at {address:#x}")
    print("cancel variants: 16- and 20-byte rows, cutoff 10001, three ordered checks, two rejected mutations")


if __name__ == "__main__":
    main()
