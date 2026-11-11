"""Check the selected updateLeverage classifier and result handoff."""
from hashlib import sha256
from pathlib import Path
from struct import unpack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.re010_action_type_matcher_115 import BINARY, Image

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def equal(actual, expected, address):
    if actual != expected:
        raise ValueError(f"{address:#x}: expected {expected!r}, got {actual!r}")


def check(image, site, expected):
    raw = bytes.fromhex(expected)
    equal(image.read(site, len(raw)), raw, site)


def relative(image, site, base, expected):
    displacement, = unpack("<i", image.read(site, 4))
    equal(base + displacement, expected, site)


def call(image, site, expected):
    check(image, site, "e8")
    relative(image, site + 1, site + 5, expected)


def classifier_branches(image):
    check(image, 0x514BA5B, "0fb704243da20100007518")
    check(image, 0x514BA66, "488b4c2410837c2408017576")
    check(image, 0x514BA72, "66c74310740148894b18eb53")


def processing_result(image):
    check(image, 0x514BB13, "66813c24a2017504b00eebb4")


def verify(image):
    relative(image, 0x9136B8 + 4 * 39, 0x9136B8, 0x4D4169F)
    check(image, 0x4D416A6, "4c8d05")
    relative(image, 0x4D416A9, 0x4D416AD, 0x64A3318)
    for index, name in enumerate([b"asset", b"isCross", b"leverage"]):
        slot = 0x64A3318 + 16 * index
        length, = unpack("<Q", image.read(slot + 8, 8))
        equal(image.read(image.relative[slot], length), name, slot)
    call(image, 0x4D416C3, 0x56F2C30)
    check(image, 0x4D416C8, "803c240975174c8b7424048b54240c41bcad000000")
    relative(image, 0x92671C + 4 * 39, 0x92671C, 0x54A3702)
    check(image, 0x54A3702, "4983c7084889e74c89ee4c89e24c89f9")
    call(image, 0x54A3712, 0x552B730)
    call(image, 0x552BD29, 0x5551140)
    check(image, 0x552BD2E, "66817c2470a2010f85de000000")
    call(image, 0x552BD67, 0x5551920)
    check(image, 0x552BD6C, "66817c2470a2010f855c010000")
    call(image, 0x552BD89, 0x514BA20)
    check(image, 0x514BA38, "8b2e8b4604440fb66608488d91301300004881c190000000")
    check(image, 0x514BA53, "89c6ff15")
    relative(image, 0x514BA57, 0x514BA5B, 0x64E5B38)
    equal(image.relative[0x64E5B38], 0x46AAC00, 0x64E5B38)
    classifier_branches(image)
    check(image, 0x514BAC9, "668943100f114318b00f8803")
    check(image, 0x514BAFC, "450fb6c44889e7488d5424704c89f64189e9")
    call(image, 0x514BB0E, 0x556A2A0)
    processing_result(image)
    check(image, 0x514BB59, "0f294310e96fffffff")


def main():
    data = BINARY.read_bytes()
    equal(sha256(data).hexdigest(), DIGEST, 0)
    verify(Image(data))
    changed = bytearray(data)
    mutant = Image(changed)
    for address, test in ((0x514BA70, classifier_branches), (0x514BB19, processing_result)):
        offset = mutant.off(address)
        changed[offset] ^= 1
        try:
            test(mutant)
        except ValueError:
            changed[offset] ^= 1
        else:
            raise ValueError(f"mutant accepted at {address:#x}")
    print("updateLeverage: linked classifier, two rejection routes, downstream result, two rejected mutations")


if __name__ == "__main__":
    main()
