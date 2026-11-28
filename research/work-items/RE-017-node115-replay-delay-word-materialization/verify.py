import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

BOUNDS = [
    (0x3C2E860, 0x3C2F45B),
    (0x55EA030, 0x55F3D4C),
    (0x54897E0, 0x548C8E0),
    (0x5AFA030, 0x5AFA1EE),
]


def verify_layout(text, base):
    def window(address, width):
        offset = address - base
        assert offset >= 0
        return text[offset:offset + width]

    def anchor(address, encoded):
        expected = bytes.fromhex(encoded)
        assert window(address, len(expected)) == expected

    def operand(address, encoded):
        prefix = bytes.fromhex(encoded)
        raw = window(address, len(prefix) + 4)
        assert raw.startswith(prefix)
        return struct.unpack("<i", raw[-4:])[0]

    def relative(address, encoded):
        return address + len(bytes.fromhex(encoded)) + 4 + operand(address, encoded)

    anchor(0x3C2E8A7, "4989f64889fb")
    assert relative(0x3C2EC6A, "4c8b2d") == 0x64DF508
    historical_destination = operand(0x3C2EFD3, "488dbb")
    historical_width = operand(0x3C2EFDA, "ba")
    historical_source = operand(0x3C2EFDF, "498db6")
    anchor(0x3C2EFE6, "41ffd5")

    source = operand(0x55F1A39, "f2410f1087")
    temporary_word = operand(0x55F1B1A, "f20f118424")
    assert relative(0x55F1FE8, "488b1d") == 0x64DF508
    clone_destination = operand(0x55F26ED, "498dbe")
    temporary_copy = operand(0x55F26F4, "488db424")
    clone_width = operand(0x55F26FC, "ba")
    anchor(0x55F2701, "ffd3")

    tracker = operand(0x548BF2D, "498db424")
    assert relative(0x548BF4B, "e8") == 0x5AFA030
    anchor(0x5AFA03E, "4989f6")
    delay = operand(0x5AFA06A, "498db6")
    anchor(0x5AFA07F, "4889742418")

    assert clone_destination == historical_destination == tracker == 0x3E50
    assert clone_width == historical_width == 0xB8
    assert delay == 0x88 and delay + 8 <= clone_width
    assert historical_source == 0x2330
    assert temporary_word - temporary_copy == delay
    assert source == tracker + delay == 0x3ED8
    return historical_source + delay, clone_destination + delay, tracker + delay


def main():
    assert __debug__, "run Python without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def section(name):
        entry = sections[name]
        offset = entry["offset"]
        return data[offset:offset + entry["size"]], entry["va"]

    eh_bytes, eh_base = section(".eh_frame")
    _, fdes = walk_eh_frame(eh_bytes, eh_base)
    ranges = {(fde["entry"], fde["end"]) for fde in fdes}
    assert set(BOUNDS) <= ranges
    relocations, _ = section(".rela.dyn")
    info, addend = {slot: (info, value) for slot, info, value in struct.iter_unpack("<QQq", relocations)}[
        0x64DF508
    ]
    assert info & 0xFFFFFFFF == 6 and addend == 0
    dynsym, _ = section(".dynsym")
    dynstr, _ = section(".dynstr")
    name_offset, = struct.unpack_from("<I", dynsym, (info >> 32) * 24)
    assert dynstr[name_offset:dynstr.index(b"\0", name_offset)] == b"memcpy"

    text, base = section(".text")
    historical, copied, consumer = verify_layout(text, base)
    offsets = [0x3C2EFDA + 1, 0x3C2EFDF + 3, 0x55F1A39 + 5, 0x55F1B1A + 5,
               0x55F26F4 + 4, 0x55F26FC + 1, 0x548BF2D + 4, 0x5AFA06A + 3, 0x5AFA07F + 4]
    altered = bytearray(text)
    for address in offsets:
        location = address - base
        altered[location] ^= 1
        try:
            verify_layout(altered, base)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"altered operand survived at {address:#x}")
        altered[location] ^= 1
    print(f"Historical input {historical:#x}; copied state {copied:#x}; replay consumer {consumer:#x}")
    print(f"PASS: 4 FDEs, memcpy import, width and pointer anchors, {len(offsets)} rejected mutations")


if __name__ == "__main__":
    main()
