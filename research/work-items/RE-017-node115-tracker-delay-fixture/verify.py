"""Pin the checked-float route and compact-copy continuation in the #115 ELF."""

from hashlib import sha256
from pathlib import Path
from random import Random
from struct import iter_unpack
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame
from project import delay_bytes

SPANS = {
    0x3423120: {
        0x3423125: "418d8040ffffff",
        0x3423131: "4c8d05908535fd",
        0x3423138: "49630480",
        0x342313c: "4c01c0",
        0x342313f: "ffe0",
        0x3423292: "4883f908",
        0x3423296: "7254",
        0x342329c: "488b10",
        0x34232a3: "480fca",
        0x34232ae: "48895708",
        0x34232b2: "c60709",
    },
    0x46f3cb0: {
        0x46f3d39: "ff15e9e4de01",
        0x46f3d49: "3c09",
        0x46f3d4b: "7565",
        0x46f3d52: "488d48ff",
        0x46f3d56: "48baffffffffffff0f00",
        0x46f3d63: "0f92c1",
        0x46f3d66: "48baffffffffffffff7f",
        0x46f3d70: "4821c2",
        0x46f3d73: "400f94c6",
        0x46f3d77: "4008ce",
        0x46f3d7a: "48b9000000000000f0ff",
        0x46f3d84: "4801d1",
        0x46f3d87: "48c1e935",
        0x46f3d8b: "81f9ff030000",
        0x46f3d91: "0f92c1",
        0x46f3d94: "4885c0",
        0x46f3d97: "0f99c0",
        0x46f3d9a: "20c8",
        0x46f3d9c: "4008f0",
        0x46f3d9f: "7438",
        0x46f3da1: "660fd64308",
        0x46f3da6: "c60309",
    },
    0x33b2a30: {
        0x33b2d86: "e8250f3401",
        0x33b2d93: "4080fd090f8517040000",
    },
    0x3c2e860: {
        0x3c2efd3: "488dbb503e0000",
        0x3c2efda: "bab8000000",
        0x3c2efdf: "498db630230000",
        0x3c2efe6: "41ffd5",
    },
}


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, address, size):
        section = sections[name]
        offset = address - section["va"]
        assert 0 <= offset <= offset + size <= section["size"]
        start = section["offset"] + offset
        return image[start:start + size]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    for fde, spans in SPANS.items():
        for address, encoded in spans.items():
            raw = bytes.fromhex(encoded)
            assert fde <= address < address + len(raw) <= bounds[fde]
            assert read(".text", address, len(raw)) == raw, hex(address)

    def end_disp(address, size, displacement_width=4):
        raw = read(".text", address, size)
        return address + size + int.from_bytes(raw[-displacement_width:], "little", signed=True)

    assert end_disp(0x33b2d86, 5) == 0x46f3cb0
    assert end_disp(0x3423296, 2, 1) == 0x34232ec
    assert end_disp(0x46f3d9f, 2, 1) == 0x46f3dd9
    table = end_disp(0x3423131, 7)
    assert table == 0x77b6c8
    assert table + int.from_bytes(read(".rodata", table + (0xcb - 0xc0) * 4, 4),
                                  "little", signed=True) == 0x342328a
    rela = sections[".rela.dyn"]
    slot = end_disp(0x46f3d39, 6)
    assert slot == 0x64e2228
    assert (slot, 8, 0x3423120) in iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"]),
    )
    assert 0x2330 + 0x88 == 0x23b8 and 0x3e50 + 0x88 == 0x3ed8

    u64 = (1 << 64) - 1
    magnitude_mask = (1 << 63) - 1
    generator = Random(115)
    cases = [0, 1, (1 << 52) - 1, 1 << 52, 1 << 63, (1 << 63) + 1,
             0x7fefffffffffffff, 0x7ff0000000000000, 0x7ff8000000000000]
    cases.extend(generator.getrandbits(64) for _ in range(4096))
    for bits in cases:
        magnitude = bits & magnitude_mask
        zero_or_subnormal = magnitude == 0 or ((bits - 1) & u64) < (1 << 52) - 1
        normal = bits <= magnitude_mask and (((magnitude - (1 << 52)) & u64) >> 53) < 0x3ff
        token = b"\xcb" + bits.to_bytes(8, "big")
        try:
            projected = delay_bytes(token)
        except ValueError:
            assert not (zero_or_subnormal or normal), hex(bits)
        else:
            assert zero_or_subnormal or normal, hex(bits)
            assert projected == bits.to_bytes(8, "little")
    print(f"PASS: #115 {TARGET_SHA256}, {sum(map(len, SPANS.values()))} ELF spans across {len(SPANS)} FDEs")
    print(f"PASS: float64 dispatch, three direct targets, relocation, copy and {len(cases)} bit-pattern controls")


if __name__ == "__main__":
    main()
