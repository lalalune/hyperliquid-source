"""Authenticate the selected begin store groups in both #115 state layouts."""

import hashlib
from pathlib import Path
import struct
import sys

from apply_begin import LAYOUTS

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

COMMON = {
    0x54838D3: "498b752848ffc648c7c2ffffffff480f45d649895528",
    0x54838E9: "49c7450000000000",
    0x54838F1: "49894d30",
}
COMPACT = {
    **COMMON,
    0x54838F5: "49898d080e0000",
    0x54838FC: "49898d280f0000",
    0x5483A78: "e8332c0300",
    0x5483E0E: "49c745000100000049c7450800000000",
    0x5483E1E: "498db5c0400000",
    0x5483E4A: "ff15b0100601",
}
EXPANDED = {
    **{address + 0x700: raw for address, raw in COMMON.items()},
    0x5483FF5: "49898d78190000",
    0x5483FFC: "49898d981a0000",
    0x5484194: "e8d75a0200",
    0x548452E: "49c745000100000049c7450800000000",
    0x548453E: "498db5304c0000",
    0x548456A: "ff1590090601",
}
OWNERS = {
    0x5483850: COMPACT,
    0x5483F50: EXPANDED,
    0x5A6BFB0: {0x5A6C05D: "bfc8420000"},
    0x548CE30: {0x548D82F: "bf384e0000"},
    0x5A04E40: {0x5A04FE9: "e862e8a7ff"},
    0x5A06600: {0x5A067AD: "e89ed7a7ff"},
}


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert hashlib.sha256(image).hexdigest() == TARGET_SHA256
    sections = {item["name"]: item for item in parse_sections(image)}

    def read(name, address, size):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + size <= section["size"]
        offset = section["offset"] + delta
        return image[offset:offset + size]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    spans = {}
    for owner, records in OWNERS.items():
        for address, raw in records.items():
            data = bytes.fromhex(raw)
            assert owner <= address < address + len(data) <= bounds[owner]
            assert read(".text", address, len(data)) == data, hex(address)
            spans[address] = data

    def immediate(address):
        return int.from_bytes(spans[address][-4:], "little")

    def edge(address):
        raw = spans[address]
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    assert edge(0x5A04FE9) == 0x5483850
    assert edge(0x5A067AD) == 0x5483F50
    assert edge(0x5483A78) == 0x54B66B0 and edge(0x5484194) == 0x54A9C70
    slot = edge(0x5483E4A)
    assert slot == edge(0x548456A) == 0x64E4F00
    section = sections[".rela.dyn"]
    bindings = [(info, addend) for va, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", section["va"], section["size"]),
    ) if va == slot]
    assert len(bindings) == 1 and bindings[0][0] == 8

    for layout, allocation_size, two_mirrors in (
        ("compact", 0x5A6C05D, (0x54838F5, 0x54838FC)),
        ("expanded", 0x548D82F, (0x5483FF5, 0x5483FFC)),
    ):
        assert (immediate(allocation_size), tuple(immediate(site) for site in two_mirrors)) == LAYOUTS[layout]
    assert immediate(0x548453E) - immediate(0x5483E1E) == 0xB70

    print(f"PASS: #115 {TARGET_SHA256}, {len(spans)} exact spans in {len(OWNERS)} FDEs")
    print(f"PASS: shared begin words, layout-specific round fanout, and initializer slot {slot:#x}")


if __name__ == "__main__":
    main()
