"""Check selected empty-delayer fixture anchors against the pinned #115 ELF."""

from hashlib import sha256
from pathlib import Path
from struct import iter_unpack
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

SPANS = {
    0x3c12800: {
        0x3c1294b: "498dbc24c0400000",
        0x3c12953: "ff15b7258d02",
    },
    0x3bec320: {
        0x3bec334: "488b07",
        0x3bec33a: "48f7d9",
        0x3bec33d: "7124",
        0x3bec363: "488b5318",
        0x3bec36a: "7428",
        0x3bec394: "31c9",
        0x3bec39a: "488b5308",
        0x3bec3fc: "e85f989100",
        0x3bec404: "741f",
        0x3bec461: "e8fa3b9600",
        0x3bec47c: "0f85fa040000",
        0x3bec97c: "48c744247000000000",
        0x3bec985: "48c744247808000000",
        0x3bec98e: "0f57c0",
        0x3bec991: "0f11842480000000",
        0x3bec9d4: "7428",
        0x3beca20: "41b802000000",
        0x3beca6e: "31ed",
        0x3becb2a: "0f84a0000000",
        0x3becbd0: "31c0",
        0x3becb53: "0f848b000000",
        0x3becc09: "498d5c2420",
        0x3becc0e: "498b742420",
        0x3becc66: "744e",
        0x3beccb6: "0f288424f0000000",
        0x3beccbe: "0f288c2400010000",
        0x3beccc6: "0f114b10",
        0x3beccca: "0f1103",
        0x3becccd: "49896c2460",
        0x3becce3: "c3",
    },
    0x4505c60: {
        0x4505c64: "4883f802",
        0x4505c92: "0f84d1010000",
        0x4505e69: "31c0",
        0x4505e70: "c3",
    },
    0x4550060: {
        0x4550072: "4d85ff",
        0x4550075: "744f",
        0x45500d9: "e9c0020000",
        0x45503ac: "c3",
    },
}

EDGES = {
    0x3bec33d: (1, 0x3bec363),
    0x3bec36a: (1, 0x3bec394),
    0x3bec3fc: (4, 0x4505c60),
    0x3bec404: (1, 0x3bec425),
    0x3bec461: (4, 0x4550060),
    0x3bec47c: (4, 0x3bec97c),
    0x3bec9d4: (1, 0x3bec9fe),
    0x3becb2a: (4, 0x3becbd0),
    0x3becb53: (4, 0x3becbe4),
    0x3becc66: (1, 0x3beccb6),
    0x4505c92: (4, 0x4505e69),
    0x4550075: (1, 0x45500c6),
    0x45500d9: (4, 0x455039e),
}


def relative_target(address, encoding, width):
    return address + len(encoding) + int.from_bytes(encoding[-width:], "little", signed=True)


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def section_bytes(name, address, size):
        section = sections[name]
        offset = address - section["va"]
        assert 0 <= offset <= offset + size <= section["size"]
        start = offset + section["offset"]
        return image[start:start + size]

    eh_frame = sections[".eh_frame"]
    va = eh_frame["va"]
    _, fdes = walk_eh_frame(section_bytes(".eh_frame", va, eh_frame["size"]), va)
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    decoded = {}
    for entry, evidence in SPANS.items():
        for address, expected in evidence.items():
            size = len(expected) // 2
            assert entry <= address < address + size <= bounds[entry]
            raw = section_bytes(".text", address, size)
            assert raw.hex() == expected, hex(address)
            decoded[address] = raw
    for address, (width, target) in EDGES.items():
        assert relative_target(address, decoded[address], width) == target, hex(address)

    call_site = 0x3c12953
    slot = relative_target(call_site, decoded[call_site], 4)
    assert slot == 0x64e4f10
    rela = sections[".rela.dyn"]
    assert any((address, info, target) == (slot, 8, 0x3bec320)
               for address, info, target in iter_unpack(
                   "<QQq", section_bytes(".rela.dyn", rela["va"], rela["size"]),
               ))
    print(f"PASS: #115 {TARGET_SHA256}, {len(decoded)} pinned spans across {len(SPANS)} FDEs")
    print(f"PASS: {len(EDGES)} relative branches/calls and loader relocation {slot:#x} -> 0x3bec320")


if __name__ == "__main__":
    main()
