"""Verify the static route of the empty #115 replay extraction fixture."""

import csv
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

EDGES = {
    0x5483E87: (4, 0x5B30F30),
    0x3BED8CE: (1, 0x3BED93E),
    0x3BED946: (4, 0x3BED9DA),
    0x3BED9DF: (1, 0x3BED9E7),
    0x3BED9F7: (4, 0x3D5C5D0),
    0x3BEDA3E: (4, 0x3BEDAE0),
    0x3BEDAF2: (4, 0x3BEDA6A),
    0x3BEDB17: (1, 0x3BEDB53),
    0x3BEDBAA: (4, 0x3BEDCDB),
    0x3BEDCE0: (4, 0x3BEDDD9),
    0x3BEDE0F: (1, 0x3BEDE29),
    0x3BEDEA2: (4, 0x3D6C090),
    0x3BEDEC5: (4, 0x3BEE2CA),
    0x3D5C5D3: (1, 0x3D5C5F2),
    0x3D6C0AF: (4, 0x3D73F20),
    0x3D6C0D9: (4, 0x3D8D210),
    0x3D73F40: (1, 0x3D73F75),
    0x3D73F92: (4, 0x3D7404E),
    0x3D74053: (1, 0x3D740C2),
    0x3D8D22D: (4, 0x458DCB0),
    0x3D8D238: (1, 0x3D8D258),
    0x3D8D25D: (1, 0x3D8D268),
    0x3D8D26D: (1, 0x3D8D280),
    0x458DCC5: (4, 0x458DDBE),
}


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def section_data(name):
        section = sections[name]
        return image[section["offset"]:section["offset"] + section["size"]]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(section_data(".eh_frame"), frame["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    text = section_data(".text")
    text_address = sections[".text"]["va"]
    fde_entries = set()
    pinned = {}
    with Path(__file__).with_name("spans.tsv").open() as source:
        for row in csv.DictReader(source, delimiter="\t"):
            fde, address = (int(row[key], 16) for key in ("fde", "address"))
            observed = bytes.fromhex(row["bytes"])
            assert fde <= address < address + len(observed) <= bounds[fde]
            relative = address - text_address
            assert 0 <= relative < relative + len(observed) <= len(text)
            actual = text[relative:relative + len(observed)]
            assert actual == observed and address not in pinned, hex(address)
            pinned[address] = actual
            fde_entries.add(fde)

    def relative_target(address, width):
        data = pinned[address]
        return address + len(data) + int.from_bytes(data[-width:], "little", signed=True)

    for address, (width, target) in EDGES.items():
        assert relative_target(address, width) == target, hex(address)

    relative = relative_target(0x5483E4A, 4)
    memcpy_slot = relative_target(0x3BEDB69, 4)
    relocations = {slot: (info, addend) for slot, info, addend in
                   struct.iter_unpack("<QQq", section_data(".rela.dyn"))}
    assert relative == 0x64E4F00 and relocations[relative] == (8, 0x3BED8A0)
    info, addend = relocations[memcpy_slot]
    assert memcpy_slot == 0x64DF508 and info & 0xFFFFFFFF == 6 and addend == 0
    sym = struct.unpack_from("<I", section_data(".dynsym"), (info >> 32) * 24)[0]
    assert section_data(".dynstr")[sym:sym + len(b"memcpy\x00")] == b"memcpy\x00"

    print(f"PASS: #115 {TARGET_SHA256}, {len(pinned)} pinned spans in {len(fde_entries)} FDEs")
    print(f"PASS: {len(EDGES)} direct targets, extractor relocation and zero-length memcpy binding")


if __name__ == "__main__":
    main()
