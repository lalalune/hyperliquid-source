"""Check the selected #115 EVM cache-return block coordinates."""

import csv
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

PREP_AND_CONSTRUCT = {
    0x38C284A: 0x3D4CBE0,
    0x38C2867: 0x3C27F30,
    0x38C287C: 0x3D4C7C0,
    0x38C2899: 0x3C284F0,
    0x38C28AE: 0x3D4D000,
    0x38C28C8: 0x3C28210,
    0x38C292D: 0x38C2580,
}
MEMCPY_CALLS = (0x38C27DD, 0x38C28DD, 0x38C2947, 0x3C27F6D, 0x3C2852D, 0x3C2824D)


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def data(name):
        section = sections[name]
        return image[section["offset"]:section["offset"] + section["size"]]

    _, fdes = walk_eh_frame(data(".eh_frame"), sections[".eh_frame"]["va"])
    bounds = {row["entry"]: row["end"] for row in fdes}
    text = data(".text")
    text_va = sections[".text"]["va"]
    pins = {}
    entries = set()
    with Path(__file__).with_name("spans.tsv").open() as source:
        for row in csv.DictReader(source, delimiter="\t"):
            entry = int(row["fde"], 16)
            address = int(row["address"], 16)
            expected = bytes.fromhex(row["bytes"])
            assert entry <= address < address + len(expected) <= bounds[entry]
            offset = address - text_va
            assert 0 <= offset < offset + len(expected) <= len(text)
            assert address not in pins and text[offset:offset + len(expected)] == expected
            pins[address] = expected
            entries.add(entry)

    def last_dword(address):
        return int.from_bytes(pins[address][-4:], "little", signed=True)

    def relative(address):
        return address + len(pins[address]) + last_dword(address)

    for address, target in PREP_AND_CONSTRUCT.items():
        assert relative(address) == target
    assert [last_dword(address) for address in (0x38C2842, 0x38C2874, 0x38C28A6)] == [26, 27, 28]

    for address in MEMCPY_CALLS:
        assert relative(address) == 0x64DF508
    relocations = {slot: (info, addend) for slot, info, addend in
                   struct.iter_unpack("<QQq", data(".rela.dyn"))}
    info, addend = relocations[0x64DF508]
    assert info & 0xFFFFFFFF == 6 and addend == 0
    offset = struct.unpack_from("<I", data(".dynsym"), (info >> 32) * 24)[0]
    assert data(".dynstr")[offset:offset + len(b"memcpy\x00")] == b"memcpy\x00"

    base = last_dword(0x38C28CD)
    assert [last_dword(a) - base for a in (0x38C28CD, 0x38C28EF, 0x38C2907)] == [0, 0x908, 0x1210]
    assert all(last_dword(a) == 0x908 for a in (0x38C28E4, 0x38C28FF, 0x38C2914))
    assert last_dword(0x38C291C) - base == 0x1B18
    assert last_dword(0x38C293A) == 0x1B20
    assert all(last_dword(a) == 0xF8 for a in (0x3C27F85, 0x3C28545, 0x3C28265))
    assert all(last_dword(a) == 0x810 for a in (0x3C27F8C, 0x3C2854C, 0x3C2826C))
    print(f"PASS: #115 {TARGET_SHA256}, {len(pins)} instruction pins across {len(entries)} FDEs")
    print("PASS: seven direct targets, six memcpy slot references, 3 x 0x908 lane writes and final 0x1b20 copy")


if __name__ == "__main__":
    main()
