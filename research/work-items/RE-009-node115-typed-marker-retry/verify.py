"""Authenticate the unchanged-existing typed checkpoint marker branch."""

from hashlib import sha256
from pathlib import Path
from struct import iter_unpack
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def data(name):
        section = sections[name]
        return image[section["offset"]:section["offset"] + section["size"]]

    _, fdes = walk_eh_frame(data(".eh_frame"), sections[".eh_frame"]["va"])
    bounds = {record["entry"]: record["end"] for record in fdes}
    text = data(".text")
    base = sections[".text"]["va"]

    def read(entry, address, encoded):
        expected = bytes.fromhex(encoded)
        assert entry <= address < address + len(expected) <= bounds[entry]
        offset = address - base
        assert text[offset:offset + len(expected)] == expected, hex(address)
        return expected

    def relative(entry, address, encoded, target, width=4):
        raw = read(entry, address, encoded)
        assert address + len(raw) + int.from_bytes(raw[-width:], "little", signed=True) == target

    owner = 0x1505A50
    relative(0x2AD7140, 0x2AD9749, "e842d4bbfe", 0x1696B90)
    relative(0x2AD7140, 0x2AD9768, "ff157272a003", 0x64E09E0)
    relative(0x2CAD9B0, 0x2CB11CF, "e8bc599efe", 0x1696B90)
    relative(0x2CAD9B0, 0x2CB11E8, "ff15f2f78203", 0x64E09E0)
    relative(owner, 0x1505A69, "ff15e1aefd04", 0x64E0950)
    read(owner, 0x1505A6F, "84c0")
    relative(owner, 0x1505A71, "7407", 0x1505A7A, width=1)
    read(owner, 0x1505A73, "31c0")
    relative(owner, 0x1505A75, "e9c3000000", 0x1505B3D)
    read(owner, 0x1505B27, "bf0100000031f6")
    relative(owner, 0x1505B37, "ff15abaefd04", 0x64E09E8)
    read(owner, 0x1505B4D, "c3")

    slots = {slot: target for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))
             if info == 8}
    assert slots[0x64E09E0] == owner
    assert slots[0x64E0950] == 0x1500D20
    assert slots[0x64E09E8] == 0x15024A0
    read(0x1500D20, 0x1500DDA, "b800f00000234424483d008000000f94c0")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: an existing regular typed marker returns success before the empty-write branch")


if __name__ == "__main__":
    main()
