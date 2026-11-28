"""Authenticate the #115 regular-file predicate before the local state reader."""

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

    owner = 0x2CC1120
    relative(owner, 0x2CC1232, "ff1518f78103", 0x64E0950)
    read(owner, 0x2CC1238, "84c0")
    relative(owner, 0x2CC123A, "7425", 0x2CC1261, width=1)
    relative(owner, 0x2CC1249, "e8c2239eff", 0x26A3610)
    slots = {slot: target for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))
             if info == 8}
    assert slots[0x64E0950] == 0x1500D20
    read(0x1500D20, 0x1500DDA, "b800f00000234424483d008000000f94c0")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: selected local-state route reaches the reader only after a regular-file predicate")


if __name__ == "__main__":
    main()
