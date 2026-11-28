"""Authenticate the native checkpoint row count and tail selection."""

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

    read(0x4D98C40, 0x4D98D51, "be64000000")
    relative(0x4D98C40, 0x4D98D59, "ff15e9077501", 0x64E9548)
    slots = {slot: target for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))
             if info == 8}
    assert slots[0x64E9548] == 0x38C51F0
    relative(0x38C51F0, 0x38C5217, "e8143cba00", 0x4468E30)
    read(0x4468E30, 0x44690EF, "4c896c081849ffc64c89742478")
    read(0x38C51F0, 0x38C5232, "4c8b7c2438")
    read(0x38C51F0, 0x38C5263, "49c1e7054901c7")
    read(0x38C51F0, 0x38C528A, "48899c2440010000")
    relative(0x38C51F0, 0x38C529F, "e80c884900", 0x3D5DAB0)
    relative(0x3D5DAB0, 0x3D5DAF5, "e83638a6ff", 0x37C1330)
    read(0x37C1330, 0x37C1341, "488b4720")
    read(0x37C1330, 0x37C1369, "4c29f548c1ed054839e8")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: count retention advances over physical 32-byte checkpoint rows")


if __name__ == "__main__":
    main()
