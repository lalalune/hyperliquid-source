"""Authenticate directory admission for both latest checkpoint bodies."""

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

    slots = {slot: target for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))
             if info == 8}
    assert slots[0x64E0968] == 0x1501290
    relative(0x4468E30, 0x4468EAE, "ff15b47a0702", 0x64E0968)
    relative(0x59FFA30, 0x59FFAC1, "ff15a10eae00", 0x64E0968)
    relative(0x1501290, 0x15012D6, "e825480b00", 0x15B5B00)
    relative(0x1501290, 0x1501338, "e883450b00", 0x15B58C0)
    relative(0x15B58C0, 0x15B5902, "e8699bf8ff", 0x153F470)
    read(0x153F470, 0x153F4D8, "f6401801")
    relative(0x153F470, 0x153F4DC, "0f8586000000", 0x153F568)
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: both latest loaders call the directory-admission wrapper before examining numeric paths")


if __name__ == "__main__":
    main()
