"""Authenticate the regular-file gate in the #115 EVM checkpoint filter."""

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

    owner = 0x3D5DCA0
    predicate = 0x1500D20
    relative(owner, 0x3D5DD85, "488d356eea6efc", 0x44C7FA)
    marker = b"\xc0\x14/MARKED_FOR_DELETION\x00"
    offset = 0x44C7FA - sections[".rodata"]["va"]
    assert data(".rodata")[offset:offset + len(marker)] == marker
    relative(owner, 0x3D5DDA4, "ff15a62b7802", 0x64E0950)
    slots = {slot: target for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))
             if info == 8}
    assert slots[0x64E0950] == predicate
    read(predicate, 0x1500DDA, "b800f00000234424483d008000000f94c0")
    read(owner, 0x3D5DDAA, "84c0")
    relative(owner, 0x3D5DDAC, "7422", 0x3D5DDD0, width=1)
    relative(owner, 0x3D5DDB6, "0f8444ffffff", 0x3D5DD00)
    relative(owner, 0x3D5DDC7, "e934ffffff", 0x3D5DD00)
    read(owner, 0x3D5DD0F, "410f114e10410f11064983c620")
    read(owner, 0x3D5DDF1, "4c3b28")
    relative(owner, 0x3D5DDF4, "0f8386000000", 0x3D5DE80)
    relative(owner, 0x3D5DE88, "7326", 0x3D5DEB0, width=1)
    relative(owner, 0x3D5DE91, "721d", 0x3D5DEB0, width=1)
    relative(owner, 0x3D5DE9B, "0f865ffeffff", 0x3D5DD00)
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: regular MARKED_FOR_DELETION file bypasses the height comparisons")


if __name__ == "__main__":
    main()
