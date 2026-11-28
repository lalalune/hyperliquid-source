"""Authenticate separate native batch preparation and storage submission."""

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

    first = 0x3D4C310
    second = 0x3D4C6A0
    relative(first, 0x3D4C31F, "ff156bb07902", 0x64E7390)
    relative(first, 0x3D4C3A2, "ff1508d37902", 0x64E96B0)
    relative(first, 0x3D4C3C0, "ff15f2d27902", 0x64E96B8)
    relative(first, 0x3D4C3DA, "e8c1270100", 0x3D5EBA0)
    relative(second, 0x3D4C6AF, "ff15dbac7902", 0x64E7390)
    relative(second, 0x3D4C71F, "ff158bcf7902", 0x64E96B0)
    relative(second, 0x3D4C73D, "ff1575cf7902", 0x64E96B8)
    relative(second, 0x3D4C757, "e844240100", 0x3D5EBA0)
    relative(0x3D5EBA0, 0x3D5EBE0, "ff1592837802", 0x64E6F78)

    slots = {slot: target for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))
             if info == 8}
    expected = {0x64E7390: 0x5D34A00, 0x64E96B0: 0x5D34AC0,
                0x64E96B8: 0x5D34A40, 0x64E6F78: 0x5D34410}
    assert all(slots[slot] == target for slot, target in expected.items())
    relative(0x5D34A00, 0x5D34A23, "e868552800", 0x5FB9F90)
    read(0x5D34AC0, 0x5D34AF4, "ff5068")
    read(0x5D34410, 0x5D34436, "488b80e0000000")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: selected native wrappers assemble a separate batch before submitting it to storage")


if __name__ == "__main__":
    main()
