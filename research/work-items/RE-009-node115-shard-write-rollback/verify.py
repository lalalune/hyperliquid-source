"""Authenticate the native write-adapter success and error split."""

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

    writer = 0x3D5EBA0
    relative(writer, 0x3D5EBE0, "ff1592837802", 0x64E6F78)
    slots = {slot: target for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))
             if info == 8}
    assert slots[0x64E6F78] == 0x5D34410
    read(0x5D34410, 0x5D34436, "488b80e0000000")
    read(writer, 0x3D5EBE6, "4c8b6424084d85e4")
    relative(writer, 0x3D5EBEE, "744e", 0x3D5EC3E, width=1)
    read(writer, 0x3D5EC3E, "48b80000000000000080")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: selected native DB wrapper classifies the storage outcome after the call")


if __name__ == "__main__":
    main()
