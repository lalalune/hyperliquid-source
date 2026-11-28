"""Authenticate the terminal mismatch edge in the selected #115 replay path."""

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

    owner = 0x5A04E40
    relative(owner, 0x5A05C5E, "e8bd4343ff", 0x4E3A020)
    read(owner, 0x5A05D07, "f3410f6f5548660f74d0f3410f6f4558660f74c1660fdbc2660fd7c03dffff0000")
    relative(owner, 0x5A05D28, "0f85be030000", 0x5A060EC)
    relative(owner, 0x5A05EE3, "e8e8fb3dff", 0x4DE5AD0)
    relative(owner, 0x5A05FC9, "e8f21e0000", 0x5A07EC0)
    relative(owner, 0x5A06212, "ff15a094ad00", 0x64DF6B8)
    slots = {slot: target for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))
             if info == 8}
    assert slots[0x64DF6B8] == 0x1680E80
    relative(owner, 0x5A06218, "e97d010000", 0x5A0639A)
    read(owner, 0x5A0639A, "0f0b")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: mismatch reaches the diagnostic and terminal edge rather than history pruning or root insertion")


if __name__ == "__main__":
    main()
