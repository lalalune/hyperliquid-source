"""Authenticate the constructor and successor calls into the #115 root selector."""

from hashlib import sha256
from pathlib import Path
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

    owner = 0x5A07EC0
    relative(0x5A08F80, 0x5A0901F, "e89ceeffff", owner)
    relative(0x5A04E40, 0x5A05FC9, "e8f21e0000", owner)
    read(owner, 0x5A07ED7, "488bb6500400004c8b7e28")
    relative(owner, 0x5A07FCE, "e8fd5aa8ff", 0x548DAD0)
    read(owner, 0x5A07FD3, "498dbe00040000")
    read(owner, 0x5A07FE2, "4c89fe")
    relative(owner, 0x5A07FE5, "e8b6bfffff", 0x5A03FA0)
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: startup and post-comparison enter one selector, keyed by the current state height")


if __name__ == "__main__":
    main()
