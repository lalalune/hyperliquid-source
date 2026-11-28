"""Authenticate the mode-2 suppression of the #115 post-comparison root."""

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
    relative(0x5A04E40, 0x5A05FC9, "e8f21e0000", owner)
    relative(owner, 0x5A07F01, "7222", 0x5A07F25, width=1)
    read(owner, 0x5A07F1D, "41833e02")
    relative(owner, 0x5A07F21, "740b", 0x5A07F2E, width=1)
    read(owner, 0x5A07F25, "40b50141833e02")
    relative(owner, 0x5A07F2C, "751a", 0x5A07F48, width=1)
    read(owner, 0x5A07F2E, "48b80000000000000080488903")
    relative(owner, 0x5A07F3B, "e911060000", 0x5A08551)
    read(owner, 0x5A07F40, "31ed41833e02")
    relative(owner, 0x5A07F46, "74e6", 0x5A07F2E, width=1)
    relative(owner, 0x5A07FCE, "e8fd5aa8ff", 0x548DAD0)
    relative(owner, 0x5A07FE5, "e8b6bfffff", 0x5A03FA0)
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: mode 2 skips the selected root helper and history insert at standard and custom cadence")


if __name__ == "__main__":
    main()
