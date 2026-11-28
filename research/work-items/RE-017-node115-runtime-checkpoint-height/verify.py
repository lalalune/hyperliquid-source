"""Authenticate the #115 checkpoint selection versus persisted-height guard."""

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

    owner = 0x3C12800
    read(owner, 0x3C12822, "4c8b7b18")
    relative(owner, 0x3C12847, "e8d4638500", 0x4468C20)
    read(owner, 0x3C128A8, "4989d4")
    read(owner, 0x3C128CA, "498b442428")
    read(owner, 0x3C128D4, "4c39f8")
    relative(owner, 0x3C128D7, "0f8539010000", 0x3C12A16)
    read(owner, 0x3C128DD, "4d897c2410")
    read(owner, 0x3C128FF, "4989742420")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: loader rejects a selected versus persisted height mismatch before normal state writes")


if __name__ == "__main__":
    main()
