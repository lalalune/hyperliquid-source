"""Authenticate the native checkpoint JSON reader end-of-document check."""

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

    reader = 0x3EF1790
    read(reader, 0x3EF17E3, "488b4c2428488b5424304839ca")
    relative(reader, 0x3EF17F0, "7347", 0x3EF1839, width=1)
    relative(reader, 0x3EF181A, "7742", 0x3EF185E, width=1)
    relative(reader, 0x3EF1820, "733c", 0x3EF185E, width=1)
    read(reader, 0x3EF185E, "48c744245816000000")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: native checkpoint JSON reader checks remaining input and rejects a non-whitespace tail")


if __name__ == "__main__":
    main()
