"""Authenticate materialized pair, coordinates and root settings used by replay."""

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

    read(0x2CC1120, 0x2CC24B2, "410f104718")
    read(0x2CB6500, 0x2CB7976, "0f104528")
    read(0x2CB6500, 0x2CB80C6, "0f1183a0090000")
    read(0x3C12800, 0x3C128CA, "498b442428")
    read(0x3C12800, 0x3C128D4, "4c39f8")
    relative(0x3C12800, 0x3C128D7, "0f8539010000", 0x3C12A16)
    read(0x5A07EC0, 0x5A07F48, "83bee810000001")
    read(0x5A07EC0, 0x5A07F51, "4c39bef0100000")
    read(0x5A07EC0, 0x5A07F85, "488b8ec8390000")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: replay pair, starting height/round, freeze and cadence come from independent materialized slots")


if __name__ == "__main__":
    main()
