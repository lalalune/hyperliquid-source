"""Authenticate independent saved ABCI round and consensus committed-round anchors."""

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

    read(0x3C12800, 0x3C128E7, "498b742430")
    read(0x5483850, 0x54838F1, "49894d30")
    read(0x2E157C0, 0x2E15E49, "488b8a80030000")
    read(0x2E157C0, 0x2E15E50, "4839c8")
    relative(0x2E157C0, 0x2E15E53, "0f86500e0000", 0x2E16CA9)
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: ABCI block round and the two-chain committed watermark are independently represented")


if __name__ == "__main__":
    main()
