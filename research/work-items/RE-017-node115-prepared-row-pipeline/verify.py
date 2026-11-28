"""Authenticate the native count guard and converted row-vector entry."""

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

    owner = 0x5A04E40
    read(owner, 0x5A04F29, "4c8b7010")
    read(owner, 0x5A04F35, "488b842418010000488b4010")
    read(owner, 0x5A04F49, "4939c6")
    relative(owner, 0x5A04F4C, "0f853e130000", 0x5A06290)
    read(owner, 0x5A04F52, "80b99a0b000003")
    relative(owner, 0x5A04FE9, "e862e8a7ff", 0x5483850)
    read(owner, 0x5A050D0, "488b842418010000488b08488b4008")
    read(owner, 0x5A05119, "4d85f6")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: original descriptor count is compared against converted vector length before begin; ordinary execution reuses the converted vector")


if __name__ == "__main__":
    main()
