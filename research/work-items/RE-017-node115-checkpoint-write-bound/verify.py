"""Authenticate the decompressed-size limit boundary in the #115 LZ4 adapter."""

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

    owner = 0x477F8C0
    read(owner, 0x477F8D1, "48898c24b0000000")
    read(owner, 0x477F8D9, "4883fa03")
    relative(owner, 0x477F8DD, "0f86d7060000", 0x477FFBA)
    read(owner, 0x477F8EE, "448b2e")
    read(owner, 0x477F8F9, "4c39e9")
    relative(owner, 0x477F8FC, "0f8277080000", 0x4780179)
    relative(owner, 0x477F914, "ff157efcd501", 0x64DF598)
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: native LZ4 adapter checks the declared decoded size against its caller bound before allocation")


if __name__ == "__main__":
    main()
