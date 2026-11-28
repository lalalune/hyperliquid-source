"""Authenticate the #115 root capture size and sparse row reduction."""

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

    capture = 0x4E34CE0
    reducer = 0x141A250
    allocation = read(capture, 0x4E35155, "bf88050000")
    count = read(capture, 0x4E3530B, "48c74424283b000000")
    assert int.from_bytes(allocation[1:], "little") == 24 * int.from_bytes(count[-4:], "little") == 24 * 59
    relative(capture, 0x4E35359, "ff15a1a16a01", 0x64DF500)
    slots = {slot: target for slot, info, target in iter_unpack("<QQq", data(".rela.dyn"))
             if info == 8}
    assert slots[0x64DF500] == reducer
    read(reducer, 0x141A3B0, "48ffc34983c718")
    read(reducer, 0x141A3C5, "48b90100000000000080")
    relative(reducer, 0x141A3D2, "74dc", 0x141A3B0, width=1)
    relative(reducer, 0x141A3F1, "ff1509510c05", 0x64DF500)
    read(reducer, 0x141A3F7, "48899c24f0000000")
    read(reducer, 0x141A3FF, "80bc24f800000002")
    relative(reducer, 0x141A407, "74a7", 0x141A3B0, width=1)
    read(reducer, 0x141A741, "4889450848895d104c897518c6450001")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: 59 capture slots; sentinel and tag-2 skips retain later original indices; empty result is a tag-1 vector")


if __name__ == "__main__":
    main()
