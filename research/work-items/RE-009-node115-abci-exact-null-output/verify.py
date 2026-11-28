"""Authenticate the raw null sink and extension branches of the #115 serializer."""

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
    serializer = next(record for record in fdes if record["entry"] == 0x26A2C80)
    text = data(".text")
    base = sections[".text"]["va"]

    def read(address, expected_hex):
        expected = bytes.fromhex(expected_hex)
        assert serializer["entry"] <= address < address + len(expected) <= serializer["end"]
        assert text[address - base : address - base + len(expected)] == expected, hex(address)
        return expected

    def relative(address, expected_hex, target, width=4):
        raw = read(address, expected_hex)
        assert address + len(raw) + int.from_bytes(raw[-width:], "little", signed=True) == target

    read(0x26A2C9E, "4c8b77084c8b7f10")  # input pointer and length
    read(0x26A2CDA, "4983ff09")  # nine bytes
    relative(0x26A2CE2, "7520", 0x26A2D04, width=1)
    prefix = read(0x26A2CE4, "48b82f6465762f6e756c")[2:]
    read(0x26A2CEE, "493306410fb64e08")
    last = read(0x26A2CF6, "4883f16c")[-1:]
    assert prefix + last == b"/dev/null"
    read(0x26A2CFA, "4809c1")
    relative(0x26A2CFD, "750a", 0x26A2D09, width=1)
    relative(0x26A2CFF, "e905020000", 0x26A2F09)

    relative(0x26A2DA4, "488d153a2cdcfd", 0x4659E5)
    suffix = 0x4659E5 - sections[".rodata"]["va"]
    assert data(".rodata")[suffix : suffix + 3] == b"rmp"
    read(0x26A2DAB, "b903000000")
    relative(0x26A2DB0, "e8ebceeffe", 0x159FCA0)
    relative(0x26A2DB7, "7462", 0x26A2E1B, width=1)
    read(0x26A2DB9, "48c744246800000000")
    read(0x26A2E1B, "bf80000000")
    print(f"PASS: authenticated {TARGET_SHA256}; raw nine-byte /dev/null comparison precedes rmp versus JSON dispatch")


if __name__ == "__main__":
    main()
