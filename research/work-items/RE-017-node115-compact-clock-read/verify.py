"""Authenticate the restored clock pair and its normal replay consumer."""

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

    for address, encoded in (
        (0x30D31FE, "896b60"), (0x30D3209, "48894364"),
        (0x30D320D, "4489636c"), (0x30D3219, "48894370"),
    ):
        read(0x30D1C60, address, encoded)
    read(0x3C2E860, 0x3C2EBF3, "baa00b00004c89f641ffd7")
    read(0x5483850, 0x548387E, "498b4560")
    read(0x5483850, 0x54838B7, "41895574")
    read(0x5483850, 0x54838BF, "4989556c")
    print(f"PASS: authenticated {TARGET_SHA256}")
    print("PASS: restored current and previous clocks occupy separate 12-byte lanes in the materialized prefix")


if __name__ == "__main__":
    main()
