"""Authenticate the #115 comparison, history split and successor root order."""

from hashlib import sha256
from pathlib import Path
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

SPANS = {
    0x5A04E40: {
        0x5A05C5E: "e8bd4343ff",
        0x5A05EA1: "41807c241000",
        0x5A05EA7: "0f8414010000",
        0x5A05EAD: "498b442418",
        0x5A05EB2: "48ffc0",
        0x5A05EB5: "48c7c1ffffffff",
        0x5A05EBC: "480f45c8",
        0x5A05EC8: "498d9c2400040000",
        0x5A05EE3: "e8e8fb3dff",
        0x5A05FC1: "488d7c2410",
        0x5A05FC9: "e8f21e0000",
    },
    0x5A07EC0: {
        0x5A07FCE: "e8fd5aa8ff",
        0x5A07FD3: "498dbe00040000",
        0x5A07FE5: "e8b6bfffff",
    },
}


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def data(name):
        section = sections[name]
        return image[section["offset"]:section["offset"] + section["size"]]

    _, fdes = walk_eh_frame(data(".eh_frame"), sections[".eh_frame"]["va"])
    bounds = {row["entry"]: row["end"] for row in fdes}
    text = data(".text")
    base = sections[".text"]["va"]
    witnesses = {}
    for entry, anchors in SPANS.items():
        for address, encoded in anchors.items():
            expected = bytes.fromhex(encoded)
            assert entry <= address < address + len(expected) <= bounds[entry]
            offset = address - base
            assert 0 <= offset < offset + len(expected) <= len(text)
            actual = text[offset:offset + len(expected)]
            assert actual == expected, hex(address)
            witnesses[address] = actual

    def relative(address):
        raw = witnesses[address]
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    assert 0x5A05C5E < 0x5A05EE3 < 0x5A05FC9
    assert relative(0x5A05C5E) == 0x4E3A020
    assert relative(0x5A05EE3) == 0x4DE5AD0
    assert relative(0x5A05EA7) == 0x5A05FC1
    assert relative(0x5A05FC9) == 0x5A07EC0
    assert relative(0x5A07FCE) == 0x548DAD0
    assert relative(0x5A07FE5) == 0x5A03FA0

    print(f"PASS: #115 {TARGET_SHA256}, {len(witnesses)} spans across {len(SPANS)} FDEs")
    print("PASS: comparison precedes saturated history split; eligible insertion follows selector")


if __name__ == "__main__":
    main()
