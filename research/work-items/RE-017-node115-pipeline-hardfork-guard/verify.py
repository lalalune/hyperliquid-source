"""Verify the #115 restored hardfork pair guard before begin-block."""

from hashlib import sha256
from pathlib import Path
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

SPANS = {
    0x5A04EA3: "488b7028",
    0x5A04EA7: "488b5030",
    0x5A04EBB: "498b8c2450040000",
    0x5A04F05: "4c8b4118",
    0x5A04F09: "488b7920",
    0x5A04F17: "4939f0",
    0x5A04F1A: "0f854d130000",
    0x5A04F20: "4839d7",
    0x5A04F23: "0f8544130000",
    0x5A04FDE: "498db42450040000",
    0x5A04FE9: "e862e8a7ff",
    0x5A06274: "488d742410",
    0x5A06279: "488d942438020000",
    0x5A06285: "ff15551eae00",
    0x5A0628B: "e90a010000",
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
    assert bounds[0x5A04E40] == 0x5A065F8
    text = data(".text")
    base = sections[".text"]["va"]
    evidence = {}
    for address, encoded in SPANS.items():
        expected = bytes.fromhex(encoded)
        assert 0x5A04E40 <= address < address + len(expected) <= bounds[0x5A04E40]
        offset = address - base
        assert 0 <= offset < offset + len(expected) <= len(text)
        actual = text[offset:offset + len(expected)]
        assert actual == expected, hex(address)
        evidence[address] = actual

    def relative(address):
        raw = evidence[address]
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    assert 0x5A04F1A < 0x5A04F23 < 0x5A04FE9
    assert relative(0x5A04F1A) == relative(0x5A04F23) == 0x5A0626D
    assert relative(0x5A04FE9) == 0x5483850
    assert relative(0x5A0628B) == 0x5A0639A

    print(f"PASS: #115 {TARGET_SHA256}, {len(evidence)} spans in the integrated apply-block FDE")
    print("PASS: both restored hardfork comparisons precede the selected begin call")


if __name__ == "__main__":
    main()
