"""Check the original #115 replay clock update in both begin paths."""

import csv
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

PACKET = Path(__file__).parent


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert hashlib.sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, address, size):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + size <= section["size"]
        offset = section["offset"] + delta
        return image[offset:offset + size]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    compact = 0x5483850
    expanded = 0x5483F50
    expected = 0x548386F
    window = bytearray()
    spans = {}
    with (PACKET / "instructions.tsv").open() as file:
        for row in csv.DictReader(file, delimiter="\t"):
            address = int(row["va"], 16)
            raw = bytes.fromhex(row["bytes"])
            assert address == expected
            expected += len(raw)
            window.extend(raw)
            spans[address] = raw

    assert expected == 0x54838D3
    for entry in (compact, expanded):
        start = entry + 0x1F
        assert start + len(window) < bounds[entry]
        assert read(".text", start, len(window)) == window

    for site, opcode, target in (
        (0x5483893, 0x75, 0x54838AE), (0x54838A0, 0x75, 0x54838AE),
        (0x54838AA, 0x77, 0x54838B2), (0x54838AC, 0xEB, 0x54838D3),
        (0x54838B0, 0x75, 0x54838D3),
    ):
        assert spans[site][0] == opcode
        assert site + 2 + int.from_bytes(spans[site][1:], "little", signed=True) == target
    assert spans[0x5483890] == bytes.fromhex("0f9ec2")  # setle, signed
    assert spans[0x548389D] == bytes.fromhex("0f96c2")  # setbe, unsigned
    assert spans[0x54838BF] == bytes.fromhex("4989556c")  # old first two words
    assert spans[0x54838B7] == bytes.fromhex("41895574")  # old third word

    for site, owner, target in ((0x5A04FE9, 0x5A04E40, compact),
                                (0x5A067AD, 0x5A06600, expanded)):
        assert owner < site < site + 5 <= bounds[owner]
        call = read(".text", site, 5)
        assert call[0] == 0xE8
        assert site + 5 + int.from_bytes(call[1:], "little", signed=True) == target

    print(f"PASS: #115 {TARGET_SHA256}; {len(spans)} spans / {len(window)} bytes match both begin FDEs")
    print("PASS: five original branch targets, signed date, unsigned subday fields, and both replay-wrapper calls")


if __name__ == "__main__":
    main()
