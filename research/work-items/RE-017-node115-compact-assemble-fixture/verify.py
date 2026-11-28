"""Verify selected original #115 layout anchors and the two reused tables."""

import hashlib
from pathlib import Path
import struct
import sys

from assemble import COMPACT_SIZE, COMPOSED_SIZE, DECODED_SIZE, EVM_BLOCK_SIZE, table

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

OWNERS = {
    0x3C12800: {0x3C128CA: "498b442428"},
    0x3C13610: {0x3C1366B: "bfc8420000", 0x3C1367E: "bac8420000", 0x3C1368F: "bea8270000"},
    0x3C2E860: {
        0x3C2EC06: "498db608110000", 0x3C2EC16: "e8d5cd7100",
        0x3C2F1AC: "488dbb08110000", 0x3C2F1B3: "488db424b0150000",
        0x3C2F1BB: "bad8260000", 0x3C2F28C: "488983bd420000",
        0x3C2F29B: "0f1183b0420000",
    },
    0x434B9F0: {
        0x434BB73: "ff15afd91902", 0x434BBAD: "488db42418270000",
        0x434BBB5: "ba201b0000", 0x434BC9D: "ba401b0000", 0x434BCD7: "f30f1183d0260000",
    },
}


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert hashlib.sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, address, size):
        section = sections[name]
        offset = address - section["va"]
        assert 0 <= offset <= offset + size <= section["size"]
        offset += section["offset"]
        return image[offset:offset + size]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    spans = {}
    for owner, records in OWNERS.items():
        for address, encoding in records.items():
            raw = bytes.fromhex(encoding)
            assert owner <= address < address + len(raw) <= bounds[owner]
            assert read(".text", address, len(raw)) == raw
            spans[address] = raw

    def immediate(address):
        return int.from_bytes(spans[address][-4:], "little")

    def edge(address):
        raw = spans[address]
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    assert edge(0x3C2EC16) == 0x434B9F0
    rela = sections[".rela.dyn"]
    assert [(info, target) for slot, info, target in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"]),
    ) if slot == edge(0x434BB73)] == [(8, 0x38C2690)]
    assert immediate(0x3C1368F) == DECODED_SIZE
    assert immediate(0x3C1366B) == immediate(0x3C1367E) == COMPACT_SIZE
    assert immediate(0x3C2F1BB) == COMPOSED_SIZE
    assert immediate(0x434BBB5) == EVM_BLOCK_SIZE
    assert immediate(0x434BCD7) + 4 == COMPOSED_SIZE - 4
    assert immediate(0x3C2F28C) + 8 == COMPACT_SIZE - 3

    print(f"PASS: #115 {TARGET_SHA256}, {len(spans)} spans in {len(OWNERS)} FDEs")
    print(f"PASS: pinned tables, {len(table('compose'))} composer spans and "
          f"{len(table('materialize'))} materializer spans")


if __name__ == "__main__":
    main()
