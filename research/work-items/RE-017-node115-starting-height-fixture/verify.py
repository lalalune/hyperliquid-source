"""Authenticate the mode, result-tag and unsigned startup check in #115."""

import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

SPANS = {
    0x2B41D2A: "4c8d7b3848897338",  # requested height in context +0x38
    0x2B41D32: "4180fc01",          # mode byte equals 1
    0x2B41D36: "0f8593010000",
    0x2B41D3C: "ff15de599a03",      # selected end-height producer
    0x2B41D42: "4883f801",          # selector returned the error tag
    0x2B41D46: "0f8567010000",
    0x2B41D4C: "488b024889d7ff10",  # ordinary error cleanup
    0x2B41D54: "e976010000",
    0x2B41EB3: "4889542430493917",  # unsigned comparison operands
    0x2B41EBB: "0f82460e0000",
    0x2B42D2D: "488d3d1a3d8ffd",
    0x2B42D46: "0f0b",
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
    for address, encoding in SPANS.items():
        raw = bytes.fromhex(encoding)
        assert 0x2B41B70 <= address < address + len(raw) <= bounds[0x2B41B70]
        assert read(".text", address, len(raw)) == raw

    def edge(address):
        raw = bytes.fromhex(SPANS[address])
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    slot = edge(0x2B41D3C)
    rel = sections[".rela.dyn"]
    assert [(kind, addend) for address, kind, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rel["va"], rel["size"]),
    ) if address == slot] == [(8, 0x595B1A0)]
    assert bounds[0x595B1A0] > 0x595B1A0
    assert edge(0x2B41D36) == edge(0x2B41D54) == 0x2B41ECF
    assert edge(0x2B41D46) == 0x2B41EB3
    assert edge(0x2B41EBB) == 0x2B42D07
    diagnostic = read(".rodata", edge(0x2B42D2D), 100)
    assert b"invalid starting height=" in diagnostic and b"last_applied_height=" in diagnostic
    print(f"PASS: #115 {TARGET_SHA256}, {len(SPANS)} exact startup spans and end-height slot")
    print("PASS: disabled mode and tag-1 error bypass; successful result uses unsigned below check")


if __name__ == "__main__":
    main()
