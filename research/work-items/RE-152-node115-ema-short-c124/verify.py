#!/usr/bin/env python3
"""Verify the pinned static FDE packet for node115 EMA short c124."""

from pathlib import Path
import hashlib
import re
import sys

sys.path.insert(0, str(Path(__file__).parents[3] / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records

START = 0x4D45730
END = 0x4D45831
FDE = "0x4d45730\t0x4d45831\t257\t.text\t0xf18690"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WITNESSES = {
    0x4D45730: "53",
    0x4D45731: "4883ec20",
    0x4D45735: "4889fb",
    0x4D45770: "c60300",
    0x4D457BA: "66c7030900",
    0x4D4580C: "c60309",
    0x4D45821: "0f114b10",
}
NEGATIVE = {
    0x4D45730: "52",
    0x4D4580C: "c60209",
}


def main() -> None:
    root = Path(__file__).parents[3]
    binary = root / "artifacts/node/115/hl-node"
    excerpt = Path(__file__).with_name("excerpts.objdump.txt")
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == TARGET_SHA256
    text = excerpt.read_text()
    sections, header = unwind_index(binary.read_bytes())
    _, fdes = eh_frame_records(binary.read_bytes(), sections)
    assert any(x["start"] == START and x["end"] == END and any(
        y["start"] == START and y["fde"] == 0xF18690 for y in header
    ) for x in fdes)
    def bytes_at(address: int) -> str:
        match = re.search(rf"^\s*{address:x}:\s+((?:[0-9a-f]{{2}}\s+)+)", text, re.MULTILINE)
        return "".join(match.group(1).split()) if match else ""

    for address, opcode in WITNESSES.items():
        assert bytes_at(address).startswith(opcode), (hex(address), opcode)
    for address, opcode in NEGATIVE.items():
        assert not bytes_at(address).startswith(opcode), (hex(address), opcode)
    print("RE-152 static FDE verification passed; 7 witnesses and 2 mutation negatives")


if __name__ == "__main__":
    main()
