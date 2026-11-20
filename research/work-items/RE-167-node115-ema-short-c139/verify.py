#!/usr/bin/env python3
"""Verify the pinned static FDE packet for node115 EMA short c139."""

from pathlib import Path
import hashlib
import re
import sys

sys.path.insert(0, str(Path(__file__).parents[3] / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records

START = 0x4D462C0
END = 0x4D46334
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WITNESSES = {
    0x4D462C0: "53",
    0x4D462C1: "4883ec50",
    0x4D462C5: "4889fb",
    0x4D462C8: "c644243807",
    0x4D462CD: "4883c708",
    0x4D462DB: "488d0556457501",
    0x4D46324: "48c70301000000",
}
NEGATIVE = {0x4D462C0: "52", 0x4D46324: "c60301"}


def main() -> None:
    root = Path(__file__).parents[3]
    binary = root / "artifacts/node/115/hl-node"
    text = Path(__file__).with_name("excerpts.objdump.txt").read_text()
    data = binary.read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    assert any(x["start"] == START and x["end"] == END and any(
        y["start"] == START and y["fde"] == 0xF18900 for y in header
    ) for x in fdes)

    def bytes_at(address: int) -> str:
        m = re.search(rf"^\s*{address:x}:\s+((?:[0-9a-f]{{2}}\s+)+)", text, re.MULTILINE)
        return "".join(m.group(1).split()) if m else ""

    for address, opcode in WITNESSES.items():
        assert bytes_at(address).startswith(opcode), (hex(address), opcode)
    for address, opcode in NEGATIVE.items():
        assert not bytes_at(address).startswith(opcode), (hex(address), opcode)
    print("RE-167 static FDE verification passed; 7 witnesses and 2 mutation negatives")


if __name__ == "__main__":
    main()
