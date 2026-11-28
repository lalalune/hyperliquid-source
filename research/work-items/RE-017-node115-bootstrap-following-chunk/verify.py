"""Authenticate the bootstrap continuation used by the offline range adapter."""
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

ANCHORS = {
    0x5a82cd5: "4839c8",
    0x5a82e0f: "48c7834802000000000000",
    0x5a82ff3: "488b8380020000",
    0x5a82ffa: "488b9390020000",
    0x5a83001: "48ffc2",
    0x5a83004: "48c7c1ffffffff",
    0x5a8300b: "480f45ca",
    0x5a8300f: "48898b88020000",
    0x5a83016: "c683c802000000",
    0x5a8301d: "4839c1",
    0x5a8304d: "48899390020000",
    0x5a883cb: "488bb368020000",
    0x5a883d2: "488b5610",
    0x5a883d6: "488b8e10010000",
    0x5a883e6: "48c1e204",
    0x5a883ed: "4883c2f0",
    0x5a883f6: "488b0a",
    0x5a88419: "488b5110",
    0x5a8841d: "48ffc2",
    0x5a88427: "480f45ca",
    0x5a88433: "4839c1",
    0x5a885d8: "41b644",
    0x5a88646: "41b62e",
}

EDGES = (
    (0x5a82cdd, "0f84", 0x5a82e0f),
    (0x5a82fdc, "74", 0x5a82ff3),
    (0x5a83020, "0f87", 0x5a883c4),
    (0x5a883e0, "74", 0x5a8842b),
    (0x5a88436, "0f85", 0x5a885e0),
)


def main():
    assert __debug__
    data = (ROOT / TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {row["name"]: row for row in parse_sections(data)}

    def read(name, address, width):
        sec = sections[name]
        delta = address - sec["va"]
        assert 0 <= delta <= delta + width <= sec["size"]
        offset = sec["offset"] + delta
        return data[offset:offset+width]

    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    start, end = 0x5a82670, 0x5a89535
    assert any(row["entry"] == start and row["end"] == end for row in fdes)
    for address, encoding in ANCHORS.items():
        raw = bytes.fromhex(encoding)
        assert start <= address < address + len(raw) <= end
        assert read(".text", address, len(raw)) == raw
    for address, opcode, dest in EDGES:
        op = bytes.fromhex(opcode)
        width = 1 if len(op) == 1 else 4
        raw = read(".text", address, len(op) + width)
        assert raw.startswith(op)
        offset = int.from_bytes(raw[len(op):], "little", signed=True)
        assert address + len(raw) + offset == dest
        assert address + len(raw) + (offset ^ 1) != dest
    assert read(".rodata", 0x93bb51, 18) == b"finished bootstrap"
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}, range {start:#x}..{end:#x}")
    print(f"PASS: {len(ANCHORS)} anchors, {len(EDGES)} checked branches and changed branch controls")
    print("PASS: drained vector advances the chunk, then reloads receive history for the final compare")


if __name__ == "__main__":
    main()
