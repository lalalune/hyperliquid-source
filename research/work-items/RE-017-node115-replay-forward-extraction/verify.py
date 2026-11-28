"""Verify the selected native wrapper writes an origin, tag, length and span."""
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    data = (ROOT / TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def read(name, address, size):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + size <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + size]

    start, end = 0x581f160, 0x581f797
    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    assert any(row["entry"] == start and row["end"] == end for row in fdes)
    for address, encoding in (
        (0x581f1ab, "894c3010"),
        (0x581f1b3, "0f110430"),
        (0x581f1b7, "4883c614"),
        (0x581f1f2, "c6043000"),
        (0x581f1f6, "48ffc6"),
        (0x581f201, "4d8b7d20"),
        (0x581f224, "498b7518"),
        (0x581f248, "4c89fa"),
        (0x581f254, "4d896e20"),
    ):
        raw = bytes.fromhex(encoding)
        assert start <= address < address + len(raw) <= end
        assert read(".text", address, len(raw)) == raw
    raw = read(".text", 0x581f210, 5)
    assert raw[0] == 0xe8 and 0x581f215 + struct.unpack("<i", raw[1:])[0] == 0x5822910
    assert read(".text", 0x581f1f2, 4) != b"\xc6\x04\x30\x01"
    print(f"PASS: node #115 SHA-256 {TARGET_SHA256}, writer FDE {start:#x}..{end:#x}")
    print("PASS: 20 raw origin bytes, tag zero, compact length and raw span")
    print("PASS: alternative tag witness rejected")


if __name__ == "__main__":
    main()
