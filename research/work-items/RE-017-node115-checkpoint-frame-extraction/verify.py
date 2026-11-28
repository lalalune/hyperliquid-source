"""Authenticate the selected checkpoint worker's LZ4 CLI format literal."""
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__
    data = (ROOT / TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {row["name"]: row for row in parse_sections(data)}

    def read(name, address, width):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + width <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + width]

    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    start = 0x1505f90
    call = 0x150621f
    assert any(row["entry"] == start and row["end"] > call + 7 for row in fdes)
    code = read(".text", call, 7)
    assert code[:3] == b"\x48\x8d\x35"
    address = call + 7 + struct.unpack("<i", code[3:])[0]
    literal = read(".rodata", address, 19)
    assert literal == bytes.fromhex("0a 6c 7a 34 20 2d 71 20 2d 39 20 c0 01 20 c0 01 20 c0 00")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}")
    print(f"PASS: LZ4 CLI archive format literal referenced from {call:#x} to {address:#x}")


if __name__ == "__main__":
    main()
