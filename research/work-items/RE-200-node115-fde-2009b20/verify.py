#!/usr/bin/env python3
"""Verify the pinned node115 FDE 0x2009b20 packet using static bytes only."""
import hashlib, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

BIN = ROOT / "artifacts/node/115/hl-node"
START, END, SIZE, FDE = 0x2009b20, 0x2009c18, 248, 0x10cee6c
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WITNESSES = {
        0x2009b20: bytes.fromhex('4156'),
        0x2009b3c: bytes.fromhex('48b8000000000000'),
        0x2009b71: bytes.fromhex('4889e7'),
        0x2009b9e: bytes.fromhex('e8bd4c1100'),
        0x2009bc9: bytes.fromhex('0f114b10'),
        0x2009bf2: bytes.fromhex('4889d8'),
        0x2009c13: bytes.fromhex('e8386e3e04'),
}

def fail(condition, message):
    if not condition:
        raise AssertionError(message)

def verify(data):
    fail(hashlib.sha256(data).hexdigest() == DIGEST, "target binary digest mismatch")
    sec_list = sections(data)
    secs = {row["name"]: row for row in sec_list}
    text = secs[".text"]
    fail(text["address"] <= START and END <= text["address"] + text["size"], "range outside .text")
    def at(va, n):
        pos = text["offset"] + va - text["address"]
        return data[pos:pos + n]
    _, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sec_list)
    fail(any(row["start"] == START and row["end"] == END and row["fde"] == FDE for row in fdes), "FDE record mismatch")
    fail(any(row["start"] == START and row["fde"] == FDE for row in header), "unwind index entry mismatch")
    for address, value in WITNESSES.items():
        fail(at(address, len(value)) == value, f"witness mismatch at {address:#x}")
    # Boundary witness: END is not part of this FDE.
    fail(END > START and at(END - 1, 1) != b"", "empty trailing byte")
    return True

def main():
    data = BIN.read_bytes()
    verify(data)
    # Negative controls: a one-byte mutation anywhere in the FDE must fail.
    for address in (START, START + SIZE // 2):
        pos = next(row["offset"] for row in sections(data) if row["name"] == ".text") + address - next(row["address"] for row in sections(data) if row["name"] == ".text")
        bad = bytearray(data)
        bad[pos] ^= 0xFF
        try:
            verify(bytes(bad))
        except AssertionError:
            pass
        else:
            raise AssertionError(f"mutation control did not fail at {address:#x}")
    print(f"RE-200 static FDE verification passed; {len(WITNESSES)} witnesses and 2 mutation negatives")

if __name__ == "__main__":
    main()
