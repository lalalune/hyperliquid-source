"""Check the response-field binding in the signed ELF without loading target code."""
import hashlib
import json
import struct
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
root = here.parents[2]
sys.path.insert(0, str(root / "tools"))
from elf_index import sections

data = (root / "artifacts/node/115/hl-node").read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
layout = sections(data)


def read(va, n):
    section = next(s for s in layout if s["address"] <= va and va + n <= s["address"] + s["size"] and s["name"] in (".text", ".rodata"))
    start = section["offset"] + va - section["address"]
    return data[start:start + n]


def rel(va, op):
    assert read(va, len(op)) == op
    after = va + len(op) + 4
    return after + struct.unpack("<i", read(after - 4, 4))[0]


assert hashlib.sha256(read(0x1767c80, 330)).hexdigest() == "db449207cd3712439957b02bf41253e8342c7fa89ebbd2d8d3e86f0c72b5c1bb"
for va, text in [(0x1767cbf, b"jsonrpc"), (0x1767cee, b"id"), (0x1767d1a, b"result"), (0x1767d3e, b"error"), (0x173e606, b"null")]:
    assert read(rel(va, bytes.fromhex("488d35")), len(text)) == text
assert read(0x1767cea, 4) == bytes.fromhex("488d4b38")
assert read(0x1767cf8, 5) == bytes.fromhex("ba02000000")
assert rel(0x1767cfd, b"\xe8") == 0x173e530
assert rel(0x173e5e6, b"\xe8") == 0x1741580
assert rel(0x173e63a, b"\xe8") == rel(0x173e587, b"\xe8") == 0x173ec30
print(json.dumps({"target_sha256": digest, "response_serializer": "0x1767c80", "id_field_offset": 56, "id_serializer": "0x173e530", "null_literal": "0x459f48", "unsigned_format": "0x1741580", "string_writer": "0x173ec30"}, indent=2))
