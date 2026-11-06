"""Verify the post-root gate cleanup against the pinned capture."""
import hashlib
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
if hashlib.sha256(data).hexdigest() != "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":
    raise ValueError("Node #115 digest mismatch")

table = sections(data)
text = next(section for section in table if section["name"] == ".text")
_, frames = eh_frame_records(data, table)
extents = {(frame["start"], frame["end"]) for frame in frames}
pattern = re.compile(r"^\s*([0-9a-f]+):[ \t]+((?:[0-9a-f]{2}[ \t]+)+)", re.M)


def read(address, size):
    offset = address - text["address"]
    if offset < 0 or offset + size > text["size"]:
        raise ValueError("address outside .text")
    start = text["offset"] + offset
    return data[start:start + size]


def check_call(site, target, code):
    if code[0] != 0xe8 or site + 5 + struct.unpack_from("<i", code, 1)[0] != target:
        raise ValueError("direct call target mismatch")


def check_variant(start, end, site):
    if (start, end) not in extents:
        raise ValueError("function extent mismatch")
    export = Path(__file__).with_name(f"replay-{start:x}.llvm.txt")
    cursor = start
    rows = []
    for address, encoded in pattern.findall(export.read_text()):
        code = bytes.fromhex(encoded)
        if int(address, 16) != cursor or read(cursor, len(code)) != code:
            raise ValueError(f"instruction mismatch at {cursor:#x}")
        rows.append(code)
        cursor += len(code)
    if cursor != end:
        raise ValueError("incomplete body")
    edge = read(site, 5)
    check_call(site, start, edge)
    changed = bytearray(edge)
    changed[1] ^= 1
    try:
        check_call(site, start, changed)
    except ValueError:
        print(f"Verified {end - start} bytes at {start:#x}, call and corruption control at {site:#x}.")
    else:
        raise ValueError("changed displacement accepted")
    print(f"Verified {len(rows)} contiguous instruction rows.")


check_variant(0x5a4f110, 0x5a4f140, 0x5a08f3c)
check_call(0x5a07c57, 0x5a4f110, read(0x5a07c57, 5))
check_call(0x5a6dd22, 0x5a4f110, read(0x5a6dd22, 5))
cursor = 0x5a08f34
export = Path(__file__).with_name("end-selector-unwind.llvm.txt")
for address, encoded in pattern.findall(export.read_text()):
    code = bytes.fromhex(encoded)
    if int(address, 16) != cursor or read(cursor, len(code)) != code:
        raise ValueError(f"caller instruction mismatch at {cursor:#x}")
    cursor += len(code)
if cursor != 0x5a08f49:
    raise ValueError("incomplete unwind window")
check_call(0x5a08f44, 0x63f0a50, read(0x5a08f44, 5))
print("Verified three cleanup call sites and the end-selector unwind continuation.")
