"""Verify replay override ring trimming."""
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
if hashlib.sha256(data).hexdigest() != "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":
    raise ValueError("wrong target")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
def read(addr, size):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= addr and addr + size <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError("invalid address")
    s = hits[0]
    off = s["offset"] + addr - s["address"]
    return data[off:off + size]

for site, target in ((0x5a6383f, 0x57e6750), (0x57e6785, 0x4dc8e00), (0x57e6821, 0x4ddd0b0), (0x4ddd0e1, 0x51d5bb0), (0x4ddd1e8, 0x5b8fc50), (0x4ddd266, 0x51e48d0)):
    opcode, displacement = struct.unpack("<Bi", read(site, 5))
    if opcode != 0xe8 or site + 5 + displacement != target:
        raise ValueError(f"wrong edge at {site:#x}")

for address, raw in {
    0x4ddd0e8: "488b43184c39330f94c14883f8200f92c220ca80fa01",
    0x4ddd10c: "48c743080000000048c7431800000000",
    0x4ddd276: "4c89234c896b0848c7431000000000488b44240848894318",
    0x4ddd339: "4839030f94c04983fc200f92c120c180f901",
    0x5b8fc63: "4c8b7e404c89fe48c1e605",
    0x5b8fd66: "e8654b65ff488b8424880000004885c07428",
    0x5b8fd80: "48c1e1050f1004080f104c0810410f114d10410f11450049ffc44983c520",
    0x5b8fdc3: "488b442418488943100f104424080f1103",
    0x57e678a: "837c2440010f85a0000000",
    0x57e67b1: "488b4318483b43400f86c1010000",
    0x57e67d0: "488b4b10488d5101488b33488b7b084839f2490f42f448f7de488d143148ffc24889531048ffc848894318",
    0x57e67fb: "48c1e1050f10040f0f104c0f10",
    0x57e6826: "488b4318483b434077a0",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong window at {address:#x}")

for capacity in range(1, 17):
    for head in range(capacity):
        for count in range(capacity + 1):
            for limit in range(count + 1):
                cursor, size = head, count
                removed = []
                while size > limit:
                    removed.append(cursor)
                    cursor += 1
                    if cursor >= capacity:
                        cursor -= capacity
                    size -= 1
                if removed != [(head + i) % capacity for i in range(count - limit)]:
                    raise ValueError("ring trim model mismatch")
                if (cursor, size) != ((head + count - limit) % capacity, limit):
                    raise ValueError("wrong final ring coordinates")
print("Verified selected replay override ring trimming.")
