"""Verify the owning history cursor in the pinned #115 ELF."""
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x51e06d0] != [(0x51e06d0, 0x51e0a7a)]:
    raise ValueError("wrong owning cursor extent")

for site, opcode, target in (
    (0x5b75046, b"\xe8", 0x51e06d0),
    (0x5b9b836, b"\xe8", 0x51e06d0),
    (0x51e06e5, b"\x0f\x84", 0x51e0779),
    (0x51e071a, b"\x0f\x83", 0x51e08b4),
    (0x51e07fc, b"\xff\x15", 0x64df4a0),
):
    raw = read(site, len(opcode) + 4)
    if raw[:-4] != opcode or site + len(raw) + struct.unpack("<i", raw[-4:])[0] != target:
        raise ValueError(f"wrong transfer at {site:#x}")

for address, raw in {
    0x51e06de: "488b4640",
    0x51e06eb: "48ffc8",
    0x51e06ee: "48894640",
    0x51e06f2: "833e01",
    0x51e06fb: "488b7e08",
    0x51e0708: "488b4610",
    0x51e070c: "4c8b7618",
    0x51e0710: "0fb78fc2010000",
    0x51e072f: "4b8d0cf7",
    0x51e0733: "4881c1d0010000",
    0x51e0753: "488d88c8010000",
    0x51e0788: "48c70600000000",
    0x51e078f: "4883fa01",
    0x51e07a4: "498b8660010000",
    0x51e07c6: "4d8d7f01",
    0x51e07cf: "490f44f4",
    0x51e07d5: "ffd3",
    0x51e0802: "49c7450000000000",
    0x51e0813: "488b7e10",
    0x51e0817: "488b4e18",
    0x51e0830: "488bbfc8010000",
    0x51e088e: "48c70601000000",
    0x51e0895: "48897e08",
    0x51e089c: "0f1100",
    0x51e08d0: "4c8bbf60010000",
    0x51e08e0: "4c8d6001",
    0x51e08e4: "440fb7b7c0010000",
    0x51e08f4: "480f44f5",
    0x51e08fa: "ffd3",
    0x51e0902: "66453bb7c2010000",
    0x51e090a: "73c4",
    0x51e091c: "498d5601",
    0x51e0964: "488d88c8010000",
    0x51e0971: "4d897d00",
    0x51e0975: "4d896508",
    0x51e0979: "4d897510",
    0x51e097d: "48894608",
    0x51e0981: "48c7461000000000",
    0x51e0989: "48895618",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

print("Verified forward cursor handoff and exhausted-chain release windows.")
