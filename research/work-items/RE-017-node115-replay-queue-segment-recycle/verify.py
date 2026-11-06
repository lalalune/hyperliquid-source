"""Verify the queue segment handoff in the pinned #115 ELF."""
import hashlib
from pathlib import Path
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

extents = {0x581a100: 0x581a2cf, 0x581b0c0: 0x581b2a8}
if sorted((frame["start"], frame["end"]) for frame in frames if frame["start"] in extents) != sorted(extents.items()):
    raise ValueError("wrong queue extents")

for address, raw in {
    0x581a142: "4839c1",
    0x581a145: "0f8420010000",
    0x581a14b: "4c8b8110020000",
    0x581a152: "490fbae020",
    0x581a157: "0f830e010000",
    0x581a15d: "4c8b8118020000",
    0x581a164: "4c3b4610",
    0x581a168: "0f87fd000000",
    0x581a190: "488b8108020000",
    0x581a197: "4885c0",
    0x581a19a: "0f8422010000",
    0x581a1a0: "48894608",
    0x581a1a4: "0f118100020000",
    0x581a1ab: "48c7811002000000000000",
    0x581a1b6: "4c8b02",
    0x581a1b9: "498b8000020000",
    0x581a1c0: "4883c020",
    0x581a1c4: "48898100020000",
    0x581a1cb: "31c0",
    0x581a1cd: "f0",
    0x581a1ce: "490fb18808020000",
    0x581a1d6: "7468",
    0x581a1d8: "4c8b8000020000",
    0x581a1e3: "4c898100020000",
    0x581a1ef: "f0",
    0x581a1f0: "490fb18808020000",
    0x581a1f8: "7446",
    0x581a205: "4c898100020000",
    0x581a211: "f0",
    0x581a212: "490fb18808020000",
    0x581a21a: "7424",
    0x581a21f: "be20020000",
    0x581a22f: "41ffd6",
    0x581b1e0: "498b842410020000",
    0x581b1e8: "83f8ff",
    0x581b1eb: "0f94c0",
    0x581b1ee: "84c3",
    0x581b1f0: "0f841affffff",
    0x581b1f6: "4c89e0",
    0x581b1f9: "f0",
    0x581b1fa: "490fb117",
    0x581b1fe: "0f850cffffff",
    0x581b204: "f0",
    0x581b205: "834c24c000",
    0x581b20a: "498b4708",
    0x581b20e: "4989842418020000",
    0x581b216: "48b800000000010000",
    0x581b220: "f0",
    0x581b221: "4909842410020000",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

def reclaim(selected, oldest, flags, watermark, cursor):
    if selected == oldest:
        return False
    if (flags >> 32) & 1 == 0:
        return False
    return watermark <= cursor


flag = 1 << 32
maximum = (1 << 64) - 1
for args, expected in (
    ((1, 1, flag, 32, 32), False),
    ((2, 1, 0xffffffff, 32, 32), False),
    ((2, 1, flag, 33, 32), False),
    ((2, 1, flag, 32, 32), True),
    ((2, 1, flag, 32, 33), True),
    ((2, 1, flag, maximum, 0), False),
    ((2, 1, flag, 0, maximum), True),
):
    if reclaim(*args) != expected:
        raise ValueError("wrong synthetic reclaim gate")
print("Verified queue watermark publication, reclaim gate and three relink attempts.")
