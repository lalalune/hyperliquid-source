"""Verify tree-to-flat history conversion in the pinned #115 ELF."""
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

extents = {0x5b74f20: 0x5b751c1, 0x5b9b710: 0x5b9b9b1}
if sorted((frame["start"], frame["end"]) for frame in frames if frame["start"] in extents) != sorted(extents.items()):
    raise ValueError("wrong collector extents")


def edge(site, prefix, target):
    opcode = bytes.fromhex(prefix)
    raw = read(site, len(opcode) + 4)
    if raw[:-4] != opcode or site + len(raw) + struct.unpack("<i", raw[-4:])[0] != target:
        raise ValueError(f"wrong transfer at {site:#x}")


for site, prefix, target in (
    (0x4de4bc3, "0f87", 0x4de4d92), (0x4de4d96, "0f87", 0x4de4fe8),
    (0x4de5c56, "0f87", 0x4de5da7), (0x4de5dab, "0f87", 0x4de5f78),
    (0x4de4cd7, "e8", 0x5b9b710), (0x4de4e1e, "e8", 0x5b9b710),
    (0x4de5ce1, "e8", 0x5b74f20), (0x4de5e39, "e8", 0x5b74f20),
    (0x5b9b836, "e8", 0x51e06d0), (0x5b75046, "e8", 0x51e06d0),
    (0x5b9b8a6, "e8", 0x51e06d0), (0x5b750b6, "e8", 0x51e06d0),
):
    edge(site, prefix, target)

for address, raw in {
    0x4de4bbf: "4883f81f",
    0x4de4bd1: "49c7460800000000",
    0x4de4bd9: "49c7461800000000",
    0x4de4d76: "49891e",
    0x4de4d82: "49c7461000000000",
    0x4de4d8e: "49894618",
    0x4de4d92: "4983fd1f",
    0x4de4e76: "4c896c2408",
    0x4de4e80: "48c744241800000000",
    0x4de4e89: "48895c2420",
    0x4de5c52: "4883f81f",
    0x4de5c64: "49c7460800000000",
    0x4de5c6c: "49c7461800000000",
    0x4de5d92: "49c7461000000000",
    0x4de5d9e: "49894618",
    0x4de5da7: "4983fd1f",
    0x5b9b723: "4c8b7e40",
    0x5b9b727: "4a8d04fd00000000",
    0x5b9b72f: "488d3480",
    0x5b9b843: "4885c0",
    0x5b9b846: "7448",
    0x5b74f33: "4c8b7e40",
    0x5b74f37: "4a8d04fd00000000",
    0x5b74f3f: "488d3480",
    0x5b75053: "4885c0",
    0x5b75056: "7448",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

# The selected per-row projection is identical in the two collectors.
projection = bytes.fromhex(
    "488b94c86801000048c1e1050f1004080f104c08100f294424200f294c2430"
    "498955f80f284424200f284c2430410f114500410f114d1049ffc44983c528"
)
for address in (0x5b75060, 0x5b9b850):
    if read(address, len(projection)) != projection:
        raise ValueError(f"wrong flat row projection at {address:#x}")

for count in range(32):
    keys = [(1 << 64) - 1 - i for i in range(count)]
    values = [bytes((i,)) * 32 for i in range(count)]
    packed = bytearray(count * 40)
    for offset in range(0, count, 11):
        node_keys = keys[offset:offset + 11]
        node_values = values[offset:offset + 11]
        node = b"".join(node_values).ljust(0x168, b"\0")
        node += b"".join(struct.pack("<Q", key) for key in node_keys)
        for slot in range(len(node_keys)):
            start = 40 * (offset + slot)
            packed[start:start + 8] = node[0x168 + 8 * slot:0x170 + 8 * slot]
            packed[start + 8:start + 40] = node[32 * slot:32 * slot + 32]
    if bytes(packed) != b"".join(struct.pack("<Q32s", k, v) for k, v in zip(keys, values)):
        raise ValueError(f"synthetic flat projection disagrees at {count} rows")

print("Verified four tree conversion branches and two key/value collectors.")
