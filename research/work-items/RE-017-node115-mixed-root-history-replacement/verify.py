"""Verify the mixed-root history replacement route in the pinned #115 ELF."""
import hashlib
from itertools import combinations_with_replacement
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

extents = {0x5a046f0: 0x5a04e3c, 0x4dce8b0: 0x4dced3e, 0x4de4a60: 0x4de509a}
if sorted((frame["start"], frame["end"]) for frame in frames if frame["start"] in extents) != sorted(extents.items()):
    raise ValueError("wrong consumer or helper extents")


def edge(site, prefix, target):
    opcode = bytes.fromhex(prefix)
    raw = read(site, len(opcode) + 4)
    if raw[:-4] != opcode or site + len(raw) + struct.unpack("<i", raw[-4:])[0] != target:
        raise ValueError(f"wrong control transfer at {site:#x}")


for site, prefix, target in (
    (0x5a08ac7, "e8", 0x5a046f0),
    (0x5a04708, "e8", 0x4dce8b0),
    (0x5a04715, "0f82", 0x5a047fa),
    (0x5a04d9a, "e8", 0x4de4a60),
    (0x5a04dab, "e8", 0x5248d30),
    (0x5a04e04, "ff15", 0x64df4a0),
    (0x4de4a85, "0f81", 0x4de4b12),
    (0x4de4b4b, "0f83", 0x4de4e93),
    (0x4de4f66, "ff15", 0x64df508),
    (0x4de4fc2, "ff15", 0x64df508),
):
    edge(site, prefix, target)

for site in range(0x5a04a4f, 0x5a04d6d + 1, 0x13):
    edge(site, "e8", 0x4e2a4e0)
    if read(site + 5, 3) != bytes.fromhex("4885c0"):
        raise ValueError(f"wrong return test at {site:#x}")
    edge(site + 8, "0f84", 0x5a047fa)

for address, raw in {
    0x5a046f7: "4889d14889f24889fb488d7c24084889de",
    0x5a0470d: "488b53184883fa33",
    0x5a04770: "488d0489488d3cc64b8d0480488d0cc6488d0492488d04c6",
    0x5a04d85: "488b004889442450488d7c2408488d5424504889de",
    0x5a04d9f: "488b034c39f0754a488d7b08",
    0x5a04df1: "4885c07414488b7b0848c1e003488d348031d2",
    0x4de4b48: "493931",
    0x4de4b6e: "4b3934c1480f42ef4829d1",
    0x4de4b8a: "493934c94883d5004801c5",
    0x4de4c6e: "4a3914c1480f42ef4829f0",
    0x4de4c8a: "483914c14883d500",
    0x4de4ea6: "4d89fc4929ec4a8d04e500000000488d3480",
    0x4de4f2a: "4929d54889e94c29e97374",
    0x4de4f35: "488d0c92498d14c94929ed",
    0x4de4f6c: "4d01fd48c1e303488d149b",
    0x4de4fa9: "4829cb488d0c89498d34c948c1e303488d149b",
    0x4de4fc8: "49896e18488b042448894424084c897c241048c7442418000000004c89642420",
    0x4de4fff: "48895010488b5424204889501848893048894808",
    0x5a04e0a: "0f104424080f104c24180f114b100f1103",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

def span_cutoff(rows, key):
    if not rows:
        return 0
    length = len(rows)
    base = 0
    while length > 1:
        half = length // 2
        mid = base + half
        if rows[mid][0] < key:
            base = mid
        length -= half
    return base + (rows[base][0] < key)


def split_flat(buffer, start, count, key):
    first = buffer[start:start + min(count, len(buffer) - start)]
    second = buffer[:count - len(first)]
    if second and second[0][0] < key:
        split = len(first) + span_cutoff(second, key)
    else:
        split = span_cutoff(first, key)
    if split < len(first):
        copies = (first[split:], second)
    else:
        copies = (second[split - len(first):],)
    return split, [row for part in copies for row in part]


checks = 0
keys = (0, 1, 1 << 63, (1 << 64) - 1)
for capacity in range(1, 8):
    for start in range(capacity):
        for count in range(capacity + 1):
            for ordered in combinations_with_replacement(keys, count):
                rows = list(zip(ordered, range(count)))
                buffer = [None] * capacity
                for index, row in enumerate(rows):
                    buffer[(start + index) % capacity] = row
                for key in (*keys, 2):
                    split, copied = split_flat(buffer, start, count, key)
                    if split != sum(row[0] < key for row in rows) or copied != [row for row in rows if row[0] >= key]:
                        raise ValueError("flat split disagrees with ordered partition")
                    checks += 1

print(f"Verified mixed-root replacement, 43 traversal/exit pairs, and {checks} flat partitions.")
