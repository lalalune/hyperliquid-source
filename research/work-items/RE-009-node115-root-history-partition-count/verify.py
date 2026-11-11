"""Verify tree partition counting in the pinned #115 ELF."""
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4ca3a30] != [(0x4ca3a30, 0x4ca3b69)]:
    raise ValueError("wrong count helper extent")

for site in (0x4de4ad7, 0x4de5b42):
    opcode, displacement = struct.unpack("<Bi", read(site, 5))
    if opcode != 0xe8 or site + 5 + displacement != 0x4ca3a30:
        raise ValueError(f"wrong count call at {site:#x}")

for address, raw in {
    0x4ca3a33: "488b7e08",
    0x4ca3a37: "488b4a08",
    0x4ca3a3b: "4839cf",
    0x4ca3a3e: "0f838b000000",
    0x4ca3a47: "0fb78ac2010000",
    0x4ca3a51: "0f8404010000",
    0x4ca3a66: "4a8b94cac8010000",
    0x4ca3a6e: "440fb78ac2010000",
    0x4ca3a76: "4c01c9",
    0x4ca3a79: "41b900000000",
    0x4ca3a82: "75dc",
    0x4ca3a91: "4839d6",
    0x4ca3aa0: "498b9060010000",
    0x4ca3aaa: "0f84ab000000",
    0x4ca3ab3: "410fb7b0c0010000",
    0x4ca3abe: "663bb2c2010000",
    0x4ca3ac5: "73d9",
    0x4ca3ac7: "48ffc6",
    0x4ca3ad2: "0fb796c2010000",
    0x4ca3adc: "0f8483000000",
    0x4ca3af6: "4a8bb4cec8010000",
    0x4ca3afe: "440fb78ec2010000",
    0x4ca3b06: "4c01ca",
    0x4ca3b09: "41b900000000",
    0x4ca3b12: "75dc",
    0x4ca3b21: "4839f7",
    0x4ca3b30: "498bb060010000",
    0x4ca3b3a: "7429",
    0x4ca3b3f: "410fb7b8c0010000",
    0x4ca3b4a: "663bbec2010000",
    0x4ca3b51: "73dd",
    0x4ca3b53: "48ffc7",
    0x4ca3b5b: "4829c8",
    0x4ca3b5e: "4889c2",
    0x4ca3b61: "4889c8",
    0x4ca3b65: "4829d0",
    0x4de4ad1: "4c89ef",
    0x4de4ad4: "4889ee",
    0x4de4adc: "4989d5",
    0x4de4adf: "49894618",
    0x4de4afb: "4c896c2420",
    0x4de5b3c: "4c89ef",
    0x4de5b3f: "4889ee",
    0x4de5b51: "4989d5",
    0x4de5b54: "49894618",
    0x4de5b70: "4c896c2420",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")


class Node:
    def __init__(self, keys, children):
        self.keys = keys
        self.children = children
        self.parent = None
        self.slot = 0
        for index, child in enumerate(children):
            child.parent = self
            child.slot = index


def make_tree(height, seed):
    keys = seed % 4
    children = [make_tree(height - 1, 3 * seed + i + 1) for i in range(keys + 1)] if height else []
    return Node(keys, children)


def oracle(node):
    return node.keys + sum(oracle(child) for child in node.children)


def walk(root, height):
    count = root.keys
    current = root
    depth = height
    index = 0
    while depth:
        while depth:
            current = current.children[index]
            count += current.keys
            index = 0
            depth -= 1
        depth = 1
        index = current.slot
        current = current.parent
        while current is not None and index >= current.keys:
            index = current.slot
            current = current.parent
            depth += 1
        if current is None:
            break
        index += 1
    return count


trees = [(make_tree(height, seed), height) for height in range(5) for seed in range(12)]
for left, lh in trees:
    for right, rh in trees:
        lc, rc = oracle(left), oracle(right)
        total = lc + rc
        if lh < rh:
            counted = walk(left, lh)
            result = counted, total - counted
        else:
            counted = walk(right, rh)
            result = total - counted, counted
        if result != (lc, rc):
            raise ValueError("partition count disagrees with recursive oracle")

print("Verified two caller projections and 3,600 synthetic partition-count cases.")
