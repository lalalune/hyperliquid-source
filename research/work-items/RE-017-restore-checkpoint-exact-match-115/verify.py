"""Verify the selected checkpoint handoff in the pinned #115 ELF."""
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x25d3f20] != [(0x25d3f20, 0x25d4cab)]:
    raise ValueError("wrong checkpoint intermediate FDE")


def signed_edge(addr, prefix, target):
    raw = read(addr, len(prefix) + (1 if len(prefix) == 1 and 0x70 <= prefix[0] <= 0x7f else 4))
    displacement = raw[len(prefix):]
    if not raw.startswith(prefix) or addr + len(raw) + int.from_bytes(displacement, "little", signed=True) != target:
        raise ValueError(f"unexpected edge at {addr:#x}")


signed_edge(0x25d4983, b"\x0f\x84", 0x25d4a7e)
signed_edge(0x25d49c2, b"\x0f\x84", 0x25d4a72)
signed_edge(0x25d49d3, b"\x74", 0x25d49a0)
signed_edge(0x25d49ad, b"\x0f\x85", 0x25d4a8d)
signed_edge(0x25d4af6, b"\xff\x15", 0x64df4a0)
signed_edge(0x2cc15de, b"\xe8", 0x25d3f20)
signed_edge(0x2cc15f8, b"\x0f\x85", 0x2cc195d)

for address, hex_code in {
    0x25d3f31: "48899424e8000000",
    0x25d4962: "488bac24e8000000",
    0x25d4976: "4989de49c1e6054d01fe4885db",
    0x25d49a0: "48b800000000000000804839c6",
    0x25d49b3: "488d4be0488d43204883c1204c39f1",
    0x25d49c8: "4889c3488b70e0483968f8",
    0x25d49da: "488b7be831d241ffd5",
    0x25d4a72: "48be0000000000000080",
    0x25d4a7e: "48be0000000000000080",
    0x25d4a8d: "488b43f8488b4c2478488941180f1043e80f114108",
    0x25d4aa2: "488b4424784889304929de",
    0x25d4ac0: "4883c32049ffce",
    0x25d4ac9: "488b73f84885f674ee488b3b31d241ffd5",
    0x25d4aea: "49c1e4054c89ff4c89e631d2",
    0x2cc15e3: "488bac244001000048b800000000000000804839c5",
}.items():
    expected = bytes.fromhex(hex_code)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

sentinel = 1 << 63


def scan(rows, requested):
    for index, row in enumerate(rows):
        first, _, _, key = row
        if key == requested and first != sentinel:
            return index, row
    return None, (sentinel,)


cases = (
    ([], 8, (None, (sentinel,))),
    ([(1, 101, 1, 7)], 8, (None, (sentinel,))),
    ([(1, 101, 1, 8), (1, 102, 1, 8)], 8, (0, (1, 101, 1, 8))),
    ([(sentinel, 0, 0, 8), (1, 102, 1, 8)], 8, (1, (1, 102, 1, 8))),
    ([(0, 1, 0, 8)], 8, (0, (0, 1, 0, 8))),
    ([(1, 101, 1, (1 << 64) - 1)], (1 << 64) - 1, (0, (1, 101, 1, (1 << 64) - 1))),
)
for rows, requested, expected in cases:
    if scan(rows, requested) != expected:
        raise ValueError("checkpoint selection model disagrees")

print("Verified exact-match checkpoint selection and six synthetic result cases.")
