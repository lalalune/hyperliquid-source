"""Verify the selected checkpoint intermediate in the pinned #115 ELF."""
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x25d3f20] != [(0x25d3f20, 0x25d4cab)]:
    raise ValueError("wrong checkpoint intermediate FDE")


def signed_edge(addr, prefix, target):
    raw = read(addr, len(prefix) + (1 if len(prefix) == 1 and 0x70 <= prefix[0] <= 0x7f else 4))
    displacement = raw[len(prefix):]
    if not raw.startswith(prefix) or addr + len(raw) + int.from_bytes(displacement, "little", signed=True) != target:
        raise ValueError(f"unexpected edge at {addr:#x}")


signed_edge(0x2cc15de, b"\xe8", 0x25d3f20)
signed_edge(0x25d3f62, b"\x48\x8d\x35", 0x434739)
signed_edge(0x25d3f95, b"\xff\x15", 0x64e0928)
signed_edge(0x25d3f9d, b"\x74", 0x25d400e)
signed_edge(0x25d401e, b"\x48\x8d\x05", 0x433a07)
signed_edge(0x25d406a, b"\xe8", 0x2a02000)
signed_edge(0x25d4097, b"\x0f\x85", 0x25d4b44)
signed_edge(0x25d410d, b"\xff\x15", 0x64e1208)
signed_edge(0x25d4137, b"\x74", 0x25d41a5)
signed_edge(0x25d4193, b"\x75", 0x25d4150)
signed_edge(0x25d4281, b"\xe8", 0x25fa9c0)
signed_edge(0x25d42cf, b"\x73", 0x25d431e)
signed_edge(0x25d42fa, b"\x0f\x87", 0x25d4230)
signed_edge(0x25d433f, b"\x0f\x80", 0x25d4230)
signed_edge(0x25d435b, b"\x0f\x87", 0x25d4230)
signed_edge(0x25d43c6, b"\xff\x15", 0x64e0950)
signed_edge(0x25d4416, b"\xe8", 0x1696b90)
signed_edge(0x25d4428, b"\xff\x15", 0x64e0950)
signed_edge(0x25d4453, b"\x74", 0x25d44be)

rela = next(section for section in secs if section["name"] == ".rela.dyn")
targets = {0x64e0928: 0x1500a60, 0x64e0950: 0x1500d20, 0x64e1208: 0x15623e0}
relocations = list(struct.iter_unpack("<QQq", read(rela["address"], rela["size"])))
if sorted(row for row in relocations if row[0] in targets) != [
    (slot, 8, target) for slot, target in sorted(targets.items())
]:
    raise ValueError("wrong helper relocations")

for address, expected in {
    0x434739: b"\xc0\x0b/checkpoint\x00",
    0x433a07: b"\x24checkpoint outer dir does not exist\x20\xc0\x00",
}.items():
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong format bytes at {address:#x}")

for address, hex_code in {
    0x25d3f7f: "4c8bac24d8000000488bac24e00000004c89ef4889ee",
    0x25d3f9b: "84c0",
    0x25d409d: "48b80000000000000080498906498b074c89ffff10",
    0x25d4113: "488b8424a0000000",
    0x25d4129: "488b9c24980000004889c148d1e9",
    0x25d4139: "48c1e103488d0c49488d0440488d04c5e8ffffff31d2",
    0x25d4150: "488b3413488b3c0348893c1348893403",
    0x25d4160: "488b741308488b7c030848897c13084889740308",
    0x25d4174: "488b741310488b7c031048897c13104889740310",
    0x25d4188: "4883c2184883c0e84839d1",
    0x25d4211: "4c896c0818",
    0x25d4286: "4885c074a54885d274a04883fa01751a",
    0x25d4296: "0fb63083fe2b749283fe2d748deb0e",
    0x25d42b3: "31c94080fe2b0f94c14889ce48f7de4889d74829cf4801c14883ff11",
    0x25d42f0: "0fb6340183c6d083fe09",
    0x25d4300: "4a8d3cad000000004c01ef89f64c8d2c7e",
    0x25d4337: "ba0a00000048f7e2",
    0x25d434b: "0fb63c3183c7d04901fd0f92c083ff09",
    0x25d4361: "48ffc684c074c1e9c3feffff",
    0x25d4411: "be02000000",
    0x25d44eb: "4a891cf049ffc64c89742410",
    0x25d4230: "4883c3184839eb",
}.items():
    expected = bytes.fromhex(hex_code)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

for count in range(257):
    stride = 24
    rows = [(i, i + 1, i + 2) for i in range(count)]
    swapped = rows.copy()
    for left in range(0, stride * (count >> 1), stride):
        right = stride * count - stride - left
        i, j = left // stride, right // stride
        swapped[i], swapped[j] = swapped[j], swapped[i]
    if swapped != rows[::-1]:
        raise ValueError(f"reversal model failed for {count} rows")

def parse_component(raw):
    if not raw or raw in (b"+", b"-"):
        return None
    digits = raw[1:] if raw.startswith(b"+") else raw
    checked = len(digits) >= 17
    value = 0
    for byte in digits:
        product = 10 * value
        digit = byte - 0x30
        if not 0 <= digit <= 9 or (checked and product + digit >= 1 << 64):
            return None
        value = product + digit
    return value


cases = {
    b"": None, b"+": None, b"-": None, b"0": 0, b"+01": 1,
    b"-0": None, b"1_2": None, b" 12": None, b"12\x00": None,
    b"9999999999999999": 9999999999999999,
    b"10000000000000000": 10000000000000000,
    b"18446744073709551615": (1 << 64) - 1,
    b"+18446744073709551615": (1 << 64) - 1,
    b"18446744073709551616": None,
    b"184467440737095516150": None,
    b"0" * 64 + b"1": 1,
}
for raw, expected in cases.items():
    if parse_component(raw) != expected:
        raise ValueError(f"component model failed for {raw!r}")

print("Verified checkpoint edges, relocations, literals, instruction windows, "
      "257 reversal cases and 16 numeric component cases.")
