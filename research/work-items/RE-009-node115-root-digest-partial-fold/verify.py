"""Verify the partial-chunk finalization route in the pinned #115 ELF."""
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x160ab60] != [(0x160ab60, 0x160b0d9)]:
    raise ValueError("preparer FDE mismatch")

def edge(site, prefix, target, code=None):
    if code is None:
        code = read(site, len(prefix) + 4)
    if code[:-4] != prefix or site + len(code) + struct.unpack("<i", code[-4:])[0] != target:
        raise ValueError(f"edge mismatch at {site:#x}")

for site, prefix, target in (
    (0x160ab7d, b"\x0f\x84", 0x160aca1),
    (0x160ab99, b"\x0f\x84", 0x160ad04),
    (0x160ac6a, b"\x48\x8d\x15", 0x46aae8),
    (0x160aef0, b"\x0f\x84", 0x160b067),
    (0x160af1b, b"\x4c\x8d\x25", 0x46aafc),
    (0x160b061, b"\x0f\x85", 0x160af57),
):
    edge(site, prefix, target)

for table, paths in (
    (0x46aae8, (0x160ae57, 0x160ae73, 0x160ac82, 0x160ac82, 0x160ae3b)),
    (0x46aafc, (0x160afa5, 0x160afc4, 0x160af86, 0x160af86, 0x160afe3)),
):
    if tuple(table + entry for entry in struct.unpack("<5i", read(table, 20))) != paths:
        raise ValueError(f"dispatch table mismatch at {table:#x}")

for address, raw in {
    0x160ab9f: "410fb6566a84c9400f94c74008d74080cf02",
    0x160ac05: "48894c24708844247840887c2479",
    0x160ac27: "4c8d7dff4939f7",
    0x160ac34: "498d9694000000488d5c24504d8d6e704d89fc49c1e4054901d4",
    0x160aca1: "41807e69000f94c0410a466a0c02",
    0x160ae9d: "410f101424410f105c24100f295424100f295c24200f294424300f294c2440",
    0x160aecd: "48c744247000000000c6442478400fb644240e88442479",
    0x160aef6: "48c1e5054901ee4983c65449ffcf",
    0x160af57: "4983c6e049ffcf",
    0x160b010: "410f1016410f105e100f295424100f295c24200f294424300f294c2440",
    0x160b05e: "4d85ff",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")


def modeled_left_offsets(count):
    last = count - 1
    offsets = [0x94 + 32 * last]
    if last:
        offset = 32 * count + 0x54
        last -= 1
        while True:
            offsets.append(offset)
            if last == 0:
                break
            offset -= 32
            last -= 1
    return offsets


for count in range(1, 65):
    expected = [0x94 + 32 * index for index in reversed(range(count))]
    if modeled_left_offsets(count) != expected:
        raise ValueError(f"stack projection mismatch for count {count}")

print("Verified partial finalization dispatch, parent layout and 64 symbolic stack walks.")
