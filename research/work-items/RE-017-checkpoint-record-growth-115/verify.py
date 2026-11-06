"""Verify the checkpoint record growth path in the pinned #115 ELF."""
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

extents = {0x14cab60: 0x14cac49, 0x14cac50: 0x14cacde}
if sorted((frame["start"], frame["end"]) for frame in frames if frame["start"] in extents) != sorted(extents.items()):
    raise ValueError("wrong growth extents")

for address, prefix, target in (
    (0x153fb25, "e8", 0x14cac50), (0x1540c51, "e8", 0x14cac50),
    (0x14cacaf, "e8", 0x14cab60), (0x14cac61, "ff15", 0x64df498),
    (0x14cacd8, "ff15", 0x64df498), (0x14cabcd, "ff15", 0x64df580),
    (0x14cabdb, "ff15", 0x64df588), (0x14cac06, "ff15", 0x64df590),
    (0x14cac11, "ff15", 0x64df480),
):
    opcode = bytes.fromhex(prefix)
    raw = read(address, len(opcode) + 4)
    displacement = struct.unpack_from("<i", raw, len(opcode))[0]
    if not raw.startswith(opcode) or address + len(raw) + displacement != target:
        raise ValueError(f"wrong transfer at {address:#x}")

slots = {0x64df480: 0x6355830, 0x64df498: 0x141e264, 0x64df580: 0x635a790,
         0x64df588: 0x635a7a0, 0x64df590: 0x63577f0}
rela = next(section for section in secs if section["name"] == ".rela.dyn")
records = struct.iter_unpack("<QQq", read(rela["address"], rela["size"]))
if sorted(row for row in records if row[0] in slots) != [
    (slot, 8, target) for slot, target in sorted(slots.items())
]:
    raise ValueError("wrong helper relocations")

for address, hex_code in {
    0x153fb10: "ba01000000b90800000041b820000000",
    0x1540c3c: "ba01000000b90800000041b818000000",
    0x14cab74: "48f7e14989c60f90c048b900000000000000804c29f94939ce0f97c108c1",
    0x14cab92: "41bc01000000740db8080000004531f6",
    0x14cabac: "4983ff110f92c04d39f70f96c184c8",
    0x14cabe8: "4983ff110f92c04d39f70f96c184c8",
    0x14cac17: "4885c0750e4c897b08b810000000eb0f",
    0x14cac27: "4c89f848894308b8100000004531e4",
    0x14cac36: "4c8934034c8923",
    0x14cac67: "4801f272f3",
    0x14cac6f: "488b37488d04364839c2480f47c2",
    0x14cac7f: "4981f9010400000f92c14983f901488d4c4901bb08000000480f45d94839d8480f47d8",
    0x14cacb4: "833c24017414488b4424084989460849891e",
}.items():
    expected = bytes.fromhex(hex_code)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

word = 1 << 64
limit = (word >> 1) - 8
for stride in (24, 32):
    maximum_count = limit // stride
    for count in (0, 1, 2, 3, 4, maximum_count // 2, maximum_count // 2 + 1, maximum_count, word - 1):
        needed = count + 1
        if needed >= word:
            actual = None
        else:
            chosen = max(needed, (2 * count) % word, 4)
            size = chosen * stride
            actual = chosen if size < word and size <= limit else None
        expected = max(count + 1, 2 * count, 4) if count < word // 2 else None
        if expected is not None and expected > maximum_count:
            expected = None
        if actual != expected:
            raise ValueError(f"growth model disagrees for stride {stride}, count {count}")
print("Verified two checkpoint growth callers, allocator routing, and 18 capacity cases.")
