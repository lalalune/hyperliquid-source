"""Verify checkpoint admission evidence against the pinned ELF."""
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
if hashlib.sha256(data).hexdigest() != "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":
    raise ValueError("wrong artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x5a64aa0] != [(0x5a64aa0, 0x5a69c05)]:
    raise ValueError("wrong worker FDE")

def read(va, size):
    matches = [s for s in secs if s["type"] != 8 and s["address"] <= va and va + size <= s["address"] + s["size"]]
    if len(matches) != 1:
        raise ValueError("ambiguous file mapping")
    s = matches[0]
    off = s["offset"] + va - s["address"]
    return data[off:off + size]

def relative(va, prefix, target, code=None):
    if code is None:
        code = read(va, len(prefix) + 4)
    if code[:-4] != prefix or va + len(code) + struct.unpack("<i", code[-4:])[0] != target:
        raise ValueError(f"relative operand mismatch at {va:#x}")

checks = [
    (0x5a65194, b"\xff\x15", 0x64e0928),
    (0x5a6519c, b"\x0f\x84", 0x5a652a9),
    (0x5a651c9, b"\x48\x8d\x05", 0x93b168),
    (0x5a65248, b"\xff\x15", 0x64e0b18),
]
for address, prefix, target in checks:
    relative(address, prefix, target)
    altered = bytearray(read(address, len(prefix) + 4))
    altered[-4] ^= 1
    try:
        relative(address, prefix, target, altered)
    except ValueError:
        pass
    else:
        raise RuntimeError("changed displacement accepted")

rela = next(s for s in secs if s["name"] == ".rela.dyn")
raw_rela = data[rela["offset"]:rela["offset"] + rela["size"]]
for slot, target in [(0x64e0928, 0x1500a60), (0x64e0b18, 0x150b310)]:
    if [(info, addend) for dst, info, addend in struct.iter_unpack("<QQq", raw_rela) if dst == slot] != [(8, target)]:
        raise ValueError("relocation mismatch")
literal = read(0x93b168, 0x69)
if not literal.startswith(b"receiving evm kvs for checkpoint that already"):
    raise ValueError("literal mismatch")
for address, raw in {
    0x5a6519a: "84c0", 0x5a651d8: "48c78424b802000069000000",
    0x5a652c4: "49898568050000", 0x5a652cb: "4d89bd70050000",
    0x5a652d2: "4d89a578050000", 0x5a652e5: "41c685e808000000",
}.items():
    code = bytes.fromhex(raw)
    if read(address, len(code)) != code:
        raise ValueError(f"decision witness mismatch at {address:#x}")
print("Verified worker FDE, two relocations, six decision witnesses and four corrupted displacements.")
print(literal.hex())

relative(0x1500a7d, b"\xff\x15", 0x64e0930)
relative(0x1500af2, b"\xff\x15", 0x64e0930)
if [(info, addend) for dst, info, addend in struct.iter_unpack("<QQq", raw_rela) if dst == 0x64e0930] != [(8, 0x5c9c810)]:
    raise ValueError("contextual metadata relocation mismatch")
for address, encoded in {
    0x1500ad8: "31c0", 0x1500b1a: "b800f00000",
    0x1500b1f: "23442448", 0x1500b23: "3d00400000",
    0x1500b28: "0f94c0",
}.items():
    code = bytes.fromhex(encoded)
    if read(address, len(code)) != code:
        raise ValueError("contextual directory predicate mismatch")
print("Verified contextual metadata target and selected normal directory test.")

for begin, end in [(0x2ad7140, 0x2adce3a), (0x2cad9b0, 0x2cb1dff)]:
    if [(f["start"], f["end"]) for f in frames if f["start"] == begin] != [(begin, end)]:
        raise ValueError(f"alternate worker FDE mismatch at {begin:#x}")
for address, prefix, target in [
    (0x2ad8fde, b"\xff\x15", 0x64e0928),
    (0x2ad8fe6, b"\x0f\x84", 0x2ad90ee),
    (0x2ad9013, b"\x48\x8d\x05", 0x605c5e),
    (0x2cadc20, b"\xff\x15", 0x64e0928),
    (0x2cadc28, b"\x0f\x84", 0x2cadd1d),
    (0x2cadc55, b"\x48\x8d\x05", 0x60f043),
]:
    relative(address, prefix, target)
for address in (0x605c5e, 0x60f043):
    phrase = b"receiving evm kvs for checkpoint that already exists"
    if read(address, len(phrase)) != phrase:
        raise ValueError("alternate diagnostic prefix mismatch")
for address, raw in {
    0x2ad9101: "488983c8050000", 0x2ad9108: "4c89b3d0050000",
    0x2ad910f: "4c89abd8050000", 0x2ad9122: "c6834809000000",
    0x2cadd3a: "4989842460030000", 0x2cadd42: "4d89bc2468030000",
    0x2cadd4a: "4d89ac2470030000",
}.items():
    code = bytes.fromhex(raw)
    if read(address, len(code)) != code:
        raise ValueError(f"alternate record mismatch at {address:#x}")
print("Verified two alternate worker FDEs, six edges and seven continuation stores.")
