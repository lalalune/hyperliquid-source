"""Compare public reference object windows to the authenticated target without execution."""
import hashlib
from pathlib import Path
import re
import struct
import subprocess
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections

if len(sys.argv) != 3:
    raise SystemExit("usage: compare.py REFERENCE_DIRECTORY READELF")
p = Path(sys.argv[1])
target = Path("artifacts/node/115/hl-node").read_bytes()
if hashlib.sha256(target).hexdigest() != "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":
    raise ValueError("wrong target")
tsections = {s["name"]: s for s in sections(target)}

def read_section(data, section, offset, size):
    if not 0 <= offset <= offset + size <= section["size"]:
        raise ValueError("range outside section")
    first = section["offset"] + offset
    return data[first:first+size]

reference_hashes = {
    "sse2": "ff63df2e2215ac9877d6b11cd18e0e6efcd66cf784a222582c4a67e8569106ab",
    "sse41": "e5f952821d973062c4bf572fb72097c662b5da577e58347672b799f25fdb8950",
    "avx512": "3d56af783be0c9fb96d455a7495a5cf1643fd14243bdbe08b2048bd0e1ae81db",
}
for name, ref_va, target_va, size in (
    ("sse2", 0x2a40, 0x633d0c4, 0x1f0),
    ("sse41", 0x25c0, 0x633fac4, 0x1b5),
    ("avx512", 0x3740, 0x6345bc4, 0x175),
):
    obj = p / f"{name}.o"
    ref = obj.read_bytes()
    if hashlib.sha256(ref).hexdigest() != reference_hashes[name]:
        raise ValueError(f"{name}: wrong reference object")
    refs = {s["name"]: s for s in sections(ref)}
    original = read_section(ref, refs[".text"], ref_va, size)
    captured = read_section(target, tsections[".text"], target_va-tsections[".text"]["address"], size)
    if original[-1] != 0xc3 or captured[-1] != 0xc3:
        raise ValueError("missing terminal return")
    if read_section(target, tsections[".text"], target_va-4-tsections[".text"]["address"], 4) != bytes.fromhex("f30f1efa"):
        raise ValueError("missing target ENDBR64 prefix")
    ref_masked, target_masked = bytearray(original), bytearray(captured)
    count = 0
    records = subprocess.check_output([sys.argv[2], "-Wr", str(obj)], text=True)
    for line in records.splitlines():
        match = re.match(r"^([0-9a-f]+)\s+\S+\s+R_X86_64_PC32\s+\S+\s+\.rodata ([+-]) ([0-9a-f]+)$", line.strip())
        if not match:
            continue
        offset, sign, value = match.groups()
        rel_va = int(offset, 16)
        addend = int(sign + value, 16)
        off = rel_va - ref_va
        if not 0 <= off <= size - 4:
            continue
        target_const = target_va + off + 4 + struct.unpack_from("<i", captured, off)[0]
        reference_constant = read_section(ref, refs[".rodata"], addend + 4, 16)
        captured_constant = read_section(
            target, tsections[".rodata"], target_const-tsections[".rodata"]["address"], 16
        )
        if reference_constant != captured_constant:
            raise ValueError("referenced constant mismatch")
        ref_masked[off:off+4] = target_masked[off:off+4] = b"\0" * 4
        count += 1
    if ref_masked != target_masked:
        offsets = [i for i,(a,b) in enumerate(zip(ref_masked,target_masked)) if a != b]
        raise ValueError(f"{name}: mismatches outside relocations: {offsets[:20]}")
    control = bytearray(target_masked)
    control[0] ^= 1
    if control == ref_masked or count != {"sse2": 5, "sse41": 3, "avx512": 1}[name]:
        raise ValueError("comparison control or relocation count mismatch")
    print(f"{name} {target_va:#x} {size} bytes, {count} qualified relocations and {sum(a==b for a,b in zip(original,captured))} raw matching bytes")

def read_target_text(va, size):
    return read_section(target, tsections[".text"], va - tsections[".text"]["address"], size)

for site, slot in [(0x41c52d8, 0x64df488), (0x41c5387, 0x64df510), (0x41c539a, 0x64df518)]:
    call = read_target_text(site, 6)
    if call[:2] != b"\xff\x15" or site + 6 + struct.unpack_from("<i", call, 2)[0] != slot:
        raise ValueError(f"root selector chain changed at {site:#x}")
rela = tsections[".rela.dyn"]
records = list(struct.iter_unpack("<QQq", target[rela["offset"]:rela["offset"] + rela["size"]]))
for slot, addend in ((0x64df488, 0x160bee0), (0x64df510, 0x160b3a0), (0x64df518, 0x160bcd0)):
    if [(info, value) for address, info, value in records if address == slot] != [(8, addend)]:
        raise ValueError("root selector relocation changed")
for address, raw in {
    0x41c5367: "888424fb000000", 0x41c5379: "488dbc2490000000",
    0x41c5392: "488db42490000000",
}.items():
    code = bytes.fromhex(raw)
    if read_target_text(address, len(code)) != code:
        raise ValueError("root selector input projection changed")
print("Verified root initialization selector, byte +0x6b projection and update/finalize consumers.")
