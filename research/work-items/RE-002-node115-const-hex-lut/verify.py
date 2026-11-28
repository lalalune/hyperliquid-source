"""Verify full data tables in the pinned node #115 ELF against released Rust crate sources."""
from hashlib import sha256
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CACHE, TOOLS = map(Path, sys.argv[1:3])
TARGET = Path("artifacts/node/115/hl-node")
sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import sections

data = TARGET.read_bytes()
assert sha256(data).hexdigest() == TARGET_SHA
layout = {section["name"]: section for section in sections(data)}


def read(section, address, size):
    row = layout[section]
    delta = address - row["address"]
    assert 0 <= delta <= row["size"] - size
    start = row["offset"] + delta
    return data[start:start + size]


def from_archive(name, digest, files):
    path = CACHE / f"{name}.crate"
    assert sha256(path.read_bytes()).hexdigest() == digest
    print(name, digest)
    with tarfile.open(path) as archive:
        return [archive.extractfile(f"{name}/src/{part}").read().decode() for part in files]


def rip_target(address, prefix):
    instruction = read(".text", address, len(prefix) + 4)
    assert instruction.startswith(prefix)
    return address + len(instruction) + struct.unpack_from("<i", instruction, len(prefix))[0]


print("node #115", TARGET_SHA)

lib, x86 = from_archive(
    "const-hex-1.14.0", "4b0485bab839b018a8f1723fc5391819fea5f8f0f32288ef8a735fd096b6160c",
    ("lib.rs", "arch/x86.rs"))
assert "pub const NIL: u8 = u8::MAX;" in lib
generator = lib.split("const fn make_decode_lut()", 1)[1].split("lut\n}", 1)[0]
ranges = re.findall(r"b'(.)'\.\.=b'(.)' => i - b'(.)'(?: \+ (\d+))?,", generator)
assert len(ranges) == 3 and "_ => NIL" in generator
lut = bytearray([255] * 256)
for first, last, subtract, add in ranges:
    for value in range(ord(first), ord(last) + 1):
        lut[value] = value - ord(subtract) + int(add or 0)
target_table = 0x46d50c
for address, prefix in [(0x167ad04, "488d35"), (0x167af8c, "488d35"), (0x167aaae, "4c8d35")]:
    assert rip_target(address, bytes.fromhex(prefix)) == target_table
    print(f"lookup reference {address:#x} -> {target_table:#x}")
assert read(".rodata", target_table, 256) == lut
print("all 256 decode entries equal; 22 hexadecimal input byte values",
      sum(value != 255 for value in lut))
assert sum(value != 255 for value in lut) == 22
for address, prefix, value in [(0x167ac11, "c4e27d7905", 255), (0x167ac1a, "c4e27d790d", 9),
                               (0x167ac23, "c4e27d7915", 15)]:
    constant = rip_target(address, bytes.fromhex(prefix))
    assert struct.unpack("<H", read(".rodata", constant, 2))[0] == value
    print(f"AVX2 broadcast {address:#x} -> {constant:#x} value={value}")
assert "_mm256_set1_epi16(9)" in x86 and "_mm256_set1_epi16(0xf)" in x86
lut[ord("a")] ^= 1
assert read(".rodata", target_table, 256) != lut
print("modified table entry rejected")
