"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
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
        return [archive.extractfile(f"{name}/{part}").read().decode() for part in files]


def rip_target(address, prefix):
    instruction = read(".text", address, len(prefix) + 4)
    assert instruction.startswith(prefix)
    return address + len(instruction) + struct.unpack_from("<i", instruction, len(prefix))[0]


print("node #115", TARGET_SHA)


def c_table(source, variable):
    count, body = re.search(rf"\b{variable}\[(\d+)\]\s*=\s*\{{(.*?)\}}", source, re.S).groups()
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    values = [int(value) for value in re.findall(r"-?\d+", body)]
    assert len(values) == int(count)
    return values


def verify_table(section, address, source_values, fmt):
    want = struct.pack(f"<{len(source_values)}{fmt}", *source_values)
    actual = read(section, address, len(want))
    assert actual == want
    modified = bytes([actual[0] ^ 1]) + actual[1:]
    assert modified != want
    return len(actual)



(older,) = from_archive(
    "libz-sys-1.1.22", "8b70e7a7df205e92a1a4cd9aaae7898dac0aa555503cc0a649494d0d60e7651d",
    ("src/zlib/inftrees.c",))
(source,) = from_archive(
    "libz-sys-1.1.31", "ff20308ecabd635a2dc1dd5834a86c462cca20efba1d5d3ddab1f8aea3455cb2",
    ("src/zlib/inftrees.c",))
refs = [
    ("lbase", 0x987540, 0x6309e70), ("lext", 0x987500, 0x6309e5c),
    ("dbase", 0x9874c0, 0x63095f5), ("dext", 0x987480, 0x6309609),
]
for name, target, instruction in refs:
    assert rip_target(instruction, bytes.fromhex("488d05")) == target
    values = c_table(source, name)
    actual = struct.unpack(f"<{len(values)}H", read(".rodata", target, 2 * len(values)))
    assert actual == tuple(c_table(older, name))
    mismatches = [(idx, observed, expected)
                  for idx, (observed, expected) in enumerate(zip(actual, values)) if observed != expected]
    if name == "lext":
        assert mismatches == [(29, 203, 199), (30, 77, 75)]
    else:
        assert not mismatches
    print(f"{name} {target:#x}: {len(values)} entries, differences (index, linked, source) {mismatches}")
print("three complete tables match; only two length-extra array entries differ")
print("all four tables match libz-sys 1.1.22")
