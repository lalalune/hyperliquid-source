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



(source,) = from_archive(
    "lz4-sys-1.9.4", "57d27b317e207b10f69f5e75494119e391a96f48861ae870d1da6edac98ca900",
    ("liblz4/lib/lz4.c",))
for name, target, sites in [
    ("inc32table", 0x986280, [(0x62e563c, "4c8d2d"), (0x62e5966, "4c8d1d")]),
    ("dec64table", 0x986260, [(0x62e5652, "4c8d2d"), (0x62e597b, "4c8d1d")]),
]:
    for instruction, prefix in sites:
        assert rip_target(instruction, bytes.fromhex(prefix)) == target
    values = c_table(source, name)
    assert len(values) == 8
    size = verify_table(".rodata", target, values, "i")
    print(f"{name} {target:#x}: {len(values)} entries / {size} bytes match; two code references")
print("modified table entries rejected")
