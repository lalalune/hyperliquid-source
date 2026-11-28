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




def initializer(source, variable):
    return re.search(rf"\b{variable}\[[^\]]+\]\s*=\s*\{{(.*?)\}};", source, re.S)[1]

(source,) = from_archive(
    "libz-sys-1.1.22", "8b70e7a7df205e92a1a4cd9aaae7898dac0aa555503cc0a649494d0d60e7651d",
    ("src/zlib/trees.h",))
for table, fmt, address, caller, prefix in [
    ("_dist_code", "B", 0x987780, 0x6301d7b, "488d05"),
    ("_length_code", "B", 0x987680, 0x6301d59, "488d15"),
    ("base_length", "I", 0x987600, 0x630a776, "488d3d"),
    ("base_dist", "I", 0x987580, 0x630a893, "488d0d"),
    ("static_ltree", "H", 0x987a00, 0x630c1b1, "488d35"),
    ("static_dtree", "H", 0x987980, 0x630c1bb, "488d15"),
]:
    values = [int(value) for value in re.findall(r"\d+", initializer(source, table))]
    assert rip_target(caller, bytes.fromhex(prefix)) == address
    size = verify_table(".rodata", address, values, fmt)
    print(f"{table} {address:#x}: {size} bytes match; code reference {caller:#x}")
print("modified encoder table entries rejected")
