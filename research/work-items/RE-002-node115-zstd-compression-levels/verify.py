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

levels, types = from_archive(
    "zstd-sys-2.0.13+zstd.1.5.6", "38ff0f21cfee8f97d94cef41359e0c89aa6113028ab0291aa8ca0038995a95aa",
    ("zstd/lib/compress/clevels.h", "zstd/lib/zstd.h"))
strategies = {name: int(value) for name, value in re.findall(
    r"\b(ZSTD_(?:fast|dfast|greedy|lazy|lazy2|btlazy2|btopt|btultra|btultra2))\s*=\s*(\d+)", types)}
assert len(strategies) == 9
rows = re.findall(
    r"\{\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(ZSTD_\w+)\s*\}",
    levels)
assert len(rows) == 92
address = 0x9810c0
refs = ((0x621008b, "4c8d1d"), (0x6210157, "4c8d2d"))
for caller, prefix in refs:
    assert rip_target(caller, bytes.fromhex(prefix)) == address
    print(f"parameter selector reference {caller:#x} -> {address:#x}")
matrix = []
for row in rows:
    matrix.extend(int(value) for value in row[:6])
    matrix.append(strategies[row[6]])
assert verify_table(".rodata", address, matrix, "I") == 2576
print("92 rows in four groups, 2576 bytes match; modified table entry rejected")
