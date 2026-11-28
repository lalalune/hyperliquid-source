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



header, source = from_archive(
    "zstd-sys-2.0.13+zstd.1.5.6", "38ff0f21cfee8f97d94cef41359e0c89aa6113028ab0291aa8ca0038995a95aa",
    ("zstd/lib/common/zstd_internal.h", "zstd/lib/decompress/zstd_decompress_block.c"))
layout_source, = from_archive(
    "zstd-sys-2.0.13+zstd.1.5.6", "38ff0f21cfee8f97d94cef41359e0c89aa6113028ab0291aa8ca0038995a95aa",
    ("zstd/lib/decompress/zstd_decompress_internal.h",))
assert re.search(r"U16\s+nextState;\s*BYTE\s+nbAdditionalBits;\s*BYTE\s+nbBits;\s*U32\s+baseValue;", layout_source)
for kind, base, caller, prefix in [
    ("LL", 0x9839c0, 0x62a9f70, "488d3d"),
    ("OF", 0x9838a0, 0x62a9ea1, "488d0d"),
    ("ML", 0x983680, 0x62a9f24, "488d05"),
]:
    log = int(re.search(rf"#define\s+{kind}_DEFAULTNORMLOG\s+(\d+)", header)[1])
    expression = re.search(rf"{kind}_defaultDTable\[.*?\]\s*=\s*\{{(.*?)\n\}};", source, re.S)[1]
    expr = re.sub(r"/\*.*?\*/", "", expression, flags=re.S).replace(f"{kind}_DEFAULTNORMLOG", str(log))
    rows = [[int(piece.strip()) for piece in row.split(",")] for row in re.findall(r"\{([^}]+)\}", expr)]
    assert len(rows) == 1 + (1 << log)
    expected = b"".join(struct.pack("<HBBI", *row) for row in rows)
    assert rip_target(caller, bytes.fromhex(prefix)) == base
    actual = read(".rodata", base, len(expected))
    assert actual == expected
    assert actual != bytes([expected[0] ^ 1]) + expected[1:]
    print(f"{kind}: {len(rows)} records / {len(actual)} bytes match at {base:#x}; code reference {caller:#x}")
print("modified sequence table entries rejected")
