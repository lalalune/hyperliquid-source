"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import re
import struct
import sys
import tarfile

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CACHE = Path(sys.argv[1])
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


def check(name, address, fmt, values, refs):
    expected = struct.pack(fmt, *values)
    actual = read(".rodata", address, len(expected))
    assert actual == expected
    for location, prefix in refs:
        assert rip_target(location, bytes.fromhex(prefix)) == address
    assert (bytes([actual[0] ^ 1]) + actual[1:]) != expected
    print(name, hex(address), len(values), len(actual), sha256(actual).hexdigest())
    for location, _ in refs:
        print("linked reference", hex(location), "->", hex(address))
    print("one-byte mutation rejected")

source, header = from_archive("lz4-sys-1.9.4",
    "57d27b317e207b10f69f5e75494119e391a96f48861ae870d1da6edac98ca900", ["liblz4/lib/lz4hc.c", "liblz4/lib/lz4hc.h"])
names = re.search(r"typedef enum \{\s*(\w+),\s*(\w+)\s*\} lz4hc_strat_e;", source).groups()
shift, = re.search(r"#define LZ4_OPT_NUM\s+\(1<<(\d+)\)", source).groups()
last, = re.search(r"#define LZ4HC_CLEVEL_MAX\s+(\d+)", header).groups()
body = re.search(r"clTable\[LZ4HC_CLEVEL_MAX\+1\] = \{(.*?)\n    \};", source, re.S)[1]
clean = re.sub(r"/\*.*?\*/", "", body)
rows = re.findall(r"\{\s*(\w+),\s*(\d+),\s*(\w+)\s*\}", clean)
assert len(rows) == int(last) + 1 == 13
values = []
for strategy, searches, length in rows:
    values.extend((names.index(strategy), int(searches),
                   1 << int(shift) if length == "LZ4_OPT_NUM" else int(length)))
check("LZ4HC strategy, searches, target length", 0x9862a0, "<39I",
      values, [(0x62f3fbc, "488d0d"), (0x62f9e2d, "488d0d")])
