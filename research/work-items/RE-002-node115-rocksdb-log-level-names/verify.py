"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import re
import subprocess
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


TOOLS = Path(sys.argv[2])
rows = subprocess.check_output([TOOLS / "readelf", "-rW", TARGET], text=True)
relative = {
    int(slot, 16): int(addr, 16)
    for slot, addr in re.findall(
        r"^([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)$", rows, re.M
    )
}


def get_source(path):
    return from_archive("librocksdb-sys-0.11.0+8.1.1",
        "d3386f101bcb4bd252d8e9d2fb41ec3b0862a15a62b478c355b2982efa469e3e",
        ["rocksdb/" + path])[0]

def literals(source, name):
    body = re.search(rf"\b{name}\[[^]]*\]\s*=\s*\{{(.*?)\}};", source, re.S)[1]
    return [label.encode() + b"\0" for label in re.findall(r'"([^"\n]*)"', body)]
FILE, NAME, COUNT = 'env/env.cc', 'kInfoLogLevelNames', 5
SITE, OPCODE, TABLE = 0x5fcd344, '488d05', 0x64cdf60

labels = literals(get_source(FILE), NAME)
assert len(labels) == COUNT
assert rip_target(SITE, bytes.fromhex(OPCODE)) == TABLE
read(".data.rel.ro", TABLE, len(labels) * 8)
for index, expected in enumerate(labels):
    slot = TABLE + index * 8
    target = relative[slot]
    actual = read(".rodata", target, len(expected))
    assert actual == expected
    assert bytes([actual[0] ^ 1]) + actual[1:] != expected
    print(index, hex(slot), hex(target), repr(actual[:-1]))
print("all source labels and the linked table base verified")
