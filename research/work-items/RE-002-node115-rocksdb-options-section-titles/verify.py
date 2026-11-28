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



def get_source(path):
    return from_archive("librocksdb-sys-0.11.0+8.1.1",
        "d3386f101bcb4bd252d8e9d2fb41ec3b0862a15a62b478c355b2982efa469e3e",
        ["rocksdb/" + path])[0]

def literals(source, name):
    body = re.search(rf"\b{name}\[[^]]*\]\s*=\s*\{{(.*?)\}};", source, re.S)[1]
    return [label.encode() + b"\0" for label in re.findall(r'"([^"\n]*)"', body)]
FILE, NAME, COUNT = 'options/options_parser.h', 'opt_section_titles', 5

labels = literals(get_source(FILE), NAME)
assert len(labels) == COUNT
loads = (0x5d84577, 0x5d84586, 0x5d84596, 0x5d845a9, 0x5d845bc)
calls = (0x5d84581, 0x5d84591, 0x5d845a4, 0x5d845b7, 0x5d845ca)
base = rip_target(0x5d84570, bytes.fromhex("488d2d"))
assert base == 0x65002c0
assert read(".text", 0x5d8457e, 3) == bytes.fromhex("4889ef")
assert read(".text", 0x5d8458d, 4) == bytes.fromhex("488d7d20")
outputs = [base, base + 0x20] + [
    rip_target(site, bytes.fromhex("488d3d"))
    for site in (0x5d8459d, 0x5d845b0, 0x5d845c3)
]
for index, (expected, load, call, out) in enumerate(zip(labels, loads, calls, outputs)):
    text = rip_target(load, bytes.fromhex("488d35"))
    actual = read(".rodata", text, len(expected))
    assert actual == expected
    assert out == base + 0x20 * index
    assert rip_target(call, b"\xe8") == 0x5d4ab80
    assert bytes([actual[0] ^ 1]) + actual[1:] != expected
    print(index, hex(text), hex(out), repr(expected[:-1]))
print("five title literals and constructor destinations verified")
