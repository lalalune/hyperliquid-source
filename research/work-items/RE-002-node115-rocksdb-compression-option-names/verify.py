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



source, header = from_archive("librocksdb-sys-0.11.0+8.1.1",
    "d3386f101bcb4bd252d8e9d2fb41ec3b0862a15a62b478c355b2982efa469e3e",
    ["rocksdb/options/options_helper.cc", "rocksdb/include/rocksdb/compression_type.h"])
body = re.search(r"compression_type_string_map = \{(.*?)\};", source, re.S)[1]
pairs = re.findall(r'\{"([^"]+)",\s*(\w+)\}', body)
codes = {name: int(value, 16) for name, value in re.findall(r"(k\w+) = (0x[0-9a-f]+),", header)}
loads = (0x60c7d4d, 0x60c7d63, 0x60c7d7d, 0x60c7d97, 0x60c7db1,
         0x60c7dcb, 0x60c7de5, 0x60c7dff, 0x60c7e19, 0x60c7e30)
calls = (0x60c7d57, 0x60c7d71, 0x60c7d8b, 0x60c7da5, 0x60c7dbf,
         0x60c7dd9, 0x60c7df3, 0x60c7e0d, 0x60c7e27, 0x60c7e3e)
stores = (0x60c7d6a, 0x60c7d84, 0x60c7d9e, 0x60c7db8, 0x60c7dd2,
          0x60c7dec, 0x60c7e06, 0x60c7e20, 0x60c7e37, 0x60c7e47)
assert len(pairs) == len(loads) == len(calls) == len(stores) == 10
for index, ((option, variant), load, call, store) in enumerate(zip(pairs, loads, calls, stores)):
    address = rip_target(load, bytes.fromhex("488d35"))
    text = option.encode() + b"\0"
    assert read(".rodata", address, len(text)) == text
    assert rip_target(call, b"\xe8") == 0x60b7d80
    displacement = -432 + 40 * index
    if displacement < -128:
        expected = b"\xc6\x85" + struct.pack("<iB", displacement, codes[variant])
    else:
        expected = b"\xc6\x45" + struct.pack("<bB", displacement, codes[variant])
    assert read(".text", store, len(expected)) == expected
    print(index, option, hex(codes[variant]), hex(address), displacement)
assert rip_target(0x60c7e54, bytes.fromhex("488d3d")) == 0x6507120
print("ten string constructions and enum stores match the source initializer")
