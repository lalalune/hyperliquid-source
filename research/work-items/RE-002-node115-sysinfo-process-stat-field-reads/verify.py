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



def sysinfo(file):
    return from_archive("sysinfo-0.29.11",
        "cd727fc423c2060f6c92d9534cef765c65a6ed3f428a03d7def74a8c4348e666",
        ["src/linux/" + file])[0]

source = sysinfo("process.rs")
method = re.search(r"fn update_time_and_memory\((.*?)^\}", source, re.S | re.M)[1]
indices = [int(i) for i in re.findall(r"u64::from_str\(parts\[(\d+)\]\)", method)]
assert indices == [23, 22, 13, 14]
links = ((0x5cb71e9, "4c8b99", 0x5cb71d3, "4c8b81"),
         (0x5cb72fa, "4c8b89", 0x5cb72ee, "488bb9"),
         (0x5cb73e9, "4c8b89", 0x5cb73dd, "4c8b81"),
         (0x5cb74d8, "488b89", 0x5cb74c8, "4c8b81"))
for index, (ptr, ptr_code, size, size_code) in zip(indices, links):
    assert read(".text", ptr, 7) == bytes.fromhex(ptr_code) + struct.pack("<I", 16 * index)
    assert read(".text", size, 7) == bytes.fromhex(size_code) + struct.pack("<I", 16 * index + 8)
    print(index, hex(ptr), hex(size), hex(16 * index))
child, = re.search(r'&path\.join\("([^"]+)"\)', method).groups()
address = rip_target(0x5cb75d3, bytes.fromhex("488d0d"))
assert read(".rodata", address, len(child)) == child.encode()
print("task child reference", child, hex(address))
print("four source-selected process stat slices and path reference verified")
