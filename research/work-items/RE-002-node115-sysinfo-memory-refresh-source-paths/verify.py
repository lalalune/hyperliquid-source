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

source = sysinfo("system.rs")
method = re.search(r"    fn refresh_memory\(&mut self\) \{(.*?)^    \}", source, re.S | re.M)[1]
paths = re.findall(r'\bread_(?:table|u64)\("(\/[^"]+)"', method)
sites = ((0x5cbb982, "488d35"), (0x5cbba89, "488d3d"), (0x5cbbaa0, "488d3d"),
         (0x5cbbaf7, "488d3d"), (0x5cbbb37, "488d35"),
         (0x5cbbb6b, "488d3d"), (0x5cbbb82, "488d3d"))
assert len(paths) == len(sites) == 7
for path, (ip, opcode) in zip(paths, sites):
    target = rip_target(ip, bytes.fromhex(opcode))
    want = path.encode()
    actual = read(".rodata", target, len(want))
    assert actual == want
    assert bytes([actual[0] ^ 1]) + actual[1:] != want
    print(hex(ip), hex(target), len(actual), path)
print("seven source-selected memory paths verified")
