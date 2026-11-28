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


source = sysinfo("disk.rs")
base, suffix = re.search(r'let path = Path::new\("([^"]+)"\).*?\.join\("([^"]+)"\);', source, re.S).groups()
assert read(".text", 0x5cd25e1, 2) == bytes.fromhex("48b8")
first = read(".text", 0x5cd25e3, 8)
assert read(".text", 0x5cd25eb, 8) == bytes.fromhex("4989450041c74507")
last = read(".text", 0x5cd25f3, 4)
assert first[-1:] == last[:1]
assert (first[:7] + last).decode() == base
address = rip_target(0x5cd261a, bytes.fromhex("488d0d"))
assert read(".rodata", address, len(suffix)) == suffix.encode()
assert read(".text", 0x5cd25fc, 5) == b"\xba" + struct.pack("<I", len(base))
assert read(".text", 0x5cd2626, 6) == bytes.fromhex("41b8") + struct.pack("<I", len(suffix))
for location in (0x5cd260a, 0x5cd262f):
    assert rip_target(location, bytes.fromhex("ff15")) == 0x64e0b58
print(base, len(base), hex(0x5cd260a))
print(suffix, len(suffix), hex(address), hex(0x5cd262f))
print("both source path components and join operands verified")
