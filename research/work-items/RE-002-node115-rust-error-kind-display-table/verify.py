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



def rust_source(path):
    archive_path = CACHE / "rust-src-1.95.0.tar.xz"
    assert sha256(archive_path.read_bytes()).hexdigest() == "67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363"
    with tarfile.open(archive_path) as archive:
        member = "rust-src-1.95.0/rust-src/lib/rustlib/src/rust/library/" + path
        return archive.extractfile(member).read().decode()

source = rust_source("std/src/io/error.rs")
enum = re.search(r"pub enum ErrorKind \{(.*?)^\}", source, re.M | re.S)[1]
order = re.findall(r"^    (\w+),$", enum, re.M)
formatter = re.search(r"fn as_str\(&self\).*?\n    \}", source, re.S)[0]
text = dict(re.findall(r'^ +([A-Z]\w+) => "([^"]+)",', formatter, re.M))
assert len(order) == 42 and set(order) == set(text)
size, offsets = 0x94a580, 0x94a6d0
assert rip_target(0x5ca85ca, bytes.fromhex("488d0d")) == size
assert rip_target(0x5ca85d5, bytes.fromhex("488d15")) == offsets
lengths = struct.unpack("<42Q", read(".rodata", size, 42 * 8))
deltas = struct.unpack("<42i", read(".rodata", offsets, 42 * 4))
for index, (variant, len_, delta) in enumerate(zip(order, lengths, deltas)):
    expected = text[variant].encode()
    assert len_ == len(expected)
    address = offsets + delta
    actual = read(".rodata", address, len_)
    assert actual == expected
    assert bytes([actual[0] ^ 1]) + actual[1:] != expected
    print(index, variant, hex(address), len_)
print("42 exact linked texts, lengths and relative addresses match source")
