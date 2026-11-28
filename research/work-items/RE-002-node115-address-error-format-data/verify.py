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


def rip_target(address, prefix):
    instruction = read(".text", address, len(prefix) + 4)
    assert instruction.startswith(prefix)
    return address + len(instruction) + struct.unpack_from("<i", instruction, len(prefix))[0]


print("node #115", TARGET_SHA)



archive_path = CACHE / "rust-src-1.95.0.tar.xz"
archive_sha = sha256(archive_path.read_bytes()).hexdigest()
assert archive_sha == "67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363"
print("Rust source archive", archive_sha)
with tarfile.open(archive_path) as archive:
    source = archive.extractfile(
        "rust-src-1.95.0/rust-src/lib/rustlib/src/rust/library/core/src/net/parser.rs"
    ).read().decode()
names = re.search(r"enum AddrKind \{(.*?)\}", source, re.S)[1]
cases = re.search(r"impl fmt::Display for AddrParseError.*?match self\.0 \{(.*?)\}", source, re.S)[1]
messages = dict(re.findall(r'AddrKind::(\w+) => "([^"]+)"', cases))
order = re.findall(r"\b(\w+),", names)
assert len(messages) == len(order) == 6
expected = [messages[name].encode() for name in order]
lengths = list(struct.unpack("<6Q", read(".rodata", 0x4793b8, 48)))
assert lengths == list(map(len, expected))
assert rip_target(0x16893b9, b"\x48\x8d\x15") == 0x4793b8
assert rip_target(0x16893c4, b"\x48\x8d\x35") == 0x6408178
assert rip_target(0x16893d2, b"\xff\x25") == 0x64df720
rows = subprocess.check_output([TOOLS / "readelf", "-rW", TARGET], text=True)
relative = {}
for slot, address in re.findall(
    r"^([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)$", rows, re.M
):
    relative[int(slot, 16)] = int(address, 16)
assert relative[0x64df720] == 0x167fa70
print("format destination", hex(relative[0x64df720]))
for i, (variant, want) in enumerate(zip(order, expected)):
    slot = 0x6408178 + i * 8
    read(".data.rel.ro", slot, 8)
    address = relative[slot]
    actual = read(".rodata", address, lengths[i])
    assert actual == want
    assert bytes([actual[0] ^ 1]) + actual[1:] != want
    print(variant, lengths[i], hex(slot), hex(address), sha256(actual).hexdigest())
assert rip_target(0x5aabaf6, b"\x48\x8d\x15") == 0x93c688
assert struct.unpack("<3Q", read(".rodata", 0x93c688, 24)) != tuple(lengths[:3])
print("unrelated same-purpose formatter candidate rejected by its selected table")
