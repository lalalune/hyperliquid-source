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



source, = from_archive("httparse-1.9.4",
    "0fcc0b4a115bf80b728eb8ea024ad5bd707b615bfed49e0665b6e0f86fd082d9",
    ["src/lib.rs"])
for name, address, ip, opcode in (
    ("HEADER_NAME_MAP", 0x61a408, 0x2e5682c, "488d1d"),
    ("HEADER_VALUE_MAP", 0x61a508, 0x2e56ae0, "488d35"),
    ("URI_MAP", 0x61a608, 0x2e573da, "4c8d1d"),
):
    text = re.search(rf"static {name}: \[bool; 256\] = byte_map!\[(.*?)\];", source, re.S)[1]
    text = re.sub(r"//[^\n]*", "", text)
    values = bytes(int(token) for token in re.findall(r"\b[01]\b", text))
    assert len(values) == 256
    assert rip_target(ip, bytes.fromhex(opcode)) == address
    actual = read(".rodata", address, 256)
    assert actual == values
    assert bytes([actual[0] ^ 1]) + actual[1:] != values
    print(name, hex(address), hex(ip), len(actual), sha256(actual).hexdigest())
print("three complete source character-class tables and operand references verified")
