"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
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



source, = from_archive("percent-encoding-2.3.1",
    "e3148f5046208a5d56bcfc03053e3ca6334e51da8dfb19b6cdc8b306fae3283e", ["src/lib.rs"])
length, values = re.search(r'ENC_TABLE: &\[u8; (\d+)\] = b"(.*?)";', source, re.S).groups()
triplets = re.findall(r"%[0-9A-F]{2}", values)
expected = "".join(triplets).encode()
assert len(triplets) == 256 and len(expected) == int(length)
assert triplets == [f"%{value:02X}" for value in range(256)]
actual = read(".rodata", 0x93fda3, len(expected))
assert actual == expected
for site, opcode in ((0x1770e23, "488d05"), (0x5d045bf, "488d05"), (0x5d0bda0, "488d05")):
    assert rip_target(site, bytes.fromhex(opcode)) == 0x93fda3
    print("reference", hex(site), "->", hex(0x93fda3))
assert bytes([actual[0] ^ 1]) + actual[1:] != expected
print("complete ordered triplet table", len(actual), sha256(actual).hexdigest())
