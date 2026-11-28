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



def zstd(*paths):
    return from_archive("zstd-sys-2.0.13+zstd.1.5.6",
        "38ff0f21cfee8f97d94cef41359e0c89aa6113028ab0291aa8ca0038995a95aa",
        ["zstd/lib/" + path for path in paths])

def initializer(source, name):
    body = re.search(rf"\b{name}\s*\[[^\]]+\]\s*=\s*\{{(.*?)\n\s*\}};", source, re.S)[1]
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", body, flags=re.S)

def verify(address, expected, sites):
    actual = read(".rodata", address, len(expected))
    assert actual == expected
    for ip, opcode in sites:
        assert rip_target(ip, bytes.fromhex(opcode)) == address
        print("reference", hex(ip), hex(address))
    assert bytes([actual[0] ^ 1]) + actual[1:] != expected
    print("matching source bytes", len(actual), sha256(actual).hexdigest())

source, = zstd("compress/zstd_compress_sequences.c")
body = initializer(source, "kInverseProbabilityLog256")
values = [int(token) for token in re.findall(r"\b\d+\b", body)]
assert len(values) == 256
verify(0x981e60, struct.pack("<256I", *values), (
    (0x62257fe, "488d15"), (0x6225af7, "488d15"), (0x6225c50, "488d05"),
    (0x6225f65, "4c8d15"), (0x622605b, "488d05")))
