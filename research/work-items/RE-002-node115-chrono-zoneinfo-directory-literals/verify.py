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



def chrono(member):
    return from_archive("chrono-0.4.38",
        "a21f936df1771bf62b77f047b726c4625ff2e8aa607c01ec06e5a05bd8463401", [member])[0]

def verify_table(address, expected, sites):
    actual = read(".rodata", address, len(expected))
    assert actual == expected
    for ip, opcode in sites:
        assert rip_target(ip, bytes.fromhex(opcode)) == address
    assert bytes([actual[0] ^ 1]) + actual[1:] != expected
    print(hex(address), len(actual), sha256(actual).hexdigest(),
          "references", " ".join(hex(site) for site, _ in sites))

source = chrono("src/offset/local/tz_info/timezone.rs")
body = re.search(r"const ZONE_INFO_DIRECTORIES: \[&str; 4\] =\s*\[(.*?)\];", source, re.S)[1]
paths = [path.encode() for path in re.findall(r'"([^"]+)"', body)]
assert len(paths) == 4
assert read(".text", 0x1625f59, 6) == bytes.fromhex("0f1100c7400f")
first_start = read(".rodata", rip_target(0x1625f52, bytes.fromhex("0f1005")), 16)
first = first_start[:15] + read(".text", 0x1625f5f, 4)
assert first_start[15:] == first[15:16]

def immediate(address, opcode, store):
    assert read(".text", address, 2) == bytes.fromhex(opcode)
    if store:
        assert read(".text", address + 10, len(bytes.fromhex(store))) == bytes.fromhex(store)
    return read(".text", address + 2, 8)

shared_tail = immediate(0x1625fde, "48bd", "48896807")
second_start = immediate(0x1625fec, "48b8", "498907")
third_start = immediate(0x1626078, "48b8", "498907")
assert read(".text", 0x1626074, 4) == bytes.fromhex("48896805")
fourth_start = read(".rodata", rip_target(0x1626100, bytes.fromhex("0f1005")), 16)
assert read(".text", 0x1626107, 7) == bytes.fromhex("0f11004889680f")
assert second_start[7:] == fourth_start[15:] == shared_tail[:1]
observed = (first, second_start[:7] + shared_tail, third_start[:5] + shared_tail,
            fourth_start[:15] + shared_tail)
for path, actual, length_site, call_site in zip(
        paths, observed, (0x1625f6e, 0x1626004, 0x1626090, 0x1626119),
        (0x1625f7c, 0x1626012, 0x162609e, 0x1626127)):
    assert path == actual
    assert read(".text", length_site, 5) == b"\xba" + struct.pack("<I", len(path))
    assert rip_target(call_site, bytes.fromhex("ff15")) == 0x64e0b58
    assert bytes([actual[0] ^ 1]) + actual[1:] != path
    print(actual.decode(), len(actual), hex(call_site))
print("four source directory literals and their shared call slot match")
