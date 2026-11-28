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


source = sysinfo("component.rs")
body = re.search(r"    fn format_label\(&self, class: &str, id: u32\).*?^    \}", source, re.S | re.M)[0]
templates = re.findall(r'format!\("([^"]+)"\)', body)
assert len(templates) == 4

def encode(template):
    pieces = re.split(r"(\{[a-z_]+\})", template)
    data = bytearray()
    for value in pieces:
        if value.startswith("{"):
            data.append(0xc0)
        elif value:
            literal = value.encode()
            data.extend(bytes([len(literal)]) + literal)
    return bytes(data) + b"\0"

refs = (0x5cc1548, 0x5cc157b, 0x5cc157b, 0x5cc14d7)
for template, ip in zip(templates, refs):
    expected = encode(template)
    address = rip_target(ip, bytes.fromhex("488d35"))
    assert read(".rodata", address, len(expected)) == expected
    assert bytes([expected[0] ^ 1]) + expected[1:] != read(".rodata", address, len(expected))
    print(template, hex(ip), hex(address), expected.hex())
assert len(set(encode(template) for template in templates)) == 3
print("all source formatting variants bind complete linked templates")
