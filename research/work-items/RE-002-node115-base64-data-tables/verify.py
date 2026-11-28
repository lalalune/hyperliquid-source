"""Verify full data tables in the pinned node #115 ELF against released Rust crate sources."""
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


def from_archive(name, digest, files):
    path = CACHE / f"{name}.crate"
    assert sha256(path.read_bytes()).hexdigest() == digest
    print(name, digest)
    with tarfile.open(path) as archive:
        return [archive.extractfile(f"{name}/src/{part}").read().decode() for part in files]


def rip_target(address, prefix):
    instruction = read(".text", address, len(prefix) + 4)
    assert instruction.startswith(prefix)
    return address + len(instruction) + struct.unpack_from("<i", instruction, len(prefix))[0]


print("node #115", TARGET_SHA)

alphabet_source, engine_source = from_archive(
    "base64-0.21.7", "9d297deb1925b89f2ccc13d7635fa0714f12c87adce1c75356b39ca9b7178567",
    ("alphabet.rs", "engine/general_purpose/mod.rs"))
invalid = int(re.search(r"const INVALID_VALUE: u8 = (\d+);", engine_source)[1])
assert "decode_table[alphabet.symbols[index] as usize] = index as u8;" in engine_source

def paired_table(name):
    alphabet = re.search(rf'pub const {name}: Alphabet = Alphabet::from_str_unchecked\(\s*"([^"]+)"', alphabet_source)[1].encode()
    assert len(alphabet) == len(set(alphabet)) == 64
    inverse = bytearray([invalid] * 256)
    for value, symbol in enumerate(alphabet):
        inverse[symbol] = value
    return alphabet + inverse

standard = paired_table("STANDARD")
for address in (0x5f405e, 0x7bd3ad):
    actual = read(".rodata", address, 320)
    assert actual == standard
    assert actual != paired_table("URL_SAFE")
    print(f"table pair {address:#x}: 64 alphabet bytes and 256 inverse entries match")
print("URL-safe pair rejected at both examined placements")
