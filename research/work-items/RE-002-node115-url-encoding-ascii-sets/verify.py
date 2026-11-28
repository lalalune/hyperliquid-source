"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import ast
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



source, = from_archive("url-2.5.4",
    "32f8b686cadd1473f4bd0117a5d28d36b1ade384ea9b5069a1c40aefed7fda60", ["src/parser.rs"])
percent, = from_archive("percent-encoding-2.3.1",
    "e3148f5046208a5d56bcfc03053e3ca6334e51da8dfb19b6cdc8b306fae3283e", ["src/lib.rs"])
assert "type Chunk = u32;" in percent
assert "const ASCII_RANGE_LEN: usize = 0x80;" in percent
assert "mask[byte as usize / BITS_PER_CHUNK] |= 1 << (byte as usize % BITS_PER_CHUNK);" in percent
assert re.search(r"const CONTROLS:.*?mask: \[\s*!0_u32,\s*0,\s*0,\s*1 << \(0x7F_u32 % 32\),\s*\]", re.sub(r"//[^\n]*", "", percent), re.S)
masks = {"CONTROLS": set(range(32)) | {127}}
for name, parent, chain in re.findall(r"const (\w+): &AsciiSet = &(\w+)(.*?);[ \t]*\n", source, re.S):
    literals = re.findall(r"\.add\(b('(?:\\.|[^'\\])')\)", chain)
    assert len(literals) == chain.count(".add(")
    masks[name] = masks[parent] | {ast.literal_eval("b" + literal)[0] for literal in literals}
checks = (
    ("FRAGMENT", 0x4506b0, 0x5d05f3d, "488d2d"),
    ("PATH", 0x455580, 0x5d04222, "488d1d"),
    ("PATH_SEGMENT", 0x451a20, 0x5d0448d, "488d15"),
    ("SPECIAL_PATH_SEGMENT", 0x453220, 0x5d046ad, "488d15"),
    ("QUERY", 0x455f10, 0x5d05643, "488d05"),
    ("SPECIAL_QUERY", 0x450a30, 0x5d0564a, "4c8d3d"),
)
for name, address, site, opcode in checks:
    expected = sum(1 << byte for byte in masks[name]).to_bytes(16, "little")
    assert rip_target(site, bytes.fromhex(opcode)) == address
    actual = read(".rodata", address, 16)
    assert actual == expected
    assert bytes([actual[0] ^ 1]) + actual[1:] != expected
    print(name, hex(address), hex(site), actual.hex())
print("96 source-derived bytes and six reference sites match")
