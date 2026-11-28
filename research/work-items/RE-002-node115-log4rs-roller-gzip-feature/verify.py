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



source, = from_archive("log4rs-1.3.0",
    "0816135ae15bd0391cf284eab37e6e3ee0a6ee63d2ceeb659862bd8d0a984ca6",
    ["src/append/rolling_file/policy/compound/roll/fixed_window.rs"])
body = re.search(r"    pub fn build\(self, pattern: &str, count: u32\)(.*?)^    \}", source, re.S | re.M)[1]
marker, diagnostic = re.search(r'pattern\.contains\("([^"]+)"\).*?let msg = "([^"]+)"', body, re.S).groups()
ext, message = re.search(
    r'#\[cfg\(not\(feature = "gzip"\)\)\]\s*Some\(e\) if e == "([^"]+)" => \{\s*bail!\("([^"]+)"\)', body
).groups()
assert marker == "{}"
assert rip_target(0x473c187, bytes.fromhex("488d3d")) == 0x7df31e
assert read(".rodata", 0x7df31e, len(diagnostic)) == diagnostic.encode()
assert read(".text", 0x473c351, 7) == bytes.fromhex("66817c1001") + ext.encode()
branch = 0x473c358
opcode = read(".text", branch, 6)
assert opcode[:2] == bytes.fromhex("0f84")
taken = branch + 6 + struct.unpack("<i", opcode[2:])[0]
assert taken == 0x473c61b
address = rip_target(taken, bytes.fromhex("488d3d"))
assert read(".rodata", address, len(message)) == message.encode()
print("pattern marker", repr(marker), diagnostic)
print("extension", ext, hex(branch), hex(taken), hex(address), message)
print("source feature-disabled diagnostic linked")
