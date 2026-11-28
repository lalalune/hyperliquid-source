"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import json
import re
import subprocess
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


TOOLS = Path(sys.argv[2])
rows = subprocess.check_output([TOOLS / "readelf", "-rW", TARGET], text=True)
relative = {
    int(slot, 16): int(addr, 16)
    for slot, addr in re.findall(
        r"^([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)$", rows, re.M
    )
}


source, = from_archive("h2-0.4.13",
    "2f44da3a8150a6703ed5d34e164b875fd14c2cdab9af1252a9a1020bde2bdc54", ["src/frame/reason.rs"])
body = re.search(r"impl fmt::Debug for Reason \{(.*?)^\}", source, re.S | re.M)[1]
rows = re.findall(r'^\s*(\d+) => "([^"]+)",', body, re.M)
assert [int(code) for code, _ in rows] == list(range(14))
length, table = 0x499e80, 0x6419fc0
assert read(".text", 0x17a4a14, 4) == bytes.fromhex("4983fd0e")
assert rip_target(0x17a4a1a, bytes.fromhex("488d05")) == length
assert rip_target(0x17a4a25, bytes.fromhex("488d05")) == table
actual_lengths = struct.unpack("<14Q", read(".rodata", length, 14 * 8))
for index, (_, name) in enumerate(rows):
    wanted = name.encode()
    slot = table + 8 * index
    address = relative[slot]
    assert len(wanted) == actual_lengths[index]
    assert read(".rodata", address, len(wanted)) == wanted
    print(index, name, hex(slot), hex(address), len(wanted))
print("all fourteen source Reason debug names and linked lengths verified")
