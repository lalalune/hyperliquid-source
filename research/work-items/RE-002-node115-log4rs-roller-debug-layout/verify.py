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


source, = from_archive("log4rs-1.3.0",
    "0816135ae15bd0391cf284eab37e6e3ee0a6ee63d2ceeb659862bd8d0a984ca6",
    ["src/append/rolling_file/policy/compound/roll/fixed_window.rs"])
body = re.search(r"#\[derive\(Clone, Debug\)\]\s*pub struct FixedWindowRoller \{(.*?)^\}", source, re.S | re.M)[1]
names = re.findall(r"^    ([a-z_]+):", body, re.M)
assert names[:4] == ["pattern", "compression", "base", "count"]
assert '#[cfg(feature = "background_rotation")]' in body and names[4:] == ["cond_pair"]
sites = (
    ("FixedWindowRoller", 0x159eb0d, "488d35"),
    (names[0], 0x159eb14, "488d0d"), (names[1], 0x159eb3d, "488d05"),
    (names[2], 0x159eaff, "4c8d1d"), (names[3], 0x159eaf1, "4c8d2d"),
)
for label, site, opcode in sites:
    address = rip_target(site, bytes.fromhex(opcode))
    expected = label.encode()
    assert read(".rodata", address, len(expected)) == expected
    print(label, hex(site), hex(address))
for label, site, encoded in (
    ("count", 0x159ead1, "4c8d5720"),
    ("compression", 0x159ead5, "4c8d7718"),
    ("base", 0x159ead9, "488d4f1c"),
):
    instruction = bytes.fromhex(encoded)
    assert read(".text", site, len(instruction)) == instruction
    print(label, "object offset", hex(instruction[-1]))
assert rip_target(0x159eb4d, bytes.fromhex("ff15")) == 0x64e0f28
assert relative[0x64e0f28] == 0x167f870
print("roller formatter binds the four-field debug writer")
