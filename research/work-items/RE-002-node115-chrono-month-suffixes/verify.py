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

(source,) = from_archive(
    "chrono-0.4.38", "a21f936df1771bf62b77f047b726c4625ff2e8aa607c01ec06e5a05bd8463401",
    ("format/scan.rs",))
array = re.search(r"static LONG_MONTH_SUFFIXES: \[&\[u8\]; 12\] = \[(.*?)\];", source, re.S)[1]
suffixes = [part.encode() for part in re.findall(r'b"([a-z]*)"', array)]
assert len(suffixes) == 12
base = rip_target(0x16256b6, bytes.fromhex("4c8d05"))
assert base == 0x64050b0
assert read(".text", 0x16256b3, 3) == bytes.fromhex("c1e604")
relocations = subprocess.check_output(
    [str(TOOLS / "readelf"), "-rW", str(TARGET)], text=True)
pointers = {int(address, 16): int(addend, 16) for address, addend in re.findall(
    r"^([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)$", relocations, re.M)}
observed = []
for i, suffix in enumerate(suffixes):
    field = base + 16 * i
    raw, length = struct.unpack("<QQ", read(".data.rel.ro", field, 16))
    assert length == len(suffix)
    if length:
        assert raw == 0 and field in pointers
        observed.append(read(".rodata", pointers[field], length))
    else:
        assert raw == 1 and field not in pointers
        observed.append(b"")
    assert suffix == observed[-1]
    print(f"month {i + 1:02}: {length} byte(s), suffix={observed[-1]!r}")
assert pointers[base + 16 * 10] == pointers[base + 16 * 11]
assert observed == suffixes and observed != list(reversed(suffixes))
print("12 ordered suffix records match, including empty May and shared November/December")
