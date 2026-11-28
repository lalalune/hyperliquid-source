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



def rust_source(path):
    archive_path = CACHE / "rust-src-1.95.0.tar.xz"
    assert sha256(archive_path.read_bytes()).hexdigest() == "67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363"
    with tarfile.open(archive_path) as archive:
        member = "rust-src-1.95.0/rust-src/lib/rustlib/src/rust/library/" + path
        return archive.extractfile(member).read().decode()

source = rust_source("std/src/sys/env/unix.rs")
function = re.search(r"pub fn getenv\(k: &OsStr\).*?^\}", source, re.S | re.M)[0]
assert "libc::getenv(k.as_ptr())" in function
assert "env_read_lock()" in function
catalog = Path("research/work-items/RE-002-node115-thinlto-std-vendor-census")
record = json.loads((catalog / "census.json").read_text())["records"][530]
assert (record["start"], record["end"]) == (0x5c81950, 0x5c81a7f)
extent = record["end"] - record["start"]
start = record["source_offset"]
source_body = (catalog / "bodies.bin").read_bytes()[start:start + extent]
target_body = read(".text", record["start"], extent)
assert sha256(source_body).hexdigest() == "0bdf7005e98f68cf9b29e3b044ebe389d2b6ec8fe2d388951da88f6ed8280503"
assert sha256(target_body).hexdigest() == "3410e7faee4b681c05946472feb6b45cbbf80970cde9e55af8e328c5bd6e9c04"
fields = {row["offset"]: row for row in record["relocations"]}
disabled = {i for offset, entry in fields.items() for i in range(offset, offset + entry["width"])}
assert all(lhs == rhs for i, (lhs, rhs) in enumerate(zip(source_body, target_body)) if i not in disabled)
print("catalogued source vs linked body", extent - len(disabled), "/", extent)
rows = subprocess.check_output([Path(sys.argv[2]) / "readelf", "-rW", TARGET], text=True)
for site, slot, binding in (
    (0x5c8198d, 0x64ec6c8, "getenv@GLIBC_2.2.5"),
    (0x5c8199e, 0x64df698, "strlen@GLIBC_2.2.5"),
    (0x5c819c6, 0x64df508, "memcpy@GLIBC_2.14"),
    (0x5c81a1b, 0x64ec6d0, 0x5c844a0),
):
    at = fields[site + 2 - record["start"]]
    assert at["kind"] == 9 and at["width"] == 4
    assert rip_target(site, bytes.fromhex("ff15")) == slot
    line, = re.findall(rf"^0*{slot:x}\s+.*$", rows, re.M)
    if isinstance(binding, str):
        assert "R_X86_64_GLOB_DAT" in line and binding in line.split()
        shown = binding
    else:
        assert "R_X86_64_RELATIVE" in line and int(line.split()[-1], 16) == binding
        shown = hex(binding)
    print(hex(site), hex(slot), shown)
print("ordinary environment lookup linkage verified without reading environment values")
