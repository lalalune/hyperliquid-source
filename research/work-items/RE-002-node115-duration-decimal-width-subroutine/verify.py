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


catalog = Path("research/work-items/RE-002-node115-thinlto-std-vendor-census")
record = json.loads((catalog / "census.json").read_text())["records"][126]
assert (record["start"], record["end"]) == (0x16864b0, 0x1686aaf)
extent = record["end"] - record["start"]
offset = record["source_offset"]
source_body = (catalog / "bodies.bin").read_bytes()[offset:offset + extent]
target_body = read(".text", record["start"], extent)
assert sha256(source_body).hexdigest() == "bbcbc8abe59e86291cbbc38766a608410a376cfe3f6f212045df230589114d54"
assert sha256(target_body).hexdigest() == "49393de849a362172da8b3ca01b58cf7e1c009b36b280cbc61443cc5978c7d6f"
refs = (
    (0x16868e8, "488d0d", 0x46d79c), (0x168690e, "e8", 0x167cb20),
    (0x1686972, "e8", 0x167cb20), (0x1686aa2, "488d3d", 0x6407f48),
    (0x1686aa9, "ff15", 0x64df878),
)
fields = {item["offset"]: item for item in record["relocations"]}
assert len(fields) == len(refs)
mask = {i for pos, item in fields.items() for i in range(pos, pos + item["width"])}
assert all(a == b for i, (a, b) in enumerate(zip(source_body, target_body)) if i not in mask)
for site, opcode, address in refs:
    field = (site - record["start"]) + len(bytes.fromhex(opcode))
    assert fields[field]["width"] == 4
    assert rip_target(site, bytes.fromhex(opcode)) == address
    print(hex(site), hex(address))
assert relative[0x6407f48] == 0x44f1ac
assert relative[0x64df878] == 0x1681d60
table = 0x46d79c
branches = [table + displacement for displacement in struct.unpack("<4i", read(".rodata", table, 16))]
assert branches == [0x16868ff, 0x1686925, 0x168692a, 0x16868ff]
assert read(".text", 0x16868e0, 8) == bytes.fromhex("89d8c1e81d83e003")
for address, operation in ((branches[0], "4531e4"), (branches[1], "4189d4"), (branches[2], "440fb7e241d1ec")):
    expected = bytes.fromhex(operation)
    assert read(".text", address, len(expected)) == expected
print("four alignment slots", *(hex(addr) for addr in branches))
print(extent - len(mask), "nonrelocated body bytes and all five links verified")
