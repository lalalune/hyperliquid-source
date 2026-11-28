"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import json
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



def compare_catalogued(address, expected_end):
    catalog = json.loads(Path("research/byte-windows.json").read_text())
    entry, = [item for item in catalog["windows"] if item["start"] == address]
    assert entry["end"] == expected_end
    source = entry["source"]
    original = Path(source["path"]).read_bytes()[source["offset"]:source["offset"] + expected_end - address]
    actual = read(".text", address, expected_end - address)
    assert sha256(original).hexdigest() == source["body_sha256"]
    assert sha256(actual).hexdigest() == entry["target_body_sha256"]
    fields = json.loads(Path(entry["relocations"]["path"]).read_text())
    for item in entry["relocations"]["pointer"]:
        fields = fields[item]
    masked = {i for row in fields for i in range(row["offset"], row["offset"] + row["width"])}
    verified = [i for i, (a, b) in enumerate(zip(original, actual)) if i not in masked and a == b]
    assert len(verified) == len(actual) - len(masked)
    print("catalogued and target bytes", len(verified), "/", len(actual))
    return {address + row["offset"]: row for row in fields}

def selected(fields, ip, prefix, target):
    field = ip + len(prefix)
    assert fields[field]["width"] == 4
    assert rip_target(ip, prefix) == target
    print("linked reference", hex(ip), "->", hex(target))


import subprocess
source, = from_archive("bytes-1.11.1", "1e748733b7cbc798e1434b6ac524f0c1ff2ab456fe201501e6497c8417a4fc33", ["src/bytes.rs"])
for name,ret,operation in (("static_to_vec","Vec<u8>","slice.to_vec()"),("static_to_mut","BytesMut","BytesMut::from(slice)")):
    body = re.search(r"unsafe fn " + name + r"\(.*?^\}", source, re.S | re.M)[0]
    assert ret in body and "slice::from_raw_parts(ptr, len)" in body and operation in body
for start,end,alloc,copy in ((0x161bd80,0x161be19,0x161bd99,0x161bdb0),(0x161be20,0x161be98,0x161be43,0x161be5e)):
    fields = compare_catalogued(start,end)
    selected(fields,alloc,b"\xff\x15",0x64df480)
    selected(fields,copy,b"\xff\x15",0x64df508)
out = subprocess.check_output([Path(sys.argv[2]) / "readelf", "-rW", TARGET], text=True)
assert re.search(r"^0*64df508\s+\S+\s+R_X86_64_GLOB_DAT\s+\S+\s+memcpy@GLIBC_2\.14\s+\+ 0$",out,re.M)
print("both static-slice adapters share allocation and memcpy links")
