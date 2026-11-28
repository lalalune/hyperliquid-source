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


source, = from_archive("http-0.2.12", "601cbb57e577e2f5ef5be8e7b83f0f63994f25aa94d673e54a92d5c516d101f1", ["src/status.rs"])
rows = re.findall(r'\((\d+),\s*[A-Z_]+,\s*"([^"]+)"\);',source)
reasons = {int(number): text.encode() for number,text in rows}
assert len(rows) == len(reasons) == 60
fields=compare_catalogued(0x2e50150,0x2e5047d)
selected(fields,0x2e50164,b"\x48\x8d\x15",0x618934)
assert read(".text",0x2e50155,9) == bytes.fromhex("83c19c81f99b010000")
for code in range(100,512):
    jump = struct.unpack("<i",read(".rodata",0x618934+4*(code-100),4))[0]
    dest = 0x618934+jump
    op = read(".text",dest,13)
    if code not in reasons:
        assert dest == 0x2e5047b and op[0] == 0xc3
        continue
    assert op[:3] == b"\x48\x8d\x05"
    text = dest + 7 + struct.unpack("<i",op[3:7])[0]
    if op[7] == 0xeb:
        length_op = dest + 9 + struct.unpack("b",op[8:9])[0]
        tail = read(".text",length_op,6)
    else:
        tail = op[7:13]
    assert tail[0] == 0xba and tail[5] == 0xc3
    size = struct.unpack("<I",tail[1:5])[0]
    assert read(".rodata",text,size) == reasons[code]
print("verified",len(reasons),"known status reasons and",412-len(reasons),"unnamed in-range codes")
