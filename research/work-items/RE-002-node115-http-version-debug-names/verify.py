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


source, = from_archive("http-0.2.12", "601cbb57e577e2f5ef5be8e7b83f0f63994f25aa94d673e54a92d5c516d101f1", ["src/version.rs"])
body = re.search(r"impl fmt::Debug for Version \{(.*?)^\}",source,re.S|re.M)[1]
variants = re.findall(r'^\s+(Http09|Http10|Http11|H2|H3) => "([^"]+)"',body,re.M)
assert len(variants)==5
fields=compare_catalogued(0x2e54900,0x2e5496d)
selected(fields,0x2e54903,b"\x48\x8d\x0d",0x619ff4)
for index,(variant,name) in enumerate(variants):
    dest=0x619ff4+struct.unpack("<i",read(".rodata",0x619ff4+4*index,4))[0]
    op=read(".text",dest,7)
    assert op[:3]==b"\x48\x8d\x05"
    address=dest+7+struct.unpack("<i",op[3:7])[0]
    assert read(".rodata",address,len(name)) == name.encode()
    print(variant,name,hex(dest),hex(address))
print("five HTTP version debug strings and jump targets verified")
