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


source, = from_archive("h2-0.3.26", "81fe527a889e1532da5c525686d96d4c2e74cdd345badf8dfef9f6b39dd5f5e8", ["src/frame/settings.rs"])
body = re.search(r"impl fmt::Debug for Settings \{(.*?)^\}",source,re.S|re.M)[1]
fields=compare_catalogued(0x17a4de0,0x17a503b)
refs = ((0x17a4df4,0x459688,"Settings"),(0x17a4e15,0x499db3,"flags"),(0x17a4e7b,0x499e1f,"enable_connect_protocol"),(0x17a4ec5,0x499db8,"header_table_size"),(0x17a4ef9,0x499dc9,"enable_push"),(0x17a4f2d,0x499dd4,"max_concurrent_streams"),(0x17a4f61,0x499dea,"initial_window_size"),(0x17a4f95,0x499dfd,"max_frame_size"),(0x17a4fc9,0x499e0b,"max_header_list_size"))
for ip,address,name in refs:
    assert '"' + name + '"' in body
    selected(fields,ip,b"\x48\x8d\x35",address)
    assert read(".rodata",address,len(name)) == name.encode()
    print("debug field",name)
print("settings debug name and eight fields verified")
