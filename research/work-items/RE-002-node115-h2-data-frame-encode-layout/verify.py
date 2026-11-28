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


data_source, head = from_archive("h2-0.3.26", "81fe527a889e1532da5c525686d96d4c2e74cdd345badf8dfef9f6b39dd5f5e8", ["src/frame/data.rs", "src/frame/head.rs"])
body=re.search(r"fn encode_chunk<.*?^    \}",data_source,re.S|re.M)[0]
assert "let len = self.data.remaining()" in body
assert "self.head().encode(len, dst)" in body and "dst.put(&mut self.data)" in body
for expr in ("dst.put_uint(payload_len as u64, 3)", "dst.put_u8(self.kind as u8)", "dst.put_u8(self.flag)", "dst.put_u32(self.stream_id.into())"):
    assert expr in head
for start,end in ((0x15e9790,0x15e9895),(0x16c33f0,0x16c34f5),(0x248b6f0,0x248b7f5),(0x248b800,0x248b905)):
    compare_catalogued(start,end)
for ip,code in ((0x15e97f9,"480fc8"),(0x15e980d,"ba03000000"),(0x15e9818,"c644240200"),(0x15e9822,"ba01000000"),(0x15e9837,"ba01000000"),(0x15e9842,"0fcd"),(0x15e984d,"ba04000000")):
    assert read(".text",ip,len(bytes.fromhex(code)))==bytes.fromhex(code)
    print("frame header operation",hex(ip),code)
print("DATA frame header field widths and big-endian conversions verified")
