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


source, = from_archive("lz4-sys-1.11.1+lz4-1.10.0", "6bd8c0d6c6ed0cd30b3652886bb8711dc4bb01d637a68105a3d5158039b418e6", ["liblz4/lib/lz4.c"])
body = re.search(r"int LZ4_setStreamDecode \(.*?^\}", source, re.S | re.M)[0]
for marker in ("lz4sd->prefixSize = (size_t)dictSize", "lz4sd->prefixEnd = (const BYTE*) dictionary + dictSize", "lz4sd->externalDict = NULL", "lz4sd->extDictSize  = 0", "return 1"):
    assert marker in body
catalog = json.loads(Path("research/byte-windows.json").read_text())
entry, = [row for row in catalog["windows"] if row["start"] == 0x62ed7f0]
assert entry["end"] == 0x62ed81d and entry["relocations"] is None
size = entry["end"] - entry["start"]
original = Path(entry["source"]["path"]).read_bytes()[entry["source"]["offset"]:][:size]
target = read(".text", entry["start"], size)
assert sha256(original).hexdigest() == entry["source"]["body_sha256"]
assert sha256(target).hexdigest() == entry["target_body_sha256"] and target == original
for ip, code in ((0x62ed7fe,"48894718"), (0x62ed807,"480f45f0"), (0x62ed80b,"48c7471000000000"), (0x62ed818,"48897708")):
    assert read(".text", ip, len(bytes.fromhex(code))) == bytes.fromhex(code)
    print("dictionary initialization", hex(ip), code)
print("complete 45-byte decode dictionary initializer verified")
