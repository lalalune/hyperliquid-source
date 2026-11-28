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


header, source = from_archive("zstd-sys-2.0.15+zstd.1.5.7", "eb81183ddd97d0c74cedf1d50d85c8d08c1b8b68ee863bdee9e706eedba1a237", ["zstd/lib/zstd.h", "zstd/lib/compress/zstd_compress.c"])
macro = re.search(r"^#define ZSTD_COMPRESSBOUND\(srcSize\).*$", header, re.M)[0]
for value in ("ZSTD_MAX_INPUT_SIZE", "(srcSize)>>8", "(128<<10)", ">> 11"):
    assert value in macro
assert "size_t const r = ZSTD_COMPRESSBOUND(srcSize);" in source
catalog = json.loads(Path("research/byte-windows.json").read_text())
entry, = [row for row in catalog["windows"] if row["start"] == 0x6211780]
assert entry["end"] == 0x62117cb and entry["relocations"] is None
original = Path(entry["source"]["path"]).read_bytes()[entry["source"]["offset"]:][:75]
target = read(".text", 0x6211780, 75)
assert sha256(original).hexdigest() == entry["source"]["body_sha256"]
assert sha256(target).hexdigest() == entry["target_body_sha256"] and target == original
for ip, code in ((0x621179d,"48c1e808"), (0x62117a4,"4881ffffff0100"), (0x62117ad,"ba00000200"), (0x62117b5,"48c1ea0b")):
    assert read(".text", ip, len(bytes.fromhex(code))) == bytes.fromhex(code)
    print("formula instruction", hex(ip), code)
print("all 75 catalogued bytes and normal compression-bound constants verified")
