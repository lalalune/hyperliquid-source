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


source, = from_archive("h2-0.3.26", "81fe527a889e1532da5c525686d96d4c2e74cdd345badf8dfef9f6b39dd5f5e8", ["src/frame/reason.rs"])
body = re.search(r"pub fn description\(&self\).*?^    \}", source, re.S | re.M)[0]
body = re.sub(r"\\\n\s+", "", body)
rows = dict((int(k),v) for k,v in re.findall(r'(\d+) =>\s*\{?\s*"([^"\n]+)"',body))
assert len(rows) == 14 and 'unknown reason' in body
fields = compare_catalogued(0x17a4b60, 0x17a4bd1)
selected(fields, 0x17a4b68, bytes.fromhex('488d15'), 0x499ef0)
selected(fields, 0x17a4b76, bytes.fromhex('488d15'), 0x499f28)
selected(fields, 0x17a4b88, bytes.fromhex('488d05'), 0x499d35)
assert read('.rodata', 0x499d35, 14) == b'unknown reason'
for i in range(14):
    offset = struct.unpack('<i', read('.rodata', 0x499ef0+i*4, 4))[0]
    length = struct.unpack('<Q', read('.rodata', 0x499f28+i*8, 8))[0]
    value = read('.rodata', 0x499ef0+offset, length).decode()
    assert value == rows[i]
    print(i, value)
print('all 14 Display descriptions and unknown fallback verified')
