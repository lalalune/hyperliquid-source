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


source, = from_archive("bytes-1.11.1", "1e748733b7cbc798e1434b6ac524f0c1ff2ab456fe201501e6497c8417a4fc33", ["src/bytes.rs"])
body = re.search(r"pub fn slice\(&self, range: impl RangeBounds<usize>\).*?^    \}", source, re.S | re.M)[0]
for fragment in ('begin <= end', 'end <= len', 'if end == begin', 'Bytes::new_empty_with_ptr', 'self.clone()', 'ret.len = end - begin', 'ret.ptr.add(begin)'):
    assert fragment in body
compare_catalogued(0x2e6d240, 0x2e6d38d)
compare_catalogued(0x2e96620, 0x2e9676d)
for ip, code in ((0x2e6d25d,'4839c2'), (0x2e6d260,'777f'), (0x2e6d262,'4839c8'), (0x2e6d265,'0f87b1000000'), (0x2e6d271,'4839d0'), (0x2e6d2aa,'4c29f0'), (0x2e6d2b8,'4c01742408')):
    assert read('.text', ip, len(bytes.fromhex(code))) == bytes.fromhex(code)
    print('slice instruction', hex(ip), code)
print('range comparisons, empty case and view offsets verified')
