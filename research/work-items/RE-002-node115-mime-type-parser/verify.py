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
    fields = []
    if entry["relocations"] is not None:
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


source, = from_archive("mime-0.3.18", "d5848f5a9e8117cf94f2f90faac24a87ff81600ff8628c1e3deaab572e76bfa1", ["src/parse.rs"])
body = re.search(r"pub fn parse\(s: &str\).*?^\}",source,re.S|re.M)[0]
lower = re.search(r"fn lower_ascii_with_params\(.*?^\}",source,re.S|re.M)[0]
for fragment in ('s == "*/*"', "Some((i, b'/')) if i > 0", "Some((i, b'+')) if i > start", "Some((i, b';')) if i > start", 'is_token(c)'):
    assert fragment in body
for fragment in ('owned[..semi].make_ascii_lowercase()', 'owned[name.0..name.1].make_ascii_lowercase()', 'CHARSET.source', 'owned[value.0..value.1].make_ascii_lowercase()'):
    assert fragment in lower
compare_catalogued(0x47580a0,0x475856b)
compare_catalogued(0x4757a90,0x47580a0)
print('MIME type parsing and parameter normalization bodies match compiled references')
