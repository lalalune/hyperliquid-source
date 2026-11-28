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


source, = from_archive("hyper-0.14.32", "41dfc780fdec9373c01bae43289ea34c972e40ee3c9f6b3c8801a35f35586ce7", ["src/client/client.rs"])
origin = re.search(r"fn origin_form\(uri: &mut Uri\).*?^\}",source,re.S|re.M)[0]
domain = re.search(r"fn domain_as_uri\(.*?^\}",source,re.S|re.M)[0]
scheme = re.search(r"fn set_scheme\(uri: &mut Uri, scheme: Scheme\).*?^\}",source,re.S|re.M)[0]
for fragment in ('uri.path_and_query()', 'parts.path_and_query = Some(path.clone())', 'Uri::default()', '*uri = path'):
    assert fragment in origin
for fragment in ('.scheme(scheme)', '.authority(auth)', '.path_and_query("/")'):
    assert fragment in domain
for fragment in ('parts.scheme = Some(scheme)', 'parts.path_and_query = Some("/".parse()', 'Uri::from_parts(parts)'):
    assert fragment in scheme
for start,end in ((0x2e92710,0x2e92ccf),(0x2e92cd0,0x2e92f5b),(0x2e92f60,0x2e932fc)):
    compare_catalogued(start,end)
print('client URI scheme, origin-form and pool domain bodies match compiled references')
