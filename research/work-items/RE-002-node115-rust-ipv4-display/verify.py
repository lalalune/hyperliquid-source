"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import json
import re
import subprocess
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
def rust_source(path):
    archive_path = CACHE / "rust-src-1.95.0.tar.xz"
    assert sha256(archive_path.read_bytes()).hexdigest() == "67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363"
    with tarfile.open(archive_path) as archive:
        member = "rust-src-1.95.0/rust-src/lib/rustlib/src/rust/library/" + path
        return archive.extractfile(member).read().decode()



source = rust_source("core/src/net/ip_addr.rs")
body = re.search(r"impl fmt::Display for Ipv4Addr \{(.*?)^\}",source,re.S|re.M)[1]
for marker in ("let octets = self.octets()", '"{}.{}.{}.{}"', '"255.255.255.255"', "fmt.precision().is_none() && fmt.width().is_none()", "fmt.pad(buf.as_str())"):
    assert marker in body
fields=compare_catalogued(0x16885f0,0x168871d)
selected(fields,0x16886ca,b"\x48\x8d\x15",0x445ab6)
selected(fields,0x16886d5,b"\xff\x15",0x64df6f0)
print("IPv4 formatting data and formatter references verified")
