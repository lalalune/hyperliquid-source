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



def verify_imports(bindings):
    output = subprocess.check_output([Path(sys.argv[2]) / "readelf", "-rW", TARGET], text=True)
    for slot, name in bindings:
        match, = re.findall(rf"^0*{slot:x}\s+.*R_X86_64_GLOB_DAT.*$", output, re.M)
        assert name in match.split()
        print(hex(slot), name)

immutable, mutable = from_archive("bytes-1.11.1",
    "1e748733b7cbc798e1434b6ac524f0c1ff2ab456fe201501e6497c8417a4fc33",
    ["src/bytes.rs", "src/bytes_mut.rs"])
a = re.search(r"pub fn split_off\(&mut self, at: usize\).*?^    \}", immutable, re.M | re.S)[0]
b = re.search(r"pub fn split_off\(&mut self, at: usize\).*?^    \}", mutable, re.M | re.S)[0]
assert "self.len = at;" in a and "ret.inc_start(at)" in a
assert "self.cap = at;" in b and "self.len = cmp::min(self.len, at);" in b and "other.advance_unchecked(at);" in b
compare_catalogued(0x161cb20, 0x161cc6f)
compare_catalogued(0x161d820, 0x161d994)
for name, ip, encoded in (
    ("immutable length", 0x161cb86, "49895f10"),
    ("immutable returned view pointer", 0x161cba0, "4801442408"),
    ("mutable capacity", 0x161d8e3, "4d897e10"),
    ("mutable length minimum selection", 0x161d8ee, "490f42c7"),
    ("mutable length store", 0x161d8f2, "49894608"),
    ("mutable returned view pointer", 0x161d8bd, "4c013c24"),
):
    data_ = bytes.fromhex(encoded)
    assert read(".text", ip, len(data_)) == data_
    print(name, hex(ip), encoded)
