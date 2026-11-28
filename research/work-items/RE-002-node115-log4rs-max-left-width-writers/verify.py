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


source, = from_archive("log4rs-1.3.0", "0816135ae15bd0391cf284eab37e6e3ee0a6ee63d2ceeb659862bd8d0a984ca6", ["src/encode/pattern/mod.rs"])
maximum = re.search(r"impl<'a> io::Write for MaxWidthWriter<'a> \{(.*?)^\}",source,re.S|re.M)[1]
left = re.search(r"impl<W: encode::Write> io::Write for LeftAlignWriter<W> \{(.*?)^\}",source,re.S|re.M)[1]
for marker in ("is_char_boundary(b)", "end = idx", "self.remaining = remaining", "char_starts(&buf[..len])"):
    assert marker in maximum
assert "self.to_fill.saturating_sub(char_starts(&buf[..len]))" in left
compare_catalogued(0x4739df0,0x4739f20)
compare_catalogued(0x473a190,0x473a210)
for ip,code in ((0x4739e35,"418038c0"),(0x4739ea5,"41803c0ec0"),(0x473a1c5,"41803c3ec0"),(0x473a1dd,"4829f1480f43f9")):
    assert read(".text",ip,len(bytes.fromhex(code))) == bytes.fromhex(code)
    print("width operation",hex(ip),code)
print("maximum and left width UTF-8 boundary operations verified")
