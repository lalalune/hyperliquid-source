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


source, = from_archive("rustc-demangle-0.1.27", "b50b8869d9fc858ce7266cce0194bd74df58b9d0e3f6df3a9fc8eb470d95c09d", ["src/v0.rs"])
body = re.search(r"fn basic_type\(tag: u8\).*?^\}", source, re.S | re.M)[0]
rows = dict(re.findall(r"b'(.)' => \"([^\"]+)\"", body))
assert len(rows) == 21 and '_ => return None' in body
fields = compare_catalogued(0x5c4bf05, 0x5c4bf30)
selected(fields, 0x5c4bf16, bytes.fromhex("488d0d"), 0x944cf8)
selected(fields, 0x5c4bf21, bytes.fromhex("488d0d"), 0x64c1bd8)
for ip, code in ((0x5c4bf05, "4080c79f"), (0x5c4bf09, "4080ff19"), (0x5c4bf13, "c1e003")):
    assert read(".text", ip, len(bytes.fromhex(code))) == bytes.fromhex(code)
rel = layout['.rela.dyn']
relocations = {}
for offset in range(rel['offset'], rel['offset'] + rel['size'], 24):
    address, info, addend = struct.unpack_from('<QQq', data, offset)
    if 0x64c1bd8 <= address < 0x64c1bd8 + 26 * 8:
        assert info == 8 and address not in relocations
        relocations[address] = addend
for i in range(26):
    tag = chr(ord('a') + i)
    length = struct.unpack('<Q', read('.rodata', 0x944cf8 + i * 8, 8))[0]
    ptr = relocations.get(0x64c1bd8 + i * 8)
    expected = rows.get(tag)
    if expected is None:
        assert length == 0 and ptr is None
    else:
        assert length == len(expected) and ptr is not None
        assert read('.rodata', ptr, length) == expected.encode()
    print(tag, expected if expected is not None else '<none>')
print("all 26 tags and 21 type strings verified via relative relocations")
