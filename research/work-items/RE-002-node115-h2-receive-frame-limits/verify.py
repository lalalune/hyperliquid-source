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


codec, frame, settings = from_archive("h2-0.3.26", "81fe527a889e1532da5c525686d96d4c2e74cdd345badf8dfef9f6b39dd5f5e8", ["src/codec/mod.rs", "src/codec/framed_read.rs", "src/frame/settings.rs"])
body = re.search(r"pub fn with_max_recv_frame_size\(.*?^    \}", codec, re.S | re.M)[0]
for fragment in ('.big_endian()', '.length_field_length(3)', '.length_adjustment(9)', '.num_skip(0)', 'inner.set_max_frame_size(max_frame_size)'):
    assert fragment in body
assert 'DEFAULT_MAX_FRAME_SIZE as usize <= val && val <= MAX_MAX_FRAME_SIZE as usize' in frame
assert 'DEFAULT_MAX_FRAME_SIZE: FrameSize = 16_384' in settings
assert 'MAX_MAX_FRAME_SIZE: FrameSize = (1 << 24) - 1' in settings
compare_catalogued(0x1717af0, 0x1717c21)
compare_catalogued(0x2bad0c0, 0x2bad2a6)
for ip, code in ((0x1717b2b, '48c744241803000000'), (0x1717b34, '48c744242809000000'), (0x1717b6f, '498d8600c0ffff'), (0x1717b76, '483d00c0ff00'), (0x1717b7c, '736f')):
    assert read('.text', ip, len(bytes.fromhex(code))) == bytes.fromhex(code)
    print('receive constructor instruction', hex(ip), code)
print('three-byte length, nine-byte adjustment and 16384..16777215 bounds verified')
