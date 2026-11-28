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


source, = from_archive("sysinfo-0.29.11", "cd727fc423c2060f6c92d9534cef765c65a6ed3f428a03d7def74a8c4348e666", ["src/users.rs"])
body = re.search(r"pub\(crate\) fn get_users_list\(\).*?^\}", source, re.S | re.M)[0]
for fragment in ('Vec::with_capacity(2048)', 'Vec::with_capacity(256)', 'File::open("/etc/passwd")', "line.split(':')", 'parts.skip(1)', 'get_user_groups(', 'uid: Uid(uid)', 'gid: Gid(group_id)'):
    assert fragment in body
fields = compare_catalogued(0x5cc8e60, 0x5cc913e)
assert read('.text', 0x5cc8f03, 10) == bytes.fromhex('48b82f6574632f706173')
assert read('.text', 0x5cc8f15, 11) == bytes.fromhex('c78424e700000073737764')
print('embedded overlapping instructions construct /etc/passwd')
for ip, code in ((0x5cc8e8a, 'bf00080000'), (0x5cc8ec9, '48c744243800010000')):
    assert read('.text', ip, len(bytes.fromhex(code))) == bytes.fromhex(code)
    print('allocation instruction', hex(ip), code)
print('passwd source path, buffer capacities and users enumeration body verified')
