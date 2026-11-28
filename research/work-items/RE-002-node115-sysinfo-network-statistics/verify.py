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


source, = from_archive("sysinfo-0.29.11", "cd727fc423c2060f6c92d9534cef765c65a6ed3f428a03d7def74a8c4348e666", ["src/linux/network.rs"])
for name in ('rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets', 'rx_errors', 'tx_errors'):
    assert 'read(parent, "' + name + '"' in source
    assert 'old_' + name in source
assert '/sys/class/net/' in source and 'interfaces.retain(|_, d| d.updated)' in source
fields = compare_catalogued(0x5ccf0c0, 0x5ccf98b)
compare_catalogued(0x5ccf990, 0x5ccfc54)
for ip, prefix, addr, literal in ((0x5ccf0d4,'488d35',0x94bfe0,b'/sys/class/net/'),(0x5ccf367,'488d0d',0x94bfef,b'statistics'),(0x5ccf438,'488d15',0x459cd0,b'rx_bytes'),(0x5ccf465,'488d15',0x458e18,b'tx_bytes'),(0x5ccf48d,'488d15',0x94bff9,b'rx_packets'),(0x5ccf4b5,'488d15',0x94c003,b'tx_packets'),(0x5ccf4dd,'488d15',0x94c00d,b'rx_errors'),(0x5ccf505,'488d15',0x94c016,b'tx_errors')):
    selected(fields, ip, bytes.fromhex(prefix), addr)
    assert read('.rodata', addr, len(literal)) == literal
    print('sysfs literal', literal.decode())
print('network refresh paths and six counters verified')
