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


source, = from_archive("url-2.5.4", "32f8b686cadd1473f4bd0117a5d28d36b1ade384ea9b5069a1c40aefed7fda60", ["src/parser.rs"])
body = re.search(r"pub fn default_port\(scheme: &str\).*?^\}", source, re.S | re.M)[0]
for text in ('"http" | "ws" => Some(80)', '"https" | "wss" => Some(443)', '"ftp" => Some(21)', '_ => None'):
    assert text in body
fields = compare_catalogued(0x5d02610, 0x5d02698)
selected(fields, 0x5d02618, b"\x48\x8d\x05", 0x94ffe8)
for ip, port in ((0x5d0263d, 80), (0x5d02658, 443), (0x5d0268e, 443), (0x5d02693, 21)):
    assert read(".text", ip, 4) == b"\x66\xba" + struct.pack("<H", port)
    print("port", port, "at", hex(ip))
for ip, prefix, value in ((0x5d02628, b"\x66\x81\x3f", b"ws"), (0x5d02631, b"\x81\x3f", b"http")):
    assert read(".text", ip, len(prefix)+len(value)) == prefix + value
print("scheme tests and default-port return values checked")
