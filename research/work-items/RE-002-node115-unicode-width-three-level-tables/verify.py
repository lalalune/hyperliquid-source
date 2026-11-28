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


import subprocess
source, = from_archive("unicode-width-0.1.13", "0336d538f7abc86d282a4189614dfaa90810dfc2c6f6427eaf88e16311dd225d", ["src/tables.rs"])
out = subprocess.check_output([Path(sys.argv[2]) / "readelf", "-rW", TARGET], text=True)
for n, address, got, ip, prefix in ((0, 0x94e500, 0x64e1d80, 0x5d01be5, b"\x48\x8b\x1d"), (1, 0x94e600, 0x64e1d88, 0x5d01bec, b"\x4c\x8b\x35"), (2, 0x94ef80, 0x64e1d90, 0x5d01bf3, b"\x4c\x8b\x3d")):
    m = re.search(r"static TABLES_" + str(n) + r":.*?= Align\d+\(\[(.*?)\]\);", source, re.S)
    values = bytes(int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", m[1]))
    assert read(".rodata", address, len(values)) == values
    assert rip_target(ip, prefix) == got
    assert re.search(r"^0*" + format(got, 'x') + r"\s+\S+\s+R_X86_64_RELATIVE\s+" + format(address, 'x') + r"$", out, re.M)
    print("table", n, "bytes", len(values), "at", hex(address), "via", hex(got), "from", hex(ip))
