"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
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



def sysinfo(file):
    return from_archive("sysinfo-0.29.11",
        "cd727fc423c2060f6c92d9534cef765c65a6ed3f428a03d7def74a8c4348e666",
        ["src/linux/" + file])[0]


source = sysinfo("cpu.rs")
body = re.search(r"    fn get_hex_value\(s: &str\)(.*?)^    \}", source, re.S | re.M)[1]
separator = re.search(r"s\.split\('(.)'\)", body)[1]
prefix = re.search(r'x\.starts_with\("([^"]+)"\)', body)[1]
radix = int(re.search(r"u32::from_str_radix\(&x\[2\.\.\], (\d+)\)", body)[1])
assert read(".text", 0x5cb32cc, 10) == b"\x48\xb8" + struct.pack("<2I", ord(separator), ord(separator))
assert read(".text", 0x5cb33ad, 5) == bytes.fromhex("668138") + prefix.encode()
assert read(".text", 0x5cb3485, 3) == bytes([0x83, 0xfa, radix])
assert read(".text", 0x5cb34c9, 3) == bytes([0x83, 0xfa, radix])
import json
catalog = Path("research/work-items/RE-002-node115-vendor-census")
row = json.loads((catalog / "census.json").read_text())["records"][180]
start, end = row["start"], row["end"]
assert (start, end) == (0x5cb3290, 0x5cb352f)
offset = row["source_offset"]
expected = (catalog / "bodies.bin").read_bytes()[offset:offset + end - start]
actual = read(".text", start, end - start)
assert sha256(expected).hexdigest() == "60e5dd107df501decb32be1bf564b7fd8471ad01b5ccc2638e1dc3f04d02e34c"
assert sha256(actual).hexdigest() == "1e7583d8bf70e511c245d17253d4defc415384f886514d049a8ad19c9c8feb9b"
fields = {index for entry in row["relocations"] for index in range(entry["offset"], entry["offset"] + entry["width"])}
assert all(a == b for index, (a, b) in enumerate(zip(expected, actual)) if index not in fields)
print("matched nonrelocated bytes", len(actual) - len(fields))
print("separator", repr(separator), "prefix", repr(prefix), "radix", radix)
