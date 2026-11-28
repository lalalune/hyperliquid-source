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


def check(name, address, fmt, values, refs):
    expected = struct.pack(fmt, *values)
    actual = read(".rodata", address, len(expected))
    assert actual == expected
    for location, prefix in refs:
        assert rip_target(location, bytes.fromhex(prefix)) == address
    assert (bytes([actual[0] ^ 1]) + actual[1:]) != expected
    print(name, hex(address), len(values), len(actual), sha256(actual).hexdigest())
    for location, _ in refs:
        print("linked reference", hex(location), "->", hex(address))
    print("one-byte mutation rejected")

source, = from_archive("librocksdb-sys-0.11.0+8.1.1",
    "d3386f101bcb4bd252d8e9d2fb41ec3b0862a15a62b478c355b2982efa469e3e",
    ["snappy/snappy.cc"])
compact = re.sub(r"//[^\n]*|\s+", "", source)
for expression in (
    "returnlen-(offset<<8);",
    "returntype==3?0xFF:type==2?MakeEntry(data+1,0):type==1?MakeEntry((data&7)+4,data>>3):data<60?MakeEntry(data+1,1):0xFF;",
    "returnLengthMinusOffset(tag>>2,tag&3);",
    "length_minus_offset;uint32_textract_masks[4];",
):
    assert expression in compact
mask_fields = re.search(r"MakeTable\(make_index_sequence<256>\{\}\),\{(.*?)\}\};", compact)[1]
extract = [int(value, 0) for value in mask_fields.split(",")]
assert len(extract) == 4

def tag_entry(tag):
    data, kind = divmod(tag, 4)
    if kind == 2:
        return data + 1
    if kind == 1:
        return (data & 7) + 4 - ((data >> 3) << 8)
    if kind == 0 and data < 60:
        return data + 1 - 256
    return 255

shift_array = re.search(r"staticconstuint8_tmasks\[\]=\{(.*?)\};", compact)[1]
shift_masks = [int(value, 16) for value in re.findall(r"0x[0-9a-fA-F]+", shift_array)]
check("tag lengths and extraction masks", 0x9809c0, "<256h4I",
      [tag_entry(tag) for tag in range(256)] + extract,
      [(0x620cc4b, "4c8d35"), (0x620d077, "488d15")])
check("left shift masks", 0x9809a0, "<32B", shift_masks, [(0x620d9bb, "4c8d3d")])
