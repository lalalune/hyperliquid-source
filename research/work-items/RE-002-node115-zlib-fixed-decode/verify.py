"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CACHE, TOOLS = map(Path, sys.argv[1:3])
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


def c_table(source, variable):
    count, body = re.search(rf"\b{variable}\[(\d+)\]\s*=\s*\{{(.*?)\}}", source, re.S).groups()
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    values = [int(value) for value in re.findall(r"-?\d+", body)]
    assert len(values) == int(count)
    return values


def verify_table(section, address, source_values, fmt):
    want = struct.pack(f"<{len(source_values)}{fmt}", *source_values)
    actual = read(section, address, len(want))
    assert actual == want
    modified = bytes([actual[0] ^ 1]) + actual[1:]
    assert modified != want
    return len(actual)




def initializer(source, variable):
    return re.search(rf"\b{variable}\[[^\]]+\]\s*=\s*\{{(.*?)\}};", source, re.S)[1]

source, types = from_archive(
    "libz-sys-1.1.22", "8b70e7a7df205e92a1a4cd9aaae7898dac0aa555503cc0a649494d0d60e7651d",
    ("src/zlib/inffixed.h", "src/zlib/inftrees.h"))
assert re.search(r"unsigned char op;.*?unsigned char bits;.*?unsigned short val;", types, re.S)
for label, count, address, caller, prefix in [
    ("lenfix", 512, 0x986c40, 0x6305a15, "488d0d"),
    ("distfix", 32, 0x986bc0, 0x6305a07, "488d15"),
]:
    values = [tuple(int(field.strip()) for field in row.split(","))
              for row in re.findall(r"\{([^}]+)\}", initializer(source, label))]
    assert len(values) == count
    assert rip_target(caller, bytes.fromhex(prefix)) == address
    expected = b"".join(struct.pack("<BBH", *row) for row in values)
    actual = read(".rodata", address, count * 4)
    assert actual == expected
    assert actual != bytes([expected[0] ^ 1]) + expected[1:]
    print(f"{label} {address:#x}: {count} complete entries match; code reference {caller:#x}")
print("modified code table entry rejected")
