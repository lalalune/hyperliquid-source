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


source, = from_archive("miniz_oxide-0.8.9",
    "1fa76a2c86f704bdb222d66965fb3d63269ce38518b83cb0575fca855ebb6316",
    ["src/inflate/core.rs"])
items = [
    ("MIN_TABLE_SIZES", 0x7dff9e, "H", [0x47597cd]),
    ("DIST_BASE", 0x7dffb8, "H", [0x4759d5b, 0x475a500]),
    ("LENGTH_BASE", 0x7dfffe, "H", [0x47593c3, 0x475a457]),
    ("LENGTH_EXTRA", 0x4582e0, "B", [0x47593b6, 0x475a44c]),
]
for name, address, fmt, refs in items:
    width, count, body = re.search(
        rf"const {name}: \[u(8|16); (\d+)\] = \[(.*?)\];", source, re.S
    ).groups()
    assert int(width) == 8 * struct.calcsize(fmt)
    values = [int(value.replace("_", "")) for value in re.findall(r"\b\d[\d_]*", body)]
    assert len(values) == int(count)
    check(name, address, f"<{count}{fmt}", values,
          [(ip, "488d35" if ip == 0x475a500 else "488d0d") for ip in refs])
