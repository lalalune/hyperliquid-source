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

source, = from_archive("sha2-0.10.8",
    "793db75ad2bcafc3ffa7c68b215fee268f537982cd901d132f89c6343f3a3dc8", ["src/consts.rs"])
count, inner = re.search(r"pub const K64: \[u64; (\d+)\] = \[(.*?)\];", source, re.S).groups()
values = [int(value.replace("_", ""), 16) for value in re.findall(r"0x[0-9a-fA-F_]+", inner)]
assert len(values) == int(count) == 80
check("SHA-512 round constants", 0x946f80, "<80Q",
      values, [(0x5c6348b, "4c8d1d"), (0x5c639fc, "4c8d05")])
# The first consumer adds two adjacent words via the indexed vector operand.
assert read(".text", 0x5c63492, 6) == bytes.fromhex("c44141d40403")
print("first reference feeds an indexed VPADDQ")
