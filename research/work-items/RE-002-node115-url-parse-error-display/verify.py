"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import ast
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



def check_dispatch(start, end, table, variants, literals, delegated):
    assert rip_target(start + 3, bytes.fromhex("488d0d")) == table
    entry = read(".text", start + 10, 9)
    assert entry == bytes.fromhex("486304814801c8ffe0")
    arms = struct.unpack(f"<{len(variants)}i", read(".rodata", table, 4 * len(variants)))
    assert len(set(arms)) == len(arms)
    for index, (variant, delta) in enumerate(zip(variants, arms)):
        address = table + delta
        assert start + 19 <= address < end
        if variant in delegated:
            expected = bytes.fromhex(delegated[variant])
            assert read(".text", address, len(expected)) == expected
            print(index, variant, hex(address), "delegated")
            continue
        want = literals[variant].encode()
        assert read(".text", address, 11) == bytes.fromhex("488b3e488b4608488b4018")
        string = rip_target(address + 11, bytes.fromhex("488d35"))
        size = read(".text", address + 18, 7)
        assert size[:1] == b"\xba" and size[5:] == b"\xff\xe0"
        assert struct.unpack("<I", size[1:5])[0] == len(want)
        actual = read(".rodata", string, len(want))
        assert actual == want
        assert bytes([actual[0] ^ 1]) + actual[1:] != want
        print(index, variant, hex(address), hex(string), len(want), sha256(actual).hexdigest())

source, = from_archive("url-2.5.4",
    "32f8b686cadd1473f4bd0117a5d28d36b1ade384ea9b5069a1c40aefed7fda60", ["src/parser.rs"])
macro = re.search(r"simple_enum_error! \{(.*?)^\}", source, re.S | re.M)[1]
strings = dict(re.findall(r'(\w+) => "([^"]+)"', macro))
assert len(strings) == 10
check_dispatch(0x5d0a2e0, 0x5d0a3ed, 0x950354, list(strings), strings, {})
print("all enum arm and literal mutation controls passed")
