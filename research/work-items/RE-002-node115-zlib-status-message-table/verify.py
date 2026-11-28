"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import re
import subprocess
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


TOOLS = Path(sys.argv[2])
rows = subprocess.check_output([TOOLS / "readelf", "-rW", TARGET], text=True)
relative = {
    int(slot, 16): int(addr, 16)
    for slot, addr in re.findall(
        r"^([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)$", rows, re.M
    )
}


source, header = from_archive("libz-sys-1.1.22",
    "8b70e7a7df205e92a1a4cd9aaae7898dac0aa555503cc0a649494d0d60e7651d",
    ["src/zlib/zutil.c", "src/zlib/zutil.h"])
body = re.search(r"z_errmsg\[10\] =\s*\{(.*?)\};", source, re.S)[1]
values = re.findall(r'"([^"]*)"', body)
assert len(values) == 10
assert "#define ERR_MSG(err) z_errmsg[(err) < -6 || (err) > 2 ? 9 : 2 - (err)]" in header
address = 0x64da260
for index, text in enumerate(values):
    slot = address + index * 8
    read(".data.rel.ro", slot, 8)
    target = relative[slot]
    expected = text.encode() + b"\0"
    actual = read(".rodata", target, len(expected))
    assert expected == actual
    assert bytes([actual[0] ^ 1]) + actual[1:] != expected
    print(index, hex(slot), hex(target), repr(text))
for ip in (0x630331e, 0x6304629, 0x6304ce0):
    assert rip_target(ip, bytes.fromhex("488d05")) == address
assert read(".text", 0x6303325, 4) == bytes.fromhex("488b4038")
assert read(".text", 0x630332d, 5) == b"\xb8" + struct.pack("<i", -5)
assert (2 - (-5)) * 8 == 0x38
print("ten strings, three base references and observed buffer status index verified")
