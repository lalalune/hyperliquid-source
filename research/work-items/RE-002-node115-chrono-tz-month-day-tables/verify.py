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



def chrono(member):
    return from_archive("chrono-0.4.38",
        "a21f936df1771bf62b77f047b726c4625ff2e8aa607c01ec06e5a05bd8463401", [member])[0]

def verify_table(address, expected, sites):
    actual = read(".rodata", address, len(expected))
    assert actual == expected
    for ip, opcode in sites:
        assert rip_target(ip, bytes.fromhex(opcode)) == address
    assert bytes([actual[0] ^ 1]) + actual[1:] != expected
    print(hex(address), len(actual), sha256(actual).hexdigest(),
          "references", " ".join(hex(site) for site, _ in sites))

source = chrono("src/offset/local/tz_info/mod.rs")
tables = (
    ("DAY_IN_MONTHS_NORMAL_YEAR", 0x46b608, ((0x16243e3, "488d15"),)),
    ("CUMUL_DAY_IN_MONTHS_NORMAL_YEAR", 0x46b560, ((0x1624256, "488d0d"), (0x1624312, "488d0d"))),
)
for name, address, sites in tables:
    values = re.search(rf"const {name}: \[i64; 12\] =\s*\[(.*?)\];", source, re.S)[1]
    days = [int(value) for value in re.findall(r"\b\d+\b", values)]
    assert len(days) == 12
    print(name)
    verify_table(address, struct.pack("<12q", *days), sites)
print("both source month-day arrays and three references match")
