"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
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

source, = from_archive("serde_json-1.0.140",
    "20068b6e96dc6c9bd23e01df8827e6c7e1f2fddd43c21810382803c136b99373", ["src/read.rs"])
definition = re.search(r"fn decode_hex_val_slow.*?^\}", source, re.S | re.M)[0]
ranges = re.findall(r"b'(.)'\.\.=b'(.)' => Some\(val - b'(.)'(?: \+ (\d+))?\)", definition)
assert len(ranges) == 3
assert "None => -1," in source and "(val as i16) << shift" in source
digits = {
    value: value - ord(low) + int(addend or 0)
    for low, high, origin, addend in ranges
    for value in range(ord(origin), ord(high) + 1)
    if low == origin
}
for name, slot, site, opcode in (
        ("HEX0", 0x64ec500, 0x5c57220, "488b15"), ("HEX1", 0x64ec4f8, 0x5c57219, "488b0d")):
    shift, = re.search(rf"static {name}: \[i16; 256\] = build_hex_table\((\d+)\);", source).groups()
    assert rip_target(site, bytes.fromhex(opcode)) == slot
    address = relative[slot]
    expected = struct.pack("<256h", *(digits[i] << int(shift) if i in digits else -1 for i in range(256)))
    actual = read(".rodata", address, len(expected))
    assert actual == expected
    assert bytes([actual[0] ^ 1]) + actual[1:] != expected
    print(name, hex(site), hex(slot), hex(address), len(actual), sha256(actual).hexdigest())
print("both complete tables match, with a byte mutation rejected")
