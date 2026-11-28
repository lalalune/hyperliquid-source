"""Verify selected optional dictionary edges into the native LZ4 stream API."""
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import sections

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == SHA
layout = {s["name"]: s for s in sections(data)}


def read(section, va, size):
    row = layout[section]
    rel = va - row["address"]
    assert 0 <= rel <= row["size"] - size
    offset = row["offset"] + rel
    return data[offset:offset + size]


def destination(va, instruction):
    assert instruction[0] == 0xe8 and len(instruction) == 5
    return va + 5 + struct.unpack_from("<i", instruction, 1)[0]


print("node #115 sha256", SHA)
for place, edge, install, dec in [
    (0x5db11a2, "7409", 0x5db11af, 0x5db11d9),
    (0x616c74d, "0f850e010000", 0x616c86c, 0x616c77c),
]:
    assert read(".text", place, 7).hex() == "488b50384885d2"
    branch = read(".text", place + 7, len(bytes.fromhex(edge)))
    assert branch.hex() == edge
    displacement = branch[1:] if len(branch) == 2 else branch[2:]
    taken = place + 7 + len(branch) + int.from_bytes(displacement, 'little', signed=True)
    assert taken == (0x5db11b4 if len(branch) == 2 else 0x616c868)
    assert read(".text", install - 4, 4).hex() == "488b7030"
    a = read(".text", install, 5)
    assert destination(install, a) == 0x62ed7f0
    b = read(".text", dec, 5)
    assert destination(dec, b) == 0x62ed820
    assert destination(install, a[:1] + bytes([a[1] ^ 1]) + a[2:]) != 0x62ed7f0
    print(f"{place:#x} tests dictionary length at +0x38; {install:#x} sets pointer from +0x30; {dec:#x} decodes")
assert read(".text", 0x616c871, 5).hex() == "e9e4feffff"
assert 0x616c876 + struct.unpack("<i", bytes.fromhex("e4feffff"))[0] == 0x616c75a
print("two altered setStreamDecode call displacements rejected")
