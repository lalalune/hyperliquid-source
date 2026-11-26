import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
edges = [(40523969, 2, 40524006), (40523997, 2, 40524011), (40524001, 5, 40525176), (40527483, 2, 40527519), (40527510, 2, 40527524), (40527514, 5, 40528221)]
anchors = [(40523965, '4883fa09'), (40523971, '48b82f6465762f6e756c'), (40523990, '4883f16c'), (40523999, '31c0'), (40527479, '4883fa09'), (40527485, '48b82f6465762f6e756c'), (40527503, '4883f16c'), (40527512, '31c0')]

def valid(data):
    for address, width, target in edges:
        size = 1 if width == 2 else 4
        offset = address + width - size - 0x1000
        displacement = struct.unpack_from("<b" if size == 1 else "<i", data, offset)[0]
        if address + width + displacement != target:
            return False
    for address, encoded in anchors:
        expected = bytes.fromhex(encoded)
        offset = address - 0x1000
        if data[offset:offset + len(expected)] != expected:
            return False
    return True

assert valid(binary)
for address in [a + w - 1 for a, w, _ in edges] + [a for a, _ in anchors]:
    damaged = bytearray(binary)
    damaged[address - 0x1000] ^= 1
    assert not valid(damaged)
print(f"PASS: pinned digest, {len(edges)} edges, {len(anchors)} instruction anchors, and {len(edges)+len(anchors)} rejected mutations")
