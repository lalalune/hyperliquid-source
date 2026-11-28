import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
edges = [(37986907, 5, 38216384), (37986918, 2, 37986936), (37986930, 6, 105772192), (37986950, 5, 37937088), (37986964, 2, 37986982), (37986976, 6, 105772192), (37986989, 5, 37937088), (37986997, 5, 104794704)]
anchors = [(37986900, '4889fb4883c740'), (37986920, '488b7b0848c1e60331d2'), (37986936, '4883c3204889df'), (37986955, '4989c6'), (37986982, '4883c3204889df'), (37986994, '4c89f7')]

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
