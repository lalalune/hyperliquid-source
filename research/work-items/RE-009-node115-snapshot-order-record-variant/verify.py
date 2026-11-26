import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
edges = [(36407765, 2, 36407789), (36407784, 5, 39703904), (36407831, 6, 36408313), (36407864, 6, 36408362), (36408260, 5, 39703904), (36408268, 2, 36408298), (36408291, 5, 36903200)]
anchors = [(36407758, '488d4f08833f01'), (36407842, '42c604285b'), (36407875, '42c604280a'), (36408247, '488b7c2410488b5c24084889de'), (36408274, '66c74424200002')]

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
