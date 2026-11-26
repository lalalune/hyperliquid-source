import hashlib
import struct
from pathlib import Path

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
edges = [(38019205, 6, 38019353), (38019379, 2, 38019486), (38019402, 2, 38019458), (38019456, 2, 38019424), (38019480, 6, 105772192)]
anchors = [(38019368, '48c70600000000'), (38019424, '4989c64d85ff4d8d7f01'), (38019434, 'be90040000490f44f4'), (38019486, '49c7450000000000')]

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
