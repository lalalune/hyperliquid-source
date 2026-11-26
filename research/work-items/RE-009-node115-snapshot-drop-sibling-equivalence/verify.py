import hashlib
from pathlib import Path
from struct import unpack_from

binary = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(binary).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
bases = (0x2428930, 0x24AA210)
size = 0x3B8
calls = {
    0x242897F: 0x230AF10, 0x24289BF: 0x230AF10, 0x2428A2E: 0x230AF10,
    0x2428A8E: 0x230AF10, 0x2428B1F: 0x230AF10, 0x2428B6C: 0x230AF10,
    0x2428BFB: 0x230AF10, 0x2428C8B: 0x230AF10,
    0x2428BA8: 0x63F0A50, 0x2428CD7: 0x63F0A50,
    0x2428C3A: 0x242A760, 0x2428C46: 0x242A760, 0x2428CCD: 0x242A760,
}
release = (0x24289F1, 0x2428A56, 0x2428AD3, 0x2428AF2, 0x2428B9D, 0x2428C2B, 0x2428CBB)
abort = (0x2428BAD, 0x2428C50, 0x2428C56, 0x2428C5C, 0x2428CDC, 0x2428CE2)
fields = [(va + 1, target, 0x24AB350 if target == 0x242A760 else target)
          for va, target in calls.items()]
fields += [(va + 2, target, target) for target, addresses in
           [(0x64DF4A0, release), (0x64DF4C0, abort)] for va in addresses]

def valid(data):
    bodies = [bytearray(data[base - 0x1000:base - 0x1000 + size]) for base in bases]
    for address, left, right in fields:
        offset = address - bases[0]
        for base, body, target in zip(bases, bodies, (left, right)):
            if base + offset + 4 + unpack_from("<i", body, offset)[0] != target:
                return False
            body[offset:offset + 4] = bytes(4)
    return bodies[0] == bodies[1]

assert valid(binary)
for address in [bases[0]] + [row[0] for row in fields]:
    changed = bytearray(binary)
    changed[address - 0x1000] ^= 1
    assert not valid(changed)
print("PASS: 848 unmasked bytes per body, 26 operand pairs, 27 corruptions rejected")
