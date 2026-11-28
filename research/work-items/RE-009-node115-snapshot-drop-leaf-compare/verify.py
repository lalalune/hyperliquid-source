import hashlib
from pathlib import Path
from struct import unpack_from

image = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(image).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BASES = (0x242A760, 0x24AB350)
SIZE = 202
OPERANDS = {
    0x242A78F: 0x230AF10,
    0x242A7C5: 0x64DF4A0,
    0x242A7EC: 0x230AF10,
    0x242A818: 0x64DF4A0,
    0x242A820: 0x63F0A50,
    0x242A826: 0x64DF4C0,
}

def normalize(body, base):
    result = bytearray(body)
    for address, target in OPERANDS.items():
        offset = address - BASES[0]
        displacement = unpack_from("<i", body, offset)[0]
        if base + offset + 4 + displacement != target:
            return None
        result[offset:offset + 4] = bytes(4)
    return result

bodies = [image[base - 0x1000:base - 0x1000 + SIZE] for base in BASES]
reference = normalize(bodies[0], BASES[0])
assert reference is not None and reference == normalize(bodies[1], BASES[1])
for base, body in zip(BASES, bodies):
    for offset in (0, *(address - BASES[0] for address in OPERANDS)):
        mutated = bytearray(body)
        mutated[offset] ^= 1
        assert normalize(mutated, base) != reference

print("PASS: two 202-byte spans, 178 literal bytes per span, six destination pairs, 14 rejected mutations")
