import hashlib
import struct
from pathlib import Path

data = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
phoff = struct.unpack_from("<Q", data, 32)[0]
entsize, count = struct.unpack_from("<HH", data, 54)
segments = [
    struct.unpack_from("<IIQQQQQQ", data, phoff + i * entsize)
    for i in range(count)
]

def offset(va):
    return next(off + va - start for kind, _, off, start, _, size, _, _
                in segments if kind == 1 and start <= va < start + size)

def verify(blob):
    def read(va, size):
        pos = offset(va)
        return blob[pos:pos + size]

    def rip(va):
        return va + 7 + struct.unpack("<i", read(va + 3, 4))[0]

    return (
        read(0x46AA482, 9) == bytes.fromhex("4881fe00e1f5057360")
        and read(0x46AA4EB, 7) == bytes.fromhex("4881c6001f0afa")
        and read(0x46AA4A3, 7) == bytes.fromhex("488d442428eb6a")
        and read(0x46AA50F, 5) == bytes.fromhex("488d442430")
        and rip(0x46AA48B) == 0x45A1D0
        and rip(0x46AA4F7) == 0x45A124
        and rip(0x46AA497) == rip(0x46AA503) == 0x64DFEE8
        and read(0x45A1D0, 1) == b"@"
        and read(0x45A124, 1) == b"#"
        and read(0x46AA536, 23) == bytes.fromhex(
            "ff15ac51e301488b442448488943100f104424380f1103"
        )
    )

assert verify(data)
for va in (0x46AA489, 0x46AA4EE, 0x46AA48E, 0x45A124, 0x46AA536):
    changed = bytearray(data)
    changed[offset(va)] ^= 1
    assert not verify(changed)
print("PASS: pinned digest, 10 observations and 5 mutation controls")
