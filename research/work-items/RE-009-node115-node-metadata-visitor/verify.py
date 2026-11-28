"""Offline checks of the selected NodeMetadata visitor edges and stores."""
import hashlib
from pathlib import Path
import struct

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CALLS = {
    0x57c3e52: 0x4d51ac0,
    0x4d51b31: 0x4e296b0,
    0x4d51b3f: 0x4e258d0,
    0x4e25996: 0x4d517e0,
    0x4e25a58: 0x4d51720,
    0x4e297db: 0x4d517e0,
    0x4e29938: 0x4d51720,
}
WINDOWS = {
    0x4e2986b: "66813f6876",
    0x4e29876: "66813f6268",
    0x4e25a3c: "48c784249800000020000000",
    0x4e25aac: "4c897b28",
    0x4e25ab0: "48c703000000004983fe02",
    0x4d51729: "48b80300000000000080",
    0x4d517e7: "48b80200000000000080",
}


def verify(data):
    if hashlib.sha256(data).hexdigest() != TARGET:
        raise ValueError("target SHA-256 mismatch")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[0][:6] != b"\x7fELF\x02\x01" or header[2] != 62:
        raise ValueError("expected little-endian x86-64 ELF")
    loads = [
        struct.unpack_from("<IIQQQQQQ", data, header[5] + i * header[9])
        for i in range(header[10])
    ]

    def read(va, size):
        for kind, flags, offset, start, _, length, _, _ in loads:
            if kind == 1 and flags & 1 and start <= va <= start + length - size:
                return data[offset + va - start:offset + va - start + size]
        raise ValueError(f"unmapped executable range {va:#x}")

    for site, expected in CALLS.items():
        raw = read(site, 5)
        op, rel = struct.unpack("<Bi", raw)
        if op != 0xe8 or site + 5 + rel != expected:
            raise ValueError(f"unexpected direct call at {site:#x}")
        print(f"{site:#x}: {raw.hex()} -> {expected:#x}")
    for site, expected in WINDOWS.items():
        raw = read(site, len(expected) // 2)
        if raw.hex() != expected:
            raise ValueError(f"unexpected instruction bytes at {site:#x}")
        print(f"{site:#x}: {raw.hex()}")


if __name__ == "__main__":
    target = Path("artifacts/node/115/hl-node").read_bytes()
    print(f"Linux x86-64 node #115 SHA-256 {TARGET}")
    verify(target)
    try:
        verify(target[:-1] + bytes([target[-1] ^ 1]))
    except ValueError as error:
        if str(error) != "target SHA-256 mismatch":
            raise
        print("Negative control: a changed target is rejected before interpretation")
    else:
        raise RuntimeError("changed target was accepted")
