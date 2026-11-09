"""Model of node #115's ROT13BlockCipher ':'-split factory 0x5ff7120.

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The factory builds a 0x28-byte rocksdb::(anonymous)::ROT13BlockCipher
(vtable 0x64cfea0) and registers one option group, "ROT13BlockCipherOptions",
with the static OptionTypeInfo map 0x65052c0. The group's options base is
the object's +0x20 field: the block size N (a size_t). The map holds exactly
one entry, "block_size": type 22, verification 1, flags 0x400, field offset 0,
so the configurable field is the +0x20 qword itself.

Spec format: "<anything>:<N>" or "<anything>" (no colon).
  * With a colon, N is the suffix parsed as a base-10 unsigned integer
    (std::stoul family, strtoull base 10 via 0x61d1540); the prefix before
    the colon is never read. Empty or non-numeric suffixes raise.
  * Without a colon, N defaults to 32 (0x20).
The transform (vtable slots 20/21) adds 13 (mod 256) to each of the first N
bytes of the buffer -- byte-wise, with no alphabet check and no wraparound
at 'z', so it is not letter-ROT13 and not self-inverse: a second pass adds
13 again. Slots 20 and 21 have identical bodies.
"""

DEFAULT_BLOCK_SIZE = 32

GROUP_NAME = "ROT13BlockCipherOptions"
GROUP_MAP = 0x65052C0
GROUP_BASE_OFFSET = 0x20
OBJECT_SIZE = 0x28
VTABLE = 0x64CFEA0

MAP_ENTRIES = {
    "block_size": {"type": 22, "verification": 1, "flags": 0x400, "offset": 0},
}


class SpecError(ValueError):
    """The ':' suffix is not a usable block size (empty / non-numeric)."""


def parse_block_size(spec: str) -> int:
    """Return the block size N for a factory spec string.

    Mirrors 0x5ff7120: find(':'); no colon -> 32; otherwise stoul(suffix).
    """
    idx = spec.find(":")
    if idx < 0:
        return DEFAULT_BLOCK_SIZE
    suffix = spec[idx + 1:]
    if not suffix or not suffix.isascii() or not suffix.isdigit():
        raise SpecError(f"bad block size suffix: {suffix!r}")
    value = int(suffix, 10)
    if value > 0xFFFFFFFFFFFFFFFF:
        raise OverflowError(f"block size out of range: {suffix!r}")
    return value


def rot13_block(data: bytes, block_size: int) -> bytes:
    """Add 13 (mod 256) to each of the first ``block_size`` bytes.

    Mirrors vtable slots 20/21 (0x5fef9b0 / 0x5fef9f0): a plain ``addb $0xd``
    loop over the first object+0x20 bytes, with no alphabet or bounds check
    in the binary. The model requires the buffer to hold ``block_size``
    bytes; the binary itself does not check.
    """
    if block_size < 0:
        raise ValueError("block_size must be non-negative")
    if len(data) < block_size:
        raise ValueError(
            f"buffer holds {len(data)} bytes, fewer than block_size {block_size}"
        )
    out = bytearray(data)
    for i in range(block_size):
        out[i] = (out[i] + 13) & 0xFF
    return bytes(out)


class Rot13BlockCipher:
    """The 0x28-byte object the factory 0x5ff7120 builds."""

    def __init__(self, block_size: int):
        self.vtable = VTABLE
        self.size = OBJECT_SIZE
        self.block_size = block_size
        self.groups = [
            {
                "name": GROUP_NAME,
                "base_offset": GROUP_BASE_OFFSET,
                "map": GROUP_MAP,
                "entries": dict(MAP_ENTRIES),
            }
        ]

    def transform(self, data: bytes) -> bytes:
        return rot13_block(data, self.block_size)


def create_cipher(spec: str, out_slot):
    """Build the cipher for ``spec`` and replace ``out_slot[0]`` with it.

    Mirrors 0x5ff7120's replace: a previous object in the slot is destroyed
    via its vtable slot 1 first (modelled as dropping the reference).
    Returns the new cipher.
    """
    cipher = Rot13BlockCipher(parse_block_size(spec))
    old = out_slot[0]
    out_slot[0] = cipher
    return cipher, old
