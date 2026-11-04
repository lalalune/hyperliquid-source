"""Python model of the RE-001 record initializer 0x5d515b0 (node #115).

Models only the established semantics from
research/work-items/RE-001-record-init-515b0-115/: the routine takes
one argument, a record pointer in rdi, and returns nothing. It is
straight-line code with no calls and no branches: it writes a fixed
set of fields and leaves every other byte untouched. Self-referential
fields are expressed as ("self", offset) pairs, i.e. the field holds
the record's own address plus that offset. The record is at least
0x171 bytes long (the highest write reaches +0x170); its total size
is not pinned.

Field readings kept separate from observations: the triples
(+0x08 -> own +0x18, +0x10 = 0, byte +0x18 = 0),
(+0x28 -> own +0x38, +0x30 = 0, byte +0x38 = 0) and
(+0x138 -> own +0x148, +0x140 = 0, byte +0x148 = 0) read as three
empty short-form strings, and the pairs (+0xb0, +0xb8) both holding
own +0xa0 and (+0x160 holding own +0x170, +0x168 = 0) read as two
empty ranges. Those readings are inferences; the field values
themselves are observations.
"""

ADDRESS = 0x5D515B0
SIZE_BYTES = 342
MIN_SIZE = 0x171

# (offset, width_in_bytes, value) for scalar writes; value 0 or
# ("self", target_offset) for a self-referential pointer field.
SCALAR_WRITES = [
    (0x00, 4, 0),
    (0x08, 8, ("self", 0x18)),
    (0x10, 8, 0),
    (0x18, 1, 0),
    (0x28, 8, ("self", 0x38)),
    (0x30, 8, 0),
    (0x38, 1, 0),
    (0x58, 8, 0),
    (0x60, 4, 0),
    (0x78, 8, 0),
    (0x90, 8, 0),
    (0xA0, 4, 0),
    (0xA8, 8, 0),
    (0xB0, 8, ("self", 0xA0)),
    (0xB8, 8, ("self", 0xA0)),
    (0xC0, 8, 0),
    (0x128, 8, 0),
    (0x130, 4, 0),
    (0x134, 2, 0),
    (0x138, 8, ("self", 0x148)),
    (0x140, 8, 0),
    (0x148, 1, 0),
    (0x158, 1, 0),
    (0x15C, 4, 0),
    (0x160, 8, ("self", 0x170)),
    (0x168, 8, 0),
    (0x170, 1, 0),
]

# 16-byte blocks written as zero.
ZERO_BLOCKS = [0x48, 0x68, 0x80, 0xC8, 0xD8, 0xE8, 0xF8, 0x108, 0x118]

# Byte ranges the routine does not write; their values are not
# established by this routine and the model never claims them.
GAPS = [(0x04, 0x08), (0x19, 0x28), (0x39, 0x48), (0x64, 0x68),
        (0x98, 0xA0), (0xA4, 0xA8), (0x136, 0x138), (0x149, 0x158),
        (0x159, 0x15C)]


def established_offsets():
    """Every byte offset the routine writes, in ascending order."""
    offsets = set()
    for offset, width, _value in SCALAR_WRITES:
        offsets.update(range(offset, offset + width))
    for base in ZERO_BLOCKS:
        offsets.update(range(base, base + 16))
    return sorted(offsets)


class Record:
    """A byte-addressable record; only established fields are modeled."""

    def __init__(self, base=0x100000):
        self.base = base
        # Pre-fill with a sentinel so a test can tell "written by
        # init" apart from "never touched by init".
        self.mem = {}

    def _resolve(self, value):
        if isinstance(value, tuple):
            return self.base + value[1]
        return value

    def init(self):
        """Apply exactly the writes of 0x5d515b0; return nothing."""
        for offset, width, value in SCALAR_WRITES:
            resolved = self._resolve(value)
            for i in range(width):
                self.mem[offset + i] = (resolved >> (8 * i)) & 0xFF
        for base in ZERO_BLOCKS:
            for i in range(16):
                self.mem[base + i] = 0
        return None

    def read(self, offset, width):
        """Read a little-endian value from the modeled bytes."""
        value = 0
        for i in range(width):
            value |= self.mem.get(offset + i, 0) << (8 * i)
        return value

    def is_established(self, offset):
        """True when the routine writes this byte offset."""
        return offset in set(established_offsets())

    def short_string(self, at):
        """Read the (pointer, size, first-buffer-byte) triple at `at`.

        This is the inferred string reading, not an observation: the
        routine itself only writes the three fields.
        """
        return (self.read(at, 8), self.read(at + 8, 8),
                self.mem.get(self.read(at, 8) - self.base, None))
