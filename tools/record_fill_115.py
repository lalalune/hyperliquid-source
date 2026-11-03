"""Python model of node #115's record-fill routine at 0x5f6eb50.

RE-001 work item: research/work-items/RE-001-record-fill-115/.
The routine takes a source object in rdi, a destination record in
rsi, and a pointer in rdx to one qword. It always copies the qword
at src+0xd8 to dst+0x58, stores 1 in the bytes at dst+0x7c and
dst+0x7f, and stores the qword at [rdx] at dst+0x70. It then reads
the byte at dst+0x134: when that byte is zero it returns at once,
with no further call and no write to dst+0x7d or dst+0x60. When
that byte is nonzero it calls the callee at 0x5d8d0c0 with
(src+0x40, dst), then stores 1 in the byte at dst+0x7d and the
callee's 32-bit return value at dst+0x60. The callee's own
semantics are not claimed; it is modelled as an oracle. No meaning
for any field beyond the offsets read and written is claimed.
"""

MASK32 = (1 << 32) - 1


def record_fill(src, dst, ptr_qword, oracle):
    """Apply the 0x5f6eb50 rule in place.

    ``src`` and ``dst`` map field offsets to values; byte fields
    hold 0/1 (or any nonzero byte value for the gate), qword fields
    hold ints, and dst+0x60 holds the 32-bit value the callee
    returned. ``ptr_qword`` is the qword at [rdx]. ``oracle`` is
    called only on the nonzero-gate arm, with (src+0x40, dst).
    Raises ValueError when a field the routine reads or writes is
    absent, so a caller cannot silently model a partially known
    record. Returns the destination mapping, for chaining.
    """
    if 0xD8 not in src:
        raise ValueError("src is missing field 0xd8")
    for offset in (0x58, 0x7C, 0x7F, 0x70, 0x134):
        if offset not in dst:
            raise ValueError("dst is missing field %#x" % offset)
    dst[0x58] = src[0xD8]
    dst[0x7C] = 1
    dst[0x7F] = 1
    dst[0x70] = ptr_qword
    if dst[0x134] == 0:
        return dst
    if 0x40 not in src:
        raise ValueError("src is missing field 0x40")
    for offset in (0x7D, 0x60):
        if offset not in dst:
            raise ValueError("dst is missing field %#x" % offset)
    result = oracle(src[0x40], dst)
    dst[0x7D] = 1
    dst[0x60] = result & MASK32
    return dst
