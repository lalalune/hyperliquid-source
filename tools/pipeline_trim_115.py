"""Node #115 pipeline prologue with its trailing-empty-group trim.

Maps RE-001 windows 0x5f884b0 (148 bytes, the pipeline prologue) and
0x5f6bc20 (65 bytes, the trim) from the digest-verified node #115
binary (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Object layout (all offsets are from the pipeline object's base):

  +0x10   signed 32-bit group count.
  +0x14   signed 32-bit trimmed group count, written by the trim.
  +0xa98 base pointer of the 24-byte group entries (begin, end, and a
          third qword the trim never reads).

Trim rule, stated literally from the native loop:

  trimmed = count is stored to +0x14 at once. If count <= 0 (signed
  32-bit), the trim returns with +0x14 holding count. Otherwise it
  scans entries from the last one downward: while the entry at the
  current index is empty (begin == end), it stores that index to
  +0x14 and moves to the previous entry; the first non-empty entry
  ends the scan and +0x14 keeps the value last stored. So +0x14 ends
  as count when the last group is non-empty, as (index + 1) of the
  last non-empty group when trailing groups are empty, and as 0 when
  every group is empty. A group entry is 24 bytes; only its begin
  (+0) and end (+8) qwords are read.

Pipeline prologue rule, stated literally from the native call order
(rdi = object, rsi = arg2, rdx = arg3; the callees other than the
trim are recorded as steps, not modelled):

  1. call 0x5f6b660(object).
  2. call trim(object) -- the trim above.
  3. call 0x5f79580(object, arg2, arg3).
  4. call 0x5f870a0(object, arg2, arg3).
  5. call 0x5f9c7b0(object + 0xd8, object + 0x1a0,
     sign_extend32(trimmed count)) -- the trimmed count, read back
     from +0x14 after the trim, is this call's third argument.
  6. call 0x5f801f0(object).
  7. call 0x5f6bc90(object).
  8. if the flag byte at arg2 + 0x193 is nonzero, tail-jump to
     0x5f880b0(object) at once; otherwise call 0x5f6d700(object)
     first and then tail-jump to 0x5f880b0(object).

The pipeline is reached only through the tail jump at 0x5f8857c
(site only; the containing wrapper is not modelled here). The
pipeline's own return value is the tail jump's; the model reports
the call sequence and the final branch instead, because the other
callees are unmodelled steps.

Notes on fidelity:

  * The trim's count test is signed 32-bit: count - 1 < 0 returns,
    so count 0 and negative counts leave +0x14 holding count.
  * The trim's empty test compares the entry's end qword against
    its begin qword; a group whose begin pointer is past its end is
    not empty to the native code, it ends the scan.
  * The native code reads memory without checks. The model raises
    PipelineTrimError instead when the group list is shorter than
    the count, when a count is outside the signed 32-bit range, or
    when a group entry is missing.
"""


MASK64 = (1 << 64) - 1


class PipelineTrimError(Exception):
    """Raised for inputs the native code would read unchecked."""


def _s32(value):
    if not isinstance(value, int) or isinstance(value, bool):
        raise PipelineTrimError("value is not an integer: %r" % (value,))
    if value < -(1 << 31) or value > (1 << 31) - 1:
        raise PipelineTrimError(
            "value outside signed 32-bit range: %r" % (value,))
    return value


def _u64(value):
    if not isinstance(value, int) or isinstance(value, bool):
        raise PipelineTrimError("value is not an integer: %r" % (value,))
    if value < 0 or value > MASK64:
        raise PipelineTrimError(
            "value outside unsigned 64-bit range: %r" % (value,))
    return value


def trim_trailing_empty_groups(count, groups):
    """Run the 0x5f6bc20 trim; return the value left in +0x14.

    groups is a list of (begin, end) pairs, one per group entry, in
    index order. Only begin/end are consulted, as the native code
    reads only those two qwords.
    """
    count = _s32(count)
    if len(groups) < count and count > 0:
        raise PipelineTrimError(
            "group list shorter than count: %d < %d" % (len(groups), count))
    trimmed = count
    if count <= 0:
        return trimmed
    index = count - 1
    while True:
        begin, end = groups[index]
        _u64(begin)
        _u64(end)
        if begin == end:
            trimmed = index
            index -= 1
            if index == -1:
                return trimmed
            continue
        return trimmed


def pipeline_prologue(count, groups, flag, steps=None):
    """Run the 0x5f884b0 prologue; return (trimmed, sequence, final).

    steps, when given, is a list the model appends one record per
    native call in order: ("0x5f6b660",), ("trim", trimmed),
    ("0x5f79580",), ("0x5f870a0",),
    ("0x5f9c7b0", trimmed), ("0x5f801f0",), ("0x5f6bc90",),
    then either ("tail 0x5f880b0",) or ("0x5f6d700",) followed by
    ("tail 0x5f880b0",). final is "tail-direct" when the flag byte
    is nonzero and "via-0x5f6d700" otherwise.
    """
    if not isinstance(flag, int) or isinstance(flag, bool):
        raise PipelineTrimError("flag is not an integer: %r" % (flag,))
    seq = steps if steps is not None else []
    seq.append(("0x5f6b660",))
    trimmed = trim_trailing_empty_groups(count, groups)
    seq.append(("trim", trimmed))
    seq.append(("0x5f79580",))
    seq.append(("0x5f870a0",))
    seq.append(("0x5f9c7b0", trimmed))
    seq.append(("0x5f801f0",))
    seq.append(("0x5f6bc90",))
    if flag != 0:
        seq.append(("tail 0x5f880b0",))
        return trimmed, seq, "tail-direct"
    seq.append(("0x5f6d700",))
    seq.append(("tail 0x5f880b0",))
    return trimmed, seq, "via-0x5f6d700"
