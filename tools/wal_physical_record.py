"""Python model of node #94 0x5161400: WAL physical-record decode,
with its block-refill helper 0x51612a0 (see
research/work-items/RE-001-wal-physical-record-94/).

The reader struct (offsets are the binary's, not names invented
here):

- +0x18: block-source handle passed to the refill read call.
- +0x28: checksum flag; nonzero means the CRC gate runs.
- +0x30: second argument passed to the refill read call.
- +0x38: buffer pointer (a Slice-like pair with +0x40).
- +0x40: bytes remaining in the buffer.
- +0x48: short-final-block flag, set by the refill helper.
- +0x49: latched read-error flag, set by the refill helper.
- +0x50: length of the short final block, set with +0x48.
- +0x60: cumulative bytes supplied by the refill helper.
- +0x68: expected log number for recyclable records.
- +0x70: sticky flag, set when a recyclable header is seen while
  the cumulative count equals the bytes remaining (meaning not
  pinned beyond that transition; see the packet README).
- +0x78: attached stream object (vtable slots +0x10 read-like
  and +0x18 skip-like). None means no stream object.
- +0x80: data pointer handed to the stream/transform calls.
- +0x88/+0x90: scratch string (pointer/length) that receives
  assembled fragments on the stream/transform paths.
- +0xb0: lazily created helper object for the transform path.

Record framing, all pinned from the bytes:

- Plain header, 7 bytes: CRC u32 at +0, length u16 at +4, type
  s8 at +6, payload at +7.
- Recyclable header, 11 bytes: the same fields plus log number
  u32 at +7, payload at +11. Types 5..8 (signed) take this form;
  every other type takes the 7-byte form.
- Block size requested by the refill helper: 0x8000 bytes. A
  block of 0x7fff bytes or fewer marks the final block.
- CRC gate (only when +0x28 is nonzero): the stored CRC is
  unmasked as rotl15(stored - 0xa282ead8) and compared against
  CRC-32C extended from seed 0 over the bytes from the type byte
  through the end of the payload, that is header_size + length
  - 6 bytes starting at buffer + 6. The CRC routine itself is
  reached through a PLT import, so the model implements the
  standard CRC-32C algorithm and the tests pin it against the
  published check value instead of claiming a byte-level match
  with the linked routine.

Return codes, each pinned by its triggering condition:

- 0..9: the record type byte itself (0 zero, 1 full, 2 first,
  3 middle, 4 last, 5..8 recyclable, 9 set-compression).
- 10: end of data (refill helper found nothing left).
- 11: zero-type record with zero length (trailer cleared), or a
  negative status from a stream/transform call (buffer cleared).
- 12: leftover bytes too short for a header after the final
  block was seen; the leftover size is written to the out
  parameter and the buffer is cleared.
- 13: recyclable record whose log number differs from +0x68;
  the buffer is left untouched on this path.
- 14: header (7 or 11 bytes plus payload) extends past the
  remaining buffer; the remaining size is written to the out
  parameter and the buffer is cleared.
- 15: CRC mismatch; the remaining size is written to the out
  parameter and the buffer is cleared.
- Above 15: the logical-reader caller (0x51618e0, both call
  sites) treats the code as an error; this window never returns
  such a code on the paths modeled here.

The stream/transform vtable calls are contracts, not pinned
implementations: the model takes them as caller-supplied
callables and pins only the call shapes, the loop condition
(continue while status != 0 or the chunk is a full 0x8000-byte
block), the scratch redirect, and the negative-status rule.
The 4th argument is a nullable out-pointer: NULL selects the
plain stream-read assembly path, non-NULL selects the transform
path and receives the cleanup call's result on completion.
"""

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
BLOCK_SIZE = 0x8000
SHORT_BLOCK_MAX = 0x7FFF
CRC_MASK_DELTA = 0xA282EAD8
LENGTH_CAP = 0x3FFFFFFFFFFFFFFF

EMPTY_SENTINEL = 0x1E629B  # buffer pointer stored on clear paths

CODE_EOF = 10
CODE_TRAILER_OR_STREAM_FAIL = 11
CODE_LEFTOVER = 12
CODE_LOG_NUMBER = 13
CODE_TRUNCATED = 14
CODE_BAD_CRC = 15

RECYCLABLE_MIN = 5
RECYCLABLE_MAX = 8
TYPE_SET_COMPRESSION = 9


def _crc32c_table():
    poly = 0x82F63B78
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        table.append(crc)
    return table


_CRC_TABLE = _crc32c_table()


def crc32c_extend(seed, data):
    """CRC-32C extended from ``seed`` (the library's Extend with
    the usual pre/post conditioning, so seed 0 gives the standard
    CRC-32C of ``data``)."""
    crc = (seed ^ MASK32) & MASK32
    for byte in data:
        crc = _CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return (crc ^ MASK32) & MASK32


def mask_crc(crc):
    """The WAL masking applied to a stored CRC."""
    return ((((crc >> 15) | (crc << 17)) & MASK32) + CRC_MASK_DELTA) & MASK32


def unmask_crc(stored):
    """Inverse of mask_crc, as the window computes it: subtract
    the delta, then rotate left by 15 (equivalently rotate right
    by 17)."""
    tmp = (stored - CRC_MASK_DELTA) & MASK32
    return ((tmp << 15) | (tmp >> 17)) & MASK32


class InconsistentReader(ValueError):
    """Raised where the binary would divide by zero, throw
    length_error, or walk a reader state that contradicts itself
    (for example a scratch append past LENGTH_CAP)."""


class Reader:
    """The reader struct state that 0x5161400 / 0x51612a0 move."""

    def __init__(self, buffer=b"", checksum=True, expected_log=0,
                 stream=None, out_pointer=None):
        self.buffer = bytes(buffer)
        self.checksum = bool(checksum)
        self.expected_log = expected_log & MASK32
        self.stream = stream  # None, or an object with read/transform
        self.out_pointer = out_pointer  # None selects the read path
        self.flag48 = False
        self.flag49 = False
        self.final_block_len = 0
        self.total_buffered = 0
        self.flag70 = False
        self.scratch = b""
        self.helper_created = False
        self.out_value = None  # last value written to the out param

    @property
    def remaining(self):
        return len(self.buffer)


def _refill(reader, block_source):
    """The 0x51612a0 helper. Returns (retry, code). ``code`` is
    meaningful only when retry is False. ``block_source`` is the
    abstracted 0x52a87d0 read call: it returns (status, chunk)
    where status 0 means success. The previous block storage is
    released on every path; that has no observable state here."""
    if reader.flag48 or reader.flag49:
        if reader.remaining == 0:
            reader.buffer = b""
            return False, CODE_EOF
        reader.out_value = reader.remaining
        reader.buffer = b""
        return False, CODE_LEFTOVER
    status, chunk = block_source()
    if status != 0:
        # Error path: buffer cleared, error latched, caller loops
        # once more and then takes the leftover path above.
        reader.buffer = b""
        reader.flag49 = True
        return True, CODE_EOF
    reader.buffer = bytes(chunk)
    reader.total_buffered += len(chunk)
    if len(chunk) <= SHORT_BLOCK_MAX:
        reader.flag48 = True
        reader.final_block_len = len(chunk)
    return True, CODE_EOF


def _assemble_via_stream(reader, length, stream_read):
    """The 0x516173e read loop (4th argument NULL): repeatedly
    call the stream read until status == 0 with a short chunk.
    Returns (fragment, code) where code is None on success or 11
    on a negative status."""
    scratch = bytearray()
    while True:
        status, chunk = stream_read(length)
        if status < 0:
            reader.buffer = b""
            return None, CODE_TRAILER_OR_STREAM_FAIL
        chunk = bytes(chunk)
        if chunk:
            if len(chunk) > LENGTH_CAP - len(scratch):
                raise InconsistentReader("scratch append past cap")
            scratch += chunk
            if status != 0 or len(chunk) == BLOCK_SIZE:
                continue
            return bytes(scratch), None
        if status == 0:
            return bytes(scratch), None
        # status != 0 with an empty chunk: loop again.


def _assemble_via_transform(reader, payload, length, transform_step):
    """The transform loop (4th argument non-NULL): the helper
    object is created on first use, then transform steps run
    until status == 0 with a short chunk. Returns
    (fragment, code, cleanup_result) where code is None on
    success or 11 on a negative status."""
    if not reader.helper_created:
        reader.helper_created = True
    scratch = bytearray()
    while True:
        status, chunk = transform_step(payload, length)
        if status < 0:
            reader.buffer = b""
            return None, CODE_TRAILER_OR_STREAM_FAIL, None
        chunk = bytes(chunk)
        if chunk:
            if len(chunk) > LENGTH_CAP - len(scratch):
                raise InconsistentReader("scratch append past cap")
            scratch += chunk
            if status != 0 or len(chunk) == BLOCK_SIZE:
                continue
            return bytes(scratch), None, "cleanup"
        if status == 0:
            return bytes(scratch), None, "cleanup"
        # status != 0 with an empty chunk: loop again.


def read_physical_record(reader, block_source, stream_read=None,
                         transform_step=None):
    """One 0x5161400 call. Returns (code, fragment, out_value):

    - code: the record type byte, or one of 10..15 above.
    - fragment: the payload bytes on success, None otherwise.
      On the stream/transform paths this is the assembled scratch
      string, not a slice of the buffer.
    - out_value: the value written to the out parameter on the
      12/14/15 paths (leftover/remaining size), else None. On the
      transform path the caller's out-pointer receives the
      cleanup result; that value is returned here as out_value
      only when it is a real value (the model reports the string
      "cleanup" as a placeholder for the unpinned call result).
    """
    while True:
        remaining = reader.remaining
        if remaining <= 6:
            retry, code = _refill(reader, block_source)
            if retry:
                continue
            return code, None, (reader.out_value
                                if code == CODE_LEFTOVER else None)
        buf = reader.buffer
        length = buf[4] | (buf[5] << 8)
        raw_type = buf[6]
        rtype = raw_type - 256 if raw_type >= 128 else raw_type
        if RECYCLABLE_MIN <= rtype <= RECYCLABLE_MAX:
            if reader.total_buffered == remaining:
                reader.flag70 = True
            if remaining <= 10:
                retry, code = _refill(reader, block_source)
                if retry:
                    continue
                return code, None, (reader.out_value
                                    if code == CODE_LEFTOVER else None)
            log_number = int.from_bytes(buf[7:11], "little")
            if log_number != reader.expected_log:
                return CODE_LOG_NUMBER, None, None
            header = 11
            if remaining < length + header:
                reader.out_value = remaining
                reader.buffer = b""
                return CODE_TRUNCATED, None, reader.out_value
        else:
            header = 7
            if remaining < length + header:
                reader.out_value = remaining
                reader.buffer = b""
                return CODE_TRUNCATED, None, reader.out_value
            if (rtype | length) == 0:
                reader.buffer = b""
                return CODE_TRAILER_OR_STREAM_FAIL, None, None
        if reader.checksum:
            stored = int.from_bytes(buf[0:4], "little")
            covered = buf[6:6 + header + length - 6]
            if crc32c_extend(0, covered) != unmask_crc(stored):
                reader.out_value = remaining
                reader.buffer = b""
                return CODE_BAD_CRC, None, reader.out_value
        payload = buf[header:header + length]
        reader.buffer = buf[header + length:]
        if reader.stream is None:
            return rtype, bytes(payload), None
        if rtype == TYPE_SET_COMPRESSION:
            return rtype, bytes(payload), None
        reader.scratch = b""
        if reader.out_pointer is None:
            fragment, code = _assemble_via_stream(
                reader, length, stream_read)
            if code is not None:
                return code, None, None
            reader.scratch = fragment
            return rtype, fragment, None
        fragment, code, _cleanup = _assemble_via_transform(
            reader, bytes(payload), length, transform_step)
        if code is not None:
            return code, None, None
        reader.scratch = fragment
        return rtype, fragment, "cleanup"
