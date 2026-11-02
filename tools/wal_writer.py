"""Python model of node #94 WAL writer AddRecord (0x5163730), its fragment
emitter (0x5163550) and its compression-type record setup (0x5163ba0).

Evidence packet: research/work-items/RE-001-wal-writer-94/ (records.json,
whole-function verbatim excerpts, verify.py). The model implements only the
semantics pinned by the branch conditions in those windows. The append
(0x52b4050), completion (0x52b13f0), compressor virtuals and factory
(0x54215e0) are oracles: the tests inject fakes that follow the recorded
call protocol. Unknowns are listed in the packet README, not hidden here.
"""

import struct

BLOCK_SIZE = 0x8000
MASK_DELTA = 0xA282EAD8
COMPRESSION_ERROR = "Unexpected WAL compression error"
PREVIOUS_ERROR = "Writer has previous error."

FULL, FIRST, MIDDLE, LAST = 1, 2, 3, 4
COMPRESSION_TYPE = 9

_POLY = 0x82F63B78
_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ _POLY if _c & 1 else _c >> 1
    _TABLE.append(_c)


def _raw_crc(data, init=0xFFFFFFFF):
    crc = init
    for byte in data:
        crc = _TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def crc32c(data):
    """CRC-32C (Castagnoli), reflected, init/xorout 0xFFFFFFFF."""
    return _raw_crc(data) ^ 0xFFFFFFFF


def _shift_raw(crc_raw, count):
    crc = crc_raw
    for _ in range(count):
        crc = _TABLE[crc & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def crc32c_combine(crc_a, crc_b, len_b):
    """CRC-32C of A||B from CRC(A), CRC(B) and len(B).

    Verified against direct crc32c(A + B) on random inputs (see tests).
    """
    raw_a = crc_a ^ 0xFFFFFFFF
    raw_b = crc_b ^ 0xFFFFFFFF
    shifted = _shift_raw(raw_a, len_b) ^ raw_b ^ _shift_raw(0xFFFFFFFF, len_b)
    return shifted ^ 0xFFFFFFFF


def mask_crc(crc):
    """RocksDB crc32c mask: ror32(crc, 15) + 0xa282ead8 mod 2^32."""
    return ((((crc >> 15) | (crc << 17)) & 0xFFFFFFFF) + MASK_DELTA) & 0xFFFFFFFF


def unmask_crc(stored):
    """Inverse of mask_crc, the reader-side rule pinned in PR #1848."""
    value = (stored - MASK_DELTA) & 0xFFFFFFFF
    return ((value << 15) | (value >> 17)) & 0xFFFFFFFF


class ResultRecord:
    """The 16-byte result record: code u32 at +0, u16 at +4, message
    pointer at +8 (bytes 6..7 are padding). Byte +0 nonzero is terminal:
    the emitter skips the data append and the AddRecord loop returns."""

    def __init__(self, code=0, field4=0, message=None):
        self.code = code
        self.field4 = field4
        self.message = message

    @property
    def terminal(self):
        return (self.code & 0xFF) != 0

    @classmethod
    def ok(cls):
        return cls(0, 0, None)

    @classmethod
    def previous_error(cls):
        return cls(5, 0, PREVIOUS_ERROR)

    @classmethod
    def compression_error(cls):
        return cls(5, 1, COMPRESSION_ERROR)


class Writer:
    """The writer object, by field offset (see records.json)."""

    def __init__(self, append, complete, compressor=None, recycle=False,
                 log_number=0, type_crc=None, block_offset=0,
                 finalize_flag=False, compression_type=0):
        self.append = append  # bytes -> ResultRecord
        self.complete = complete  # (writer, aux) -> ResultRecord
        self.compressor = compressor  # None, or an object with begin()/step()
        self.recycle = recycle
        self.log_number = log_number
        self.type_crc = type_crc or {}
        self.block_offset = block_offset
        self.finalize_flag = finalize_flag
        self.compression_type = compression_type
        self.scratch = bytearray()


def build_header(ftype, data, writer):
    """7-byte header, 11 bytes for recyclable types 5..8 (never type 9)."""
    assert len(data) < 65536
    crc = mask_crc(crc32c_combine(writer.type_crc[ftype], crc32c(data),
                                  len(data)))
    header = struct.pack("<IHB", crc, len(data), ftype)
    if 5 <= ftype <= 8:
        header += struct.pack("<I", writer.log_number)
    return header


def emit_fragment(writer, ftype, data, aux=0):
    """Emit one fragment: header append, then the data append unless the
    header append's result is terminal. The block offset always advances
    by header plus payload, as in the binary."""
    header = build_header(ftype, data, writer)
    first = writer.append(header)
    if first.terminal:
        writer.block_offset += len(header) + len(data)
        return first
    second = writer.append(data)
    writer.block_offset += len(header) + len(data)
    return second


def add_record(writer, data, aux=0):
    """The AddRecord loop. `data` is the input slice. With a compressor,
    chunks come from the scratch buffer; without one, fragments come from
    the input slice directly."""
    out = ResultRecord.ok()
    if writer.compressor is not None:
        writer.compressor.begin()
    first_call = writer.compressor is not None
    first = True
    status = 0
    pending = data
    pos = 0
    remaining = len(data)
    while True:
        header_size = 11 if writer.recycle else 7
        block_remaining = BLOCK_SIZE - writer.block_offset
        if block_remaining < header_size:
            if block_remaining > 0:
                out = writer.append(bytes(block_remaining))
                if out.terminal:
                    return out
            writer.block_offset = 0
            block_remaining = BLOCK_SIZE
        if writer.compressor is not None:
            if first_call or remaining == 0:
                was_first_call = first_call
                out_len, status = writer.compressor.step(data, writer.scratch)
                if status < 0:
                    return ResultRecord.compression_error()
                remaining = out_len
                pending = bytes(writer.scratch[:out_len])
                pos = 0
                first_call = False
                if remaining == 0 and not was_first_call:
                    break
        else:
            status = 0
        avail = block_remaining - header_size
        frag_len = min(remaining, avail)
        consumes = avail >= remaining
        if consumes and status == 0:
            ftype = FULL if first else LAST
        elif first:
            ftype = FIRST
        else:
            ftype = MIDDLE
        if writer.recycle:
            ftype += 4
        frag = pending[pos:pos + frag_len]
        out = emit_fragment(writer, ftype, frag, aux)
        if out.terminal:
            return out
        first = False
        pos += frag_len
        remaining -= frag_len
        if remaining != 0:
            continue
        if status > 0:
            continue
        break
    if not writer.finalize_flag:
        out = writer.complete(writer, aux)
    return out


def emit_compression_record(writer, aux=4, compressor_factory=None):
    """The 0x5163ba0 setup: emit a type 9 record, then install the
    compressor. A terminal helper result clears the compression type and
    returns without installing anything."""
    if writer.compression_type == 0:
        return ResultRecord.ok()
    payload = struct.pack("<I", writer.compression_type)
    out = emit_fragment(writer, COMPRESSION_TYPE, payload, aux)
    if out.terminal:
        writer.compression_type = 0
        return out
    if not writer.finalize_flag:
        out = writer.complete(writer, aux)
    buf_size = BLOCK_SIZE - (11 if writer.recycle else 7)
    if compressor_factory is not None:
        writer.compressor = compressor_factory(buf_size)
    writer.scratch = bytearray(buf_size)
    return out
