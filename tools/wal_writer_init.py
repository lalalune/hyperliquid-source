"""Python model of node #94 WAL writer initializer (0x51645d0) and its
three construction sites.

Evidence packet: research/work-items/RE-001-wal-writer-init-94/
(records.json, whole-function verbatim excerpts, verify.py). The model
implements only the semantics pinned by the branch conditions in those
windows. The CRC import (0x5421fc0), the compression-type setup
(0x5163ba0) and the handle release (0x51641d0) are oracles: the tests
inject fakes that follow the recorded call protocol. Unknowns are listed
in the packet README, not hidden here.
"""

OBJECT_SIZE = 0x58

# Writer field offsets (see PR #1958's layout, confirmed here).
OFF_MOVED = 0x00
OFF_BLOCK_OFFSET = 0x08
OFF_LOG_NUMBER = 0x10
OFF_RECYCLE_FLAG = 0x18
OFF_TYPE_CRC = 0x1C
OFF_FINALIZE_FLAG = 0x44
OFF_COMPRESSION_TYPE = 0x45
OFF_COMPRESSOR = 0x48
OFF_SCRATCH = 0x50

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


def type_crc_table():
    """type_crc[i] = crc32c of the single type byte i, for i in 0..9.

    The initializer calls the CRC import as (0, &byte, 1) once per
    entry; with seed 0 that is the standard CRC-32C of the one-byte
    input. Validated against the published check value 0xe3069283
    for b'123456789' (see tests).
    """
    return {i: crc32c(bytes([i])) for i in range(10)}


class Writer:
    """A fresh WAL writer object as built by the initializer."""

    def __init__(self):
        self.moved_qword = 0
        self.block_offset = 0
        self.log_number = 0
        self.recycle_flag = 0
        self.type_crc = {}
        self.finalize_flag = 0
        self.compression_type = 0
        self.compressor = None
        self.scratch = None

    def as_fields(self):
        fields = {
            OFF_MOVED: self.moved_qword,
            OFF_BLOCK_OFFSET: self.block_offset,
            OFF_LOG_NUMBER: self.log_number,
            OFF_RECYCLE_FLAG: self.recycle_flag,
            OFF_FINALIZE_FLAG: self.finalize_flag,
            OFF_COMPRESSION_TYPE: self.compression_type,
        }
        for i, value in self.type_crc.items():
            fields[OFF_TYPE_CRC + 4 * i] = value
        return fields


def initialize(source_slot, log_number, recycle_flag, finalize_flag,
               compression_type):
    """Run the 0x51645d0 initializer.

    source_slot is a one-element list holding the source qword: the
    initializer moves it into the writer and zeroes the slot, exactly
    as the window does with (%rsi). Returns the fresh Writer.
    """
    writer = Writer()
    writer.moved_qword = source_slot[0]
    source_slot[0] = 0
    writer.block_offset = 0
    writer.log_number = log_number
    writer.recycle_flag = recycle_flag & 0xFF
    writer.type_crc = type_crc_table()
    writer.finalize_flag = finalize_flag & 0xFF
    writer.compression_type = compression_type & 0xFF
    writer.compressor = None
    writer.scratch = None
    return writer


def construct_setup_site(moved_qword, log_number, recycle_flag,
                         finalize_flag, compression_type, setup):
    """The 0x50bbf5a site: allocate, init, then run the setup call.

    setup is the 0x5163ba0 oracle, called with the new writer; its
    return value is passed through. Returns (writer, setup_result).
    """
    source_slot = [moved_qword]
    writer = initialize(source_slot, log_number, recycle_flag,
                        finalize_flag, compression_type)
    return writer, setup(writer)


def construct_zero_site(moved_qword):
    """The 0x50be17b site: in-place build with every argument zero."""
    return initialize([moved_qword], 0, 0, 0, 0)


def construct_replace_site(slot, moved_qword, release, free):
    """The 0x51f7c20 site: replace the writer stored in slot[0].

    slot is a one-element list standing for the enclosing object's
    +0x130 field. The new writer is stored first; the old writer, when
    non-null, is then released (0x51641d0 oracle) and freed with
    sized delete 0x58 (free oracle). Returns the new writer.
    """
    writer = initialize([moved_qword], 0, 0, 0, 0)
    old = slot[0]
    slot[0] = writer
    if old is not None:
        release(old)
        free(old, OBJECT_SIZE)
    return writer
