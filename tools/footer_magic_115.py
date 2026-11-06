"""Model of the node #115 table-footer magic behavior pinned by the
RE-001 footer-magic packet (research/work-items/RE-001-footer-magic-115).

Constants (stored qwords in .rodata, VA == file offset):
  BLOCK_LEGACY   0xdb4775248b80fb57 at 0x97a0a0
  BLOCK_CURRENT  0x88e241b785f4cff7 at 0x97a0a8
  PAIR2_WRITTEN  0x4f3418eb7a8f13b8 at 0x97bdf0
  PAIR2_CURRENT  0x8242229663bf9564 at 0x97bdf8
  CUCKOO_CANDIDATE 0x926789d0c5f17873 (immediate only, never stored)

build_footer reproduces FooterBuilder::Build (0x6168620): the two
BlockHandle encodings are inputs (their varint encoding is produced
by the routine at 0x6167dd0 and is modeled here by
encode_block_handle); Build zero-pads the handle region and places
the magic:
  format_version == 0 -> 48 bytes: handles at 0, pad to 40, magic at
    40, with BLOCK_CURRENT replaced by BLOCK_LEGACY and
    PAIR2_CURRENT replaced by PAIR2_WRITTEN;
  format_version != 0 -> 53 bytes: checksum-type byte at 0, handles
    at 1, pad to 41, the 4-byte format version at 41, the candidate
    magic unchanged at 45.

decode_gate reproduces only the entry gate of Footer::DecodeFrom
(0x6168780): given the footer's trailing 8 bytes and the
caller-supplied expected value (0 = no specific expectation), it
returns (accepted, normalized_magic, type_byte, branch) with branch
one of "decode48", "decode48_versioned", "decode_current" (the
continuation at 0x6169240) or "error" (the 'Bad table magic number'
corruption path). type_byte is None on the "decode_current" branch:
the gate jumps away before the type-byte store. The handle decoding
and version checks after the gate are not modeled.
"""

BLOCK_LEGACY = 0xDB4775248B80FB57
BLOCK_CURRENT = 0x88E241B785F4CFF7
PAIR2_WRITTEN = 0x4F3418EB7A8F13B8
PAIR2_CURRENT = 0x8242229663BF9564
CUCKOO_CANDIDATE = 0x926789D0C5F17873

SUBSTITUTIONS = {BLOCK_CURRENT: BLOCK_LEGACY,
                 PAIR2_CURRENT: PAIR2_WRITTEN}


def encode_block_handle(offset, size):
    """Unsigned LEB128 varint64 pair, as written by the helper at
    0x6167dd0 (rocksdb::BlockHandle::EncodeTo)."""
    out = bytearray()
    for value in (offset, size):
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                break
    return bytes(out)


def build_footer(format_version, checksum_type, table_magic,
                 metaindex_handle, index_handle):
    """Assemble one footer exactly as Build does.

    metaindex_handle / index_handle are (offset, size) pairs; their
    encodings are laid down sequentially by the two EncodeTo calls.
    """
    handles = (encode_block_handle(*metaindex_handle)
               + encode_block_handle(*index_handle))
    if format_version == 0:
        magic = SUBSTITUTIONS.get(table_magic, table_magic)
        if len(handles) > 40:
            raise ValueError("handle encodings exceed the 40-byte region")
        body = handles + bytes(40 - len(handles))
        return body + magic.to_bytes(8, "little")
    body = bytes([checksum_type]) + handles
    if len(body) > 41:
        raise ValueError("handle encodings exceed the 41-byte region")
    body += bytes(41 - len(body))
    return (body + format_version.to_bytes(4, "little")
            + table_magic.to_bytes(8, "little"))


def decode_gate(trailing, expected):
    """Entry gate of Footer::DecodeFrom (see module docstring)."""
    if trailing == BLOCK_LEGACY:
        if expected not in (0, BLOCK_CURRENT):
            return (False, None, None, "error")
        return (True, BLOCK_CURRENT, 5, "decode48")
    if trailing == PAIR2_WRITTEN:
        if expected not in (0, PAIR2_CURRENT):
            return (False, None, None, "error")
        return (True, PAIR2_CURRENT, 0, "decode48")
    if expected == 0 or trailing == expected:
        if trailing == BLOCK_CURRENT:
            return (True, BLOCK_CURRENT, None, "decode_current")
        return (True, trailing, 0, "decode48_versioned")
    return (False, None, None, "error")
