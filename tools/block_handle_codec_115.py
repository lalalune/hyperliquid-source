"""Model of the node #115 BlockHandle wire codec.

Transcribed from the target bodies (see the packet
RE-001-block-handle-codec-115 for the verbatim excerpts):

  * 0x6167d00  BlockHandle::EncodeTo(std::string*)  (200 bytes)
  * 0x6167dd0  BlockHandle::EncodeTo(char*)         (93 bytes)
  * 0x6167e30  BlockHandle::DecodeFrom(Slice*)      (247 bytes)
  * 0x61bd540  GetVarint64Ptr                       (75 bytes, leaf)

A BlockHandle is two uint64 fields, offset (this +0x0) and size
(this +0x8).  Its wire form is varint64(offset) followed by
varint64(size): unsigned LEB128, 7 bits per byte, low groups
first, continuation bit 0x80 on every byte but the last.  Each
varint64 takes at most 10 bytes, so a handle takes at most 20.

The decoder is not the exact inverse of the encoder:

  * it accepts overlong encodings (a value padded with 0x80
    continuation groups up to the 10-byte cap);
  * the 10th byte contributes only its lowest bit (the group is
    shifted by 63, so bits 1..6 of that byte are dropped), and a
    10th byte with the continuation bit set fails the decode;
  * running out of input at any point fails the decode.

DecodeFrom reports failure as a corruption status carrying the
message "bad block handle"; on failure it zeroes both handle
fields.  The input slice is advanced past each varint as soon as
that varint parses, so a failure in the second varint leaves the
slice advanced past the first one (consumed == length of the
first varint) with the handle zeroed.
"""

MASK64 = (1 << 64) - 1


def encode_varint64(value):
    """The encoder loop shared by both EncodeTo bodies."""
    if not 0 <= value <= MASK64:
        raise ValueError("varint64 value out of range")
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0xFF) | 0x80)
        value >>= 7
    out.append(value & 0xFF)
    return bytes(out)


def block_handle_encode(offset, size):
    """Bytes written by EncodeTo (either overload)."""
    return encode_varint64(offset) + encode_varint64(size)


def get_varint64(data, pos=0, limit=None):
    """GetVarint64Ptr over a bytes buffer.

    Returns (value, new_pos) on success, None on failure.  Mirrors
    the target leaf exactly: the limit is checked before every
    byte, the shift cap is checked after each continuation group,
    and the final group is stored without a separate overflow
    check, so at shift 63 only bit 0 of the last byte survives.
    """
    if limit is None:
        limit = len(data)
    if pos >= limit:
        return None
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        if byte & 0x80:
            result = (result | ((byte & 0x7F) << shift)) & MASK64
            shift += 7
            if shift > 63:
                return None
            if pos >= limit:
                return None
        else:
            result = (result | (byte << shift)) & MASK64
            return result, pos


def block_handle_decode(data):
    """DecodeFrom over a bytes buffer standing in for the Slice.

    Returns a dict: ok (bool), offset, size (the handle fields as
    left by the routine; both zero on failure), consumed (the
    final slice position), status ("ok" or "corruption") and
    message (None on success, "bad block handle" on failure).
    """
    first = get_varint64(data, 0, len(data))
    if first is None:
        return {"ok": False, "offset": 0, "size": 0, "consumed": 0,
                "status": "corruption", "message": "bad block handle"}
    offset, mid = first
    second = get_varint64(data, mid, len(data))
    if second is None:
        return {"ok": False, "offset": 0, "size": 0, "consumed": mid,
                "status": "corruption", "message": "bad block handle"}
    size, end = second
    return {"ok": True, "offset": offset, "size": size, "consumed": end,
            "status": "ok", "message": None}
