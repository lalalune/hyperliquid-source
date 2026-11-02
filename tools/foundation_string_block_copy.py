#!/usr/bin/env python3
"""Model for node #94's string-plus-block copy 0x514de00 (RE-001).

The window function takes a destination object, a source string object
and a 72-byte block. It deep-copies the source string into the
destination's string member and copies the block verbatim into the
destination at +0x20, building a 0x68-byte object. The string arms
are: length 0 (no copy, NUL at the SSO buffer start), length 1 (the
single byte moved directly, no memcpy), lengths 2..15 (memcpy into
the SSO buffer), length above 15 (heap buffer via _M_create plus
memcpy). The source string's union/capacity is never read, so SSO
and heap sources copy identically. The function returns no value.

The model represents the destination as a dict: "arm" is "sso" or
"heap"; "length" is the source length; "content" is the copied
string bytes; "buffer" is the SSO buffer bytes (content plus the
NUL terminator) for the SSO arm; "capacity_slot" is the value left
in the heap union slot for the heap arm, which in this call shape
(old capacity 0) is the source length, since the same slot value
feeds both the union and the length stores in the bytes; "block"
is the copied 72 bytes. Bytes the window does not write (SSO buffer
past the NUL terminator, dest+0x18 in the heap arm) are not
represented. Stdlib only.
"""

SSO_LIMIT = 15
BLOCK_SIZE = 72


def copy_string_block(source, block):
    """Copy a source string and a 72-byte block into a fresh object.

    source is the source string's bytes; block is exactly 72 bytes.
    Returns the destination dict described in the module docstring.
    Raises ValueError when the block is not exactly 72 bytes.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(
            "block must be exactly %d bytes, got %d" % (BLOCK_SIZE, len(block)))
    length = len(source)
    dest = {"length": length, "content": bytes(source),
            "block": bytes(block)}
    if length <= SSO_LIMIT:
        dest["arm"] = "sso"
        dest["buffer"] = bytes(source) + b"\x00"
        dest["capacity_slot"] = None
    else:
        dest["arm"] = "heap"
        dest["buffer"] = None
        # Observed slot behavior: the capacity slot is initialized
        # to the source length and _M_create is called with old
        # capacity 0; the same slot value is then stored to both
        # the union (+0x10) and the length (+0x8).
        dest["capacity_slot"] = length
    return dest


def dest_string_bytes(dest):
    """The destination string's bytes, as governed by its length."""
    return dest["content"][:dest["length"]]
