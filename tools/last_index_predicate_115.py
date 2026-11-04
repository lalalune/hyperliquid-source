"""Python model of node #115's last-index predicate at 0x5f6afa0.

RE-001 work item: research/work-items/RE-001-last-index-predicate-115/.
The predicate takes (obj, index, flag) in (rdi, esi, dl) and returns
0 or 1. All arithmetic below is 32-bit, matching the native code:
the index test is signed, the count-minus-one wraps mod 2**32, and
the final comparison is on 32-bit patterns.
"""


def _s32(value):
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def _u32(value):
    return value & 0xFFFFFFFF


def last_index_predicate(link_byte, index, flag_byte, count):
    """Return the predicate result for the given inputs.

    link_byte: the byte at [obj+0x10]+0x654 (0..255).
    index: the signed 32-bit index argument.
    flag_byte: the low byte of the rdx argument (upper bits ignored).
    count: the signed 32-bit value at obj+0x54.
    """
    if link_byte == 0:
        return 0
    if not (_s32(index) > 0 or (flag_byte & 0xFF) != 0):
        return 0
    if _u32(count - 1) == _u32(index):
        return 1
    return 0


def predicate_from_obj(obj, index, flag_byte):
    """Read the predicate inputs from an obj mapping.

    obj must carry "link_byte" (the byte at [obj+0x10]+0x654) and
    "count" (the signed 32-bit value at obj+0x54). Raises KeyError
    when either field is absent, so a caller cannot silently model
    a partially known object.
    """
    if "link_byte" not in obj:
        raise KeyError("obj is missing link_byte")
    if "count" not in obj:
        raise KeyError("obj is missing count")
    return last_index_predicate(obj["link_byte"], index, flag_byte,
                                 obj["count"])
