"""Model of node #115 group-report formatter 0x5f6c320 (RE-001, work item
RE-001-group-report-formatter-115).

Window (digest-verified node #115 binary, see the work-item packet):
  formatter 0x5f6c320 -- whole 439-byte function, end to end.

Layout pinned by the disassembly:
  obj+0xa90  flag byte; nonzero skips the base-level prefix line
  obj+0x10   signed 32-bit group count
  obj+0xaf8  double level multiplier (special-branch gate)
  obj+0xaf0  signed 32-bit base level (special-branch %d)
  obj+0x18   pointer to a qword array, indexed by the signed base
             level for the special-branch %lu
  obj+0xa98  24-byte group entries: begin qword, end qword, third
             qword never read; elements are 8-byte pointers in
             [begin, end)
  obj+0xf38  pointer to the double printed as the max score
  obj+0xbd0, obj+0xbc8, obj+0xb38  qwords feeding the compaction
             count: ((bd0 - bc8) >> 4, arithmetic) + b38, wrapping
             at 64 bits, printed as %zu

Format literals pinned by the disassembly (rodata addresses in the
packet's records):
  "base level %d level multiplier %.2f max bytes base %lu " (0x96c108)
  "files[" (0x43408a)
  "%d " (0x44b345)
  "] max score %.2f" (0x4446c7)
  " (%zu files need compaction)" (0x443873)

The function writes into a 1000-byte caller buffer and returns the
buffer pointer. This model returns the buffer text. It covers the
non-truncating regime only: every test keeps the total output well
under 1000 bytes, so the native snprintf truncation arms (a group
line whose return is negative or reaches the remaining space, which
breaks the group loop) are not pinned here; they are recorded as an
unknown in the packet.
"""

MASK = (1 << 64) - 1


def _u64(value):
    return value & MASK


def _s64(value):
    value &= MASK
    return value - (1 << 64) if value >= (1 << 63) else value


def _s32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >= (1 << 31) else value


def _c_percent_d(value64):
    """C %d of a 64-bit register value: the low 32 bits, signed."""
    return _s32(value64)


def _group_element_count(begin, end):
    """(end - begin) >> 3, arithmetic shift on the wrapped 64-bit
    difference, as the formatter's group loop computes it."""
    return _s64(end - begin) >> 3


def _compaction_count(bd0, bc8, b38):
    """((bd0 - bc8) >> 4, arithmetic) + b38, wrapping at 64 bits."""
    return _u64((_s64(bd0 - bc8) >> 4) + b38)


def _fmt_double_2(value):
    """C %.2f of a double. Python's format uses the same binary-double
    value and the same round-half-even rule glibc printf applies."""
    return format(float(value), ".2f")


def format_group_report(obj, groups):
    """Render the formatter's output string.

    obj is a dict with keys: flag_a90 (byte), count (signed 32-bit
    int), af8 (float), af0 (signed 32-bit int), arr18 (sequence of
    qwords indexed by af0), max_score (float, the double at
    [obj+0xf38]), bd0, bc8, b38 (qwords).
    groups is a list of (begin, end) pairs; only groups[:count] are
    read, and only when count > 0.
    """
    flag = obj["flag_a90"]
    count = obj["count"]
    af8 = float(obj["af8"])
    # Special branch: flag == 0, count > 1, and af8 != 0.0. The native
    # test is ucomisd against +0.0 with jp/jne to the special branch,
    # so NaN also takes it (NaN != 0.0 in Python too) and -0.0 does
    # not (it compares equal to +0.0).
    special = flag == 0 and count > 1 and af8 != 0.0
    out = ""
    if special:
        level = _s32(obj["af0"])
        base = obj["arr18"][level]
        out += ("base level %d level multiplier %s max bytes base %d "
                % (level, _fmt_double_2(af8), _u64(base)))
    out += "files["
    # Tracked offset ebp: special length + 6, then one "%d " line per
    # group. In the non-truncating regime ebp == len(out) throughout,
    # so the strip below (ebp -= 1 when ebp > 0) drops the last
    # character of the text built so far.
    ebp = len(out)
    if count > 0:
        for i in range(count):
            begin, end = groups[i]
            cnt64 = _group_element_count(begin, end)
            out += "%d " % _c_percent_d(cnt64)
            ebp += len("%d " % _c_percent_d(cnt64))
    if ebp > 0:
        out = out[:-1]
        ebp -= 1
    out += "] max score %s" % _fmt_double_2(obj["max_score"])
    need = _compaction_count(obj["bd0"], obj["bc8"], obj["b38"])
    if need != 0:
        # C %zu prints the unsigned 64-bit value; Python %d of the
        # already-unsigned value renders the same decimal text.
        out += " (%d files need compaction)" % need
    return out
