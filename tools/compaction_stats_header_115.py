"""Python model of node #115's compaction-stats table header formatter.

The formatter is the routine at 0x5eedda0 (FDE 0x5eedda0..0x5eee30c).  It
writes one complete table header block into the caller's character
buffer: the title line, the 21-column header row, and a dash underline
as long as the header row:

    \\n** Compaction Stats [<name>] **\\n
    <label>    Files   Size     Score Read(GB)  Rn(GB) ... Wblob(GB)\\n
    -----------------------------------------------------------------...\\n

The 21 header-row columns are the caller-supplied label followed by the
pair map's SECOND strings (the display names) for keys 1, 3..21.  Key 2
("CompactedFiles") is never read: the formatter looks its keys up
through map::at (0x5eeb7f0, 13 sites) and through seven inlined
lower_bound + equality lookups, and none of them asks for key 2.  A
missing key throws __throw_out_of_range("map::at").

Each of the three lines is produced by one __snprintf_chk call with a
2000-byte budget, so the model reproduces the C snprintf truncation
semantics exactly: a call writes at most maxlen-1 characters plus the
terminating NUL and reports the would-be length, and the next call
starts at min(would-be length, 2000).
"""

# Second strings of the global pair map at 0x6503a00, keys 1..21,
# derived from the static initializer 0x5efbd80 (see
# research/work-items/RE-001-compaction-stats-header-115/derive_names.py).
SECOND = {
    1: "Files",
    2: "CompactedFiles",
    3: "Size",
    4: "Score",
    5: "Read(GB)",
    6: "Rn(GB)",
    7: "Rnp1(GB)",
    8: "Write(GB)",
    9: "Wnew(GB)",
    10: "Moved(GB)",
    11: "W-Amp",
    12: "Rd(MB/s)",
    13: "Wr(MB/s)",
    14: "Comp(sec)",
    15: "CompMergeCPU(sec)",
    16: "Comp(cnt)",
    17: "Avg(sec)",
    18: "KeyIn",
    19: "KeyDrop",
    20: "Rblob(GB)",
    21: "Wblob(GB)",
}

# Header-row column keys after the label, in the order the formatter
# passes them to the row snprintf (derived from main.txt: the 13
# map::at calls plus the 7 inlined lookups, then the 20 stack varargs
# in reverse push order).  Key 2 is absent by construction.
COLUMN_KEYS = [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
               18, 19, 20, 21]

MAXLEN = 2000
HEADER_FMT = "\n** Compaction Stats [%s] **\n"
ROW_FMT = "%s    %s   %s     %s %s  %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n"
DASH_FMT = "%s\n"


class MissingKeyError(KeyError):
    """Analogue of the binary's __throw_out_of_range("map::at")."""


def _snprintf(buf, offset, maxlen, text):
    """Mimic one C snprintf(buf+offset, maxlen, "%s", text) call.

    Returns the would-be length (as C snprintf does).  Writes at most
    maxlen-1 bytes of text plus a terminating NUL when maxlen > 0.
    """
    data = text.encode("utf-8")
    if maxlen > 0:
        n = min(len(data), maxlen - 1)
        buf[offset:offset + n] = data[:n]
        buf[offset + n] = 0
    return len(data)


def header_row(label, second=None):
    """The 21-column header row (without truncation) for a label."""
    names = second if second is not None else SECOND
    cols = [label] + [names[k] for k in COLUMN_KEYS]
    if len(cols) != 21:
        raise AssertionError("header row must have 21 columns")
    return ROW_FMT % tuple(cols)


def format_header(name, label, second=None):
    """Render the full header block the formatter writes into its buffer.

    `name` is the stats name for the title line (the caller passes
    *( *(owner+0x788) + 0x08 )); `label` is the first-column string
    (the caller passes "Level" or "Priority" via a stack string).
    Returns the bytes the caller appends: the buffer contents up to the
    first NUL, exactly as string::append(const char*) would read them.
    Raises MissingKeyError when a looked-up pair-map key is absent,
    mirroring the binary's map::at throw.
    """
    names = second if second is not None else SECOND
    for key in COLUMN_KEYS:
        if key not in names:
            raise MissingKeyError(key)
    # The caller's stack buffer is 2024 bytes; the formatter never
    # writes past offset 2000 (the three snprintf budgets sum to 2000).
    buf = bytearray(2024)
    header = HEADER_FMT % name
    n1 = _snprintf(buf, 0, MAXLEN, header)
    pos1 = min(n1, MAXLEN)
    row = header_row(label, names)
    n2 = _snprintf(buf, pos1, MAXLEN - pos1, row)
    pos2 = min(pos1 + n2, MAXLEN)
    dashes = "-" * n2
    _snprintf(buf, pos2, MAXLEN - pos2, DASH_FMT % dashes)
    end = buf.index(0)
    return bytes(buf[:end])
