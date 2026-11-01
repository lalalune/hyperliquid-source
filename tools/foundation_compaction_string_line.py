"""Model of node #94's compaction-stats string line (0x514d770).

Evidence: research/work-items/RE-001-compaction-string-line-94/.

The window function writes three lines into a destination buffer under
one shared 2000-byte limit budget:

  1. header: "\\n** Compaction Stats [<name>] **\\n"
  2. data: 21 "%s" fields -- the caller-provided first column, then the
     value + 0x20 strings of map keys 1, 3..21 (key 2 is NOT read)
  3. dashes: one '-' per character of the data line (its raw snprintf
     return, trailing newline included), then a newline

Each snprintf position advances by the raw return clamped to 2000, so
the visible buffer content is the ideal concatenation truncated to at
most 1999 characters. Any missing key throws OutOfRange in lookup
order (21, 20, ..., 3, 1) before the output completes.
"""

BUFFER_LIMIT = 2000

LOOKUP_ORDER = [21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8,
                7, 6, 5, 4, 3, 1]

FIELD_ORDER = [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
               18, 19, 20, 21]


class OutOfRange(Exception):
    """Models std::out_of_range("map::at") from a missing key."""


def _snprintf_would_be(text):
    """snprintf return for a fully-written string (no NUL counted)."""
    return len(text)


def render_data_line(first_column, strings_by_key):
    """Build the data line, throwing on the first missing key.

    ``strings_by_key`` maps int key -> str (the value + 0x20 string).
    Lookup order is descending 21..1 skipping 2, so a missing key 20
    throws before a missing key 1 is ever reached.
    """
    for key in LOOKUP_ORDER:
        if key not in strings_by_key:
            raise OutOfRange("map::at (missing key %d)" % key)
    fields = [first_column] + [strings_by_key[k] for k in FIELD_ORDER]
    # The recorded format: "%s    %s   %s     %s %s  %s %s ..." -- gaps
    # of 4, 3, 5, 1, 2, then single spaces between remaining fields.
    gaps = [4, 3, 5, 1, 2] + [1] * (len(fields) - 6)
    line = fields[0]
    for gap, field in zip(gaps, fields[1:]):
        line += " " * gap + field
    return line + "\n"


def render_compaction_string_line(name, first_column, strings_by_key):
    """Render the whole window output as it would appear in the buffer.

    Returns the visible buffer string: the ideal three-line
    concatenation truncated to at most BUFFER_LIMIT - 1 characters,
    exactly as the chained snprintf calls with the shared 2000 budget
    produce. A negative snprintf return is unmodelled (see packet
    unknowns) and raises ValueError if ever constructed.
    """
    header = "\n** Compaction Stats [%s] **\n" % name
    data = render_data_line(first_column, strings_by_key)
    dashes = "-" * _snprintf_would_be(data) + "\n"
    ideal = header + data + dashes
    if len(ideal) < 0:  # pragma: no cover - defensive, never true
        raise ValueError("negative snprintf return is unmodelled")
    return ideal[:BUFFER_LIMIT - 1]


def header_line(name):
    return "\n** Compaction Stats [%s] **\n" % name
