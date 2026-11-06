"""Tests for the node #115 compaction-stats table header formatter.

The formatter (0x5eedda0) writes one header block into the caller's
buffer: title line, 21-column header row, dash underline.  Expected
outputs below are pinned from the binary: the three format literals
(0x4382dd, 0x9572f8, 0x43616f) and the pair map's second strings
(derive_names.py).  The ctypes cross-checks run the same formats
through the C library's snprintf to prove the model's truncation
semantics match the binary's __snprintf_chk calls byte for byte.
"""

import ctypes
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import compaction_stats_header_115 as m

LIBC = ctypes.CDLL(None)
LIBC.snprintf.restype = ctypes.c_int
LIBC.snprintf.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                          ctypes.c_char_p, ctypes.c_char_p]


def c_snprintf(maxlen, fmt, *args):
    """Run C snprintf(buf, maxlen, fmt, *args); return (would-be, bytes)."""
    buf = ctypes.create_string_buffer(maxlen if maxlen > 0 else 1)
    c_args = [ctypes.c_char_p(a.encode("utf-8")) for a in args]
    ret = LIBC.snprintf(buf, maxlen, fmt.encode("utf-8"), *c_args)
    return ret, buf.raw.split(b"\x00", 1)[0]


EXPECTED_ROW_LEVEL = (
    "Level    Files   Size     Score Read(GB)  Rn(GB) Rnp1(GB) Write(GB) "
    "Wnew(GB) Moved(GB) W-Amp Rd(MB/s) Wr(MB/s) Comp(sec) "
    "CompMergeCPU(sec) Comp(cnt) Avg(sec) KeyIn KeyDrop Rblob(GB) "
    "Wblob(GB)\n")

EXPECTED_ROW_PRIORITY = EXPECTED_ROW_LEVEL.replace("Level", "Priority", 1)


def test_header_row_level():
    assert m.header_row("Level") == EXPECTED_ROW_LEVEL
    assert m.header_row("Level").count("Files") == 1
    assert "CompactedFiles" not in m.header_row("Level")


def test_header_row_priority():
    assert m.header_row("Priority") == EXPECTED_ROW_PRIORITY


def test_column_keys():
    # 20 pair-map columns after the label: keys 1, 3..21.  Key 2 is
    # never read by the formatter, so it is absent by construction.
    assert m.COLUMN_KEYS == [1] + list(range(3, 22))
    assert 2 not in m.COLUMN_KEYS
    cols = m.header_row("Level").rstrip("\n").split(" ")
    cols = [c for c in cols if c]
    assert cols[0] == "Level"
    assert cols[1:] == [m.SECOND[k] for k in m.COLUMN_KEYS]


def test_format_header_level():
    out = m.format_header("default", "Level").decode("utf-8")
    header = "\n** Compaction Stats [default] **\n"
    row = EXPECTED_ROW_LEVEL
    assert out == header + row + "-" * len(row) + "\n"
    assert len(out) == len(header) + 2 * len(row) + 1


def test_format_header_priority():
    out = m.format_header("default", "Priority").decode("utf-8")
    header = "\n** Compaction Stats [default] **\n"
    row = EXPECTED_ROW_PRIORITY
    assert out == header + row + "-" * len(row) + "\n"


def test_dash_line_length_is_row_length():
    # The dash string is built with the row snprintf's would-be length,
    # so the underline is exactly as long as the row (including the
    # row's trailing newline, which the dashes do not replace).
    for label in ("Level", "Priority", "L0", ""):
        out = m.format_header("db", label).decode("utf-8")
        lines = out.split("\n")
        row = m.header_row(label)
        assert lines[2] == row.rstrip("\n")
        assert lines[3] == "-" * len(row)
        assert lines[4] == ""


def test_missing_key_throws():
    # Every looked-up key must exist, mirroring map::at's throw.
    for key in m.COLUMN_KEYS:
        second = dict(m.SECOND)
        del second[key]
        try:
            m.format_header("default", "Level", second)
        except m.MissingKeyError as exc:
            assert exc.args[0] == key
        else:
            raise AssertionError("key %d did not throw" % key)


def test_key_two_is_never_read():
    # Key 2 ("CompactedFiles") is absent from the column list, so a
    # table without it still renders exactly the same output.
    second = dict(m.SECOND)
    del second[2]
    assert (m.format_header("default", "Level", second)
            == m.format_header("default", "Level"))


def test_empty_name_and_label():
    out = m.format_header("", "").decode("utf-8")
    assert out.startswith("\n** Compaction Stats [] **\n")
    assert out.split("\n")[2].startswith("    Files")


def test_percent_in_name_is_literal():
    # The name is a %s argument, never a format string: % sequences in
    # it must pass through unchanged.
    out = m.format_header("100%_x%n", "Level").decode("utf-8")
    assert "[100%_x%n]" in out
    assert out.count("%") == 2


def _libc_render(name, label):
    """Replay the formatter's three __snprintf_chk calls through libc.

    Returns the buffer's C-string contents, exactly as the caller's
    string::append(const char*) would read them.
    """
    cols = [label] + [m.SECOND[k] for k in m.COLUMN_KEYS]
    buf = ctypes.create_string_buffer(2024)
    base = ctypes.addressof(buf)
    snprintf = LIBC.snprintf
    snprintf.restype = ctypes.c_int
    r1 = snprintf(ctypes.c_char_p(base), ctypes.c_size_t(m.MAXLEN),
                  ctypes.c_char_p(m.HEADER_FMT.encode()),
                  ctypes.c_char_p(name.encode()))
    p1 = min(r1, m.MAXLEN)
    r2 = snprintf(ctypes.c_char_p(base + p1),
                  ctypes.c_size_t(m.MAXLEN - p1),
                  ctypes.c_char_p(m.ROW_FMT.encode()),
                  *[ctypes.c_char_p(c.encode()) for c in cols])
    p2 = min(p1 + r2, m.MAXLEN)
    snprintf(ctypes.c_char_p(base + p2),
             ctypes.c_size_t(m.MAXLEN - p2),
             ctypes.c_char_p(m.DASH_FMT.encode()),
             ctypes.c_char_p(("-" * r2).encode()))
    return buf.value


def test_snprintf_cross_check():
    # The model against a literal libc replay of the three snprintf
    # calls, for both observed labels and edge-case names.
    for name, label in (("default", "Level"), ("default", "Priority"),
                        ("", "Level"), ("100%_x", "Priority"),
                        ("x" * 3000, "Level"), ("y" * 1400, "Priority")):
        assert m.format_header(name, label) == _libc_render(name, label), \
            (name[:20], label)


def test_long_name_truncation():
    # A name longer than the 2000-byte budget: the title snprintf is
    # capped, the row and dash calls get a zero budget and write
    # nothing, so the output is exactly the truncated title.
    name = "x" * 3000
    out = m.format_header(name, "Level")
    title = ("\n** Compaction Stats [%s] **\n" % name).encode("utf-8")
    assert out == title[:1999]
    assert len(out) == 1999
    # Cross-check against libc: snprintf reports the would-be length.
    ret, _ = c_snprintf(m.MAXLEN, m.HEADER_FMT, name)
    assert ret == len(title)
    # A name that lands the title well under the cap gets the full row
    # and underline appended (title 1427 + row 192 + dashes 193 < 2000).
    name2 = "y" * 1400
    out2 = m.format_header(name2, "Level")
    title2 = ("\n** Compaction Stats [%s] **\n" % name2).encode("utf-8")
    row = m.header_row("Level").encode("utf-8")
    assert out2 == title2 + row + b"-" * len(row) + b"\n"


def test_row_format_literals_match_binary():
    data = (Path(__file__).resolve().parents[1] / "work"
            / "hl-node-115.bin").read_bytes()

    def cstr(addr):
        end = data.find(b"\x00", addr)
        return data[addr:end].decode("utf-8")

    assert cstr(0x4382dd) == m.HEADER_FMT
    assert cstr(0x9572f8) == m.ROW_FMT
    assert cstr(0x43616f) == m.DASH_FMT
    assert cstr(0x44d03d) == "Level"
    assert cstr(0x43e67f) == "Priority"
    assert m.ROW_FMT.count("%s") == 21


def main():
    tests = [test_header_row_level, test_header_row_priority,
             test_column_keys, test_format_header_level,
             test_format_header_priority, test_dash_line_length_is_row_length,
             test_missing_key_throws, test_key_two_is_never_read,
             test_empty_name_and_label, test_percent_in_name_is_literal,
             test_snprintf_cross_check, test_long_name_truncation,
             test_row_format_literals_match_binary]
    for fn in tests:
        fn()
        print("PASS", fn.__name__)
    print("ALL TESTS PASSED (%d)" % len(tests))


if __name__ == "__main__":
    main()
