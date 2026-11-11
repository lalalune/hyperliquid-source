#!/usr/bin/env python3
"""Python model of node #115's rocksdb::TracerHelper::ParseTraceHeader.

Reconstructs one function from the node #115 binary
(work/hl-node-115.bin, SHA-256 a6e2897c...):

  * TracerHelper::ParseTraceHeader  0x61b4840
    (FDE 0x61b4840..0x61b530d, 2765 bytes; census node115-vendor-61b4840)

The function is the only caller of TracerHelper::ParseVersionStr
(0x61b10f0): it splits the header trace's payload on TAB into exactly
three fields, skips the 15-byte "Trace Version: " prefix of field 1 and
the 17-byte "RocksDB Version: " prefix of field 2, and parses each
remainder with ParseVersionStr, writing the two version ints to the
caller's out-parameters.  The ParseVersionStr model (status codes,
messages, digit-concatenation rule, 32-bit wrap) is adapted from
tools/tracer_helper115.py (open PR #5863, same author); that tool is
not on upstream main yet, so the model is copied here rather than
imported.  The binary is never executed; this tool is a behavioural
model of the one function only.

Trace layout (from the codec packet): the binary reads only the
payload std::string at Trace+0x18 (ptr +0x18, size +0x20,
capacity +0x28); timestamp (+0x00) and type (+0x08) are not read here.

Status codes follow rocksdb::Status::Code (kOk=0, kCorruption=2,
kIncomplete=7).  ParseTraceHeader returns a Status by value (hidden
sret Status* in rdi): const Trace& in rsi, int* trace_version in rdx,
int* rocksdb_version in rcx.

Usage:
  python3 tools/tracer_helper_parse_header115.py --write-cases <path>
      Regenerate cases.tsv (2,400 rows) from the seeded generator.
  python3 tools/tracer_helper_parse_header115.py --demo
      Print a short parse demo on a realistic header payload.
"""

import argparse
import hashlib
import random
import sys
from pathlib import Path

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
DELIMITER = b"\t"

# Prefix lengths skipped before each version string.  The producer
# (Tracer::WriteHeader, 0x61b3860) writes exactly these labels:
# "Trace Version: " at .rodata 0x4478de (15 bytes) and
# "RocksDB Version: " at .rodata 0x442aec (17 bytes).  ParseTraceHeader
# itself never checks the label bytes -- it skips the offsets only.
TRACE_VERSION_PREFIX_LEN = 15
ROCKSDB_VERSION_PREFIX_LEN = 17

# Status codes (rocksdb::Status::Code).
K_OK = 0
K_CORRUPTION = 2
K_INCOMPLETE = 7

# Error messages, verbatim from .rodata (addresses in records.json).
# Adapted from tools/tracer_helper115.py (open PR #5863).
MSG_VERSION_FORMAT = b"Corrupted trace file. Incorrect version format."
MSG_VERSION_FORMAT_NOPERIOD = b"Corrupted trace file. Incorrect version format"

# The header payload the producer writes: magic + TAB + label + version
# + TAB + label + version (see the demo and the README).
MAGIC = b"feedcafedeadbeef"


class OutOfRange_(ValueError):
    """Mirror of std::out_of_range from std::string::substr.

    Raised when a field is shorter than the prefix skip (15 for the
    trace version field, 17 for the RocksDB version field).  The binary
    throws __throw_out_of_range_fmt with "%s: __pos (which is %zu) >
    this->size() (which is %zu)" and the function name
    "basic_string::substr" (.rodata 0x43e542 / 0x958cf8).
    """


class Status:
    """A rocksdb::Status value: code + message (empty when OK)."""

    def __init__(self, code=K_OK, message=b""):
        self.code = code
        self.message = bytes(message)

    def ok(self):
        return self.code == K_OK

    def __eq__(self, other):
        return (
            isinstance(other, Status)
            and self.code == other.code
            and self.message == other.message
        )

    def __repr__(self):
        if self.ok():
            return "Status(OK)"
        return f"Status(code={self.code}, message={self.message!r})"


def _to_int32(value):
    """Wrap an accumulated value to a signed 32-bit C++ int."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def parse_version_str(s):
    """Model of TracerHelper::ParseVersionStr (0x61b10f0).

    Adapted from tools/tracer_helper115.py (open PR #5863, same
    author).  Returns (Status, version).  The binary requires at least
    two '.' characters, then walks the whole string: '.' bytes are
    skipped, digit bytes accumulate value = value * 10 + digit (32-bit
    wrap), any other byte is an error.  The value is the decimal
    concatenation of every digit in the string, e.g. b"1.0.0" -> 100.
    On error the version out-parameter is left untouched (None here).
    """
    if not isinstance(s, (bytes, bytearray)):
        raise TypeError("parse_version_str takes bytes")
    s = bytes(s)
    first = s.find(b".")
    if first < 0:
        return Status(K_CORRUPTION, MSG_VERSION_FORMAT), None
    if first == s.rfind(b"."):
        return Status(K_CORRUPTION, MSG_VERSION_FORMAT_NOPERIOD), None
    value = 0
    for ch in s:
        if ch == 0x2E:  # '.'
            continue
        if 0x30 <= ch <= 0x39:
            value = (value * 10 + (ch - 0x30)) & 0xFFFFFFFF
        else:
            return Status(K_CORRUPTION, MSG_VERSION_FORMAT_NOPERIOD), None
    return Status(), _to_int32(value)


def split_payload(payload):
    """Model of the payload split loop in ParseTraceHeader.

    Splits `payload` on TAB into exactly three fields.  The loop runs
    three times (a counter at rsp+0x18, decremented per field); each
    iteration takes payload[pos : pos+len] where len is the distance to
    the next TAB, or the remainder when no TAB follows.  Two quirks,
    both read off the disassembly:

    * The 32-bit position wraps: when find returns npos, pos becomes
      (npos + 1) & 0xFFFFFFFF == 0, so the next iteration searches from
      the start of the payload again (a one-TAB payload's third field
      is the payload's own first field).
    * The substr pos check (pos > size -> out_of_range) is present in
      the binary but unreachable: pos is always <= size here, because
      pos is a found TAB index + 1, or 0 after the wrap.  The check is
      kept in the model for fidelity.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("split_payload takes bytes")
    payload = bytes(payload)
    fields = []
    pos = 0
    size = len(payload)
    for _ in range(3):
        if pos > size:
            raise OutOfRange_(
                "basic_string::substr: __pos (which is %d) > "
                "this->size() (which is %d)" % (pos, size)
            )
        found = payload.find(DELIMITER, pos)
        if found < 0:
            n = size - pos
        else:
            n = found - pos
        fields.append(payload[pos:pos + n])
        pos = (found + 1) & 0xFFFFFFFF
    return fields


def parse_trace_header(payload):
    """Model of TracerHelper::ParseTraceHeader (0x61b4840).

    Returns (Status, trace_version, rocksdb_version).  A version is an
    int when its ParseVersionStr call wrote it, else None (the binary
    leaves the caller's out-parameter untouched on failure).

    Rules, in order:
      * fields = split_payload(payload) -- exactly 3 fields.
      * len(fields[1]) < 15 -> OutOfRange_ (substr(15) throw).
      * len(fields[2]) < 17 -> OutOfRange_ (substr(17) throw).
      * status1, trace_version = ParseVersionStr(fields[1][15:]).
        On failure return (status1, None, None) at once: the second
        parse never runs and the returned Status is status1.
      * status2, rocksdb_version = ParseVersionStr(fields[2][17:]).
        The returned Status is status2 -- it overwrites status1 in the
        out Status (the binary moves status2 over status1, freeing
        status1's state; status1 is OK here so there is nothing to
        free).  trace_version keeps the value from the first call even
        when the second call fails; rocksdb_version stays None then.
    """
    fields = split_payload(payload)
    if len(fields[1]) < TRACE_VERSION_PREFIX_LEN:
        raise OutOfRange_(
            "basic_string::substr: __pos (which is %d) > "
            "this->size() (which is %d)"
            % (TRACE_VERSION_PREFIX_LEN, len(fields[1]))
        )
    trace_str = fields[1][TRACE_VERSION_PREFIX_LEN:]
    if len(fields[2]) < ROCKSDB_VERSION_PREFIX_LEN:
        raise OutOfRange_(
            "basic_string::substr: __pos (which is %d) > "
            "this->size() (which is %d)"
            % (ROCKSDB_VERSION_PREFIX_LEN, len(fields[2]))
        )
    rocksdb_str = fields[2][ROCKSDB_VERSION_PREFIX_LEN:]
    status1, trace_version = parse_version_str(trace_str)
    if not status1.ok():
        return status1, None, None
    status2, rocksdb_version = parse_version_str(rocksdb_str)
    return status2, trace_version, rocksdb_version


# ---------------------------------------------------------------------------
# Case generation (2,400 deterministic cases, seeded).
# ---------------------------------------------------------------------------

def _version_value(s):
    """Digit-concatenation value of a valid version string, or None."""
    v = 0
    for ch in s:
        if ch == 0x2E:
            continue
        v = (v * 10 + (ch - 0x30)) & 0xFFFFFFFF
    return _to_int32(v)


def _gen_split_cases(rng):
    cases = []
    # Hand-picked: no tabs, one tab, two tabs, three tabs, extra tabs.
    for payload in [
        b"",
        b"feedcafedeadbeef",
        b"a",
        b"\t",
        b"\t\t",
        b"\t\t\t",
        b"a\tb",
        b"a\tb\tc",
        b"a\tb\tc\td",
        b"a\tb\tc\td\te",
        b"feedcafedeadbeef\tTrace Version: 1.2.3\tRocksDB Version: 4.5.6",
        b"feedcafedeadbeef\tTrace Version: 1.2.3\tRocksDB Version: 4.5.6\textra",
        b"\tTrace Version: 1.2.3\tRocksDB Version: 4.5.6",
        b"0123456789abcde\tTrace Version: 1.2.3\tRocksDB Version: 4.5.6",
        # One TAB only: the third field wraps to the payload's start.
        b"0123456789abcde\tTrace Version: 1.2.3",
        b"short\tTrace Version: 1.2.3",
        # Empty middle / last fields.
        b"f0\t\tRocksDB Version: 1.2.3",
        b"f0\tTrace Version: 1.2.3\t",
        b"f0\t\t",
        # Long fields (heap-allocated std::string in the binary).
        b"x" * 100 + b"\t" + b"y" * 100 + b"\t" + b"z" * 100,
        b"x" * 16 + b"\t" + b"y" * 17 + b"\t" + b"z" * 18,
    ]:
        cases.append(payload)
    # Random: 0-5 tabs, random field lengths 0..40, random bytes.
    while len(cases) < 600:
        nfields = rng.randrange(1, 6)
        parts = []
        for _ in range(nfields):
            ln = rng.randrange(0, 41)
            parts.append(bytes(rng.choice(b"abcXYZ0123456789.-_ ")
                               for _ in range(ln)))
        cases.append(b"\t".join(parts))
    return cases


def _gen_parse_cases(rng):
    cases = []
    # Hand-picked valid versions (value = digit concatenation).
    for s, want in [
        (b"1.0.0", 100), (b"0.0.0", 0), (b"12.34.56", 123456),
        (b"1.2.3.4", 1234), (b"..", 0), (b".1.2", 12), (b"1.2.", 12),
        (b"1..2.3", 123), (b"9.9.9", 999), (b"10.20.30", 102030),
        (b"0.0.1", 1), (b"255.255.255", 255255255),
        (b"42949672.9.5", None),  # overflow: wraps mod 2**32
        (b"99999.99999.99999", None),  # overflow wrap
        (b"21474836.47.0", None),  # wraps into the negative int32 range
    ]:
        if want is None:
            want = _version_value(s)
        cases.append((s, want))
    # Hand-picked errors.
    for s in [
        b"", b".", b"1.2", b"12.34", b"1", b"12", b"1.2.x", b"1.a.2",
        b"v1.2.3", b"1.2.3 ", b"1.2.3\n", b"1.2.3-", b"1.2.3\t",
        b"1.2.3\x00", b"1.2.3\x80", b"a.b.c", b"..a", b"1.2.3.4a",
    ]:
        cases.append((s, None))
    # Random valid: 3-5 dot-separated digit runs (at least two dots).
    while len(cases) < 400:
        runs = [str(rng.randrange(0, 10 ** rng.randrange(1, 4)))
                for _ in range(rng.randrange(3, 6))]
        s = ".".join(runs).encode()
        cases.append((s, _version_value(s)))
    # Random invalid: one dot only, or a bad byte somewhere.
    while len(cases) < 600:
        if rng.random() < 0.5:
            s = (str(rng.randrange(0, 100)) + "." +
                 str(rng.randrange(0, 100))).encode()
        else:
            runs = [str(rng.randrange(0, 100)) for _ in range(3)]
            s = ".".join(runs).encode()
            pos = rng.randrange(len(s))
            bad = rng.choice(b"abxz- _\t\x00\xff")
            s = s[:pos] + bytes([bad]) + s[pos + 1:]
        cases.append((s, None))
    return cases


def _valid_version(rng):
    runs = [str(rng.randrange(0, 10 ** rng.randrange(1, 4)))
            for _ in range(rng.randrange(3, 5))]
    return ".".join(runs).encode()


def _invalid_version(rng):
    if rng.random() < 0.5:
        return (str(rng.randrange(0, 100)) + "." +
                str(rng.randrange(0, 100))).encode()
    s = _valid_version(rng)
    pos = rng.randrange(len(s))
    bad = rng.choice(b"abxz- _\t\x00\xff")
    return s[:pos] + bytes([bad]) + s[pos + 1:]


def _header_payload(rng, trace_ver, rocksdb_ver, prefix1=b"Trace Version: ",
                    prefix2=b"RocksDB Version: ", field0=None, extra=b""):
    if field0 is None:
        field0 = MAGIC if rng.random() < 0.7 else bytes(
            rng.choice(b"abcdef0123456789") for _ in range(16))
    payload = (field0 + b"\t" + prefix1 + trace_ver + b"\t" + prefix2
               + rocksdb_ver + extra)
    return payload


def _header_outcome(payload):
    """Expected outcome of parse_trace_header, as a cases.tsv want cell.

    OK:<tv>:<rv> | ERR1:<code>:<msg-hex> | ERR2:<tv>:<code>:<msg-hex>
    | THROW:15 | THROW:17
    """
    try:
        fields = split_payload(payload)
    except OutOfRange_:
        return "THROW:SPLIT"
    if len(fields[1]) < TRACE_VERSION_PREFIX_LEN:
        return "THROW:15"
    if len(fields[2]) < ROCKSDB_VERSION_PREFIX_LEN:
        return "THROW:17"
    status1, tv = parse_version_str(fields[1][TRACE_VERSION_PREFIX_LEN:])
    if not status1.ok():
        return "ERR1:%d:%s" % (status1.code, status1.message.hex())
    status2, rv = parse_version_str(fields[2][ROCKSDB_VERSION_PREFIX_LEN:])
    if not status2.ok():
        return "ERR2:%d:%d:%s" % (tv, status2.code, status2.message.hex())
    return "OK:%d:%d" % (tv, rv)


def _gen_header_cases(rng):
    cases = []
    # Hand-picked valid headers (field 0 is ignored entirely).
    for tv, rv in [
        (b"1.2.3", b"4.5.6"), (b"1.0.0", b"8.1.1"), (b"0.0.0", b"0.0.0"),
        (b"12.34.56", b"7.8.9"), (b"..", b".."), (b"1.2.3.4", b"5.6.7.8"),
        (b"42949672.9.5", b"1.2.3"), (b"1.2.3", b"42949672.9.5"),
    ]:
        cases.append(_header_payload(rng, tv, rv))
    # Arbitrary 15/17-char prefixes: only the offsets matter, the label
    # bytes are never checked.
    cases.append(_header_payload(rng, b"1.2.3", b"4.5.6",
                                 prefix1=b"XXXXXXXXXXXXXXX",
                                 prefix2=b"YYYYYYYYYYYYYYYYY"))
    cases.append(_header_payload(rng, b"1.2.3", b"4.5.6",
                                 prefix1=b"Trace Version: ",
                                 prefix2=b"ZZZZZZZZZZZZZZZZZ"))
    # Extra tabs after field 2 are ignored; field 2 stops at the 3rd TAB.
    cases.append(_header_payload(rng, b"1.2.3", b"4.5.6", extra=b"\textra\tfields"))
    cases.append(_header_payload(rng, b"1.2.3", b"4.5.6",
                                 extra=b"\t9.9.9"))
    # Field 0 empty / junk / very long.
    cases.append(_header_payload(rng, b"1.2.3", b"4.5.6", field0=b""))
    cases.append(_header_payload(rng, b"1.2.3", b"4.5.6", field0=b"junk"))
    cases.append(_header_payload(rng, b"1.2.3", b"4.5.6",
                                 field0=b"x" * 200))
    # First-version errors: second parse never runs, versions untouched.
    for tv in [b"1.2", b"1.2.x", b"", b"v1.2.3", b"1.2.3.4a"]:
        cases.append(_header_payload(rng, tv, b"4.5.6"))
    # Second-version errors: trace version is written, rocksdb is not.
    for rv in [b"1.2", b"1.2.x", b"", b"v1.2.3", b"1.2.3.4a"]:
        cases.append(_header_payload(rng, b"1.2.3", rv))
    # Throws: field 1 shorter than 15, field 2 shorter than 17.
    for f1 in [b"", b"x", b"Trace Version", b"Trace Version:"]:
        cases.append(b"f0\t" + f1 + b"\tRocksDB Version: 1.2.3")
    for f2 in [b"", b"x", b"RocksDB Version", b"RocksDB Version:"]:
        cases.append(b"f0\tTrace Version: 1.2.3\t" + f2)
    # Missing tabs: fields 1/2 are empty -> substr(15) throws.
    for payload in [b"", b"feedcafedeadbeef", b"a", b"f0\tTrace Version: 1.2.3",
                    b"0123456789abcde\tTrace Version: 1.2.3",
                    b"short\tTrace Version: 1.2.3"]:
        cases.append(payload)
    # Random valid headers.
    while len(cases) < 800:
        cases.append(_header_payload(rng, _valid_version(rng),
                                     _valid_version(rng)))
    # Random first-version errors.
    while len(cases) < 950:
        cases.append(_header_payload(rng, _invalid_version(rng),
                                     _valid_version(rng)))
    # Random second-version errors.
    while len(cases) < 1100:
        cases.append(_header_payload(rng, _valid_version(rng),
                                     _invalid_version(rng)))
    # Random throw cases: short field 1 or field 2.
    while len(cases) < 1200:
        if rng.random() < 0.5:
            f1 = bytes(rng.choice(b"abcXYZ0123456789")
                       for _ in range(rng.randrange(0, 15)))
            cases.append(b"f0\t" + f1 + b"\tRocksDB Version: 1.2.3")
        else:
            f2 = bytes(rng.choice(b"abcXYZ0123456789")
                       for _ in range(rng.randrange(0, 17)))
            cases.append(b"f0\tTrace Version: 1.2.3\t" + f2)
    return cases


def generate_cases(seed=20261109):
    """Return (split, parse, header) case lists; 600 + 600 + 1200."""
    rng = random.Random(seed)
    split = _gen_split_cases(rng)
    parse = _gen_parse_cases(rng)
    header = _gen_header_cases(rng)
    assert len(split) == 600 and len(parse) == 600 and len(header) == 1200
    return split, parse, header


def write_cases(path):
    """Write cases.tsv (2,400 rows + header) from the seeded generator."""
    split, parse, header = generate_cases()
    with open(path, "w") as fh:
        fh.write("kind\tinput\twant\n")
        for payload in split:
            fields = split_payload(payload)
            fh.write("split_payload\t%s\t%s\n" % (
                payload.hex(),
                ":".join(f.hex() for f in fields)))
        for s, want in parse:
            fh.write("parse_version_str\t%s\t%s\n" % (
                s.hex(), "ERR" if want is None else str(want)))
        for payload in header:
            fh.write("parse_trace_header\t%s\t%s\n" % (
                payload.hex(), _header_outcome(payload)))
    return 2400


def _demo():
    payload = (MAGIC + b"\tTrace Version: 1.2.3\t"
               b"RocksDB Version: 8.1.1")
    print("payload:", payload)
    print("fields:", split_payload(payload))
    status, tv, rv = parse_trace_header(payload)
    print("status:", status, "trace_version:", tv, "rocksdb_version:", rv)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write-cases", metavar="PATH")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args(argv)
    if args.write_cases:
        n = write_cases(args.write_cases)
        print(f"wrote {n} cases to {args.write_cases}")
        return 0
    if args.demo:
        _demo()
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
