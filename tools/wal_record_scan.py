"""Python model of node #94 WAL record scan loop 0x51628f0 (RE-001).

The model implements the state machine pinned in
research/work-items/RE-001-wal-record-scan-94/records.json: a scan loop
over an injectable buffered read, fragment assembly into a reader-local
accumulator, compression-record handling, error/unknown arms, and
completion into the caller's out_record/scratch strings.

The buffered read is injected as a callable taking the scan object and
returning (status, code, fragment_bytes, aux_word). The reporter and
the body parser are likewise injected; the model records their calls
so tests can assert the exact report sequence. The detail builder is
not injected: per the evidence packet (and PR #1860's pin of
0x542f040), its constant argument 2 lands in the decision byte, so
the detail path always takes the could-not-decode report branch in
node #94; the parser is called directly only on the tag 0/7 path.
"""

APPEND_CAP = 0x3FFFFFFFFFFFFFFF


class LengthError(ValueError):
    """Mirror of std::length_error, thrown on the append cap breach."""

FULL = (1, 5)
FIRST = (2, 6)
MIDDLE = (3, 7)
LAST = (4, 8)
ERROR_CODES = (10, 11, 12, 13)


class WalRecordScan:
    """State for one scan over one reader object."""

    def __init__(self, entry_remaining, flag_70=False, flag_71=False,
                 flag_73=False, stream=None):
        self.entry_remaining = entry_remaining
        self.flag_70 = flag_70
        self.flag_71 = flag_71
        self.flag_73 = flag_73
        self.stream = stream
        self.accumulator = bytearray()
        self.in_fragment = False
        self.out_record = b""
        self.scratch = b""
        self.success_offset = None
        self.reports = []      # list of (message, value)
        self.parser_calls = []  # list of (tag, payload_after_tag)
        self.stream_finished = False

    def report(self, message, value):
        self.reports.append((message, value))

    def _clear_accumulator(self):
        self.accumulator = bytearray()

    def _append(self, fragment):
        if len(fragment) > APPEND_CAP - len(self.accumulator):
            raise LengthError("accumulator append exceeds 0x3fffffffffffffff")
        self.accumulator += fragment

    def _complete(self, status, record):
        self.out_record = bytes(record)
        self.success_offset = self.entry_remaining
        self.flag_71 = True
        self.in_fragment = False
        return status

    def scan(self, read, parser=None):
        """Run the loop. `read` takes this scan and returns
        (status, code, fragment, aux). `parser` takes (tag, rest)."""
        # Prologue: out_record initialised empty, scratch cleared,
        # stream finish called when the stream object is present.
        self.out_record = b""
        self.scratch = b""
        if self.stream is not None:
            self.stream.finish()
            self.stream_finished = True
        while True:
            status, code, fragment, aux = read(self)
            if status == 0:
                return 0
            if code in FULL:
                if self.in_fragment and len(self.accumulator) > 0:
                    self.report("partial record without end(1)",
                                len(self.accumulator))
                self._clear_accumulator()
                return self._complete(status, fragment)
            if code in FIRST:
                if self.in_fragment or len(self.accumulator) > 0:
                    self.report("partial record without end(2)",
                                len(self.accumulator))
                self.accumulator = bytearray(fragment)
                self.in_fragment = True
                continue
            if code in MIDDLE:
                if not self.in_fragment:
                    self.report("missing start of fragmented record(1)",
                                len(fragment))
                    continue
                self._append(fragment)
                continue
            if code in LAST:
                if not self.in_fragment:
                    self.report("missing start of fragmented record(2)",
                                len(fragment))
                    continue
                self._append(fragment)
                self.scratch = bytes(self.accumulator)
                record = self.scratch
                self._clear_accumulator()
                return self._complete(status, record)
            if code == 9:
                if self.flag_73:
                    self.report("read multiple SetCompressionType records",
                                len(fragment))
                if self.flag_71:
                    self.report("SetCompressionType not the first record",
                                len(fragment))
                self._clear_accumulator()
                # 0x5162bda clears the in-fragment flag, and the
                # completion jump targets 0x5162aff, skipping the set
                # at 0x5162af8: compression never sets in-fragment.
                self.in_fragment = False
                if len(fragment) <= 3:
                    self.report("could not decode SetCompressionType record",
                                len(fragment))
                else:
                    tag = fragment[0]
                    rest = fragment[4:]
                    if tag in (0, 7):
                        if parser is not None:
                            parser(tag, rest)
                        self.parser_calls.append((tag, rest))
                    else:
                        # The binary advances the slice past the 4-byte
                        # tag before the detail path, so the reported
                        # value is the advanced length, not the original.
                        self.report(
                            "could not decode SetCompressionType record",
                            len(rest))
                continue
            if code in ERROR_CODES:
                if self.in_fragment:
                    self.report("error in middle of record",
                                len(self.accumulator))
                    self._clear_accumulator()
                    self.in_fragment = False
                continue
            if code == 15:
                if self.flag_70:
                    self._clear_accumulator()
                    return 0
                self.report("checksum mismatch", aux)
                if self.in_fragment:
                    self.report("error in middle of record",
                                len(self.accumulator))
                    self._clear_accumulator()
                    self.in_fragment = False
                continue
            # Unknown: code 0, 14, above 15, or negative (unsigned compare).
            # The arm joins the error tail at 0x5162a15, so after the
            # report the accumulator and the in-fragment flag are cleared.
            value = len(fragment)
            if self.in_fragment:
                value += len(self.accumulator)
            self.report("unknown record type %u" % (code & 0xFFFFFFFF), value)
            self._clear_accumulator()
            self.in_fragment = False
            continue
