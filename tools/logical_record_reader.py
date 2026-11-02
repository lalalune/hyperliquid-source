"""Python model of node #94 0x51618e0: the WAL logical-record reader,
with its two physical-record decode call sites (0x51619c6, 0x5161ec9)
into 0x5161400 (see research/work-items/RE-001-wal-physical-record-94/).

The window reads physical records through the decode interface and
assembles logical records from fragments. It is one complete behavior:
the prologue, the fragment state machine, the SetCompressionType arm,
and both error-continuation loops (mode 3 skips and continues, the
other modes return or continue per the flag and mode checks below).

The decode routine itself is NOT modeled here; it is the subject of
PR #1848. The model takes it as a caller-supplied hook returning the
decode code, the fragment bytes, and the remaining-size out value,
exactly as 0x5161400 reports them (codes 0..9 are record types,
10 end of data, 11 trailer, 12 leftover, 13 log-number mismatch,
14 truncated, 15 CRC mismatch, above 15 an error the caller treats
as an unknown record type).

Arguments (the binary's registers, not invented names):
- reader state fields, by binary offset (see the packet README).
- out_slice: the caller's Slice, reset to empty at entry and filled
  with the assembled record on success (the fragment itself for a
  full record, the accumulator contents for a fragmented record).
- accumulator: the caller's string, cleared at entry, holding the
  fragments of a record in progress.
- mode: the low byte of the 4th argument. Only the low byte is
  consulted: 3 selects the skip-and-continue loop; 1 and 2 select
  the strict reporting arms of the other loop; 0 selects the
  tolerate arms. The enum names behind these values are recorded
  in the packet README as the inferred reading (they match the WAL
  recovery-mode pattern); every branch condition below is pinned
  exactly as the bytes state it, independent of the names.
- transform_out: the nullable 5th argument. None selects the plain
  assembly path; a Slot selects the stream path and receives the
  finish/transform result on completion.

Callee contracts (hooks; the callees themselves are not modeled):
- decode(state) -> (code, fragment, remaining_out). The hook also
  updates state.cumulative / state.buffer_remaining, from which the
  model computes the loop-head snapshot (cumulative - remaining),
  exactly as the window computes [rbx+0x60] - [rbx+0x40].
- report(nbytes, message): the 0x5160f90 corruption reporter.
- stream_create() / stream_reset(obj) / stream_append(obj, frag) /
  stream_finish(obj): the 0x543bde0 / 0x543be50 / 0x543bed0 /
  0x543dc30 stream object at reader +0xa8. stream_reset is called
  with None in plain mode (the binary calls it with a possibly-null
  object; the callee guards null and returns 1).
- transform_one_shot(frag): the 0x543b020 one-shot transform used
  only on the full-record finalize path.
- attached_hook(obj): the +0x78 object's vtable+0x18 slot, invoked
  in the prologue when an attached object is present.
- parse_compression(type_byte): the 0x5161850 body parser. The
  default implementation applies the parser contract pinned from
  its 82 bytes: compression_seen = True, compression_type =
  type_byte, attached = create_attached(), plus a fresh 0x8000-byte
  buffer. Override it only to observe the call.
- detail_builder(prefix, detail): the 0x542f040 string joiner. The
  default builds "prefix: detail". On the compression arm's detail
  path the built string is freed unread by the window; the arm's
  decision byte is the callee's constant argument 2, so that path
  always reports (see the packet README).
"""

MASK64 = (1 << 64) - 1
APPEND_CAP = 0x3FFFFFFFFFFFFFFF

CODE_EOF = 10
CODE_TRAILER = 11
CODE_LEFTOVER = 12
CODE_LOG_NUMBER = 13
CODE_TRUNCATED = 14
CODE_BAD_CRC = 15

TYPE_FULL = (1, 5)
TYPE_FIRST = (2, 6)
TYPE_MIDDLE = (3, 7)
TYPE_LAST = (4, 8)
TYPE_SET_COMPRESSION = 9

MODE_SKIP = 3
MODE_STRICT = (1, 2)

COMPRESSION_PREFIX = "CompressionTypeRecord"
COMPRESSION_TAG_OK = (0, 7)
DETAIL_SHORT_BODY = "Error decoding WAL compression type"
DETAIL_UNSUPPORTED = "WAL compression type not supported"

MSG_PARTIAL_NO_END_1 = "partial record without end(1)"
MSG_PARTIAL_NO_END_2 = "partial record without end(2)"
MSG_MISSING_START_1 = "missing start of fragmented record(1)"
MSG_MISSING_START_2 = "missing start of fragmented record(2)"
MSG_ERROR_IN_MIDDLE = "error in middle of record"
MSG_TRAILING_DATA = "error reading trailing data"
MSG_TRUNCATED_HEADER = "truncated header"
MSG_TRUNCATED_BODY = "truncated record body"
MSG_BAD_LENGTH = "bad record length"
MSG_CHECKSUM = "checksum mismatch"
MSG_DECODE_COMPRESSION = "could not decode SetCompressionType record"
MSG_MULTIPLE_COMPRESSION = "read multiple SetCompressionType records"
MSG_COMPRESSION_NOT_FIRST = "SetCompressionType not the first record"


class LengthError(Exception):
    """The window's _M_append overflow path (basic_string::append)."""


class Slot:
    """A nullable out-pointer cell (the transform out-pointer)."""

    def __init__(self):
        self.value = None


class ReaderState:
    """The reader fields the window touches, by binary offset."""

    def __init__(self, mode=0, transform_out=None):
        self.mode = mode & 0xFF
        self.transform_out = transform_out
        # Buffer accounting, updated by the decode hook:
        self.cumulative = 0  # +0x60
        self.buffer_remaining = 0  # +0x40
        self.short_final = False  # +0x48
        self.sticky = False  # +0x70
        self.seen_record = False  # +0x71
        self.compression_type = None  # +0x72
        self.compression_seen = False  # +0x73
        self.attached = None  # +0x78
        self.stream = None  # +0xa8
        self.stream_buffer = None  # +0x80, allocated by the parser
        # Call outputs:
        self.accumulator = bytearray()
        self.out_slice = b""
        self.success_offset = None  # +0x58
        self.first_snapshot = None  # stack [rsp+0x18]
        self.reports = []  # (nbytes, message) pairs, in order


def _default_parse_compression(state, type_byte):
    state.compression_seen = True
    state.compression_type = type_byte
    state.attached = object()
    state.stream_buffer = bytes(0x8000)


class LogicalReader:
    """The 0x51618e0 state machine over a caller-supplied decode hook."""

    def __init__(self, decode, report=None, stream_create=None,
                 stream_reset=None, stream_append=None,
                 stream_finish=None, transform_one_shot=None,
                 attached_hook=None, parse_compression=None,
                 detail_builder=None):
        self.decode = decode
        self.report = report if report is not None else (lambda n, m: None)
        self.stream_create = stream_create if stream_create is not None \
            else (lambda: object())
        self.stream_reset = stream_reset if stream_reset is not None \
            else (lambda obj: 1)
        self.stream_append = stream_append if stream_append is not None \
            else (lambda obj, frag: None)
        self.stream_finish = stream_finish if stream_finish is not None \
            else (lambda obj: None)
        self.transform_one_shot = transform_one_shot \
            if transform_one_shot is not None else (lambda frag: None)
        self.attached_hook = attached_hook if attached_hook is not None \
            else (lambda obj: None)
        if parse_compression is not None:
            self.parse_compression = parse_compression
        else:
            self.parse_compression = \
                lambda state, t: _default_parse_compression(state, t)
        self.detail_builder = detail_builder \
            if detail_builder is not None \
            else (lambda prefix, detail: prefix + ": " + detail)

    def read_record(self, state):
        """Returns True on a successfully assembled record, else False."""
        # Prologue: clear the accumulator, reset the out slice.
        state.accumulator = bytearray()
        state.out_slice = b""
        if state.transform_out is not None:
            if state.stream is None:
                state.stream = self.stream_create()
            self.stream_reset(state.stream)
        if state.attached is not None:
            self.attached_hook(state.attached)
        in_fragment = False
        skip_loop = state.mode == MODE_SKIP
        while True:
            snapshot = state.cumulative - state.buffer_remaining
            code, fragment, remaining_out = self.decode(state)
            if code == 0 or code > 15:
                nbytes = len(fragment) + (
                    len(state.accumulator) if in_fragment else 0)
                self.report(nbytes, "unknown record type %u" % code)
                state.accumulator = bytearray()
                in_fragment = False
                continue
            if code in TYPE_FULL:
                if in_fragment and len(state.accumulator) != 0:
                    self.report(len(state.accumulator),
                                MSG_PARTIAL_NO_END_1)
                if state.transform_out is not None \
                        and state.attached is None:
                    state.transform_out.value = \
                        self.transform_one_shot(fragment)
                state.accumulator = bytearray()
                state.out_slice = bytes(fragment)
                state.success_offset = snapshot
                state.seen_record = True
                return True
            if code in TYPE_FIRST:
                if in_fragment and len(state.accumulator) != 0:
                    self.report(len(state.accumulator),
                                MSG_PARTIAL_NO_END_2)
                    self.stream_reset(state.stream)
                if state.transform_out is not None:
                    self.stream_append(state.stream, fragment)
                state.accumulator = bytearray(fragment)
                in_fragment = True
                state.first_snapshot = snapshot
                continue
            if code in TYPE_MIDDLE:
                if not in_fragment:
                    self.report(len(fragment), MSG_MISSING_START_1)
                    in_fragment = False
                    continue
                if state.transform_out is not None:
                    self.stream_append(state.stream, fragment)
                self._append(state, fragment)
                continue
            if code in TYPE_LAST:
                if not in_fragment:
                    self.report(len(fragment), MSG_MISSING_START_2)
                    in_fragment = False
                    continue
                if state.transform_out is not None:
                    self.stream_append(state.stream, fragment)
                    state.transform_out.value = \
                        self.stream_finish(state.stream)
                self._append(state, fragment)
                state.out_slice = bytes(state.accumulator)
                state.success_offset = state.first_snapshot
                state.seen_record = True
                return True
            if code == TYPE_SET_COMPRESSION:
                self._compression_arm(state, fragment, snapshot)
                continue
            if skip_loop:
                if self._skip_loop_error(state, code, remaining_out,
                                         in_fragment):
                    return False
                in_fragment = False
                continue
            done = self._strict_loop_error(state, code, remaining_out,
                                           in_fragment)
            if done == "return":
                return False
            in_fragment = False
            # done == "continue": loop again with a fresh snapshot.

    def _append(self, state, fragment):
        if len(fragment) > APPEND_CAP - len(state.accumulator):
            raise LengthError("basic_string::append")
        state.accumulator += fragment

    def _compression_arm(self, state, fragment, snapshot):
        if state.compression_seen:
            self.report(len(fragment), MSG_MULTIPLE_COMPRESSION)
        if state.seen_record:
            self.report(len(fragment), MSG_COMPRESSION_NOT_FIRST)
        state.accumulator = bytearray()
        state.success_offset = snapshot
        if len(fragment) <= 3:
            self.detail_builder(COMPRESSION_PREFIX, DETAIL_SHORT_BODY)
            self.report(len(fragment), MSG_DECODE_COMPRESSION)
            state.first_snapshot = snapshot
            return
        tag = fragment[0]
        if tag in COMPRESSION_TAG_OK:
            self.parse_compression(state, tag)
            state.first_snapshot = snapshot
            return
        # Detail path: the callee writes its constant argument 2 into
        # the decision byte, so this path always reports (the parse
        # branch from here is unreachable in node #94). The built
        # string is freed unread by the window.
        self.detail_builder(COMPRESSION_PREFIX, DETAIL_UNSUPPORTED)
        self.report(len(fragment), MSG_DECODE_COMPRESSION)
        state.first_snapshot = snapshot

    def _error_in_middle_continue(self, state, in_fragment):
        if in_fragment:
            self.report(len(state.accumulator), MSG_ERROR_IN_MIDDLE)
            state.accumulator = bytearray()

    def _skip_loop_error(self, state, code, remaining_out, in_fragment):
        """Mode-3 loop. Returns True when the call returns False."""
        if code in (CODE_EOF, CODE_LEFTOVER):
            if in_fragment:
                state.accumulator = bytearray()
            return True
        if code in (CODE_TRAILER, CODE_LOG_NUMBER):
            self._error_in_middle_continue(state, in_fragment)
            return False
        if code == CODE_TRUNCATED:
            if state.short_final:
                return True
            self.report(remaining_out, MSG_BAD_LENGTH)
            self._error_in_middle_continue(state, in_fragment)
            return False
        if code == CODE_BAD_CRC:
            self.report(remaining_out, MSG_CHECKSUM)
            self._error_in_middle_continue(state, in_fragment)
            return False
        raise AssertionError("unhandled skip-loop code %r" % code)

    def _strict_loop_error(self, state, code, remaining_out, in_fragment):
        """The other loop. Returns 'return' or 'continue'."""
        strict = state.mode in MODE_STRICT
        if code == CODE_EOF:
            if not in_fragment:
                return "return"
            if strict:
                self.report(len(state.accumulator), MSG_TRAILING_DATA)
            state.accumulator = bytearray()
            return "return"
        if code == CODE_TRAILER:
            self._error_in_middle_continue(state, in_fragment)
            return "continue"
        if code == CODE_LEFTOVER:
            if strict:
                self.report(remaining_out, MSG_TRUNCATED_HEADER)
                if in_fragment:
                    self.report(len(state.accumulator),
                                MSG_TRAILING_DATA)
                    state.accumulator = bytearray()
                return "return"
            if in_fragment:
                state.accumulator = bytearray()
            return "return"
        if code == CODE_LOG_NUMBER:
            if not in_fragment:
                return "return"
            if strict:
                self.report(len(state.accumulator), MSG_TRAILING_DATA)
            state.accumulator = bytearray()
            return "return"
        if code == CODE_TRUNCATED:
            if state.short_final:
                if strict:
                    self.report(remaining_out, MSG_TRUNCATED_BODY)
                return "return"
            if state.mode != 0:
                self.report(remaining_out, MSG_BAD_LENGTH)
                self._error_in_middle_continue(state, in_fragment)
                return "continue"
            if state.sticky:
                state.accumulator = bytearray()
                return "return"
            self.report(remaining_out, MSG_BAD_LENGTH)
            self._error_in_middle_continue(state, in_fragment)
            return "continue"
        if code == CODE_BAD_CRC:
            if not state.sticky:
                self.report(remaining_out, MSG_CHECKSUM)
                self._error_in_middle_continue(state, in_fragment)
                return "continue"
            if state.mode == 0:
                state.accumulator = bytearray()
                return "return"
            self.report(remaining_out, MSG_CHECKSUM)
            self._error_in_middle_continue(state, in_fragment)
            return "continue"
        raise AssertionError("unhandled strict-loop code %r" % code)
