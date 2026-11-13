#!/usr/bin/env python3
"""Node #115 RocksDB LineFileReader::ReadLine: reconstruction.

RE-002 work item. Reconstructs the OPTIONS-file line reader at
0x60d4cf0..0x60d4f62 (626 B), the only caller of
``SequentialFileReader::Read`` (0x6048e00) left unidentified by the
#5992 packet:

  rocksdb::LineFileReader::ReadLine   0x60d4cf0 (626 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
This FDE has NO vendor census record (body hash only, per the
#5992 no-census convention used by WriteDirect #6204 and the
other no-census engine packets); its identity is pinned three
other ways: (1) the class is named by the census-bound destructor
``_ZN7rocksdb14LineFileReaderD1Ev`` at 0x60cbea0 in member
d7ece8bd5f9dc186-options_parser.o, whose body destroys exactly
this layout; (2) its only caller in the whole .text is
``rocksdb::RocksDBOptionsParser::Parse`` 0x60cfb60 (call site
0x60d0343, census-bound symbol
``_ZN7rocksdb20RocksDBOptionsParser5ParseERKNS_13ConfigOptionsE
RKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS_10File
SystemE``), which loops ``while (ReadLine(&line, IO_TOTAL))``;
(3) upstream v8.1.1, read live this cycle: ``LineFileReader`` is
declared in file/line_file_reader.h (60 lines) and ``ReadLine``
is defined in file/line_file_reader.cc:30-71, and the binary
matches it step for step (see the packet README).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  bool ReadLine(std::string* out, Env::IOPriority priority)
  -- rdi is the LineFileReader*, rsi the std::string* out, edx
  the priority (forwarded to SequentialFileReader::Read as r9d).
  Steps, in binary order:

  1. Entry gate (0x60d4d16..0x60d4d1d): if io_status_.code
     (this+0x20a8, byte 0) != 0, return false at once -- out is
     NOT cleared and NOT touched (the sticky-error gate; upstream
     line_file_reader.cc:33-37 does the same check, then
     ``io_status_.MustCheck(); return false;`` -- MustCheck() is
     an empty inline in this build and has no binary call).
  2. out->clear() (0x60d4d23..0x60d4d45): out->size() = 0 and
     out->data()[0] = 0. The reader state is loaded: r12 = pos_
     (this+0x20b8), r15 = end_ (this+0x20c0).
  3. Loop head (0x60d4ebc..0x60d4ed2): remaining = end_ - pos_;
     p = memchr(pos_, '\\n', remaining) (PLT memchr 0x63f1790).
     If p is null, go to the refill path (step 5).
  4. Newline found (0x60d4ed8..0x60d4f17): len = p - pos_; the
     length check (0x60d4ede..0x60d4eef) throws
     ``__throw_length_error("basic_string::append")`` (PLT
     0x63f0de0, string at 0x4474d2) if len > MAX - out->size()
     with MAX = 0x3fffffffffffffff; else out->append(pos_, len)
     (std::string::_M_append, PLT 0x63f0f40) -- the returned line
     EXCLUDES the newline; pos_ += len + 1 (the newline is
     skipped); line_number_ (this+0x20c8) += 1; return true.
  5. Refill path, no newline in the buffer (0x60d4d70..0x60d4d96):
     if at_eof_ (this+0x20d0) is set, return false -- out keeps
     whatever earlier refills of THIS call already appended, and
     the caller (Parse) discards it. Else the same length check
     (MAX - out->size() vs remaining) and out->append(pos_,
     remaining) -- the leftover partial line is appended BEFORE
     the refill, so a line spanning several 8 KiB chunks is built
     up across refills.
  6. Refill read (0x60d4d9b..0x60d4dc7): io_status_ =
     sfr_.Read(buf_.size(), &result, buf_.data(),
     rate_limiter_priority) -- the call at 0x6048e00 with the
     hidden 16-byte sret in rdi (the stack slot at rsp+0x30),
     sfr_ (the embedded SequentialFileReader at this+0x2000) in
     rsi, n = 0x2000 in rdx, the result Slice (stack, rsp+0x20,
     initialised to {"", 0} -- the empty-string literal at
     0x4376fd, exactly Slice::clear()) in rcx, the scratch
     buf_.data() (= this+0x0, the first 8192 bytes of the object)
     in r8, and the priority in r9d. SequentialFileReader::Read
     itself is the #5992 subject (not census-bound; identified by
     the call-site signature match and the IO_TOTAL bypass branch
     in the ReadMore packet); this model scripts it as an oracle.
  7. Status move (0x60d4dcc..0x60d4e2b): the sret IOStatus is
     moved into io_status_ (this+0x20a8): bytes 0-1, 3-4, 5 and
     8-15 are copied (byte 2 and bytes 6-7 are NOT copied -- the
     move leaves them at their previous values); the old
     state_ pointer is freed with operator delete[] (PLT
     0x63f0dc0) and the sret slot is zeroed. The second delete[]
     at 0x60d4e2b is dead (its argument was just zeroed).
  8. IOSTATS (0x60d4e30..0x60d4e79): two calls to the TLS-marker
     helper 0x606d9f0 (the same helper the WritableFileWriter
     family calls at its sync-point sites; it sets a TLS
     once-flag at fs-0x400 and clears the guard byte at
     fs-0x3f8+0x98) bracketing the guarded counter add:
     if the guard byte is clear, the TLS bytes-read counter at
     fs-0x3f8+0x10 += result.size(). This is the expansion of
     upstream ``IOSTATS_ADD(bytes_read, result.size())``
     (line_file_reader.cc:59); it runs BEFORE the status check,
     so a failed Read still adds its (partial) result size. No
     sync-point string is passed at either helper call site, so
     no upstream sync-point name is pinned for these calls.
  9. Status check (0x60d4e7d..0x60d4e84): if io_status_.code != 0,
     return false -- out keeps the partial line appended in step
     5, pos_/end_ are NOT updated (the buffered bytes stay where
     they were), and the next ReadLine call will fail at once at
     the entry gate (the error is sticky). Upstream: MustCheck();
     return false (line_file_reader.cc:60-63).
 10. Short-read EOF (0x60d4e8a..0x60d4e98): if result.size() !=
     0x2000, at_eof_ = true -- upstream calls this "The obscure
     way of indicating EOF" (line_file_reader.cc:64-67). A full
     8192-byte read does NOT set at_eof_, even if it was the last
     chunk: the next call refills, reads 0 bytes (OK), and only
     then learns EOF. Then buf_begin_ = result.data() and
     buf_end_ = result.data() + result.size() (0x60d4e9f..
     0x60d4eb5, via movups), and the loop repeats at step 3.
 11. Epilogue (0x60d4f22..0x60d4f40): stack-canary check, restore
     the six callee-saved registers, return the bool in eax.
     The length-error path (0x60d4f41..0x60d4f58) checks the
     canary first, then throws. There is NO .cold landing pad:
     the FDE has no LSDA, and the function never throws except
     through __throw_length_error (which propagates to the
     caller).

Layout (pinned by the disassembly AND upstream
file/line_file_reader.h:16-24, declaration order):

  +0x0000  buf_            std::array<char, 8192>  (the scratch)
  +0x2000  sfr_            SequentialFileReader (0xa8 bytes)
  +0x20a8  io_status_      IOStatus (16 B)
  +0x20b8  buf_begin_      const char* (pos_)
  +0x20c0  buf_end_        const char* (end_)
  +0x20c8  line_number_    size_t (lines returned so far)
  +0x20d0  at_eof_         bool

The constructor is a forwarding template
(file/line_file_reader.h:28-30): it forwards all arguments to
the SequentialFileReader ctor and has an empty body; buf_begin_
and buf_end_ start at buf_.data() by their default member
initialisers, line_number_ at 0, at_eof_ at false. There is NO
explicit destructor in the upstream source (implicit default);
the census-bound ``_ZN7rocksdb14LineFileReaderD1Ev`` at
0x60cbea0 is that implicit destructor, and its body destroys
exactly this layout (it frees io_status_.state_ at +0x20b0 first,
then destroys the vector<shared_ptr> at sfr_+0x88..+0x98).

Caller (whole-.text census, Capstone-validated): exactly ONE
direct call, at 0x60d0343 inside
``rocksdb::RocksDBOptionsParser::Parse`` 0x60cfb60..0x60d1354
(census-bound), in its ``while (lf_reader.ReadLine(&line,
Env::IO_TOTAL))`` loop (options_parser.cc:273); 0 tail jumps, 0
LEA refs. Parse constructs the reader on its stack as
``LineFileReader lf_reader(std::move(seq_file), file_name,
config_options.file_readahead_size)`` (options_parser.cc:264-265)
and reads the status back with ``lf_reader.GetStatus()`` after
the loop (options_parser.cc:310).

Environment limits (stated honestly): no cargo/rustc/git-lfs/
Ghidra on this VM; the model is Python evidence, not a Rust
reconstruction; SequentialFileReader::Read is scripted as an
oracle (its record bytes and rate-limiter internals are the
#5992 subject, not reimplemented here); the TLS IOSTATS counter
is modelled as a plain integer (the guard byte is cleared by the
helper on first use, so the add is unconditional in practice).
"""
import hashlib
import json
import random
import sys
import tempfile
from pathlib import Path

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / \
    "re-002-node115-line-file-reader-readline-115"
CASES = PACKET / "cases.tsv"

# Binary facts.
FDE_START = 0x60D4CF0
FDE_END = 0x60D4F62
BUF_SIZE = 8192  # buf_ is std::array<char, 8192>; Read n = 0x2000
MAX_SIZE = 0x3FFFFFFFFFFFFFFF  # libstdc++ std::string::max_size()
IO_TOTAL = 4  # Env::IOPriority, the priority Parse passes

# IOStatus codes (rocksdb/status.h, implicit 0-based).
CODE_OK = 0
CODE_NOT_FOUND = 1
CODE_CORRUPTION = 2
CODE_NOT_SUPPORTED = 3
CODE_INVALID_ARGUMENT = 4
CODE_IO_ERROR = 5


class LengthError(ValueError):
    """std::string::_M_append overflow: __throw_length_error
    ("basic_string::append")."""


class IOStatus:
    """A 16-byte IOStatus: code (byte 0), subcode (byte 1), state_ ptr."""

    def __init__(self, code=CODE_OK, subcode=0, message=None):
        self.code = code
        self.subcode = subcode
        self.message = message

    @classmethod
    def ok(cls):
        return cls(CODE_OK)

    @classmethod
    def io_error(cls, message):
        return cls(CODE_IO_ERROR, 0, message)

    def is_ok(self):
        return self.code == CODE_OK

    def summary(self):
        return {"code": self.code, "subcode": self.subcode,
                "state": 1 if self.message is not None else 0,
                "message": self.message}

    def __eq__(self, other):
        return isinstance(other, IOStatus) and \
            self.summary() == other.summary()

    def __repr__(self):
        return "IOStatus(%r)" % (self.summary(),)


class OutStr:
    """A std::string* out-parameter: the model mutates .value, so
    the entry-gate 'out untouched' behaviour is observable."""

    def __init__(self, value=b""):
        self.value = value


class FakeSequentialFile:
    """An in-memory SequentialFile: Read(n) returns up to n bytes
    from the current offset. A script can fail a chosen Read with
    a chosen status and partial size."""

    def __init__(self, data=b"", script=None):
        self.data = bytes(data)
        self.offset = 0
        self.script = script or {}
        self.reads = 0
        self.calls = []

    def read(self, n):
        """SequentialFileReader::Read (oracle): returns
        (IOStatus, bytes)."""
        self.calls.append({"op": "read", "n": n})
        idx = self.reads
        self.reads += 1
        fail = self.script.get("fail_at_read")
        if fail is not None and idx == fail:
            size = self.script.get("fail_size", 0)
            chunk = self.data[self.offset:self.offset + size]
            self.offset += len(chunk)
            status = self.script.get(
                "fail_status", IOStatus.io_error("read failed"))
            return status, chunk
        chunk = self.data[self.offset:self.offset + n]
        self.offset += len(chunk)
        return IOStatus.ok(), chunk


class RealSequentialFile:
    """A SequentialFile backed by a real file on disk (for --live)."""

    def __init__(self, path, script=None):
        self.path = Path(path)
        self.fh = open(self.path, "rb")
        self.script = script or {}
        self.reads = 0
        self.calls = []

    def read(self, n):
        self.calls.append({"op": "read", "n": n})
        idx = self.reads
        self.reads += 1
        fail = self.script.get("fail_at_read")
        if fail is not None and idx == fail:
            size = self.script.get("fail_size", 0)
            chunk = self.fh.read(size)
            status = self.script.get(
                "fail_status", IOStatus.io_error("read failed"))
            return status, chunk
        return IOStatus.ok(), self.fh.read(n)

    def close(self):
        self.fh.close()


class LineFileReader:
    """The LineFileReader model. buf_/pos_/end_ are indices into
    the buffered chunk (the binary keeps pointers into buf_); the
    embedded SequentialFileReader is the file oracle."""

    def __init__(self, seq_file):
        self.seq_file = seq_file
        self.buf = b""          # buf_ contents (<= 8192 bytes)
        self.buf_begin = 0      # buf_begin_ index
        self.buf_end = 0        # buf_end_ index
        self.io_status = IOStatus.ok()
        self.line_number = 0
        self.at_eof = False
        self.iostats_bytes_read = 0
        self.trace = []

    def _append(self, out, chunk):
        """std::string::_M_append with the length guard (steps 4/5):
        throws LengthError when out + chunk would exceed max_size."""
        if len(chunk) > MAX_SIZE - len(out.value):
            raise LengthError("basic_string::append")
        out.value = out.value + chunk

    def read_line(self, out, priority=IO_TOTAL):
        """The ReadLine model. Returns True when a line (without its
        '\\n') was stored in out; False at EOF or on a read error
        (distinguish with get_status(), exactly as Parse does)."""
        # 1. Entry gate: sticky error -- out untouched.
        if not self.io_status.is_ok():
            self.trace.append({"op": "entry_gate",
                               "status_ok": False,
                               "reason": "sticky_status"})
            return False
        self.trace.append({"op": "entry_gate", "status_ok": True})
        # 2. out->clear().
        out.value = b""
        self.trace.append({"op": "clear_out"})
        # 3-10. The for(;;) loop.
        while True:
            remaining = self.buf_end - self.buf_begin
            idx = self.buf.find(b"\n", self.buf_begin, self.buf_end)
            if idx >= 0:
                # 4. Newline found.
                length = idx - self.buf_begin
                self.trace.append({"op": "memchr", "remaining": remaining,
                                   "found": idx - self.buf_begin})
                self._append(out, self.buf[self.buf_begin:idx])
                self.trace.append({"op": "append", "n": length,
                                   "from": "buffer"})
                self.buf_begin = idx + 1
                self.line_number += 1
                self.trace.append({"op": "line_returned",
                                   "line_number": self.line_number})
                return True
            self.trace.append({"op": "memchr", "remaining": remaining,
                               "found": None})
            # 5. Refill path: at_eof_ -> false (partial line stays
            # in out, the caller discards it).
            if self.at_eof:
                self.trace.append({"op": "return_false",
                                   "reason": "at_eof"})
                return False
            self._append(out, self.buf[self.buf_begin:self.buf_end])
            self.trace.append({"op": "append", "n": remaining,
                               "from": "refill"})
            # 6. sfr_.Read(buf_.size(), &result, buf_.data(), priority).
            self.trace.append({"op": "tls_helper",
                               "addr": "0x606d9f0", "which": 1})
            status, chunk = self.seq_file.read(BUF_SIZE)
            self.trace.append({"op": "read", "n": BUF_SIZE,
                               "priority": priority,
                               "result_size": len(chunk),
                               "status_code": status.code})
            # 7. Status move into io_status_ (old state_ freed).
            self.io_status = status
            self.trace.append({"op": "status_move",
                               "code": status.code})
            # 8. IOSTATS_ADD(bytes_read, result.size()) -- the TLS
            # helper calls bracket the guarded counter add; the
            # guard byte is cleared by the helper on first use, so
            # the add is unconditional in practice. Runs BEFORE
            # the status check (a failed Read still adds its
            # partial size).
            self.trace.append({"op": "tls_helper",
                               "addr": "0x606d9f0", "which": 2})
            self.iostats_bytes_read += len(chunk)
            self.trace.append({"op": "iostats_add",
                               "bytes": len(chunk)})
            # 9. Status check.
            if not status.is_ok():
                self.trace.append({"op": "return_false",
                                   "reason": "read_error"})
                return False
            # 10. Short read -> at_eof_; install the new buffer.
            if len(chunk) != BUF_SIZE:
                self.at_eof = True
                self.trace.append({"op": "at_eof_set"})
            self.buf = chunk
            self.buf_begin = 0
            self.buf_end = len(chunk)

    def get_status(self):
        """GetStatus(): the reader's io_status_ (Parse reads it
        after the loop to tell EOF from an I/O error)."""
        return self.io_status

    def get_line_number(self):
        return self.line_number


def make_reader(inputs):
    """Build a LineFileReader from a case inputs dict."""
    script = {}
    if inputs.get("fail_at_read") is not None:
        script["fail_at_read"] = inputs["fail_at_read"]
        script["fail_size"] = inputs.get("fail_size", 0)
        msg = inputs.get("fail_message", "read failed")
        script["fail_status"] = (IOStatus.io_error(msg) if msg
                                 else IOStatus(CODE_IO_ERROR))
    seq = FakeSequentialFile(bytes.fromhex(inputs["file"]), script=script)
    return LineFileReader(seq)


def run_case(inputs):
    """Run one case: loop ReadLine until it returns False (capped),
    reusing one out holder exactly as Parse does. Returns the
    expected-output dict."""
    reader = make_reader(inputs)
    out = OutStr(bytes.fromhex(inputs.get("initial_out", "")))
    calls = []
    cap = inputs.get("max_calls", 1000)
    for _ in range(cap):
        before = out.value
        ok = reader.read_line(out, inputs.get("priority", IO_TOTAL))
        calls.append({"ok": ok, "line": out.value.hex(),
                      "out_untouched": out.value == before
                      if not ok else None})
        if not ok:
            break
    return {
        "calls": calls,
        "final_out": out.value.hex(),
        "status": reader.get_status().summary(),
        "line_number": reader.get_line_number(),
        "at_eof": reader.at_eof,
        "iostats_bytes_read": reader.iostats_bytes_read,
        "trace": reader.trace,
    }

def _rand_lines(rng, n, max_len=60):
    """Random file content: n lines, each a random byte string
    (printable ASCII plus occasional \\r / tab / high bytes),
    joined with \\n; the trailing newline is decided by the caller."""
    lines = []
    for _ in range(n):
        ln = rng.choice([0, 1, 2, 5, 10, 30, 60, max_len])
        alphabet = b"abcdefghij0123456789 \t=;[]"
        line = bytes(rng.choice(alphabet) for _ in range(ln))
        if rng.random() < 0.15:
            line += b"\r"
        if rng.random() < 0.1:
            line += bytes([rng.choice([0x00, 0xFF, 0x80, 0x7F])])
        lines.append(line)
    return lines


def _gen_group(rng, group, n):
    rows = []
    for i in range(n):
        case_id = "%s-%03d" % (group, i)
        lines = _rand_lines(rng, rng.choice([0, 1, 2, 3, 5, 8]))
        trailing = rng.random() < 0.7
        data = b"\n".join(lines) + (b"\n" if trailing and lines else b"")
        if not lines:
            data = rng.choice([b"", b"\n", b"\n\n"])
        script = {}
        if group == "gate":
            # Read failures, sticky-error sequences, priorities.
            if rng.random() < 0.4:
                script["fail_at_read"] = rng.choice([0, 0, 1, 2])
                script["fail_size"] = rng.choice([0, 0, 5, 100])
                script["fail_message"] = rng.choice(
                    ["read failed", "disk error", ""])
            if rng.random() < 0.2:
                script["priority"] = rng.choice([0, 1, 2, 3, 4, 4, 4])
        elif group == "lines":
            # Line shapes: empty lines, CRLF, long lines, exact
            # buffer-boundary lines.
            kind = rng.choice(["empty", "crlf", "long", "boundary",
                               "plain"])
            if kind == "empty":
                data = b"\n" * rng.choice([1, 2, 5, 20])
            elif kind == "crlf":
                data = b"a\r\nb\r\n\r\nc\r\n"
            elif kind == "long":
                ln = rng.choice([8193, 10000, 16384, 20000, 25000])
                data = b"x" * ln + b"\n" + b"y" * rng.choice(
                    [0, 1, 8192]) + b"\n"
            elif kind == "boundary":
                ln = rng.choice([8191, 8192, 8193, 16383, 16384, 16385])
                data = b"z" * ln + b"\nshort\n"
            else:
                data = b"hello world\nsecond line\n"
            if rng.random() < 0.3:
                data = data[:-1]  # drop the trailing newline
        elif group == "chunking":
            # Files sized around the 8192 refill boundary, with and
            # without a trailing newline. Newlines are sparse (one
            # every ~500-2000 bytes) so a case stays small.
            total = rng.choice([8191, 8192, 8193, 16383, 16384, 16385,
                                24576, 24577, 32768])
            parts = []
            left = total
            while left > 0:
                seg = rng.choice([500, 1000, 1500, 2000])
                seg = min(seg, left)
                parts.append(bytes(rng.choice(b"abcdefgh")
                                   for _ in range(seg)))
                left -= seg
                if left > 0:
                    parts.append(b"\n")
                    left -= 1
            data = b"".join(parts)[:total]
            if rng.random() < 0.5 and not data.endswith(b"\n"):
                data += b"\n"
        elif group == "bindings":
            # Full end-to-end traces: mixed shapes + occasional
            # scripted failures + varied priorities.
            if rng.random() < 0.3:
                script["fail_at_read"] = rng.choice([0, 1])
                script["fail_size"] = rng.choice([0, 7])
                script["fail_message"] = "read failed"
            if rng.random() < 0.3:
                script["priority"] = rng.choice([0, 4])
        inputs = {"case_id": case_id, "group": group,
                  "file": data.hex(),
                  "fail_at_read": script.get("fail_at_read"),
                  "fail_size": script.get("fail_size", 0),
                  "fail_message": script.get("fail_message", ""),
                  "priority": script.get("priority", IO_TOTAL),
                  "max_calls": 1000,
                  "initial_out": ""}
        expected = run_case(inputs)
        rows.append((group, case_id, inputs, expected))
    return rows


def write_cases():
    all_rows = []
    for gi, group in enumerate(
            ["gate", "lines", "chunking", "bindings"]):
        rng = random.Random(115000 + gi)
        all_rows.extend(_gen_group(rng, group, 600))
    with open(CASES, "w") as fh:
        fh.write("group\tcase_id\tinputs_json\texpected_json\n")
        for group, case_id, inputs, expected in all_rows:
            fh.write("%s\t%s\t%s\t%s\n" % (
                group, case_id,
                json.dumps(inputs, sort_keys=True),
                json.dumps(expected, sort_keys=True)))
    print("wrote %d cases to %s" % (len(all_rows), CASES))


def verify_cases():
    rows = []
    with open(CASES) as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    mismatches = 0
    for row in rows:
        inputs = json.loads(row["inputs_json"])
        expected = json.loads(row["expected_json"])
        got = run_case(inputs)
        if got != expected:
            mismatches += 1
            print("MISMATCH %s:\n  got %s\n  exp %s" % (
                row["case_id"], json.dumps(got, sort_keys=True),
                json.dumps(expected, sort_keys=True)))
            if mismatches >= 3:
                break
    print("verify: %d cases, %d mismatches"
          % (len(rows), mismatches))
    return mismatches == 0 and len(rows) == 2400


def live_engine_check():
    """Drive real files through the model in a temp dir; the model
    output must equal the real file bytes split on '\\n' after every
    ReadLine. 9 legs."""
    report = {"ok": False, "legs": []}
    try:
        # Leg 1: plain file -- lines come back without '\\n', the
        # line number counts, the final call is False with OK status.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "opts.txt"
            p.write_bytes(b"[Version]\nrocksdb_version=8.1.1\n\n"
                          b"[DBOptions]\nmax_open_files=12345\n")
            reader = LineFileReader(RealSequentialFile(p))
            out = OutStr()
            got = []
            while reader.read_line(out):
                got.append(out.value)
            assert got == [b"[Version]", b"rocksdb_version=8.1.1", b"",
                           b"[DBOptions]", b"max_open_files=12345"], got
            assert reader.get_line_number() == 5
            assert reader.get_status().is_ok()
            assert reader.at_eof is True
            assert reader.iostats_bytes_read == p.stat().st_size
            report["legs"].append({"leg": "plain_options_file",
                                  "ok": True})
        # Leg 2: empty file -- the first call is False, status OK
        # (EOF, not an error).
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "empty.txt"
            p.write_bytes(b"")
            reader = LineFileReader(RealSequentialFile(p))
            out = OutStr(b"sentinel")
            assert reader.read_line(out) is False
            assert out.value == b""
            assert reader.get_status().is_ok()
            assert reader.at_eof is True
            report["legs"].append({"leg": "empty_file", "ok": True})
        # Leg 3: no trailing newline -- the last partial line is
        # NOT returned (false), and out is empty: the partial line
        # was already in the buffer from call 1's refill, and the
        # at_eof_ arm returns before appending it. The caller
        # discards it.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "notrail.txt"
            p.write_bytes(b"first\nsecond-no-newline")
            reader = LineFileReader(RealSequentialFile(p))
            out = OutStr()
            got = []
            while reader.read_line(out):
                got.append(out.value)
            assert got == [b"first"], got
            assert reader.get_line_number() == 1
            assert reader.get_status().is_ok()
            assert out.value == b"", out.value
            report["legs"].append({"leg": "no_trailing_newline",
                                  "ok": True})
        # Leg 3b: an unterminated tail spanning two chunks -- the
        # refill path appends the first chunk's remainder to out,
        # then the short Read sets at_eof_ and the next memchr
        # fails, so the call returns False with that remainder in
        # out (the final chunk is never appended).
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "notrail-long.txt"
            p.write_bytes(b"x" * 9000 + b"tail-no-newline")
            reader = LineFileReader(RealSequentialFile(p))
            out = OutStr()
            assert reader.read_line(out) is False
            assert out.value == b"x" * 8192, len(out.value)
            assert reader.get_status().is_ok()
            report["legs"].append({"leg": "unterminated_long_tail",
                                  "ok": True})
        # Leg 4: a 20000-byte line spanning three 8192-byte refills
        # comes back whole.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "long.txt"
            p.write_bytes(b"L" * 20000 + b"\nshort\n")
            reader = LineFileReader(RealSequentialFile(p))
            out = OutStr()
            assert reader.read_line(out) is True
            assert out.value == b"L" * 20000
            assert reader.read_line(out) is True
            assert out.value == b"short"
            assert reader.read_line(out) is False
            assert reader.get_line_number() == 2
            assert reader.iostats_bytes_read == 20007
            report["legs"].append({"leg": "long_line_three_chunks",
                                  "ok": True})
        # Leg 5: a line of exactly 8192 bytes + '\\n' (the refill
        # boundary) -- the newline is found only after the refill.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "boundary.txt"
            p.write_bytes(b"B" * 8192 + b"\nend\n")
            reader = LineFileReader(RealSequentialFile(p))
            out = OutStr()
            assert reader.read_line(out) is True
            assert out.value == b"B" * 8192
            assert reader.read_line(out) is True
            assert out.value == b"end"
            assert reader.read_line(out) is False
            report["legs"].append({"leg": "exact_boundary_line",
                                  "ok": True})
        # Leg 6: a file ending exactly on an 8192-byte boundary --
        # EOF is learned only by a zero-byte refill Read.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "exact.txt"
            p.write_bytes(b"E" * 8191 + b"\n")
            reader = LineFileReader(RealSequentialFile(p))
            out = OutStr()
            assert reader.read_line(out) is True
            assert out.value == b"E" * 8191
            assert reader.at_eof is False  # full read, no EOF yet
            assert reader.read_line(out) is False
            assert reader.at_eof is True
            assert reader.get_status().is_ok()
            report["legs"].append({"leg": "boundary_eof",
                                  "ok": True})
        # Leg 7: scripted read failure -- the long first line needs
        # a second refill Read, which fails: False with code 5, the
        # partial line (the first chunk) stays in out, the error is
        # sticky, and the next call leaves out untouched.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "fail.txt"
            p.write_bytes(b"A" * 9000 + b"\ntwo\nthree\n")
            reader = LineFileReader(RealSequentialFile(
                p, script={"fail_at_read": 1,
                           "fail_status": IOStatus.io_error(
                               "disk error")}))
            out = OutStr()
            assert reader.read_line(out) is False
            assert out.value == b"A" * 8192, len(out.value)
            assert reader.get_status().code == 5
            out.value = b"keep-me"
            assert reader.read_line(out) is False
            assert out.value == b"keep-me"  # entry gate: untouched
            report["legs"].append({"leg": "sticky_read_error",
                                  "ok": True})
        # Leg 8: empty lines and CRLF -- empty lines return b"",
        # and '\\r' stays in the line (only '\\n' splits).
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "crlf.txt"
            p.write_bytes(b"\n\r\na\r\nb\n")
            reader = LineFileReader(RealSequentialFile(p))
            out = OutStr()
            got = []
            while reader.read_line(out):
                got.append(out.value)
            assert got == [b"", b"\r", b"a\r", b"b"], got
            assert reader.get_line_number() == 4
            report["legs"].append({"leg": "empty_and_crlf", "ok": True})
        report["ok"] = True
    except Exception as exc:  # noqa: BLE001 - report, do not raise
        report["ok"] = False
        report["error"] = repr(exc)
    print("live engine check:", json.dumps(report))
    return report["ok"], report


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true",
                    help="replay cases.tsv through the model")
    ap.add_argument("--gen-cases", action="store_true",
                    help="generate cases.tsv")
    ap.add_argument("--live", action="store_true",
                    help="run the live engine check")
    args = ap.parse_args(argv)
    ok = True
    if args.gen_cases:
        write_cases()
    if args.verify:
        ok = verify_cases() and ok
    if args.live:
        live_ok, _ = live_engine_check()
        ok = live_ok and ok
    if not (args.gen_cases or args.verify or args.live):
        ap.print_help()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
