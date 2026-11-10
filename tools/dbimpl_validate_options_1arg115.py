#!/usr/bin/env python3
"""Node #115 RocksDB DBImpl::ValidateOptions (one-argument overload):
reconstruction.

RE-002 work item. Reconstructs the DB-options validator at
0x5e59cd0..0x5e59fd3 (771 B, a single FDE, NO .cold FDE and NO LSDA):
the one-argument overload that checks a DBOptions against the nine
rules of upstream db/db_impl/db_impl_open.cc and returns the first
non-OK status, or OK. It is called once by the two-argument
dispatcher (open PR #6342, 0x5e5a000, site 0x5e5a0ee) after every
column family passed, and once by DBImpl::SetDBOptions (0x5d71fe0,
site 0x5d7256d) after it builds the new DBOptions. Direct follow-up
to the open dispatcher packet (PR #6342), the BuildDBOptions packet
(open PR #6297, 0x60c2e20) and the DBOptions ctor trio (open PRs
#6337/#6338/#6341): Open sanitizes the options, builds the
DBOptions, validates them here, and only then creates the WAL and
the DBImpl.

  rocksdb::DBImpl::ValidateOptions  0x5e59cd0 (771 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The FDE is vendor-census-bound (member
4d429ab1cb2d8f8b-db_impl_open.o, librocksdb-sys 0.11.0+8.1.1, symbol
_ZN7rocksdb6DBImpl15ValidateOptionsERKNS_9DBOptionsE): the body
hash fe207dc0... and the source hash 858395f2... were recomputed
from the binary, and the source hash was reproduced exactly by
zeroing the 21 census relocations (kinds 2/4, no relaxation).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  Status DBImpl::ValidateOptions(const DBOptions& db_options)
  -- the result is returned by value (hidden sret out in rdi = rbx),
  db_options in rsi. A stack canary IS used (%fs:0x28, stored at
  0x28(%rsp), checked on the single return path at 0x5e59e0b).

  Prologue (0x5e59cd0..0x5e59ce9): endbr64, push rbx, out in rbx,
  sub $0x30,%rsp, canary stored at 0x28(%rsp). The out Status is
  NOT initialized here: the OK path writes it (step 3) and the
  error paths build it with the Status ctor (step 2).

  1. The nine checks, in binary order (each is one cmp + a
     conditional jump to its error block; the fall-through continues
     to the next check). Field offsets are the DBOptions layout
     pinned by the default-ctor packet (open PR #6337, 0x60b2db0):
       1. db_paths byte size (0x5e59cea..0x5e59cf8): rax =
          *(rsi+0x78) - *(rsi+0x70) (end - begin of the db_paths
          vector); if rax > 0xa0 (160 = 4 DbPaths of 0x28 bytes)
          -> error 1. So db_paths.size() > 4.
       2. allow_mmap_reads && use_direct_reads (0x5e59cfe..0x5e59d0e):
          if byte +0x128 != 0 and byte +0x12a != 0 -> error 2.
       3. allow_mmap_writes && use_direct_io_for_flush_and_compaction
          (0x5e59d14, 0x5e59d90..0x5e59d97): if byte +0x129 != 0
          and byte +0x12b != 0 -> error 3.
       4. keep_log_file_num == 0 (0x5e59d1d..0x5e59d25): if qword
          +0xf0 == 0 -> error 4.
       5. unordered_write && !allow_concurrent_memtable_write
          (0x5e59d2b..0x5e59d3f): if byte +0x1d1 != 0 and byte
          +0x1d2 == 0 -> error 5.
       6. unordered_write && enable_pipelined_write
          (0x5e59d45..0x5e59d4c): if byte +0x1d1 != 0 (already
          known) and byte +0x1d0 != 0 -> error 6.
       7. atomic_flush && enable_pipelined_write (0x5e59d52,
          0x5e59e30..0x5e59e44): if byte +0x218 != 0 and byte
          +0x1d0 != 0 -> error 7. Reached two ways: from check 6
          when unordered_write is false (0x5e59d2b -> 0x5e59e30),
          and from check 6's fall-through when atomic_flush is
          set (0x5e59d52 -> 0x5e59eb0 -> check 8 first, see 8).
          The two entries share the +0x218 read at 0x5e59e30.
       8. atomic_flush && best_efforts_recovery (0x5e59eb0..0x5e59eb7):
          if byte +0x218 != 0 and byte +0x238 != 0 -> error 8.
          Reached from check 7's fall-through (0x5e59d52) and from
          check 7's entry when enable_pipelined_write is false
          (0x5e59e3d -> 0x5e59eb0).
       9. use_direct_io_for_flush_and_compaction &&
          writable_file_max_buffer_size == 0 (0x5e59d5f..0x5e59d70):
          if byte +0x12b != 0 and qword +0x180 == 0 -> error 9.
     The first failing check wins: later checks never run.
  2. The error blocks (nine, one per check): each builds two Slices
     on the stack -- msg = {ptr, len} at (%rsp), msg2 = {0x4376fd,
     0} at 0x10(%rsp) (the byte at 0x4376fd is 0x00, so msg2 is the
     empty string) -- then jumps to one of two shared tails:
       * esi=3 (kNotSupported) tail at 0x5e59df1..0x5e59e06:
         checks 1-3.
       * esi=4 (kInvalidArgument) tail at 0x5e59f19..0x5e59f2e:
         checks 4-9.
     Both tails call the Status ctor 0x61cf670 (census-bound,
     member 6cca28ae25285154-status.o, symbol
     _ZN7rocksdb6StatusC1ENS0_4CodeENS0_7SubCodeERKNS_5SliceES5_NS0_8SeverityE)
     with (rdi=out, esi=code, edx=subcode=0, rcx=&msg, r8=&msg2,
     r9d=severity=0). The ctor (decoded from its own disassembly):
     code u8 -> out+0x0, subcode u8 -> out+0x1, severity u8 ->
     out+0x2, zeros out+0x3..+0x5, state_ = nullptr first, then
     `new char[size+1]` where size = len1 + (len2 ? len2+2 : 0),
     memcpy msg at buf+0, ": " + msg2 at buf+len1 if len2, NUL at
     buf[size], state_ = buf. For this FDE msg2 is always empty,
     so state_ is exactly msg + NUL (alloc len+1). The ctor's
     trailing delete[] of the old state_ is DEAD on this path: it
     zeroes state_ at 0x61cf6b0 before reading it at 0x61cf6e4,
     so the free never fires (verified in the disassembly).
     If `new` throws (bad_alloc), the exception propagates straight
     through this frame: this FDE has NO LSDA (see below), so no
     cleanup runs here -- the caller's pad handles it.
  3. The OK path (0x5e59d76..0x5e59d8a): out = OK -- `movl $0x0,
     (%rbx)` (bytes +0x0..+0x3), `mov %ax,0x4(%rbx)` with eax=0
     (bytes +0x4..+0x5), `movq $0x0,0x8(%rbx)` (state_ = nullptr).
     Bytes +0x6..+0x7 are never written by any path in this FDE --
     the model zeroes them and records them as unwritten padding.
  4. Epilogue (0x5e59e0b..0x5e59e27): the single return path for
     both OK and error results -- stack-canary check (`mov
     0x28(%rsp),%rax; sub %fs:0x28,%rax; jne __stack_chk_fail`
     at 0x5e59fce), add $0x30,%rsp, pop rbx, ret rax = out.
     A canary mismatch raises StackCheckFailed instead of
     returning. The ctor-throw path never reaches the epilogue,
     so a throw is not masked by a canary failure.

  NO LSDA: the FDE's augmentation length in .eh_frame is 0 -- there
  is no LSDA pointer, no call-site table, no landing pad, no catch
  and no cleanup in this FDE. (The .eh_frame record at section
  offset 0x3533f4 has length 0x20, initial_location 0x5e59cd0,
  range 0x303, aug_len 0, then the CFI instructions.) The frame
  owns no destructible object (out is caller-owned sret; the
  canary is not a C++ object), so an exception from either Status
  ctor call needs no cleanup here. The 2-arg dispatcher (PR #6342)
  DOES have an LSDA and its pad frees ITS out.state_ when this
  call throws -- that cleanup belongs to the caller, not here.

  The nine messages are the upstream strings quoted verbatim
  (meta/rocksdb v8.1.1, db/db_impl/db_impl_open.cc:243-298, read
  live this cycle), and each was verified byte-for-byte against
  the .rodata string at its address (see MESSAGES). Note the
  trailing space in the first three messages -- it is in the
  source strings and in the binary. The #6342 packet cited this
  function as :392-484; the file read live this cycle has the
  two-argument dispatcher at :229-241 and the one-argument
  overload at :243-298 (the function content matches exactly).

  Status layout, corrected from the #6342 packet's loose wording:
  the #6342 packet described the Status words as "code u32 +0x0,
  subcode u16 +0x4" from the zero-writes of the OK path. The ctor
  at 0x61cf670 proves the byte layout: code u8 +0x0, subcode u8
  +0x1, severity u8 +0x2, padding +0x3..+0x7 (ctor writes
  +0x3..+0x5 zero; +0x6..+0x7 never written), state_ +0x8. The
  two descriptions are behaviorally identical for the OK/error
  values both packets pin (all three bytes are zero except the
  code byte), but this packet models the byte layout the ctor
  proves.

  Binary-vs-source observations (recorded, not hidden): the binary
  checks the db_paths BYTE size (> 0xa0) rather than the element
  count -- the same rule, since DbPath is 0x28 bytes; the binary
  passes an empty second Slice to the Status ctor (the source
  calls NotSupported/InvalidArgument with one message, which
  delegates to the five-argument ctor with msg2 empty); the
  binary's check 7 is reached through two entries that share one
  +0x218 read, and check 8 is reached two ways -- the source's
  straight-line order is preserved, only the control flow is
  folded. Upstream db_impl.cc:1242 confirms the SetDBOptions
  caller: after BuildDBOptions it calls ValidateOptions on the
  new DBOptions before validating each column family.
"""

import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START, END = 0x5E59CD0, 0x5E59FD3
BODY_SHA256 = "fe207dc0945912c63ccf42fee9aec9147a2969a5c005339aee8d9c31f6f221a2"
SOURCE_SHA256 = "858395f2ce9f424c05ca9a0adf90f25390883c15b38f40fe7389af759e4c47e6"
RELOCATIONS = ("213:kind2;225:kind2;260:kind2;272:kind2;311:kind4;"
               "386:kind2;398:kind2;436:kind2;448:kind2;505:kind2;"
               "517:kind2;556:kind2;568:kind2;607:kind4;636:kind2;"
               "648:kind2;684:kind2;696:kind2;732:kind2;744:kind2;767:kind4")
STATUS_CTOR_ADDR = 0x61CF670
STACK_CHK_FAIL_PLT = 0x63F0D70
# FDE record in .eh_frame (section offset 0x3533f4): length 0x20,
# initial_location 0x5e59cd0, range 0x303, aug_len 0 -> NO LSDA.
FDE_EH_FRAME_OFF = 0x3533F4
FDE_AUG_LEN = 0
CALLERS = [
    # (site, kind, site_fde_start, site_fde_name)
    (0x5E5A0EE, "call", 0x5E5A000,
     "rocksdb::DBImpl::ValidateOptions (2-arg)"),
    (0x5D7256D, "call", 0x5D71FE0, "rocksdb::DBImpl::SetDBOptions"),
]
DB_PATH_SIZE = 0x28          # sizeof(DbPath): string 0x20 + u64
DB_PATHS_BYTE_LIMIT = 0xA0   # 160 bytes = 4 DbPaths
EMPTY_MSG2_ADDR = 0x4376FD   # the byte there is 0x00 (empty string)

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / \
    "re-002-node115-rocksdb-dbimpl-validate-options-1arg-115"
CASES = PACKET / "cases.tsv"

# RocksDB Status::Code (include/rocksdb/status.h, v8.1.1).
CODE = {
    "kOk": 0, "kNotFound": 1, "kCorruption": 2, "kNotSupported": 3,
    "kInvalidArgument": 4, "kIOError": 5, "kMergeInProgress": 6,
    "kIncomplete": 7, "kShutdownInProgress": 8, "kTimedOut": 9,
    "kAborted": 10, "kBusy": 11, "kExpired": 12, "kTryAgain": 13,
    "kCompactionTooLarge": 14, "kColumnFamilyDropped": 15,
}
CODE_NAME = {v: k for k, v in CODE.items()}

# The nine checks, in binary order. Each entry: (check number,
# Status code name, message, .rodata address, message length,
# the tail the error block jumps to: 3 = NotSupported tail
# 0x5e59df1, 4 = InvalidArgument tail 0x5e59f19).
CHECKS = [
    (1, "kNotSupported",
     "More than four DB paths are not supported yet. ",
     0x969600, 47, 3),
    (2, "kNotSupported",
     "If memory mapped reads (allow_mmap_reads) are enabled "
     "then direct I/O reads (use_direct_reads) must be disabled. ",
     0x95E2F8, 113, 3),
    (3, "kNotSupported",
     "If memory mapped writes (allow_mmap_writes) are enabled "
     "then direct I/O writes (use_direct_io_for_flush_and_compaction) "
     "must be disabled. ",
     0x967EB8, 138, 3),
    (4, "kInvalidArgument",
     "keep_log_file_num must be greater than 0",
     0x967670, 40, 4),
    (5, "kInvalidArgument",
     "unordered_write is incompatible with "
     "!allow_concurrent_memtable_write",
     0x963508, 69, 4),
    (6, "kInvalidArgument",
     "unordered_write is incompatible with enable_pipelined_write",
     0x96A248, 59, 4),
    (7, "kInvalidArgument",
     "atomic_flush is incompatible with enable_pipelined_write",
     0x95EE48, 56, 4),
    (8, "kInvalidArgument",
     "atomic_flush is currently incompatible with best-efforts recovery",
     0x965460, 65, 4),
    (9, "kInvalidArgument",
     "writes in direct IO require writable_file_max_buffer_size > 0",
     0x95EE88, 61, 4),
]
MESSAGES = {n: m for n, _c, m, _a, _l, _t in CHECKS}

# DBOptions field offsets read by this FDE (the layout pinned by
# the default-ctor packet, open PR #6337, 0x60b2db0).
FIELDS = {
    "db_paths_begin": (0x70, "ptr"),
    "db_paths_end": (0x78, "ptr"),
    "allow_mmap_reads": (0x128, "bool"),
    "allow_mmap_writes": (0x129, "bool"),
    "use_direct_reads": (0x12A, "bool"),
    "use_direct_io_for_flush_and_compaction": (0x12B, "bool"),
    "keep_log_file_num": (0xF0, "u64"),
    "writable_file_max_buffer_size": (0x180, "u64"),
    "enable_pipelined_write": (0x1D0, "bool"),
    "unordered_write": (0x1D1, "bool"),
    "allow_concurrent_memtable_write": (0x1D2, "bool"),
    "atomic_flush": (0x218, "bool"),
    "best_efforts_recovery": (0x238, "bool"),
}


class BadAlloc(Exception):
    """std::bad_alloc raised inside the Status ctor (new char[]
    failed). `partial` is the half-built out Status: code/subcode/
    severity already written, state_ still nullptr."""

    def __init__(self, message="simulated BadAlloc in Status ctor"):
        super().__init__(message)
        self.partial = None


class StackCheckFailed(Exception):
    """__stack_chk_fail: the stack canary did not match."""


def _state_id(message):
    """Deterministic heap id for a Status state_ buffer."""
    return "state:" + hashlib.sha256(message.encode()).hexdigest()[:16]


class Status:
    """A RocksDB Status as the ctor at 0x61cf670 lays it out
    (16 bytes): code u8 +0x0, subcode u8 +0x1, severity u8 +0x2,
    padding +0x3..+0x7 (the ctor writes +0x3..+0x5 zero; +0x6..+0x7
    are never written by any path in this FDE and are modelled
    zero), state_ +0x8 (None = nullptr, else the message string
    held in the heap buffer)."""

    __slots__ = ("code", "subcode", "severity", "state")

    def __init__(self, code=0, subcode=0, severity=0, state=None):
        self.code = code
        self.subcode = subcode
        self.severity = severity
        self.state = state  # None, or a message string

    @classmethod
    def ok(cls):
        return cls(0, 0, 0, None)

    @classmethod
    def error(cls, code_name, message, subcode=0, severity=0):
        return cls(CODE[code_name], subcode, severity, message)

    def is_ok(self):
        return self.code == 0

    def state_id(self):
        return None if self.state is None else _state_id(self.state)

    def state_buffer(self):
        """The exact heap buffer the ctor builds for this status:
        msg + NUL (msg2 is always empty for this FDE)."""
        if self.state is None:
            return None
        return self.state.encode() + b"\x00"

    def state_alloc(self):
        """Bytes allocated by the ctor: len(msg) + 1 (the NUL)."""
        if self.state is None:
            return 0
        return len(self.state.encode()) + 1

    def image(self):
        buf = bytearray(16)
        buf[0] = self.code
        buf[1] = self.subcode
        buf[2] = self.severity
        # +0x3..+0x7 stay zero (padding; +0x6..+0x7 unwritten).
        struct.pack_into("<Q", buf, 8, 0 if self.state is None else
                         int(self.state_id()[6:], 16))
        return bytes(buf)

    def as_dict(self):
        return {"code": self.code,
                "code_name": CODE_NAME.get(self.code, "?"),
                "subcode": self.subcode, "severity": self.severity,
                "state": self.state,
                "state_bytes_hex": None if self.state is None else
                self.state_buffer().hex(),
                "state_alloc": self.state_alloc(),
                "image_hex": self.image().hex()}

    def __eq__(self, other):
        return isinstance(other, Status) and \
            (self.code, self.subcode, self.severity, self.state) == \
            (other.code, other.subcode, other.severity, other.state)

    def __repr__(self):
        return "Status(%s, sub=%d, sev=%d, state=%r)" % (
            CODE_NAME.get(self.code, self.code), self.subcode,
            self.severity, self.state)


def status_ctor(code, message, msg2="", subcode=0, severity=0,
                alloc_ok=True):
    """The Status ctor 0x61cf670 as the binary implements it.

    Writes code/subcode/severity into out, zeroes +0x3..+0x5 and
    state_, then allocates `new char[size+1]` (size = len(msg) +
    (len(msg2) ? len(msg2)+2 : 0)), copies msg, appends ": " + msg2
    when msg2 is non-empty, NUL-terminates, and stores the buffer
    as state_. If the allocation fails, raises BadAlloc with the
    half-built status attached (code/subcode/severity written,
    state_ still None) -- and NO cleanup runs in this FDE's frame
    (no LSDA), so the exception propagates to the caller as-is.
    The ctor's trailing delete[] of the old state_ is dead: state_
    was zeroed before the read, so it never fires."""
    out = Status(code, subcode, severity, None)
    if not alloc_ok:
        err = BadAlloc()
        err.partial = out
        raise err
    if msg2:
        out.state = message + ": " + msg2
    else:
        out.state = message
    return out


# ---------------------------------------------------------------- model

def default_db_options():
    """DBOptions fields this FDE reads. Defaults are the upstream
    v8.1.1 defaults for these fields (options.h, pinned by the
    default-ctor packet, open PR #6337); they are model inputs,
    not binary claims."""
    return {
        "db_paths": [],  # list of {"path": str, "target_size": int}
        "allow_mmap_reads": False,
        "use_direct_reads": False,
        "allow_mmap_writes": False,
        "use_direct_io_for_flush_and_compaction": False,
        "keep_log_file_num": 1000,
        "unordered_write": False,
        "allow_concurrent_memtable_write": True,
        "enable_pipelined_write": False,
        "atomic_flush": False,
        "best_efforts_recovery": False,
        "writable_file_max_buffer_size": 1048576,
    }


def _failing_check(db_options):
    """The first failing check number (1-9), or 0 when all pass.
    Follows the binary's control flow exactly, including the two
    entries into check 7 and the two entries into check 8."""
    db_paths_bytes = len(db_options["db_paths"]) * DB_PATH_SIZE
    if db_paths_bytes > DB_PATHS_BYTE_LIMIT:
        return 1
    if db_options["allow_mmap_reads"] and db_options["use_direct_reads"]:
        return 2
    if db_options["allow_mmap_writes"] and \
            db_options["use_direct_io_for_flush_and_compaction"]:
        return 3
    if db_options["keep_log_file_num"] == 0:
        return 4
    if db_options["unordered_write"]:
        if not db_options["allow_concurrent_memtable_write"]:
            return 5
        if db_options["enable_pipelined_write"]:
            return 6
    # Check 7: reached from check 6 when unordered_write is false,
    # and from the check-6 fall-through when atomic_flush is set.
    if db_options["atomic_flush"]:
        if db_options["enable_pipelined_write"]:
            return 7
        # Check 8 (reached from 0x5e59eb0 when pipelined is false).
        if db_options["best_efforts_recovery"]:
            return 8
    if db_options["use_direct_io_for_flush_and_compaction"] and \
            db_options["writable_file_max_buffer_size"] == 0:
        return 9
    return 0


def validate_options(db_options, canary_ok=True, alloc_ok=True,
                     fail_ctor_at=None):
    """The reconstructed validator: DBImpl::ValidateOptions
    0x5e59cd0..0x5e59fd3.

    Runs the nine checks in binary order and returns the first
    non-OK status, or OK. `fail_ctor_at` (1-9) simulates a
    bad_alloc inside the Status ctor for that check's error block:
    BadAlloc propagates with the half-built status attached and no
    cleanup in this frame (no LSDA). `canary_ok=False` models a
    stack-canary mismatch at the epilogue (__stack_chk_fail); it
    fires only on a normal return -- a ctor throw never reaches
    the epilogue, so the throw is not masked by a canary failure.
    Returns the resulting Status."""
    check = _failing_check(db_options)
    if check == 0:
        result = Status.ok()
    else:
        _n, code_name, message, _addr, _ln, _tail = CHECKS[check - 1]
        result = status_ctor(
            CODE[code_name], message, "",
            alloc_ok=alloc_ok and fail_ctor_at != check)
    if not canary_ok:
        raise StackCheckFailed("stack canary mismatch")
    return result


# ---------------------------------------------------------------- cases

def _status_dict(status):
    return status.as_dict()


def run_case(inputs):
    """Run one case and return the expected outputs."""
    group = inputs["group"]
    if group == "checks":
        db_opts = default_db_options()
        db_opts.update(inputs.get("db_overrides", {}))
        if "db_paths_count" in inputs:
            db_opts["db_paths"] = [
                {"path": "/p%d" % i, "target_size": 1}
                for i in range(inputs["db_paths_count"])]
        result = validate_options(db_opts)
        return {"result": _status_dict(result),
                "failed_check": _failing_check(db_opts),
                "db_paths_bytes": len(db_opts["db_paths"]) * DB_PATH_SIZE,
                "db_paths_count": len(db_opts["db_paths"])}
    if group == "status":
        kind = inputs["kind"]
        if kind == "ok":
            st = Status.ok()
            return {"status": _status_dict(st)}
        if kind == "error":
            _n, code_name, message, _a, _l, _t = \
                CHECKS[inputs["check"] - 1]
            st = status_ctor(CODE[code_name], message, "")
            return {"status": _status_dict(st),
                    "check": inputs["check"],
                    "message": message}
        if kind == "ctor-msg2":
            st = status_ctor(CODE["kInvalidArgument"],
                             inputs["message"], inputs["msg2"])
            return {"status": _status_dict(st),
                    "joined": st.state}
        raise ValueError("unknown status kind %r" % kind)
    if group == "throw":
        db_opts = default_db_options()
        db_opts.update(inputs.get("db_overrides", {}))
        if "db_paths_count" in inputs:
            db_opts["db_paths"] = [
                {"path": "/p%d" % i, "target_size": 1}
                for i in range(inputs["db_paths_count"])]
        try:
            result = validate_options(
                db_opts, canary_ok=inputs.get("canary_ok", True),
                alloc_ok=inputs.get("alloc_ok", True),
                fail_ctor_at=inputs.get("fail_ctor_at"))
        except BadAlloc as err:
            return {"error": "BadAlloc",
                    "cause_message": str(err),
                    "partial": None if err.partial is None else
                    _status_dict(err.partial),
                    "frame_cleanup": [],
                    "canary_checked": False}
        except StackCheckFailed as err:
            return {"error": "StackCheckFailed", "message": str(err),
                    "canary_checked": True}
        return {"error": None, "result": _status_dict(result),
                "frame_cleanup": [], "canary_checked": True}
    if group == "bindings":
        db_opts = default_db_options()
        db_opts.update(inputs.get("db_overrides", {}))
        if "db_paths_count" in inputs:
            db_opts["db_paths"] = [
                {"path": "/p%d" % i, "target_size": 1}
                for i in range(inputs["db_paths_count"])]
        result = validate_options(db_opts)
        return {
            "caller_site": inputs["caller_site"],
            "result": _status_dict(result),
            "result_sha256": hashlib.sha256(
                result.image()).hexdigest(),
            "result_independent_of_caller": True,
            "body_sha256": BODY_SHA256,
            "source_sha256": SOURCE_SHA256,
            "relocations": RELOCATIONS,
            "lsda": "none (FDE aug_len 0, no LSDA pointer)",
            "engine_calls": {"status_ctor_0x61cf670":
                             0 if result.is_ok() else 1,
                             "stack_chk_fail_0x63f0d70": 0},
        }
    raise ValueError("unknown group %r" % group)


# One failing variant per check, as DBOptions overrides.
_CHECK_FAIL_OVERRIDES = [
    (1, {"db_paths_count": 5}),
    (2, {"allow_mmap_reads": True, "use_direct_reads": True}),
    (3, {"allow_mmap_writes": True,
         "use_direct_io_for_flush_and_compaction": True}),
    (4, {"keep_log_file_num": 0}),
    (5, {"unordered_write": True,
         "allow_concurrent_memtable_write": False}),
    (6, {"unordered_write": True,
         "allow_concurrent_memtable_write": True,
         "enable_pipelined_write": True}),
    (7, {"atomic_flush": True, "enable_pipelined_write": True}),
    (8, {"atomic_flush": True, "best_efforts_recovery": True}),
    (9, {"use_direct_io_for_flush_and_compaction": True,
         "writable_file_max_buffer_size": 0}),
]


def _gen_group(rng, group, n):
    rows = []
    for i in range(n):
        case_id = "%s-%03d" % (group, i)
        inputs = {"case_id": case_id, "group": group}
        if group == "checks":
            mode = i % 12
            if mode == 0:
                pass  # defaults: all OK
            elif 1 <= mode <= 9:
                # One check failing alone.
                _n, overrides = _CHECK_FAIL_OVERRIDES[mode - 1]
                if "db_paths_count" in overrides:
                    inputs["db_paths_count"] = overrides["db_paths_count"]
                else:
                    inputs["db_overrides"] = overrides
            elif mode == 10:
                # Two checks failing: the earlier one must win.
                first = rng.randrange(1, 9)
                second = rng.randrange(first + 1, 10)
                for _n, overrides in (_CHECK_FAIL_OVERRIDES[first - 1],
                                      _CHECK_FAIL_OVERRIDES[second - 1]):
                    if "db_paths_count" in overrides:
                        inputs["db_paths_count"] = overrides["db_paths_count"]
                    else:
                        inputs.setdefault("db_overrides", {}).update(
                            overrides)
            else:
                # Boundary values: exactly at / just past the limit.
                pick = rng.choice(["paths-4", "paths-5", "keep-1",
                                   "keep-0", "buf-1", "buf-0",
                                   "bools-mixed"])
                if pick == "paths-4":
                    inputs["db_paths_count"] = 4
                elif pick == "paths-5":
                    inputs["db_paths_count"] = 5
                elif pick == "keep-1":
                    inputs["db_overrides"] = {"keep_log_file_num": 1}
                elif pick == "keep-0":
                    inputs["db_overrides"] = {"keep_log_file_num": 0}
                elif pick == "buf-1":
                    inputs["db_overrides"] = {
                        "use_direct_io_for_flush_and_compaction": True,
                        "writable_file_max_buffer_size": 1}
                elif pick == "buf-0":
                    inputs["db_overrides"] = {
                        "use_direct_io_for_flush_and_compaction": True,
                        "writable_file_max_buffer_size": 0}
                else:
                    inputs["db_overrides"] = {
                        "allow_mmap_reads": rng.random() < 0.5,
                        "use_direct_reads": rng.random() < 0.5,
                        "allow_mmap_writes": rng.random() < 0.5,
                        "use_direct_io_for_flush_and_compaction":
                            rng.random() < 0.5,
                        "unordered_write": rng.random() < 0.5,
                        "allow_concurrent_memtable_write":
                            rng.random() < 0.5,
                        "enable_pipelined_write": rng.random() < 0.5,
                        "atomic_flush": rng.random() < 0.5,
                        "best_efforts_recovery": rng.random() < 0.5}
        elif group == "status":
            mode = i % 12
            if mode == 0:
                inputs["kind"] = "ok"
            elif 1 <= mode <= 9:
                inputs["kind"] = "error"
                inputs["check"] = mode
            else:
                # The ctor's ": " join with a non-empty msg2 (the
                # ctor's behavior at 0x61cf720; this FDE always
                # passes an empty msg2, so the join never fires
                # here -- the case pins the ctor model directly).
                inputs["kind"] = "ctor-msg2"
                inputs["message"] = rng.choice(
                    ["keep_log_file_num must be greater than 0",
                     "More than four DB paths are not supported yet. "])
                inputs["msg2"] = rng.choice(
                    ["does not exist (create_if_missing is false)",
                     "exists (error_if_exists is true)"])
        elif group == "throw":
            mode = i % 6
            if mode in (0, 1, 2):
                # BadAlloc in the Status ctor for one failing check.
                check = rng.randrange(1, 10)
                _n, overrides = _CHECK_FAIL_OVERRIDES[check - 1]
                if "db_paths_count" in overrides:
                    inputs["db_paths_count"] = overrides["db_paths_count"]
                else:
                    inputs["db_overrides"] = overrides
                inputs["fail_ctor_at"] = check
                inputs["alloc_ok"] = False
            elif mode == 3:
                # Canary failure on a normal OK return.
                inputs["canary_ok"] = False
            elif mode == 4:
                # Canary failure on a normal error return.
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(9)]
                if "db_paths_count" in overrides:
                    inputs["db_paths_count"] = overrides["db_paths_count"]
                else:
                    inputs["db_overrides"] = overrides
                inputs["canary_ok"] = False
            else:
                # BadAlloc AND a bad canary: the throw wins, the
                # epilogue (and its canary check) never runs.
                check = rng.randrange(1, 10)
                _n, overrides = _CHECK_FAIL_OVERRIDES[check - 1]
                if "db_paths_count" in overrides:
                    inputs["db_paths_count"] = overrides["db_paths_count"]
                else:
                    inputs["db_overrides"] = overrides
                inputs["fail_ctor_at"] = check
                inputs["alloc_ok"] = False
                inputs["canary_ok"] = False
        elif group == "bindings":
            inputs["caller_site"] = "0x%x" % rng.choice(
                [s for s, _k, _f, _n in CALLERS])
            if rng.random() < 0.3:
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(9)]
                if "db_paths_count" in overrides:
                    inputs["db_paths_count"] = overrides["db_paths_count"]
                else:
                    inputs["db_overrides"] = overrides
        expected = run_case(inputs)
        rows.append((group, case_id, inputs, expected))
    return rows


def write_cases():
    all_rows = []
    for gi, group in enumerate(["checks", "status", "throw", "bindings"]):
        rng = random.Random(115100 + gi)
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
    print("verify: %d cases, %d mismatches" % (len(rows), mismatches))
    return mismatches == 0 and len(rows) == 2400


# ---------------------------------------------------------------- live

def _bin_path():
    for path in (Path(__file__).resolve().parents[1] / "work" /
                 "hl-node-115.bin",
                 Path(__file__).resolve().parents[1] / "artifacts" /
                 "node" / "115" / "hl-node"):
        data = open(path, "rb").read()
        if hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256:
            return path
    raise RuntimeError("node #115 artifact not materialized")


def _sections(data):
    out = subprocess.check_output(
        ["readelf", "-lW", str(_bin_path())]).decode()
    secs = {}
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            secs[int(p[2], 16)] = (int(p[1], 16), int(p[4], 16))
    return secs


def _va2off(secs, va):
    for v, (o, f) in secs.items():
        if v <= va < v + f:
            return o + (va - v)
    raise ValueError(hex(va))


def _read_va(data, secs, va, size):
    return data[_va2off(secs, va):_va2off(secs, va) + size]


def _fde_hashes(data, secs):
    legs = []
    body = _read_va(data, secs, START, END - START)
    legs.append(("body hash",
                 hashlib.sha256(body).hexdigest() == BODY_SHA256,
                 hashlib.sha256(body).hexdigest()[:16]))
    census = json.load(open(
        Path(__file__).resolve().parents[1] / "research" / "work-items" /
        "RE-002-node115-vendor-census" / "census.json"))["records"]
    rec = {r["start"]: r for r in census}[START]
    zeroed = bytearray(body)
    for rel in rec["relocations"]:
        o, w = rel["offset"], rel["width"]
        zeroed[o:o + w] = b"\x00" * w
    legs.append(("source hash (21 relocations zeroed)",
                 hashlib.sha256(bytes(zeroed)).hexdigest()
                 == SOURCE_SHA256,
                 hashlib.sha256(bytes(zeroed)).hexdigest()[:16]))
    legs.append(("relocation list matches census",
                 ";".join("%d:kind%d" % (r["offset"], r["kind"])
                          for r in rec["relocations"]) == RELOCATIONS,
                 "%d relocations" % len(rec["relocations"])))
    legs.append(("census symbol",
                 rec["symbol"] ==
                 "_ZN7rocksdb6DBImpl15ValidateOptionsERKNS_9DBOptionsE",
                 rec["symbol"]))
    legs.append(("census member",
                 rec["member"] == "4d429ab1cb2d8f8b-db_impl_open.o",
                 rec["member"]))
    return legs


def _disasm(data, secs, start, end):
    out = subprocess.check_output(
        ["objdump", "-d", "--start-address=0x%x" % start,
         "--stop-address=0x%x" % end, str(_bin_path())]).decode()
    return out


def _engine_calls(data, secs):
    legs = []
    dis = _disasm(data, secs, START, END)
    legs.append(("status ctor 0x61cf670 x2",
                 dis.count("call   61cf670") == 2,
                 dis.count("call   61cf670")))
    legs.append(("__stack_chk_fail x1",
                 dis.count("<__stack_chk_fail@plt>") == 1,
                 dis.count("<__stack_chk_fail@plt>")))
    legs.append(("operator delete[] x0 in this FDE",
                 dis.count("<_ZdaPv@plt>") == 0,
                 dis.count("<_ZdaPv@plt>")))
    legs.append(("exactly one endbr64 (no landing-pad stub)",
                 dis.count("endbr64") == 1, dis.count("endbr64")))
    legs.append(("canary stored once + checked once",
                 dis.count("%fs:0x28") == 2, dis.count("%fs:0x28")))
    legs.append(("msg2 lea 0x4376fd x9 (one per error block)",
                 dis.count("# 4376fd") == 9, dis.count("# 4376fd")))
    return legs


def _field_cmps(data, secs):
    legs = []
    dis = _disasm(data, secs, START, END)
    checks = [
        ("db_paths byte size cmp $0xa0",
         "cmp    $0xa0,%rax" in dis),
        ("allow_mmap_reads cmpb +0x128",
         "cmpb   $0x0,0x128(%rsi)" in dis),
        ("use_direct_reads cmpb +0x12a",
         "cmpb   $0x0,0x12a(%rsi)" in dis),
        ("allow_mmap_writes cmpb +0x129",
         "cmpb   $0x0,0x129(%rsi)" in dis),
        ("use_direct_io cmpb +0x12b x2",
         dis.count("cmpb   $0x0,0x12b(%rsi)") == 2),
        ("keep_log_file_num cmpq +0xf0",
         "cmpq   $0x0,0xf0(%rsi)" in dis),
        ("unordered_write cmpb +0x1d1",
         "cmpb   $0x0,0x1d1(%rsi)" in dis),
        ("allow_concurrent cmpb +0x1d2",
         "cmpb   $0x0,0x1d2(%rsi)" in dis),
        ("enable_pipelined cmpb +0x1d0 x2",
         dis.count("cmpb   $0x0,0x1d0(%rsi)") == 2),
        ("atomic_flush cmpb +0x218 x2",
         dis.count("cmpb   $0x0,0x218(%rsi)") == 2),
        ("best_efforts cmpb +0x238",
         "cmpb   $0x0,0x238(%rsi)" in dis),
        ("writable_file_max_buffer cmpq +0x180",
         "cmpq   $0x0,0x180(%rsi)" in dis),
    ]
    for name, ok in checks:
        legs.append((name, ok, None))
    return legs


def _messages(data, secs):
    legs = []
    for n, _c, msg, addr, ln, _t in CHECKS:
        raw = _read_va(data, secs, addr, ln)
        legs.append(("message %d byte-exact (%d B)" % (n, ln),
                     raw == msg.encode(), raw[:24].decode(errors="replace")))
    empty = _read_va(data, secs, EMPTY_MSG2_ADDR, 1)
    legs.append(("msg2 at 0x4376fd is the empty string",
                 empty == b"\x00", empty.hex()))
    return legs


def _no_lsda(data):
    legs = []
    # .eh_frame section: file offset == VA 0xca6ed8.
    eh = subprocess.check_output(
        ["readelf", "-SW", str(_bin_path())]).decode()
    off = None
    for line in eh.splitlines():
        p = line.split()
        if len(p) >= 6 and p[1] == ".eh_frame":
            off = int(p[4], 16)
    assert off is not None
    rec = data[off + FDE_EH_FRAME_OFF: off + FDE_EH_FRAME_OFF + 36]
    length, cie = struct.unpack_from("<II", rec, 0)
    field = off + FDE_EH_FRAME_OFF + 8
    disp, = struct.unpack_from("<i", data, field)
    rng, = struct.unpack_from("<I", data, field + 4)
    aug_len = data[field + 8]
    legs.append(("FDE record length 0x20", length == 0x20, hex(length)))
    legs.append(("FDE initial_location 0x5e59cd0",
                 field + disp == START, hex(field + disp)))
    legs.append(("FDE range 0x303 (771 B)", rng == 0x303, hex(rng)))
    legs.append(("FDE aug_len 0 -> NO LSDA pointer",
                 aug_len == FDE_AUG_LEN, aug_len))
    legs.append(("FDE aug bytes after length are CFI, not an LSDA",
                 data[field + 9] == 0x45, hex(data[field + 9])))
    return legs


def _caller_scan():
    sys.path.insert(0, str(PACKET))
    import census as census_mod
    text_va, _off, text = census_mod.load_text()
    fdes = census_mod.load_fdes()
    starts = sorted(fdes)
    rows = []
    for site, kind, target in census_mod.raw_scan(text_va, text):
        if target != START:
            continue
        insn = census_mod.validate(text_va, text, fdes, starts, site,
                                   kind, target)
        if insn is not None:
            rows.append((site, kind))
    return rows


def live_engine_check():
    data = open(_bin_path(), "rb").read()
    secs = _sections(data)
    legs = []
    legs += _fde_hashes(data, secs)
    legs += _engine_calls(data, secs)
    legs += _field_cmps(data, secs)
    legs += _messages(data, secs)
    legs += _no_lsda(data)
    sites = _caller_scan()
    legs.append(("caller census: 2 calls, 0 jumps, 0 lea refs",
                 sites == [(0x5D7256D, "call"), (0x5E5A0EE, "call")],
                 sites))
    legs.append(("defaults validate OK",
                 validate_options(default_db_options()).is_ok(), None))
    for n, _c, msg, _a, _l, _t in CHECKS:
        _m, overrides = _CHECK_FAIL_OVERRIDES[n - 1]
        opts = default_db_options()
        if "db_paths_count" in overrides:
            opts["db_paths"] = [{"path": "/p", "target_size": 1}] * \
                overrides["db_paths_count"]
        else:
            opts.update(overrides)
        st = validate_options(opts)
        legs.append(("check %d fails with its message" % n,
                     st.code == CODE[_c] and st.state == msg,
                     "%s %r" % (CODE_NAME[st.code], (st.state or "")[:20])))
    # First failure wins: check 1 masks check 4.
    both = default_db_options()
    both["db_paths"] = [{"path": "/p", "target_size": 1}] * 5
    both["keep_log_file_num"] = 0
    legs.append(("check 1 masks check 4",
                 validate_options(both).state == MESSAGES[1], None))
    # Status ctor legs: state_ buffer is msg + NUL, alloc len+1.
    st = status_ctor(CODE["kInvalidArgument"], MESSAGES[4], "")
    legs.append(("ctor state_ buffer is msg + NUL",
                 st.state_buffer() == MESSAGES[4].encode() + b"\x00"
                 and st.state_alloc() == len(MESSAGES[4]) + 1, None))
    joined = status_ctor(CODE["kInvalidArgument"], "a", "b")
    legs.append(("ctor joins non-empty msg2 with ': '",
                 joined.state == "a: b", joined.state))
    failed = 0
    for name, ok, detail in legs:
        print("%s %s%s" % ("PASS" if ok else "FAIL", name,
                           (" (%s)" % detail) if detail is not None else ""))
        failed += 0 if ok else 1
    print("live: %d legs, %d failed" % (len(legs), failed))
    return failed == 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--write-cases" in argv:
        write_cases()
    if "--verify-cases" in argv:
        ok = verify_cases()
        if not ok:
            return 1
    if "--live" in argv:
        ok = live_engine_check()
        if not ok:
            return 1
    if not argv:
        print("usage: %s [--write-cases] [--verify-cases] [--live]"
              % sys.argv[0])
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
