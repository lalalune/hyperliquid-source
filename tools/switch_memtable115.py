#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::DBImpl::SwitchMemtable.

Target: rocksdb::DBImpl::SwitchMemtable(ColumnFamilyData*,
WriteContext*) at 0x5e8a890..0x5e8c518 (7304 B, main FDE) + its
.cold FDE 0x5e8a7ae..0x5e8a882 (212 B) in node #115
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The memtable switch: it persists the recoverable state, decides
whether a new WAL is needed (log_empty_, under
log_write_mutex_ when two_write_queues_ is set), recycles a WAL
file number when one is available, takes a new file number from
versions_, copies the MutableCFOptions, creates the new WAL
(CreateWAL, oracle) and the new memtable (ConstructNewMemtable,
oracle) with a fresh SuperVersion, logs the switch, seals the
old memtable's fragmented range tombstones, relocks, pops the
recycled number, writes the buffered WAL out through the last
log writer (WriteBuffer, oracle) and, on success, records the
new log file. When track_and_verify_wals_in_manifest is on and
2PC is off, the minimum WAL with unflushed data
(PreComputeMinLogNumberWithUnflushedData: each CF contributes
its log number, an empty CF contributes the new log number,
dropped CFs ignored) is compared with the WalSet minimum and,
when larger, a VersionEdit deleting WALs before it is applied
to the default column family (LogAndApply, oracle); otherwise
every empty column family is updated in a plain loop (its
creation sequence is set even when no new log is created).
The tail installs the
new memtable (SetNextLogNumber, imm()->Add, Ref, SetMemtable,
InstallSuperVersionAndScheduleWork, NotifyOnMemTableSealed).
Any failure goes to the error path: delete the new memtable and
log, reset the superversion, SetBGError(io_s or s, kMemTable)
and return GetBGError().

Whole-FDE facts (verified live, see --live):
- Signature: Status by value (hidden sret out in rdi = r15),
  this in rsi = r14, cfd in rdx = rbx, context in rcx. Stack
  canary used (stored -0x38(%rbp), checked at the epilogue
  0x5e8acde and in the .cold chain at 0x5e8a814 before
  _Unwind_Resume).
- The FDE has a .cold FDE with a 21-entry LSDA (main LSDA at
  0x4111c4, 129 bytes; cold LSDA at 0x41124a, 1 entry). All
  entries are cleanup-only (action 0); entry [0] (the
  AssertHeld no-op call) has NO landing pad. The 9
  landing-pad stubs at 0x5e8c4ac..0x5e8c50c jump into the .cold
  FDE, which is a partial-destruction ladder for the
  MutableCFOptions copy: the entry block depends on how far
  the copy had progressed (shared_ptr only, +0xc0 vector,
  +0x1c8 vector, or the completed copy, which runs the dtor).
  The WriteBuffer pads (0x5e8c50c) unlock the mutex held at
  the throw point first (r14 = &log_write_mutex_).
- 0x60d52f0 is port::Mutex::Unlock, not Lock: the census lists
  9 identical candidate symbols for that 149-byte body
  (Lock/Unlock/CondVar::Signal/...); the disassembly calls
  pthread_mutex_unlock (PLT 0x63f0b70). The Lock copy is
  0x60d5230, reached through the InstrumentedMutexLock wrapper
  0x606ca40 (not in the vendor census). AssertHeld is the
  empty 0x60d5390 (endbr64; ret).
- 0x5d5b080 is a std::vector buffer free (the _M_deallocate of
  a vector destructor: free *(obj) with size *(obj+0x10) -
  *(obj) via _ZdlPvm), NOT a std::string destructor: the
  string dtor shape (SSO check, capacity+1) is different, as
  a g++ -O2 control compile shows. It frees the empty_cfs
  overflow vector buffer (rdi = &vect_). The sibling
  SetDBOptions packet's "string dtor" label for this address
  is a misread; this packet does not repeat it.
- GetWalPreallocateBlockSize (0x5e87d60) is pinned from its own
  disassembly: bsize = write_buffer_size / 10 +
  write_buffer_size, min with max_total_wal_size when
  non-zero, min with db_write_buffer_size when non-zero, then
  max with write_buffer_manager->buffer_size_ when the manager
  is non-null and its size is non-zero (the manager is final,
  so *(ptr) IS buffer_size_). The v8.1.1 tag source shows
  only the two mins; the third max term is a binary-vs-source
  observation. The two log lines sit at 2146/2178 in the
  binary but at 2147/2179 in the v8.1.1 tag source -- a
  one-line skew in the vendored file.
- DBImpl/ColumnFamilyData layout (binary offsets): versions_
  +0x68, mutex_ +0x700, error_handler_ +0x760,
  log_write_mutex_ +0x9c8, logfile_number_ +0xa60, log_empty_
  +0xab9, log_dir_synced_ +0xab8, log_recycle_files_ +0xa78,
  recycle_log_file_num +0x400 (immutable_db_options_),
  logs_ +0xb20, alive_log_files_ +0xb00, directories_ +0xd08,
  two_write_queues_ +0x17b0, track_and_verify_wals_in_manifest
  +0x335, allow_2pc +0x4a3, info_log +0x360,
  max_total_wal_size (mutable) +0x5c0, db_write_buffer_size
  (immutable) +0x440, write_buffer_manager (immutable) +0x448.
  ColumnFamilyData: mem_ +0x8e8, imm_ +0x8f0, log_number_
  +0x948, last_memtable_id_ +0x980, dropped_ +0x3d, next_
  +0x938, mutable_cf_options_ +0x6c0. MemTable: refs_ +0x70,
  num_entries +0xa70, num_deletes +0xa78, first_seqno +0xc18,
  earliest_seqno +0xc20, creation_seq +0xc28, next_log_number
  +0xc30, id +0xcc0, size 0xd20. SuperVersion 0x290,
  log::Writer 0x58. ColumnFamilyData::IsEmpty is
  first_seqno == 0 && NumNotFlushed() == 0 (column_family.h:
  348-350); SetMemtable assigns last_memtable_id_.fetch_add(1)
  +1 as the new id and stores mem_ (column_family.h).
- The caller census is exactly 6 direct E8 calls, 0 tail
  jumps, 0 LEA refs: two in DBImpl::FlushMemtable (0x5ddfb4a,
  0x5de0835), one in DBImpl::AtomicFlushMemTables (0x5de189a),
  one in DBImpl::SwitchWAL (0x5e8c901), one in
  DBImpl::HandleWriteBufferManagerFlush (0x5e8d404) and one in
  DBImpl::ScheduleFlushes (0x5e8dd1c). The raw whole-.text scan
  finds exactly these six candidates, all validated. The
  upstream source calls
  SwitchMemtable from WriteImpl variants (db_impl_write.cc:
  1666, 1757, 2035); the binary's callers differ -- recorded
  as observed.

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM. The
target binary is never executed. Status state_ buffers are
deterministic heap ids, not real pointers.
"""

import copy
import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

ARTIFACT_SHA256 = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f"
                   "249e98c3867b5301")
START = 0x5E8A890
END = 0x5E8C518
BODY_SHA256 = ("7e3e454f2700b6e9454be33342d3ccdbb063c2c5d3f98a9"
               "08a8db6e8f3549cb6")
SOURCE_SHA256 = ("647a18ffb789cbb850d2fbdde9c329ff8aba41eb8433bb5"
                 "73ba251ceb069220b")
RELOCATIONS = ("80:kind4;124:kind4;311:kind4;412:kind4;429:kind4;"
               "486:kind2;516:kind2;524:kind4;540:kind4;552:kind4;"
               "794:kind4;854:kind4;872:kind4;907:kind4;934:kind4;"
               "961:kind4;988:kind4;1034:kind42;1085:kind4;"
               "1288:kind42;1538:kind4;1605:kind4;1997:kind4;"
               "2064:kind4;2146:kind4;2213:kind4;2295:kind4;"
               "2387:kind4;2409:kind4;2428:kind4;2487:kind4;"
               "2504:kind4;2522:kind2;2576:kind2;2684:kind4;"
               "2697:kind4;2728:kind4;2864:kind4;2877:kind4;"
               "2897:kind4;2910:kind4;2948:kind4;2961:kind4;"
               "3012:kind4;3048:kind4;3059:kind2;3080:kind4;"
               "3186:kind4;3212:kind4;3389:kind4;3438:kind4;"
               "3481:kind4;3567:kind4;3668:kind4;3685:kind4;"
               "3725:kind2;3742:kind4;3762:kind4;3858:kind4;"
               "3888:kind4;3961:kind4;4015:kind4;4244:kind4;"
               "4437:kind4;4596:kind4;4628:kind4;5000:kind4;"
               "5062:kind4;5077:kind2;5094:kind4;5140:kind4;"
               "5152:kind4;5164:kind4;5376:kind4;5658:kind4;"
               "5784:kind4;5795:kind4;5918:kind4;5982:kind4;"
               "5994:kind4;6006:kind4;6074:kind4;6242:kind4;"
               "6363:kind4;6419:kind4;6495:kind4;6536:kind4;"
               "6618:kind4;6701:kind4;6752:kind4;6825:kind4;"
               "6835:kind4;6875:kind4;6937:kind4;6976:kind4;"
               "7036:kind4;7062:kind2;7067:kind4;7093:kind2;"
               "7098:kind4;7192:kind4;7204:kind2;7216:kind2;"
               "7228:kind2;7240:kind2;7252:kind2;7264:kind2;"
               "7276:kind2;7288:kind2;7300:kind2")
MEMBER = "4d429ab1cb2d8f8b-db_impl_write.o"
SYMBOL = ("_ZN7rocksdb6DBImpl14SwitchMemtableEPNS_16ColumnFamilyData"
          "EPNS0_12WriteContextE")
COLD_START = 0x5E8A7AE
COLD_END = 0x5E8A882
COLD_BODY_SHA256 = ("00213ad0c4d7f2e46b6f72d9b9c9da82d921bb0a1b3e6"
                    "7003bd0565e8f90c277")
COLD_SOURCE_SHA256 = ("160ff7529d61df2534cd6f5ac254d8b9e895aa8deeac"
                      "e9ebc8fc870c731bca6f")
COLD_RELOCATIONS = ("23:kind4;50:kind4;67:kind4;81:kind4;98:kind4;"
                    "121:kind4;136:kind4;148:kind4;156:kind4;"
                    "170:kind4;189:kind4;201:kind4;208:kind4")
COLD_SYMBOL = SYMBOL + ".cold"
# FDE record in .eh_frame (section offset 0x73fe08): length 0x4c,
# range 0x1c88, aug_len 4, LSDA at 0x4111c4 (21 entries, all
# cleanup, entry [0] has no landing pad).
FDE_SECTION_OFFSET = 0x73FE08
FDE_LENGTH = 0x4C
FDE_RANGE = 0x1C88
FDE_LSDA = 0x4111C4
# .cold FDE record (section offset 0x73fe58): length 0x20, range
# 0xd4, aug_len 4, LSDA at 0x41124a (1 entry, no landing pad).
COLD_FDE_SECTION_OFFSET = 0x73FE58
COLD_FDE_LENGTH = 0x20
COLD_FDE_RANGE = 0xD4
COLD_FDE_LSDA = 0x41124A
# Engine callees (census-bound unless noted).
STATUS_CTOR = 0x61CF670
STATUS_TOSTRING = 0x61CFED0
STACK_CHK_FAIL = 0x63F0D70
UNWIND_RESUME = 0x63F0A50
EMPTY_MSG2_ADDR = 0x4376FD
LOG_FILE_ADDR = 0x963FE0
LOG_FILE = "db/db_impl/db_impl_write.cc"
CODE = {"kOk": 0, "kNotFound": 1, "kCorruption": 2, "kNotSupported": 3,
        "kInvalidArgument": 4, "kIOError": 5, "kMergeInProgress": 6,
        "kIncomplete": 7, "kShutdownInProgress": 8, "kTimedOut": 9,
        "kAborted": 10, "kBusy": 11, "kExpired": 12, "kTryAgain": 13,
        "kCompactionTooLarge": 14, "kColumnFamilyDropped": 15}
CODE_NAME = {v: k for k, v in CODE.items()}

# (message, address, length) -- byte-verified against .rodata.
MESSAGES = {
    "log-info": ("[%s:2146] [%s] New memtable created with log "
                 "file: #%lu. Immutable memtables: %d.\n",
                 0x95B0B0, 82),
    "log-warn": ("[%s:2178] [%s] Failed to switch from #%lu to "
                 "#%lu  WAL file\n", 0x962CF0, 60),
    "deque-length-error": ("cannot create std::deque larger than "
                           "max_size()", 0x961990, 47),
}
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / "re-002-node115-rocksdb-dbimpl-switch-memtable-115"
CASES = PACKET / "cases.tsv"
class Throw(Exception):
    """An exception escaping a call inside the FDE. `partial` is
    the half-built out Status for the Status ctor case; the
    .cold chain runs `cleanup` in order and then checks the
    canary before _Unwind_Resume, so a throw with a bad canary
    becomes StackCheckFailed after cleanup. A throw from a call
    with no landing pad (pad None) propagates with no cleanup
    and no canary check."""

    def __init__(self, kind, site=None, pad=None, cleanup=None,
                 partial=None):
        super().__init__(kind)
        self.kind = kind
        self.site = site
        self.pad = pad
        self.cleanup = list(cleanup or [])
        self.partial = partial


class BadAlloc(Throw):
    """std::bad_alloc raised inside the Status ctor (new char[]
    failed). `partial` is the half-built out Status: code/subcode/
    severity already written, state_ still nullptr."""

    def __init__(self, message="simulated BadAlloc", **kw):
        super().__init__("BadAlloc", **kw)
        self.args = (message,)


class StackCheckFailed(Throw):
    """__stack_chk_fail: the stack canary did not match -- on a
    normal return at the epilogue (0x5e8acde), or in the .cold
    chain (0x5e8a814) after cleanup on a throw path."""

    def __init__(self, message="stack canary mismatch", **kw):
        super().__init__("StackCheckFailed", **kw)
        self.args = (message,)


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
        if self.state is None:
            return None
        return self.state.encode() + b"\x00"

    def state_alloc(self):
        if self.state is None:
            return 0
        return len(self.state.encode()) + 1

    def image(self):
        buf = bytearray(16)
        buf[0] = self.code
        buf[1] = self.subcode
        buf[2] = self.severity
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


def status_from_dict(d):
    if d is None:
        return Status.ok()
    return Status(d.get("code", 0), d.get("subcode", 0),
                  d.get("severity", 0), d.get("state"))


def status_ctor(code, message, msg2="", subcode=0, severity=0,
                alloc_ok=True, site=None, pad=None, cleanup=None):
    """The Status ctor 0x61cf670 as the binary implements it.

    Writes code/subcode/severity into out, zeroes +0x3..+0x5 and
    state_, then allocates `new char[size+1]` (size = len(msg) +
    (len(msg2) ? len(msg2)+2 : 0)), copies msg, appends ": " + msg2
    when msg2 is non-empty, NUL-terminates, and stores the buffer
    as state_. If the allocation fails, raises BadAlloc with the
    half-built status attached (code/subcode/severity written,
    state_ still None). The ctor's trailing delete[] of the old
    state_ is dead: state_ was zeroed before the read, so it
    never fires."""
    out = Status(code, subcode, severity, None)
    if not alloc_ok:
        raise BadAlloc(site=site, pad=pad, cleanup=cleanup,
                       partial=out)
    if msg2:
        out.state = message + ": " + msg2
    else:
        out.state = message
    return out


# Status::ToString 0x61cfed0, pinned from its own disassembly: a
# jump table at 0x97e958 over the code byte (codes 0..15) loads a
# prefix string (each ending in ": "), and a RELATIVE-relocated
# table at 0x64d7b00 holds the subcode strings. kOk is built inline
# as "OK" (0x4b4f at 0x61d01a7). Codes > 15 render as
# "Unknown code(%d): " (snprintf at 0x61cff33). With subcode 0 the
# state_ is appended straight after the prefix (which already ends
# in ": "); with a non-zero subcode the subcode string is appended
# first, then ": " + state_. With no state_ the result is the
# prefix alone (trailing space included).
CODE_PREFIX = {
    1: "NotFound: ",
    2: "Corruption: ",
    3: "Not implemented: ",
    4: "Invalid argument: ",
    5: "IO error: ",
    6: "Merge in progress: ",
    7: "Result incomplete: ",
    8: "Shutdown in progress: ",
    9: "Operation timed out: ",
    10: "Operation aborted: ",
    11: "Resource busy: ",
    12: "Operation expired: ",
    13: "Operation failed. Try again.: ",
    14: "Compaction too large: ",
    15: "Column family dropped: ",
}
SUBCODE_STRINGS = {
    0: "",
    1: "Timeout Acquiring Mutex",
    2: "Timeout waiting to lock key",
    3: "Failed to acquire lock due to max_num_locks limit",
    4: "No space left on device",
    5: "Deadlock",
    6: "Stale file handle",
    7: "Memory limit reached",
    8: "Space limit reached",
    9: "No such file or directory",
}


def status_tostring(status):
    """Status::ToString 0x61cfed0: "OK" for code 0; else the
    code prefix from the jump table at 0x97e958, then (subcode
    string + ": " + state) when the subcode is non-zero, else
    the state straight after the prefix; with no state the
    result is the prefix alone. Codes > 15 render as
    "Unknown code(%d): " + state."""
    if status.code == 0:
        return "OK"
    if status.code > 15:
        result = "Unknown code(%d): " % status.code
    else:
        result = CODE_PREFIX[status.code]
    if status.subcode:
        if status.subcode not in SUBCODE_STRINGS:
            raise ValueError("subcode %d has no ToString string "
                             "(table has 10 entries)" % status.subcode)
        result += SUBCODE_STRINGS[status.subcode]
        if status.state is not None:
            result += ": " + status.state
    elif status.state is not None:
        result += status.state
    return result


# ---------------------------------------------------------------- model

# DBImpl field offsets in the binary (see header note).
OFF_VERSIONS = 0x68
OFF_IMMUTABLE = 0x330
OFF_MUTABLE = 0x5A0
OFF_MUTEX = 0x700
OFF_ERROR_HANDLER = 0x760
OFF_LOG_WRITE_MUTEX = 0x9C8
OFF_LOGFILE_NUMBER = 0xA60
OFF_LOG_EMPTY = 0xAB9
OFF_LOG_DIR_SYNCED = 0xAB8
OFF_LOG_RECYCLE_FILES = 0xA78
OFF_RECYCLE_LOG_FILE_NUM = 0x400
OFF_LOGS = 0xB20
OFF_ALIVE_LOG_FILES = 0xB00
OFF_DIRECTORIES = 0xD08
OFF_TWO_WRITE_QUEUES = 0x17B0
OFF_TRACK_AND_VERIFY = 0x335
OFF_ALLOW_2PC = 0x4A3
OFF_INFO_LOG = 0x360
OFF_MAX_TOTAL_WAL_SIZE = 0x5C0
OFF_DB_WRITE_BUFFER_SIZE = 0x440
OFF_WRITE_BUFFER_MANAGER = 0x448

# ColumnFamilyData field offsets (column_family.h, verified
# against v8.1.1: mem_ +0x8e8, imm_ +0x8f0, dropped_ +0x3d,
# next_ +0x938, log_number_ +0x948, last_memtable_id_ +0x980).
CFD_MEM = 0x8E8
CFD_IMM = 0x8F0
CFD_LOG_NUMBER = 0x948
CFD_LAST_MEMTABLE_ID = 0x980
CFD_DROPPED = 0x3D
CFD_NEXT = 0x938
CFD_MUTABLE_CF_OPTIONS = 0x6C0

# MemTable field offsets (memtable.h: refs_ +0x70; the counters
# and sequence numbers are at +0xa70/+0xa78/+0xc18/+0xc20/+0xc28/
# +0xc30/+0xcc0 in the binary).
MEM_REFS = 0x70
MEM_NUM_ENTRIES = 0xA70
MEM_NUM_DELETES = 0xA78
MEM_FIRST_SEQNO = 0xC18
MEM_EARLIEST_SEQNO = 0xC20
MEM_CREATION_SEQ = 0xC28
MEM_NEXT_LOG_NUMBER = 0xC30
MEM_ID = 0xCC0
MEM_SIZE = 0xD20
SUPER_VERSION_SIZE = 0x290
LOG_WRITER_SIZE = 0x58

# MutableCFOptions field offsets (options/cf_options.h): the
# copy the FDE makes spans cfd+0x6c0 for 0x210 B on the stack
# (-0x470..-0x260). The shared_ptr at +0x40/+0x48 is
# prefix_extractor; the three vectors the dtor frees are at
# +0xc0 (max_bytes_for_level_multiplier_additional), +0x1c8
# (compression_per_level) and +0x1e0 (max_file_size).
MCO_WRITE_BUFFER_SIZE = 0x0
MCO_PREFIX_EXTRACTOR = 0x40
MCO_MBFLMA = 0xC0
MCO_COMPRESSION_PER_LEVEL = 0x1C8
MCO_MAX_FILE_SIZE = 0x1E0

# .cold cleanup chains, in execution order. The cold FDE is a
# ladder: the entry block depends on how far the
# MutableCFOptions copy had progressed when the throw escaped.
# - 0x5e8a7ae (pad 0x5e8c4d0): the copy had allocated the
#   +0x1c8 and +0xc0 vectors and the shared_ptr -- free both
#   vectors, release the shared_ptr, then the common tail.
# - 0x5e8a7c9 (pad 0x5e8c4e8): only the +0xc0 vector and the
#   shared_ptr existed -- free the vector, release the ptr.
# - 0x5e8a7e4 (pad 0x5e8c500): only the shared_ptr existed.
# - 0x5e8a7f5 (pad 0x5e8c4ac): nothing constructed yet (the
#   two_write_queues lock region) -- delete the two Status
#   state_ buffers (both null here).
# - 0x5e8a803 (pad 0x5e8c4f4): only io_s exists (the
#   WriteRecoverableState call) -- delete io_s.state_.
# - 0x5e8a82b (pad 0x5e8c50c): the throw happened while
#   log_write_mutex_ was held (r14) -- unlock it first, then
#   the completed-copy chain.
# - 0x5e8a83a (pad 0x5e8c4b8): the copy is complete -- dispose
#   memtable_info.cf_name, run the MutableCFOptions dtor, then
#   the common tail.
# - 0x5e8a850 (pad 0x5e8c4dc): the LogAndApply region -- destroy
#   the VersionEdit, then the empty-CF chain.
# - 0x5e8a85c (pad 0x5e8c4c4): the empty-CF region -- clear the
#   empty_cfs autovector and free its overflow vector buffer,
#   then the completed-copy chain.
# The common tail (0x5e8a7f5/0x5e8a803) deletes s.state_ and
# io_s.state_ (each only when non-null), checks the canary and
# calls _Unwind_Resume; a bad canary becomes StackCheckFailed
# after the cleanup.
_CHAIN_TAIL = ["delete[] s.state_?", "delete[] io_s.state_?",
               "canary-check", "_Unwind_Resume"]
_CHAIN_COPY = ["dispose memtable_info.cf_name",
               "MutableCFOptions dtor (max_file_size, "
               "compression_per_level, "
               "max_bytes_for_level_multiplier_additional, "
               "prefix_extractor release)"] + _CHAIN_TAIL
_CHAIN_7AE = ["free compression_per_level buffer",
              "free max_bytes_for_level_multiplier_additional buffer",
              "release prefix_extractor"] + _CHAIN_TAIL
_CHAIN_7C9 = ["free max_bytes_for_level_multiplier_additional buffer",
              "release prefix_extractor"] + _CHAIN_TAIL
_CHAIN_7E4 = ["release prefix_extractor"] + _CHAIN_TAIL
_CHAIN_7F5 = list(_CHAIN_TAIL)
_CHAIN_803 = ["delete[] io_s.state_?", "canary-check",
              "_Unwind_Resume"]
_CHAIN_82B = ["Mutex::Unlock (log_write_mutex_, held at the throw)"] \
    + _CHAIN_COPY
_CHAIN_850 = ["VersionEdit dtor",
              "autovector<ColumnFamilyData*,8> clear (empty_cfs)",
              "free empty_cfs overflow vector buffer"] + _CHAIN_COPY
_CHAIN_85C = ["autovector<ColumnFamilyData*,8> clear (empty_cfs)",
              "free empty_cfs overflow vector buffer"] + _CHAIN_COPY

# Throw sites: fail_at name -> (call address, LSDA pad stub or
# None, cleanup chain). The pad is the landing-pad stub
# address; the cleanup is the .cold chain that stub runs. pad
# None means the LSDA has no landing pad for that call (entry
# [0], the AssertHeld no-op): the exception propagates with no
# cleanup and no canary check. The copy-allocation sites use
# the ladder chains above; every other site in the
# post-copy region uses the completed-copy chain.
THROW_SITES = {
    "assert-held": (0x5E8A8DF, None, []),
    "write-recoverable-state": (0x5E8A90B, 0x5E8C4F4, _CHAIN_803),
    "copy-alloc-1": (0x5E8AE91, 0x5E8C500, _CHAIN_7E4),
    "copy-alloc-2": (0x5E8B05C, 0x5E8C4E8, _CHAIN_7C9),
    "copy-alloc-3": (0x5E8B0F1, 0x5E8C4D0, _CHAIN_7AE),
    "mutable-cf-options-copy": (0x5E8B186, 0x5E8C4B8, _CHAIN_COPY),
    "create-wal": (0x5E8A9C6, 0x5E8C4B8, _CHAIN_COPY),
    "get-wal-preallocate-block-size": (0x5E8B1F8, 0x5E8C4B8,
                                       _CHAIN_COPY),
    "construct-new-memtable": (0x5E8B246, 0x5E8C4B8, _CHAIN_COPY),
    "new-superversion": (0x5E8B257, 0x5E8C4B8, _CHAIN_COPY),
    "num-not-flushed": (0x5E8B1E2, 0x5E8C4B8, _CHAIN_COPY),
    "log-info": (0x5E8AA9B, 0x5E8C4B8, _CHAIN_COPY),
    "construct-fragmented-range-tombstones": (0x5E8AAAB, 0x5E8C4B8,
                                              _CHAIN_COPY),
    "mutex-lock": (0x5E8AAB7, 0x5E8C4B8, _CHAIN_COPY),
    "imm-add": (0x5E8ABA9, 0x5E8C4B8, _CHAIN_COPY),
    "install-superversion": (0x5E8ABE5, 0x5E8C4B8, _CHAIN_COPY),
    "notify-sealed": (0x5E8ABF7, 0x5E8C4B8, _CHAIN_COPY),
    "log-write-mutex-lock": (0x5E8B501, 0x5E8C4AC, _CHAIN_7F5),
    "log-write-mutex-unlock": (0x5E8B51B, 0x5E8C4AC, _CHAIN_7F5),
    "set-bg-error": (0x5E8B453, 0x5E8C4B8, _CHAIN_COPY),
    "set-bg-error-2": (0x5E8B5FD, 0x5E8C4B8, _CHAIN_COPY),
    "status-copy-ctor": (0x5E8B477, 0x5E8C4B8, _CHAIN_COPY),
    "write-buffer": (0x5E8B67E, 0x5E8C50C, _CHAIN_82B),
    "log-warn": (0x5E8B72D, 0x5E8C50C, _CHAIN_82B),
    "status-copy-assign": (0x5E8B7A1, 0x5E8C4B8, _CHAIN_COPY),
    "status-copy-assign-2": (0x5E8B83E, 0x5E8C50C, _CHAIN_82B),
    "get-default-cf": (0x5E8BC17, 0x5E8C4DC, _CHAIN_850),
    "log-and-apply": (0x5E8BC55, 0x5E8C4DC, _CHAIN_850),
    "set-bg-error-manifest": (0x5E8BF27, 0x5E8C4DC, _CHAIN_850),
    "status-copy-assign-3": (0x5E8BF32, 0x5E8C4DC, _CHAIN_850),
    "autovector-grow": (0x5E8C16A, 0x5E8C4C4, _CHAIN_85C),
}


# Sites whose call allocates (operator new, or a Status copy
# that allocates a state_ buffer): when alloc_ok is False the
# allocation fails and the site raises BadAlloc instead of a
# generic throw.
ALLOC_SITES = {"copy-alloc-1", "copy-alloc-2", "copy-alloc-3",
               "new-superversion", "status-copy-ctor",
               "status-copy-assign", "status-copy-assign-2",
               "status-copy-assign-3"}


def _throw(name, fail_at, canary_ok, alloc_ok=True, partial=None):
    """Raise the exception for throw site `name` when it is the
    armed fail_at, or when it is an allocating site and
    alloc_ok is False. A throw with a landing pad runs the
    .cold cleanup chain and then the pad canary check, so a bad
    canary turns the throw into StackCheckFailed after cleanup.
    A throw with no pad propagates with no cleanup and no
    canary check. Allocation sites raise BadAlloc."""
    if fail_at != name and not (not alloc_ok and
                                name in ALLOC_SITES):
        return
    site, pad, cleanup = THROW_SITES[name]
    if pad is not None and not canary_ok:
        raise StackCheckFailed(site=site, pad=pad, cleanup=cleanup,
                               partial=partial)
    if name in ALLOC_SITES:
        raise BadAlloc(site=site, pad=pad, cleanup=cleanup,
                       partial=partial)
    raise Throw("CalleeThrew", site=site, pad=pad, cleanup=cleanup,
                partial=partial)


def _log(db, log_lines, level, key, *args):
    """rocksdb::Log (0x5fcf060): level 1 = INFO, 2 = WARN. A
    null logger is skipped silently (the Log wrapper checks
    the shared_ptr first). The format strings carry the source
    line ([%s:line]) and the file argument is
    db/db_impl/db_impl_write.cc. Returns the rendered line, or
    None when the logger is null."""
    if not db["immutable"]["info_log_present"]:
        return None
    fmt = MESSAGES[key][0]
    line = fmt % ((LOG_FILE,) + args)
    log_lines.append({"level": level, "message": line})
    return line


# ---------------------------------------------------------------- defaults

def default_mutable_cf_options():
    """The MutableCFOptions this FDE copies from the column
    family. Only the fields the FDE reads or destroys are
    modelled: write_buffer_size (GetWalPreallocateBlockSize),
    the three vectors the dtor frees (as plain lists -- the
    copy reallocates each one, so the copy gets fresh heap
    ids), and prefix_extractor (a shared_ptr, modelled as a
    name plus a refcount the copy bumps)."""
    return {
        "write_buffer_size": 67108864,
        "max_bytes_for_level_multiplier_additional": [],
        "compression_per_level": [],
        "max_file_size": [],
        "prefix_extractor": None,
    }


def default_memtable(seq=0, entries=0, deletes=0):
    """A MemTable: refs_ starts at 0 (memtable.cc:78); the
    switch does new_mem->Ref() at the tail. first_seqno /
    earliest_seqno / creation_seq are SequenceNumbers; id is
    assigned by ColumnFamilyData::SetMemtable."""
    return {"refs": 0, "num_entries": entries,
            "num_deletes": deletes, "first_seqno": seq,
            "earliest_seqno": seq, "creation_seq": seq,
            "next_log_number": 0, "id": 0,
            "fragmented_tombstones_built": False}


def default_column_family(cf_id=0, name="default", seq=0):
    """One column family in ColumnFamilySet iteration order.
    `dropped` is the +0x3d byte the empty-CF min loop tests;
    `log_number` is cfd+0x948; `last_memtable_id` is the
    atomic at cfd+0x980; `imm_not_flushed` is
    imm()->NumNotFlushed()."""
    return {"id": cf_id, "name": name, "dropped": False,
            "log_number": 0, "last_memtable_id": 0,
            "mem": default_memtable(seq),
            "imm": {"not_flushed": 0, "tables": []},
            "mutable_cf_options": default_mutable_cf_options()}


def default_immutable_db_options():
    """The ImmutableDBOptions fields this FDE (and
    GetWalPreallocateBlockSize) reads. `info_log_present` is
    the null check the Log calls perform. `write_buffer_manager`
    is None or {"buffer_size": n} -- the third
    GetWalPreallocateBlockSize term, pinned from the binary
    (0x5e87d60: max with wbm->buffer_size_ when the manager is
    non-null and its size is non-zero)."""
    return {
        "info_log_present": True,
        "recycle_log_file_num": 0,
        "db_write_buffer_size": 0,
        "write_buffer_manager": None,
        "track_and_verify_wals_in_manifest": False,
        "allow_2pc": False,
    }


def default_db_state():
    """The DBImpl state this FDE reads or writes, keyed by the
    binary field offsets. `column_families` is the
    ColumnFamilySet list in iteration order (dummy_cfd_->next_
    chain, +0x938). `log_recycle_files` is the deque at
    DBImpl+0xa78; `logs` is the deque at +0xb20 of
    (log_number, writer) pairs; `alive_log_files` is the
    vector at +0xb00 of log numbers. `versions` is the
    VersionSet: last_sequence (+0x108), next_file_number
    (the atomic at +0xd8), min_wal_to_keep (the WalSet at
    +0x38) and io_status (+0x280)."""
    return {
        "immutable": default_immutable_db_options(),
        "mutable": {"max_total_wal_size": 0},
        # DBImpl+0x700 mutex_ (held on entry, AssertHeld).
        "mutex_locked": True,
        # DBImpl+0x9c8 log_write_mutex_.
        "log_write_mutex_locked": False,
        # DBImpl+0x17b0 two_write_queues_.
        "two_write_queues": False,
        # DBImpl+0xa60 logfile_number_.
        "logfile_number": 0,
        # DBImpl+0xab9 log_empty_.
        "log_empty": True,
        # DBImpl+0xab8 log_dir_synced_.
        "log_dir_synced": False,
        # DBImpl+0xa78 log_recycle_files_ deque.
        "log_recycle_files": [],
        # DBImpl+0xb20 logs_ deque of (log_number, writer).
        "logs": [],
        # DBImpl+0xb00 alive_log_files_ vector of log numbers.
        "alive_log_files": [],
        # DBImpl+0x760 error_handler_: bg_error_ (+0x10) and
        # the recovery-in-progress flag (+0x809).
        "error_handler": {"bg_error": Status.ok(),
                          "recovery_in_progress": False},
        # DBImpl+0x68 versions_.
        "versions": {"last_sequence": 100,
                     "next_file_number": 7,
                     "min_wal_to_keep": 0,
                     "io_status": Status.ok()},
        "column_families": [default_column_family()],
    }


def default_write_context():
    """A WriteContext: superversion_context.new_superversion
    (context+0x210) starts null and is installed by the
    inlined NewSuperVersion; memtables_to_free_
    (context+0x218) collects the old memtables imm()->Add
    hands over."""
    return {"new_superversion": None, "memtables_to_free": []}


def default_oracle():
    """The callee outcomes the engine takes as oracle inputs.
    Each is the status (or object) the corresponding call
    returns; the model never invents one. `create_wal` is
    (status_dict, writer_dict-or-None); `construct_memtable`
    is a MemTable dict (or None for the default fresh table);
    `set_bg_error` / `get_bg_error` are the ErrorHandler
    outcomes (SetBGError returns a Status; GetBGError is
    inlined -- a copy of bg_error_ at error_handler_+0x10)."""
    return {
        "recoverable_state": Status.ok(),
        "create_wal": (Status.ok(), None),
        "construct_memtable": None,
        "write_buffer": Status.ok(),
        "log_and_apply": Status.ok(),
        "versions_io_status": Status.ok(),
        "set_bg_error": Status.ok(),
        "get_bg_error": Status.ok(),
        "last_sequence": 100,
        "new_file_number": 7,
        "min_wal_to_keep": 0,
    }


def get_wal_preallocate_block_size(db, write_buffer_size):
    """DBImpl::GetWalPreallocateBlockSize (0x5e87d60), pinned
    from its own disassembly: bsize = write_buffer_size / 10 +
    write_buffer_size (the /10 is the 0xcccccccccccccccd magic
    multiply at 0x5e87d7c), then min with
    mutable_db_options_.max_total_wal_size when that is
    non-zero (this+0x5c0), then min with
    immutable_db_options_.db_write_buffer_size when that is
    non-zero (this+0x440), then max with
    write_buffer_manager->buffer_size_ when the manager is
    non-null and its size is non-zero (this+0x448; the
    WriteBufferManager is final, so *(ptr) IS buffer_size_).
    The v8.1.1 tag source shows only the two mins -- the
    third max term is a binary-vs-source observation (see
    records.json)."""
    bsize = write_buffer_size // 10 + write_buffer_size
    max_total = db["mutable"]["max_total_wal_size"]
    if max_total:
        bsize = min(bsize, max_total)
    db_write_buffer_size = db["immutable"]["db_write_buffer_size"]
    if db_write_buffer_size:
        bsize = min(bsize, db_write_buffer_size)
    wbm = db["immutable"]["write_buffer_manager"]
    if wbm is not None and wbm["buffer_size"]:
        bsize = max(bsize, wbm["buffer_size"])
    return bsize


def _is_empty(cf):
    """ColumnFamilyData::IsEmpty (column_family.h:348-350):
    mem()->GetFirstSequenceNumber() == 0 &&
    imm()->NumNotFlushed() == 0. Matches the binary exactly
    (mem+0xc18 first_seqno, the 0x5f12a10 call)."""
    return cf["mem"]["first_seqno"] == 0 and \
        cf["imm"]["not_flushed"] == 0


def _copy_mutable_cf_options(cfd, fail_at, canary_ok, effects,
                             alloc_ok=True):
    """The MutableCFOptions copy (cfd+0x6c0, 0x210 B on the
    stack at -0x470): a deep copy -- each of the three vectors
    is reallocated (the copy-allocation sites are
    copy-alloc-1/2/3) and the prefix_extractor shared_ptr is
    copied (refcount +1). The copy order the ladder proves is
    prefix_extractor, max_bytes_for_level_multiplier_additional,
    compression_per_level, max_file_size."""
    _throw("copy-alloc-1", fail_at, canary_ok, alloc_ok)
    _throw("copy-alloc-2", fail_at, canary_ok, alloc_ok)
    _throw("copy-alloc-3", fail_at, canary_ok, alloc_ok)
    src = cfd["mutable_cf_options"]
    out = copy.deepcopy(src)
    if src["prefix_extractor"] is not None:
        effects.append("prefix_extractor refcount +1 (copy)")
    _throw("mutable-cf-options-copy", fail_at, canary_ok, alloc_ok)
    return out


def _destroy_mutable_cf_options(mco, effects):
    """The MutableCFOptions dtor (0x5d55870), inlined at the
    epilogue in dtor order: free max_file_size, free
    compression_per_level, free
    max_bytes_for_level_multiplier_additional, release
    prefix_extractor."""
    for name in ("max_file_size", "compression_per_level",
                 "max_bytes_for_level_multiplier_additional"):
        if mco[name]:
            effects.append("free %s buffer (dtor)" % name)
    if mco["prefix_extractor"] is not None:
        effects.append("prefix_extractor refcount -1 (dtor)")


def _epilogue(db, s, io_s, mco, cf_name, canary_ok, effects):
    """The normal-return epilogue (0x5e8abfc..0x5e8acf5):
    dispose memtable_info.cf_name, destroy the
    MutableCFOptions copy (inlined), release the shared_ptr,
    delete[] io_s.state_ when non-null, then the canary check
    at 0x5e8acde. s.state_ is NOT deleted -- s IS the return
    value (out in r15). When mco is None the copy never
    happened (the WriteRecoverableState early return jumps
    straight to 0x5e8acc0) and only the io_s delete and the
    canary check run."""
    if cf_name:
        effects.append("dispose memtable_info.cf_name")
    if mco is not None:
        _destroy_mutable_cf_options(mco, effects)
    if io_s.state is not None:
        effects.append("delete[] io_s.state_")
    if not canary_ok:
        raise StackCheckFailed(site=0x5E8ACDE, pad=None,
                               cleanup=["epilogue canary check"])
    return s


def switch_memtable(db, cfd, context, oracle, *, fail_at=None,
                    canary_ok=True, alloc_ok=True):
    """rocksdb::DBImpl::SwitchMemtable(ColumnFamilyData*,
    WriteContext*) -- Status by value (hidden sret out in rdi
    = r15), this in rsi = r14, cfd in rdx = rbx, context in
    rcx. The engine follows the binary step for step; the
    oracle supplies every callee outcome. `effects` records
    each observable mutation in order; `log` holds the
    (level, message) lines rocksdb::Log emitted."""
    effects = []
    log = []
    # s IS out (r15); io_s is the Status at -0x490.
    s = Status.ok()
    io_s = Status.ok()
    mco = None
    cf_name = None
    new_mem = None
    new_log = None
    creating_new_log = False
    recycle_log_number = 0
    new_log_number = 0

    # mutex_.AssertHeld() -- 0x60d5390, an empty body in this
    # build (endbr64; ret). A throw here has no landing pad.
    _throw("assert-held", fail_at, canary_ok, alloc_ok)
    effects.append("assert-held mutex_")

    # Status s = WriteRecoverableState().
    _throw("write-recoverable-state", fail_at, canary_ok, alloc_ok)
    s = status_from_dict(oracle["recoverable_state"].as_dict())
    if not s.is_ok():
        effects.append("return WriteRecoverableState status")
        return {"result": _epilogue(db, s, io_s, None, None,
                                    canary_ok, effects),
                "log": log, "effects": effects, "db": db,
                "cfd": cfd, "context": context,
                "creating_new_log": False, "recycle_log_number": 0,
                "new_log_number": 0, "preallocate_block_size": None,
                "memtable_info": None}

    # bool creating_new_log = !log_empty_; with two_write_queues_
    # the read is taken under log_write_mutex_.
    if db["two_write_queues"]:
        _throw("log-write-mutex-lock", fail_at, canary_ok, alloc_ok)
        db["log_write_mutex_locked"] = True
        effects.append("lock log_write_mutex_ (two_write_queues)")
    creating_new_log = not db["log_empty"]
    if db["two_write_queues"]:
        _throw("log-write-mutex-unlock", fail_at, canary_ok, alloc_ok)
        db["log_write_mutex_locked"] = False
        effects.append("unlock log_write_mutex_ (two_write_queues)")

    # Recycle: front of log_recycle_files_ when creating, the
    # count is set and the deque is non-empty.
    if creating_new_log and \
            db["immutable"]["recycle_log_file_num"] and \
            db["log_recycle_files"]:
        recycle_log_number = db["log_recycle_files"][0]
        effects.append("recycle log #%d" % recycle_log_number)

    # new_log_number = creating ? versions_->NewFileNumber()
    # (atomic fetch-add on versions_+0xd8) : logfile_number_.
    if creating_new_log:
        new_log_number = oracle["new_file_number"]
        effects.append("new file number #%d" % new_log_number)
    else:
        new_log_number = db["logfile_number"]

    # const MutableCFOptions mutable_cf_options =
    # *cfd->GetLatestMutableCFOptions() -- deep copy.
    mco = _copy_mutable_cf_options(cfd, fail_at, canary_ok, effects,
                                   alloc_ok)

    # MemTableInfo: cf_name, first_seqno, earliest_seqno,
    # num_entries, num_deletes (from cfd->mem()).
    cf_name = cfd["name"]
    memtable_info = {
        "cf_name": cf_name,
        "first_seqno": cfd["mem"]["first_seqno"],
        "earliest_seqno": cfd["mem"]["earliest_seqno"],
        "num_entries": cfd["mem"]["num_entries"],
        "num_deletes": cfd["mem"]["num_deletes"],
    }
    effects.append("memtable_info %r" % (memtable_info,))

    # int num_imm_unflushed = cfd->imm()->NumNotFlushed().
    _throw("num-not-flushed", fail_at, canary_ok, alloc_ok)
    num_imm_unflushed = cfd["imm"]["not_flushed"]

    # preallocate_block_size =
    # GetWalPreallocateBlockSize(write_buffer_size).
    _throw("get-wal-preallocate-block-size", fail_at, canary_ok, alloc_ok)
    preallocate = get_wal_preallocate_block_size(
        db, mco["write_buffer_size"])
    effects.append("preallocate_block_size %d" % preallocate)

    # mutex_.Unlock() -- the WAL creation and the new memtable
    # happen without the db mutex.
    db["mutex_locked"] = False
    effects.append("unlock mutex_")

    # if (creating_new_log) { io_s = CreateWAL(...); if (s.ok())
    #   s = io_s; }
    if creating_new_log:
        _throw("create-wal", fail_at, canary_ok, alloc_ok)
        wal_status, new_log = oracle["create_wal"]
        io_s = status_from_dict(wal_status.as_dict())
        if s.is_ok():
            # s = io_s -- the copy-assign at 0x5e8b7a1
            # (out-of-line). It copies io_s.state_ (allocating).
            _throw("status-copy-assign", fail_at, canary_ok, alloc_ok)
            s = status_from_dict(io_s.as_dict())
        effects.append("CreateWAL -> %s" % io_s)

    # if (s.ok()) { new_mem = ConstructNewMemtable(...);
    #   context->superversion_context.NewSuperVersion(); }
    if s.is_ok():
        _throw("construct-new-memtable", fail_at, canary_ok, alloc_ok)
        if oracle["construct_memtable"] is not None:
            new_mem = copy.deepcopy(oracle["construct_memtable"])
        else:
            new_mem = default_memtable(
                oracle["last_sequence"])
        new_mem["earliest_seqno"] = oracle["last_sequence"]
        new_mem["first_seqno"] = oracle["last_sequence"]
        new_mem["creation_seq"] = oracle["last_sequence"]
        effects.append("new memtable (seq %d)"
                       % oracle["last_sequence"])
        _throw("new-superversion", fail_at, canary_ok, alloc_ok)
        context["new_superversion"] = {
            "mem": new_mem, "size": SUPER_VERSION_SIZE,
            "installed": False}
        effects.append("NewSuperVersion installed in context")

    # ROCKS_LOG_INFO -- always logged, even on the error path.
    _throw("log-info", fail_at, canary_ok, alloc_ok)
    _log(db, log, 1, "log-info", cf_name, new_log_number,
         num_imm_unflushed)

    # cfd->mem()->ConstructFragmentedRangeTombstones().
    _throw("construct-fragmented-range-tombstones", fail_at,
           canary_ok)
    cfd["mem"]["fragmented_tombstones_built"] = True
    effects.append("ConstructFragmentedRangeTombstones on old mem")

    # mutex_.Lock().
    _throw("mutex-lock", fail_at, canary_ok, alloc_ok)
    db["mutex_locked"] = True
    effects.append("lock mutex_")

    # if (recycle_log_number != 0) log_recycle_files_.pop_front().
    if recycle_log_number != 0:
        assert db["log_recycle_files"] and \
            db["log_recycle_files"][0] == recycle_log_number
        db["log_recycle_files"].pop(0)
        effects.append("pop_front log_recycle_files_")

    # Error path: delete new_mem/new_log, reset the
    # superversion, SetBGError(io_s or s, kMemTable), return
    # GetBGError(). Reached whenever s is not OK at this point.
    if not s.is_ok():
        return _error_path(db, cfd, context, oracle, s, io_s,
                           new_mem, new_log, mco, cf_name, fail_at,
                           canary_ok, effects, log,
                           creating_new_log, recycle_log_number,
                           new_log_number, preallocate,
                           memtable_info, alloc_ok)

    # if (s.ok() && creating_new_log) { lock log_write_mutex_;
    #   if (!logs_.empty()) { WriteBuffer the last log; ... }
    #   if (s.ok()) { record the new log file } } -- the record
    #   step is OUTSIDE the !logs_.empty() check (binary
    #   0x5e8b642 jumps straight to the s check at 0x5e8b734 when
    #   logs_ is empty, and the update at 0x5e8b84d runs then).
    if creating_new_log:
        _throw("log-write-mutex-lock", fail_at, canary_ok, alloc_ok)
        db["log_write_mutex_locked"] = True
        effects.append("lock log_write_mutex_ (log write)")
        if db["logs"]:
            cur_number, cur_writer = db["logs"][-1]
            if db["error_handler"]["recovery_in_progress"]:
                cur_writer["file"]["seen_error"] = False
                effects.append("reset_seen_error on log #%d"
                               % cur_number)
            _throw("write-buffer", fail_at, canary_ok, alloc_ok)
            io_s = status_from_dict(
                oracle["write_buffer"].as_dict())
            if s.is_ok():
                # s = io_s -- the copy-assign at 0x5e8b83e.
                _throw("status-copy-assign-2", fail_at, canary_ok, alloc_ok)
                s = status_from_dict(io_s.as_dict())
            effects.append("WriteBuffer -> %s" % io_s)
            if not s.is_ok():
                _throw("log-warn", fail_at, canary_ok, alloc_ok)
                _log(db, log, 2, "log-warn", cf_name, cur_number,
                     new_log_number)
        if s.is_ok():
            # logfile_number_ = new_log_number (0x5e8b860);
            # log_dir_synced_ = 0 and log_empty_ = 1 in one
            # 16-bit store of 0x100 at +0xab8 (0x5e8b86e);
            # logs_.emplace_back + alive_log_files_.push_back.
            db["logfile_number"] = new_log_number
            db["log_empty"] = True
            db["log_dir_synced"] = False
            db["logs"].append((new_log_number, new_log))
            db["alive_log_files"].append(new_log_number)
            effects.append(
                "logs_.emplace_back #%d; alive_log_files_ "
                "push #%d" % (new_log_number, new_log_number))
        _throw("log-write-mutex-unlock", fail_at, canary_ok, alloc_ok)
        db["log_write_mutex_locked"] = False
        effects.append("unlock log_write_mutex_ (log write)")

    if not s.is_ok():
        return _error_path(db, cfd, context, oracle, s, io_s,
                           new_mem, new_log, mco, cf_name, fail_at,
                           canary_ok, effects, log,
                           creating_new_log, recycle_log_number,
                           new_log_number, preallocate,
                           memtable_info, alloc_ok)

    # Empty-CF handling. When track_and_verify is on, 2PC is
    # off and a new log is being created, the min WAL over the
    # empty CFs (dropped CFs excluded) is compared with the
    # WalSet minimum; when it is larger, the empty CFs are
    # collected and a VersionEdit deleting WALs before it is
    # applied to the default CF. Otherwise every empty CF is
    # updated in the plain loop.
    empty_cf_updated = False
    if db["immutable"]["track_and_verify_wals_in_manifest"] and \
            not db["immutable"]["allow_2pc"] and creating_new_log:
        # PreComputeMinLogNumberWithUnflushedData(logfile_number_)
        # (version_set.h): each CF contributes its log_number_,
        # except an empty CF, which contributes the new
        # logfile_number_; dropped CFs never lower the minimum
        # (binary 0x5e8b580-0x5e8b82f: the +0x3d dropped byte is
        # only consulted when the candidate is below the running
        # minimum, via cmovne). No qualifying CF leaves UINT64_MAX.
        min_wal = (1 << 64) - 1
        for other in db["column_families"]:
            num = db["logfile_number"] if _is_empty(other) else \
                other["log_number"]
            if min_wal > num and not other["dropped"]:
                min_wal = num
        effects.append("min WAL with unflushed data: %d" % min_wal)
        if min_wal > oracle["min_wal_to_keep"]:
            empty_cfs = [other for other in db["column_families"]
                         if _is_empty(other)]
            effects.append("empty_cfs collected: %d"
                           % len(empty_cfs))
            if len(empty_cfs) > 8:
                _throw("autovector-grow", fail_at, canary_ok, alloc_ok)
                effects.append("empty_cfs overflow vector grown")
            _throw("get-default-cf", fail_at, canary_ok, alloc_ok)
            _throw("log-and-apply", fail_at, canary_ok, alloc_ok)
            s = status_from_dict(
                oracle["log_and_apply"].as_dict())
            effects.append("LogAndApply(DeleteWalsBefore %d) -> %s"
                           % (min_wal, s))
            if not s.is_ok() and \
                    oracle["versions_io_status"].code == 5:
                _throw("set-bg-error-manifest", fail_at, canary_ok, alloc_ok)
                # s = SetBGError(...) -- the copy-assign at
                # 0x5e8bf32 (the return temp is copied, not moved).
                _throw("status-copy-assign-3", fail_at, canary_ok, alloc_ok)
                s = status_from_dict(
                    oracle["set_bg_error"].as_dict())
                effects.append(
                    "SetBGError(io_status, kManifestWrite) -> %s"
                    % s)
            if not s.is_ok():
                # The LogAndApply failure return: destroy the
                # VersionEdit, the empty_cfs autovector and
                # its overflow buffer, then the epilogue.
                effects.append("destroy VersionEdit")
                effects.append("destroy empty_cfs autovector")
                effects.append("free empty_cfs overflow buffer")
                return {"result": _epilogue(
                            db, s, io_s, mco, cf_name, canary_ok,
                            effects),
                        "log": log, "effects": effects, "db": db,
                        "cfd": cfd, "context": context,
                        "creating_new_log": creating_new_log,
                        "recycle_log_number": recycle_log_number,
                        "new_log_number": new_log_number,
                        "preallocate_block_size": preallocate,
                        "memtable_info": memtable_info}
            for other in empty_cfs:
                if _is_empty(other):
                    other["log_number"] = db["logfile_number"]
                    other["mem"]["creation_seq"] = \
                        oracle["last_sequence"]
                    effects.append(
                        "empty CF %r: SetLogNumber #%d, "
                        "SetCreationSeq %d"
                        % (other["name"], db["logfile_number"],
                           oracle["last_sequence"]))
            empty_cf_updated = True
    if not empty_cf_updated:
        for other in db["column_families"]:
            if _is_empty(other):
                if creating_new_log:
                    other["log_number"] = db["logfile_number"]
                    effects.append(
                        "empty CF %r: SetLogNumber #%d"
                        % (other["name"], db["logfile_number"]))
                # SetCreationSeq is unconditional in the binary
                # (0x5e8b35f) and in v8.1.1 db_impl_write.cc -- it
                # runs even when no new log is being created.
                other["mem"]["creation_seq"] = \
                    oracle["last_sequence"]
                effects.append(
                    "empty CF %r: SetCreationSeq %d"
                    % (other["name"], oracle["last_sequence"]))

    # Success tail: SetNextLogNumber, imm()->Add, new_mem->Ref(),
    # SetMemtable, InstallSuperVersionAndScheduleWork,
    # NotifyOnMemTableSealed, io_s.PermitUncheckedError().
    cfd["mem"]["next_log_number"] = db["logfile_number"]
    effects.append("SetNextLogNumber #%d" % db["logfile_number"])
    _throw("imm-add", fail_at, canary_ok, alloc_ok)
    cfd["imm"]["tables"].append(cfd["mem"])
    context["memtables_to_free"].append(cfd["mem"])
    effects.append("imm()->Add(old mem)")
    new_mem["refs"] += 1
    effects.append("new_mem->Ref() -> %d" % new_mem["refs"])
    cfd["last_memtable_id"] += 1
    new_mem["id"] = cfd["last_memtable_id"]
    cfd["mem"] = new_mem
    effects.append("SetMemtable id %d" % new_mem["id"])
    _throw("install-superversion", fail_at, canary_ok, alloc_ok)
    context["new_superversion"]["installed"] = True
    effects.append("InstallSuperVersionAndScheduleWork")
    _throw("notify-sealed", fail_at, canary_ok, alloc_ok)
    effects.append("NotifyOnMemTableSealed %r" % (memtable_info,))
    if io_s.state is not None:
        effects.append("io_s.PermitUncheckedError()")
    return {"result": _epilogue(db, s, io_s, mco, cf_name,
                                canary_ok, effects),
            "log": log, "effects": effects, "db": db,
            "cfd": cfd, "context": context,
            "creating_new_log": creating_new_log,
            "recycle_log_number": recycle_log_number,
            "new_log_number": new_log_number,
            "preallocate_block_size": preallocate,
            "memtable_info": memtable_info}


def _error_path(db, cfd, context, oracle, s, io_s, new_mem,
                new_log, mco, cf_name, fail_at, canary_ok,
                effects, log, creating_new_log,
                recycle_log_number, new_log_number, preallocate,
                memtable_info, alloc_ok=True):
    """The error path (0x5e8b3b0): delete new_mem (MemTable
    dtor + _ZdlPvm 0xd20) and new_log (log::Writer dtor +
    _ZdlPvm 0x58) when non-null, reset the superversion
    context (SuperVersion dtor + _ZdlPvm 0x290), then
    SetBGError(io_s when it failed, else s, kMemTable=3) --
    two call sites, one per branch -- and return GetBGError()
    (inlined: a copy of bg_error_ at error_handler_+0x10).
    The returned status is the GetBGError oracle value."""
    if new_mem is not None:
        effects.append("delete new_mem (MemTable dtor)")
        new_mem = None
    if new_log is not None:
        effects.append("delete new_log (log::Writer dtor)")
        new_log = None
    if context["new_superversion"] is not None:
        effects.append("reset new_superversion (SuperVersion dtor)")
        context["new_superversion"] = None
    _throw("set-bg-error", fail_at, canary_ok, alloc_ok)
    if not io_s.is_ok():
        effects.append("SetBGError(io_s, kMemTable) -> %s"
                       % oracle["set_bg_error"])
    else:
        effects.append("SetBGError(s, kMemTable) -> %s"
                       % oracle["set_bg_error"])
    _throw("status-copy-ctor", fail_at, canary_ok, alloc_ok)
    s = status_from_dict(oracle["get_bg_error"].as_dict())
    effects.append("return GetBGError() -> %s" % s)
    return {"result": _epilogue(db, s, io_s, mco, cf_name,
                                canary_ok, effects),
            "log": log, "effects": effects, "db": db,
            "cfd": cfd, "context": context,
            "creating_new_log": creating_new_log,
            "recycle_log_number": recycle_log_number,
            "new_log_number": new_log_number,
            "preallocate_block_size": preallocate,
            "memtable_info": memtable_info}


# ---------------------------------------------------------------- cases

# Engine call counts verified live (objdump, main FDE then .cold
# FDE). Keys are "call <target>" as objdump prints the address.
ENGINE_CALLS = {
    "main": {
        "call   63f0d80": 11, "call   63f0a70": 9,
        "call   63f0dd0": 8, "call   63f0dc0": 7,
        "call   5f12a10": 5, "call   63f0ec0": 4,
        "call   63f0ed0": 3, "call   60d52f0": 3,
        "call   606ca40": 3, "call   5ead310": 3,
        "call   5e86040": 3, "call   63f0de0": 2,
        "call   5fcf060": 2, "call   5e85ea0": 2,
        "call   5d8d820": 2, "call   5d5b710": 2,
        "call   5d5b080": 2, "call   5d516f0": 2,
        "call   63f0f00": 1, "call   63f0d70": 1,
        "call   60d5390": 1, "call   5f140c0": 1,
        "call   5f10d40": 1, "call   5f0a3d0": 1,
        "call   5f04800": 1, "call   5f03a90": 1,
        "call   5e8a4e0": 1, "call   5e87e10": 1,
        "call   5e87d60": 1, "call   5e5c270": 1,
        "call   5de3060": 1, "call   5d8ce80": 1,
        "call   5d8ca00": 1, "call   5d68760": 1,
        "call   5d67c10": 1, "call   5d4fce0": 1,
        "call   5d35070": 1,
        "call   *0x18(%rax)": 1, "call   *0x10(%rax)": 1,
    },
    "cold": {
        "call   63f0dc0": 2, "call   63f0d80": 2,
        "call   63f0db0": 1, "call   63f0d70": 1,
        "call   63f0a50": 1, "call   60d52f0": 1,
        "call   5d5b710": 1, "call   5d5b080": 1,
        "call   5d55870": 1, "call   5d516f0": 1,
        "call   5d350c0": 1,
    },
}

# Landing-pad stub -> .cold target, verified live (each stub is
# endbr64 + mov %rax,%rbx + jmp rel32 at stub+7).
PAD_TO_COLD = {
    0x5E8C4AC: 0x5E8A7F5, 0x5E8C4B8: 0x5E8A83A,
    0x5E8C4C4: 0x5E8A85C, 0x5E8C4D0: 0x5E8A7AE,
    0x5E8C4DC: 0x5E8A850, 0x5E8C4E8: 0x5E8A7C9,
    0x5E8C4F4: 0x5E8A803, 0x5E8C500: 0x5E8A7E4,
    0x5E8C50C: 0x5E8A82B,
}

# The six validated caller sites (census.py): the callers that
# reach SwitchMemtable directly. The raw whole-.text scan finds
# exactly these six E8 candidates, all validated by decoding
# forward from their enclosing FDE start; SwitchWAL is the
# sixth (0x5e8c901, in DBImpl::SwitchWAL 0x5e8c5e0..0x5e8d007,
# census-bound), matching v8.1.1 db_impl_write.cc SwitchWAL,
# which calls SwitchMemtable once per column family.
CALLER_SITES = {
    "0x5ddfb4a": "rocksdb::DBImpl::FlushMemtable",
    "0x5de0835": "rocksdb::DBImpl::FlushMemtable",
    "0x5de189a": "rocksdb::DBImpl::AtomicFlushMemTables",
    "0x5e8c901": "rocksdb::DBImpl::SwitchWAL",
    "0x5e8d404": "rocksdb::DBImpl::HandleWriteBufferManagerFlush",
    "0x5e8dd1c": "rocksdb::DBImpl::ScheduleFlushes",
}


def _apply_overrides(db, overrides):
    for key, value in (overrides or {}).items():
        if key == "column_families":
            db["column_families"] = value
        elif isinstance(value, dict) and isinstance(db.get(key), dict):
            db[key].update(value)
        else:
            db[key] = value
    return db


def _status_dict(status):
    return status.as_dict()


def _mem_summary(mem):
    return {"refs": mem["refs"], "num_entries": mem["num_entries"],
            "num_deletes": mem["num_deletes"],
            "first_seqno": mem["first_seqno"],
            "earliest_seqno": mem["earliest_seqno"],
            "creation_seq": mem["creation_seq"],
            "next_log_number": mem["next_log_number"],
            "id": mem["id"],
            "fragmented_tombstones_built":
                mem["fragmented_tombstones_built"]}


def _cf_summary(cf):
    return {"id": cf["id"], "name": cf["name"],
            "dropped": cf["dropped"],
            "log_number": cf["log_number"],
            "last_memtable_id": cf["last_memtable_id"],
            "mem": _mem_summary(cf["mem"]),
            "imm_not_flushed": cf["imm"]["not_flushed"],
            "imm_tables": len(cf["imm"]["tables"])}


def _db_summary(db):
    return {
        "logfile_number": db["logfile_number"],
        "log_empty": db["log_empty"],
        "log_dir_synced": db["log_dir_synced"],
        "log_recycle_files": list(db["log_recycle_files"]),
        "logs": [[n, w["file"]["seen_error"] if w else None]
                 for n, w in db["logs"]],
        "alive_log_files": list(db["alive_log_files"]),
        "mutex_locked": db["mutex_locked"],
        "log_write_mutex_locked": db["log_write_mutex_locked"],
        "two_write_queues": db["two_write_queues"],
        "bg_error": _status_dict(db["error_handler"]["bg_error"]),
        "recovery_in_progress":
            db["error_handler"]["recovery_in_progress"],
        "versions": {
            "last_sequence": db["versions"]["last_sequence"],
            "next_file_number": db["versions"]["next_file_number"],
            "min_wal_to_keep": db["versions"]["min_wal_to_keep"],
            "io_status": _status_dict(
                db["versions"]["io_status"])},
        "column_families": [_cf_summary(cf) for cf in
                            db["column_families"]]}


def _context_summary(context):
    sv = context["new_superversion"]
    return {
        "new_superversion": None if sv is None else {
            "installed": sv["installed"],
            "mem_id": sv["mem"]["id"]},
        "memtables_to_free": len(context["memtables_to_free"])}


def _oracle_from_json(oracle_json):
    oracle = default_oracle()
    for key, value in (oracle_json or {}).items():
        if key == "create_wal":
            st = status_from_dict(value["status"])
            oracle["create_wal"] = (st, value.get("writer"))
        elif key in ("recoverable_state", "write_buffer",
                     "log_and_apply", "versions_io_status",
                     "set_bg_error", "get_bg_error"):
            oracle[key] = status_from_dict(value)
        else:
            oracle[key] = value
    return oracle


def _writer(number):
    return {"file_number": number, "seen_error": False,
            "file": {"name": "%06d.log" % number,
                     "seen_error": False, "size": 0}}


def run_case(inputs):
    """Run one case and return the expected outputs.

    The inputs are deep-copied first: the model mutates the db
    state it is given (_apply_overrides hands it the override
    lists by reference, and the switch appends to logs_ and pops
    from log_recycle_files_), so without the copy the recorded
    inputs in cases.tsv would already contain the run's own
    mutations and a replay would append/pop a second time.
    """
    inputs = copy.deepcopy(inputs)
    group = inputs["group"]
    if group == "checks":
        db = default_db_state()
        _apply_overrides(db, inputs.get("db_overrides"))
        if "cfs" in inputs:
            db["column_families"] = inputs["cfs"]
        if "cf_overrides" in inputs:
            _apply_overrides(db["column_families"][0],
                             inputs["cf_overrides"])
        cfd = db["column_families"][0]
        context = default_write_context()
        oracle = _oracle_from_json(inputs.get("oracle"))
        out = switch_memtable(
            db, cfd, context, oracle,
            fail_at=inputs.get("fail_at"),
            canary_ok=inputs.get("canary_ok", True),
            alloc_ok=inputs.get("alloc_ok", True))
        return {"result": _status_dict(out["result"]),
                "log": [line["message"] for line in out["log"]],
                "effects": out["effects"],
                "db_summary": _db_summary(out["db"]),
                "cfd_summary": _cf_summary(out["cfd"]),
                "context_summary": _context_summary(out["context"]),
                "creating_new_log": out["creating_new_log"],
                "recycle_log_number": out["recycle_log_number"],
                "new_log_number": out["new_log_number"],
                "preallocate_block_size":
                    out["preallocate_block_size"],
                "memtable_info": out["memtable_info"]}
    if group == "status":
        kind = inputs["kind"]
        if kind == "ok":
            return {"status": _status_dict(Status.ok())}
        if kind == "error":
            st = status_from_dict(inputs["status"])
            return {"status": _status_dict(st),
                    "tostring": status_tostring(st)}
        if kind == "image":
            st = Status(inputs["code"], inputs["subcode"],
                        inputs["severity"], inputs.get("state"))
            return {"status": _status_dict(st)}
        if kind == "tostring":
            st = status_from_dict(inputs["status"])
            return {"status": _status_dict(st),
                    "tostring": status_tostring(st)}
        if kind == "copy-assign":
            src = status_from_dict(inputs["status"])
            dst = Status.ok()
            # Status::operator=(const Status&) 0x5e86040: delete
            # the old state_, copy code/subcode/severity, steal
            # a fresh copy of the state_ buffer.
            dst.code, dst.subcode, dst.severity = \
                src.code, src.subcode, src.severity
            dst.state = src.state
            return {"status": _status_dict(dst),
                    "source_state_id": src.state_id()}
        if kind == "alloc-fail":
            try:
                status_ctor(CODE["kIOError"], "copy failed",
                            alloc_ok=False, site=0x5E8B477,
                            pad=0x5E8C4B8,
                            cleanup=THROW_SITES[
                                "status-copy-ctor"][2])
            except BadAlloc as err:
                return {"error": "BadAlloc",
                        "site": None if err.site is None else
                        hex(err.site),
                        "pad": None if err.pad is None else
                        hex(err.pad),
                        "cleanup": err.cleanup,
                        "partial": None if err.partial is None else
                        _status_dict(err.partial),
                        "canary_checked": False}
            return {"error": None}
        raise ValueError("unknown status kind %r" % kind)
    if group == "throw":
        db = default_db_state()
        _apply_overrides(db, inputs.get("db_overrides"))
        if "cfs" in inputs:
            db["column_families"] = inputs["cfs"]
        if "cf_overrides" in inputs:
            _apply_overrides(db["column_families"][0],
                             inputs["cf_overrides"])
        cfd = db["column_families"][0]
        context = default_write_context()
        oracle = _oracle_from_json(inputs.get("oracle"))
        try:
            out = switch_memtable(
                db, cfd, context, oracle,
                fail_at=inputs.get("fail_at"),
                canary_ok=inputs.get("canary_ok", True),
                alloc_ok=inputs.get("alloc_ok", True))
        except BadAlloc as err:
            return {"error": "BadAlloc",
                    "site": None if err.site is None else
                    hex(err.site),
                    "pad": None if err.pad is None else hex(err.pad),
                    "cleanup": err.cleanup,
                    "partial": None if err.partial is None else
                    _status_dict(err.partial),
                    "canary_checked": err.pad is not None and
                    not inputs.get("canary_ok", True)}
        except StackCheckFailed as err:
            return {"error": "StackCheckFailed",
                    "message": str(err),
                    "site": None if err.site is None else
                    hex(err.site),
                    "pad": None if err.pad is None else hex(err.pad),
                    "cleanup": err.cleanup,
                    "canary_checked": True}
        except Throw as err:
            return {"error": err.kind,
                    "site": None if err.site is None else
                    hex(err.site),
                    "pad": None if err.pad is None else hex(err.pad),
                    "cleanup": err.cleanup,
                    "canary_checked": err.pad is not None and
                    not inputs.get("canary_ok", True)}
        return {"error": None,
                "result": _status_dict(out["result"]),
                "canary_checked": True}
    if group == "bindings":
        db = default_db_state()
        _apply_overrides(db, inputs.get("db_overrides"))
        if "cfs" in inputs:
            db["column_families"] = inputs["cfs"]
        cfd = db["column_families"][0]
        context = default_write_context()
        oracle = _oracle_from_json(inputs.get("oracle"))
        out = switch_memtable(
            db, cfd, context, oracle,
            fail_at=inputs.get("fail_at"),
            canary_ok=inputs.get("canary_ok", True),
            alloc_ok=inputs.get("alloc_ok", True))
        result = out["result"]
        return {
            "caller_site": inputs["caller_site"],
            "caller_function": CALLER_SITES[inputs["caller_site"]],
            "result": _status_dict(result),
            "result_sha256": hashlib.sha256(
                result.image()).hexdigest(),
            "result_independent_of_caller": True,
            "body_sha256": BODY_SHA256,
            "source_sha256": SOURCE_SHA256,
            "cold_body_sha256": COLD_BODY_SHA256,
            "cold_source_sha256": COLD_SOURCE_SHA256,
            "relocations": RELOCATIONS,
            "cold_relocations": COLD_RELOCATIONS,
            "engine_calls": ENGINE_CALLS,
            "pad_to_cold": {hex(k): hex(v) for k, v in
                            PAD_TO_COLD.items()},
            "caller_sites": sorted(CALLER_SITES),
        }
    raise ValueError("unknown group %r" % group)


def _inputs_to_reach(site):
    """The overrides that drive execution to throw site
    `site`. The default path (creating, logs_ non-empty,
    track_and_verify off) reaches the early and tail sites;
    the other sites need their branch armed."""
    db_overrides = {"log_empty": False,
                    "logs": [[3, _writer(3)]]}
    oracle = {}
    if site in ("write-buffer", "log-warn",
                "status-copy-assign-2"):
        # creating + a previous log + CreateWAL OK.
        if site == "log-warn":
            oracle["write_buffer"] = {"code": 5, "subcode": 0,
                                      "severity": 0,
                                      "state": "write failed"}
        return db_overrides, oracle
    if site in ("log-write-mutex-lock", "log-write-mutex-unlock"):
        db_overrides["two_write_queues"] = True
        return db_overrides, oracle
    if site in ("get-default-cf", "log-and-apply",
                "set-bg-error-manifest", "status-copy-assign-3"):
        db_overrides["immutable"] = {
            "track_and_verify_wals_in_manifest": True}
        db_overrides["column_families"] = [
            default_column_family(0, "default", seq=0),
            default_column_family(1, "cf1", seq=0)]
        db_overrides["column_families"][1]["log_number"] = 9
        oracle["min_wal_to_keep"] = 5
        if site in ("set-bg-error-manifest",
                    "status-copy-assign-3"):
            oracle["log_and_apply"] = {
                "code": 5, "subcode": 0, "severity": 0,
                "state": "manifest write failed"}
            oracle["versions_io_status"] = {
                "code": 5, "subcode": 0, "severity": 0,
                "state": "manifest write failed"}
        return db_overrides, oracle
    if site == "autovector-grow":
        db_overrides["immutable"] = {
            "track_and_verify_wals_in_manifest": True}
        cfs = [default_column_family(i, "cf%d" % i, seq=0)
               for i in range(10)]
        for i, cf in enumerate(cfs):
            cf["log_number"] = 9 + i
        db_overrides["column_families"] = cfs
        oracle["min_wal_to_keep"] = 5
        return db_overrides, oracle
    if site in ("set-bg-error", "set-bg-error-2",
                "status-copy-ctor"):
        oracle["create_wal"] = {
            "status": {"code": 5, "subcode": 0, "severity": 0,
                       "state": "create wal failed"},
            "writer": None}
        oracle["get_bg_error"] = {"code": 5, "subcode": 0,
                                  "severity": 0,
                                  "state": "background error"}
        return db_overrides, oracle
    return db_overrides, oracle


def _gen_group(rng, group, n):
    rows = []
    if group == "checks":
        modes = ["recoverable-fail", "no-create", "create-ok",
                 "create-fail", "two-write-queues",
                 "two-write-queues-no-create", "recycle-hit",
                 "recycle-empty", "recycle-num-zero",
                 "write-buffer-fail", "write-buffer-ok",
                 "logs-empty", "recovery-in-progress",
                 "track-min-apply", "track-min-no-apply",
                 "track-allow-2pc", "track-no-create",
                 "log-and-apply-fail-ioerror",
                 "log-and-apply-fail-other",
                 "dropped-cf-excluded", "plain-loop-multi",
                 "preallocate-max-total", "preallocate-db-wbs",
                 "preallocate-wbm", "mixed"]
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = modes[i % len(modes)]
            inputs = {"group": group, "case_id": case_id}
            db_overrides = {"log_empty": False,
                            "logs": [[3, _writer(3)]]}
            oracle = {"new_file_number": 7 + (i % 5),
                      "last_sequence": 100 + (i % 7)}
            if mode == "recoverable-fail":
                oracle["recoverable_state"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "recoverable state write failed"}
                inputs["oracle"] = oracle
            elif mode == "no-create":
                db_overrides = {"log_empty": True,
                                "logfile_number": 3}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "create-ok":
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "create-fail":
                oracle["create_wal"] = {
                    "status": {"code": 5, "subcode": 0,
                               "severity": 0,
                               "state": "create wal failed"},
                    "writer": None}
                oracle["get_bg_error"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "background error"}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "two-write-queues":
                db_overrides["two_write_queues"] = True
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "two-write-queues-no-create":
                db_overrides["two_write_queues"] = True
                db_overrides["log_empty"] = True
                db_overrides["logfile_number"] = 3
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "recycle-hit":
                db_overrides["log_recycle_files"] = [5, 6]
                db_overrides["immutable"] = {
                    "recycle_log_file_num": 2}
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "recycle-empty":
                db_overrides["immutable"] = {
                    "recycle_log_file_num": 2}
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "recycle-num-zero":
                db_overrides["log_recycle_files"] = [5, 6]
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "write-buffer-fail":
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                oracle["write_buffer"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "write failed"}
                oracle["get_bg_error"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "background error"}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "write-buffer-ok":
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "logs-empty":
                db_overrides["logs"] = []
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "recovery-in-progress":
                db_overrides["error_handler"] = {
                    "recovery_in_progress": True}
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "track-min-apply":
                db_overrides["immutable"] = {
                    "track_and_verify_wals_in_manifest": True}
                cfs = [default_column_family(0, "default", seq=0),
                       default_column_family(1, "cf1", seq=0),
                       default_column_family(2, "cf2", seq=5)]
                cfs[1]["log_number"] = 9
                cfs[2]["mem"]["first_seqno"] = 5
                # cf2 is non-empty (first_seqno 5) with log 9, so
                # the min is 9 > 5 and LogAndApply runs. (Without
                # this log_number the default 0 dragged the min
                # to 0 and the mode never applied.)
                cfs[2]["log_number"] = 9
                inputs["cfs"] = cfs
                oracle["min_wal_to_keep"] = 5
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "track-min-no-apply":
                db_overrides["immutable"] = {
                    "track_and_verify_wals_in_manifest": True}
                cfs = [default_column_family(0, "default", seq=0),
                       default_column_family(1, "cf1", seq=0)]
                # cf1 is non-empty (first_seqno 5) with log 3, so
                # the min is 3 <= 5 and the plain loop runs.
                # (Without first_seqno set cf1 counted as empty
                # and contributed the new log number, so the mode
                # always applied.)
                cfs[1]["mem"]["first_seqno"] = 5
                cfs[1]["mem"]["earliest_seqno"] = 5
                cfs[1]["log_number"] = 3
                inputs["cfs"] = cfs
                oracle["min_wal_to_keep"] = 5
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "track-allow-2pc":
                db_overrides["immutable"] = {
                    "track_and_verify_wals_in_manifest": True,
                    "allow_2pc": True}
                cfs = [default_column_family(0, "default", seq=0),
                       default_column_family(1, "cf1", seq=0)]
                cfs[1]["log_number"] = 9
                inputs["cfs"] = cfs
                oracle["min_wal_to_keep"] = 5
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "track-no-create":
                db_overrides["immutable"] = {
                    "track_and_verify_wals_in_manifest": True}
                db_overrides["log_empty"] = True
                db_overrides["logfile_number"] = 3
                cfs = [default_column_family(0, "default", seq=0),
                       default_column_family(1, "cf1", seq=0)]
                cfs[1]["log_number"] = 9
                inputs["cfs"] = cfs
                oracle["min_wal_to_keep"] = 5
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "log-and-apply-fail-ioerror":
                db_overrides["immutable"] = {
                    "track_and_verify_wals_in_manifest": True}
                cfs = [default_column_family(0, "default", seq=0),
                       default_column_family(1, "cf1", seq=0)]
                cfs[1]["log_number"] = 9
                inputs["cfs"] = cfs
                oracle["min_wal_to_keep"] = 5
                oracle["log_and_apply"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "manifest write failed"}
                oracle["versions_io_status"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "manifest write failed"}
                oracle["set_bg_error"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "manifest write failed"}
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "log-and-apply-fail-other":
                db_overrides["immutable"] = {
                    "track_and_verify_wals_in_manifest": True}
                cfs = [default_column_family(0, "default", seq=0),
                       default_column_family(1, "cf1", seq=0)]
                cfs[1]["log_number"] = 9
                inputs["cfs"] = cfs
                oracle["min_wal_to_keep"] = 5
                oracle["log_and_apply"] = {
                    "code": 2, "subcode": 0, "severity": 0,
                    "state": "corruption in manifest"}
                oracle["versions_io_status"] = {
                    "code": 0, "subcode": 0, "severity": 0,
                    "state": None}
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "dropped-cf-excluded":
                db_overrides["immutable"] = {
                    "track_and_verify_wals_in_manifest": True}
                cfs = [default_column_family(0, "default", seq=0),
                       default_column_family(1, "cf1", seq=0),
                       default_column_family(2, "cf2", seq=0)]
                cfs[1]["log_number"] = 2
                cfs[1]["dropped"] = True
                cfs[2]["log_number"] = 9
                inputs["cfs"] = cfs
                oracle["min_wal_to_keep"] = 5
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "plain-loop-multi":
                cfs = [default_column_family(0, "default", seq=0),
                       default_column_family(1, "cf1", seq=0),
                       default_column_family(2, "cf2", seq=5)]
                cfs[2]["mem"]["first_seqno"] = 5
                inputs["cfs"] = cfs
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "preallocate-max-total":
                db_overrides["mutable"] = {"max_total_wal_size": 1000}
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "preallocate-db-wbs":
                db_overrides["immutable"] = {
                    "db_write_buffer_size": 2000}
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            elif mode == "preallocate-wbm":
                db_overrides["immutable"] = {
                    "write_buffer_manager": {"buffer_size": 200000000}}
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            else:  # mixed
                db_overrides["mutable"] = {
                    "max_total_wal_size": rng.choice([0, 1000, 10 ** 9])}
                db_overrides["immutable"] = {
                    "db_write_buffer_size": rng.choice([0, 2000]),
                    "recycle_log_file_num": rng.choice([0, 2])}
                db_overrides["log_recycle_files"] = rng.choice(
                    [[], [5]])
                oracle["create_wal"] = {
                    "status": {"code": 0, "subcode": 0,
                               "severity": 0, "state": None},
                    "writer": _writer(7 + (i % 5))}
                inputs["db_overrides"] = db_overrides
                inputs["oracle"] = oracle
            rows.append((group, case_id, inputs, run_case(inputs)))
        return rows
    if group == "status":
        kinds = ["ok", "error", "image", "tostring",
                 "copy-assign", "alloc-fail"]
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            kind = kinds[i % len(kinds)]
            inputs = {"group": group, "case_id": case_id,
                      "kind": kind}
            if kind == "error":
                inputs["status"] = {
                    "code": [4, 5, 2, 11][i % 4],
                    "subcode": [0, 4, 9][i % 3],
                    "severity": 0,
                    "state": ["bad wal", "manifest write failed",
                              "no space"][i % 3]}
            elif kind == "image":
                inputs["code"] = [0, 4, 5, 15, 16][i % 5]
                inputs["subcode"] = [0, 1, 4][i % 3]
                inputs["severity"] = 0
                inputs["state"] = ["x", None, "msg"][i % 3] \
                    if inputs["code"] else None
            elif kind == "tostring":
                inputs["status"] = {
                    "code": [0, 4, 5, 13, 16][i % 5],
                    "subcode": [0, 1, 4, 9][i % 4],
                    "severity": 0,
                    "state": ["wal failed", None, "detail"][i % 3]}
            elif kind == "copy-assign":
                inputs["status"] = {
                    "code": [5, 4][i % 2], "subcode": 0,
                    "severity": 0,
                    "state": ["create wal failed",
                              "write failed"][i % 2]}
            rows.append((group, case_id, inputs, run_case(inputs)))
        return rows
    if group == "throw":
        sites = sorted(THROW_SITES)
        modes = ["throw", "throw-bad-canary",
                 "badalloc-bad-canary", "canary-return",
                 "alloc-false"]
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = modes[i % len(modes)]
            site = sites[(i // len(modes)) % len(sites)]
            db_overrides, oracle = _inputs_to_reach(site)
            inputs = {"group": group, "case_id": case_id,
                      "fail_at": site,
                      "db_overrides": db_overrides,
                      "oracle": oracle}
            if mode == "throw-bad-canary":
                inputs["canary_ok"] = False
            elif mode == "badalloc-bad-canary":
                if site not in ALLOC_SITES:
                    site = "copy-alloc-2"
                    db_overrides, oracle = _inputs_to_reach(site)
                    inputs["fail_at"] = site
                    inputs["db_overrides"] = db_overrides
                    inputs["oracle"] = oracle
                inputs["canary_ok"] = False
            elif mode == "canary-return":
                inputs["fail_at"] = None
                inputs["canary_ok"] = False
            elif mode == "alloc-false":
                inputs["fail_at"] = None
                inputs["alloc_ok"] = False
            rows.append((group, case_id, inputs, run_case(inputs)))
        return rows
    if group == "bindings":
        sites = sorted(CALLER_SITES)
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            site = sites[i % len(sites)]
            inputs = {"group": group, "case_id": case_id,
                      "caller_site": site,
                      "db_overrides": {"log_empty": False,
                                       "logs": [[3, _writer(3)]]},
                      "oracle": {
                          "new_file_number": 7,
                          "last_sequence": 100,
                          "create_wal": {
                              "status": {"code": 0, "subcode": 0,
                                         "severity": 0, "state": None},
                              "writer": _writer(7)}}}
            rows.append((group, case_id, inputs, run_case(inputs)))
        return rows
    raise ValueError("unknown group %r" % group)


def write_cases():
    all_rows = []
    for gi, group in enumerate(["checks", "status", "throw", "bindings"]):
        rng = random.Random(115200 + gi)
        all_rows.extend(_gen_group(rng, group, 600))
    PACKET.mkdir(parents=True, exist_ok=True)
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
    census = json.load(open(
        Path(__file__).resolve().parents[1] / "research" / "work-items" /
        "RE-002-node115-vendor-census" / "census.json"))["records"]
    rec = {r["start"]: r for r in census}
    for label, start, end, body_sha, source_sha, relocs, symbol in [
            ("main", START, END, BODY_SHA256, SOURCE_SHA256,
             RELOCATIONS, SYMBOL),
            ("cold", COLD_START, COLD_END, COLD_BODY_SHA256,
             COLD_SOURCE_SHA256, COLD_RELOCATIONS, COLD_SYMBOL)]:
        body = _read_va(data, secs, start, end - start)
        legs.append(("%s body hash" % label,
                     hashlib.sha256(body).hexdigest() == body_sha,
                     hashlib.sha256(body).hexdigest()[:16]))
        r = rec[start]
        zeroed = bytearray(body)
        for rel in r["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
        legs.append(("%s source hash (%d relocations zeroed)"
                     % (label, len(r["relocations"])),
                     hashlib.sha256(bytes(zeroed)).hexdigest()
                     == source_sha,
                     hashlib.sha256(bytes(zeroed)).hexdigest()[:16]))
        legs.append(("%s relocation list matches census" % label,
                     ";".join("%d:kind%d" % (x["offset"], x["kind"])
                              for x in r["relocations"]) == relocs,
                     "%d relocations" % len(r["relocations"])))
        legs.append(("%s census symbol" % label,
                     r["symbol"] == symbol, r["symbol"][-24:]))
        legs.append(("%s census member" % label,
                     r["member"] == MEMBER, r["member"]))
    return legs


def _disasm(data, secs, start, end):
    out = subprocess.check_output(
        ["objdump", "-d", "--start-address=0x%x" % start,
         "--stop-address=0x%x" % end, str(_bin_path())]).decode()
    return out


def _engine_calls(data, secs):
    legs = []
    for label, start, end in [("main", START, END),
                              ("cold", COLD_START, COLD_END)]:
        dis = _disasm(data, secs, start, end)
        total = sum(1 for l in dis.splitlines() if "\tcall" in l)
        expect_total = sum(ENGINE_CALLS[label].values())
        legs.append(("%s total call lines %d" % (label, expect_total),
                     total == expect_total, total))
        for key, count in sorted(ENGINE_CALLS[label].items()):
            got = dis.count(key)
            legs.append(("%s %s x%d" % (label, key, count),
                         got == count, got))
        legs.append(("%s endbr64 x%d"
                     % (label, 10 if label == "main" else 0),
                     dis.count("endbr64") ==
                     (10 if label == "main" else 0),
                     dis.count("endbr64")))
        # The canary is stored once (mov %fs:0x28,%rax) and
        # checked at ten return points (sub %fs:0x28,%rax).
        legs.append(("%s canary refs %%fs:0x28 x%d"
                     % (label, 11 if label == "main" else 1),
                     dis.count("%fs:0x28") ==
                     (11 if label == "main" else 1),
                     dis.count("%fs:0x28")))
    return legs


def _field_cmps(data, secs):
    legs = []
    dis = _disasm(data, secs, START, END)
    checks = [
        ("mutex_ AssertHeld at DBImpl+0x700",
         "lea    0x700(%rsi),%rax" in dis),
        ("canary stored at -0x38(%rbp)",
         "mov    %rax,-0x38(%rbp)" in dis),
        ("two_write_queues_ at DBImpl+0x17b0 checked twice",
         dis.count("cmpb   $0x0,0x17b0(%r14)") == 2,
         dis.count("cmpb   $0x0,0x17b0(%r14)")),
        ("log_empty_ at DBImpl+0xab9 read twice",
         "movzbl 0xab9(%rax),%eax" in dis
         and "movzbl 0xab9(%r14),%r13d" in dis),
        ("recycle_log_file_num at immutable+0x400",
         "mov    0x400(%rdx),%r14" in dis),
        ("log_recycle_files_ at DBImpl+0xa78",
         "mov    0xa78(%rdx),%rax" in dis
         and "mov    0xa78(%rcx),%rax" in dis),
        ("versions_ NewFileNumber atomic at +0xd8",
         "lock xadd %rdx,0xd8(%rax)" in dis),
        ("logfile_number_ at DBImpl+0xa60",
         "mov    0xa60(%r14),%rax" in dis),
        ("info_log at immutable+0x360",
         "lea    0x360(%rcx),%rsi" in dis),
        ("track_and_verify at immutable+0x335",
         "cmpb   $0x0,0x335(%rcx)" in dis),
        ("allow_2pc at immutable+0x4a3",
         "cmpb   $0x1,0x4a3(%rcx)" in dis),
        ("error_handler_ at DBImpl+0x760 (3 SetBGError sites)",
         dis.count("lea    0x760(%rax),%rdi") == 3,
         dis.count("lea    0x760(%rax),%rdi")),
        ("log_write_mutex_ at DBImpl+0x9c8",
         "lea    0x9c8(%r14),%r12" in dis
         and "lea    0x9c8(%rcx),%r14" in dis),
        ("alive_log_files_ at DBImpl+0xb00",
         "mov    0xb00(%rsi),%rax" in dis
         and "mov    %rax,0xb00(%rsi)" in dis),
        ("directories_ at DBImpl+0xd08",
         "mov    0xd08(%rax),%r14" in dis),
        ("logs_ deque at DBImpl+0xb20",
         "mov    0xb20(%rdi),%rdi" in dis
         and "mov    %rdx,0xb20(%rax)" in dis),
        ("CF next chain at ColumnFamilyData+0x938",
         "mov    0x938(%r12),%r12" in dis
         and "mov    0x938(%r14),%r12" in dis),
        ("dropped CF byte at +0x3d",
         "movzbl 0x3d(%r12),%edx" in dis),
        ("CF log_number_ at +0x948",
         "mov    0x948(%r12),%rax" in dis),
        ("MemTable first_seqno at +0xc18",
         "mov    0xc18(%rax),%rax" in dis),
        ("MemTable creation_seq store at +0xc28",
         "mov    %rdx,0xc28(%rax)" in dis),
        ("MemTable next_log_number store at +0xc30",
         "mov    %rax,0xc30(%rsi)" in dis),
        ("last_memtable_id_ atomic at CF+0x980",
         "lock xadd %rax,0x980(%rbx)" in dis),
        ("GetWalPreallocateBlockSize call 0x5e87d60",
         "call   5e87d60" in dis),
        ("CreateWAL call 0x5e5c270",
         "call   5e5c270" in dis),
        ("ConstructNewMemtable call 0x5d8ca00",
         "call   5d8ca00" in dis),
        ("LogAndApply call 0x5d68760",
         "call   5d68760" in dis),
        ("InstallSuperVersionAndScheduleWork call 0x5de3060",
         "call   5de3060" in dis),
        ("NotifyOnMemTableSealed call 0x5e87e10",
         "call   5e87e10" in dis),
        ("SetBGError call 0x5ead310 x3",
         dis.count("call   5ead310") == 3,
         dis.count("call   5ead310")),
        ("log-info fmt lea 0x95b0b0",
         "# 95b0b0" in dis),
        ("log-warn fmt lea 0x962cf0",
         "# 962cf0" in dis),
        ("deque-length-error lea 0x961990 x2",
         dis.count("# 961990") == 2, dis.count("# 961990")),
        ("s.code checked at the epilogue (cmpb $0x0,(%r15))",
         dis.count("cmpb   $0x0,(%r15)") >= 2,
         dis.count("cmpb   $0x0,(%r15)")),
        ("SuperVersion size 0x290 new",
         "mov    $0x290,%edi" in dis),
        ("MemTable size 0xd20 delete",
         "mov    $0xd20,%esi" in dis),
        ("log::Writer size 0x58 delete",
         "mov    $0x58,%esi" in dis),
    ]
    for name, ok, *rest in checks:
        legs.append((name, ok, rest[0] if rest else None))
    return legs


def _messages(data, secs):
    legs = []
    for key, (msg, addr, ln) in MESSAGES.items():
        raw = _read_va(data, secs, addr, ln)
        legs.append(("message %s byte-exact (%d B)" % (key, ln),
                     raw == msg.encode(),
                     raw[:24].decode(errors="replace")))
    empty = _read_va(data, secs, EMPTY_MSG2_ADDR, 1)
    legs.append(("msg2 at 0x4376fd is the empty string",
                 empty == b"\x00", empty.hex()))
    raw = _read_va(data, secs, LOG_FILE_ADDR, len(LOG_FILE))
    legs.append(("log file string byte-exact",
                 raw == LOG_FILE.encode(), raw.decode()))
    return legs


def _eh_frame_record(data, target):
    """Walk .eh_frame records; return the FDE record for the
    function starting at `target`: (section offset, length,
    range, aug_len, lsda target)."""
    out = subprocess.check_output(
        ["readelf", "-SW", str(_bin_path())]).decode()
    off = None
    size = None
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 6 and p[1] == ".eh_frame":
            off = int(p[4], 16)
            size = int(p[5], 16)
    assert off is not None
    i = 0
    while i < size:
        length, cie = struct.unpack_from("<II", data, off + i)
        if length == 0:
            break
        if cie != 0:
            field = off + i + 8
            disp, = struct.unpack_from("<i", data, field)
            rng, = struct.unpack_from("<I", data, field + 4)
            if field + disp == target:
                aug_len = data[field + 8]
                lsda = None
                if aug_len == 4:
                    d, = struct.unpack_from("<i", data, field + 9)
                    lsda = field + 9 + d
                return (i, length, rng, aug_len, lsda)
        i += 4 + length
    raise ValueError("FDE not found for 0x%x" % target)


def _read_uleb(data, off):
    result = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return result, off


def _parse_lsda(data, secs, lsda_va):
    """Decode an LSDA call-site table: returns a list of
    (start_off, length, lpad_off, action) with offsets relative
    to the FDE start."""
    off = _va2off(secs, lsda_va)
    lpstart_enc = data[off]
    off += 1
    if lpstart_enc != 0xFF:
        raise ValueError("unexpected lpstart encoding 0x%x"
                         % lpstart_enc)
    ttype_enc = data[off]
    off += 1
    if ttype_enc != 0xFF:
        raise ValueError("unexpected ttype encoding 0x%x" % ttype_enc)
    callsite_enc = data[off]
    off += 1
    if callsite_enc != 0x01:  # DW_EH_PE_uleb128
        raise ValueError("unexpected call-site encoding 0x%x"
                         % callsite_enc)
    table_len, off = _read_uleb(data, off)
    end = off + table_len
    entries = []
    while off < end:
        start, off = _read_uleb(data, off)
        length, off = _read_uleb(data, off)
        lpad, off = _read_uleb(data, off)
        action, off = _read_uleb(data, off)
        entries.append((start, length, lpad, action))
    return entries


def _lsda_legs(data, secs):
    legs = []
    for label, target, sec_off, rec_len, rec_rng, lsda_va, \
            expect_entries in [
                ("main", START, FDE_SECTION_OFFSET, FDE_LENGTH,
                 FDE_RANGE, FDE_LSDA, 21),
                ("cold", COLD_START, COLD_FDE_SECTION_OFFSET,
                 COLD_FDE_LENGTH, COLD_FDE_RANGE, COLD_FDE_LSDA, 1)]:
        off, length, rng, aug_len, lsda = _eh_frame_record(data, target)
        legs.append(("%s FDE record section offset 0x%x"
                     % (label, sec_off),
                     off == sec_off, hex(off)))
        legs.append(("%s FDE record length 0x%x" % (label, rec_len),
                     length == rec_len, hex(length)))
        legs.append(("%s FDE range 0x%x" % (label, rec_rng),
                     rng == rec_rng, hex(rng)))
        legs.append(("%s FDE aug_len 4 (LSDA pointer)"
                     % label, aug_len == 4, aug_len))
        legs.append(("%s LSDA at 0x%x" % (label, lsda_va),
                     lsda == lsda_va,
                     None if lsda is None else hex(lsda)))
        entries = _parse_lsda(data, secs, lsda_va)
        legs.append(("%s LSDA has %d call-site entries"
                     % (label, expect_entries),
                     len(entries) == expect_entries, len(entries)))
        legs.append(("%s LSDA all entries cleanup (action 0)"
                     % label,
                     all(a == 0 for _s, _l, _p, a in entries), None))
        legs.append(("%s LSDA entry [0] has no landing pad" % label,
                     entries[0][2] == 0, hex(entries[0][2])))
        if label == "main":
            pads = sorted({START + p for _s, _l, p, _a in entries
                           if p})
            legs.append(("main LSDA has 9 distinct landing pads",
                         len(pads) == 9, len(pads)))
            legs.append(("main LSDA pads are exactly the 9 stubs",
                         pads == sorted(PAD_TO_COLD), None))
    return legs


def _pad_mapping(data, secs):
    """Each landing-pad stub is endbr64 + mov %rax,%rbx + jmp
    rel32 at stub+7; verify the jmp target is the .cold address
    recorded in PAD_TO_COLD."""
    legs = []
    for stub, cold in sorted(PAD_TO_COLD.items()):
        off = _va2off(secs, stub)
        ok = data[off:off + 4] == b"\xf3\x0f\x1e\xfa" and \
            data[off + 4:off + 7] == b"\x48\x89\xc3" and \
            data[off + 7] == 0xE9
        rel, = struct.unpack_from("<i", data, off + 8)
        target = stub + 7 + 5 + rel
        legs.append(("pad stub 0x%x -> cold 0x%x" % (stub, cold),
                     ok and target == cold and
                     COLD_START <= cold < COLD_END,
                     hex(target)))
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
    legs += _lsda_legs(data, secs)
    legs += _pad_mapping(data, secs)
    sites = _caller_scan()
    expect_sites = sorted((int(a, 16), "call")
                          for a in CALLER_SITES)
    legs.append(("caller census: 6 direct calls, 0 jumps, 0 lea refs",
                 sites == expect_sites, len(sites)))
    legs.append(("caller sites are the 6 CALLER_SITES",
                 sorted(a for a, _k in sites)
                 == sorted(int(a, 16) for a in CALLER_SITES), None))
    legs.append(("SwitchWAL calls SwitchMemtable (0x5e8c901)",
                 (0x5E8C901, "call") in sites, None))
    # The raw whole-.text scan finds exactly these six E8
    # candidates targeting SwitchMemtable, and Capstone
    # validation from the enclosing FDE start accepts all six.
    sys.path.insert(0, str(PACKET))
    import census as census_mod
    text_va, _off, text = census_mod.load_text()
    fdes = census_mod.load_fdes()
    starts = sorted(fdes)
    raw = sorted((site, kind)
                 for site, kind, target in
                 census_mod.raw_scan(text_va, text)
                 if target == START)
    legs.append(("raw scan yields exactly the 6 validated sites",
                 raw == expect_sites, len(raw)))
    # Model legs.
    db = default_db_state()
    cfd = db["column_families"][0]
    out = switch_memtable(db, cfd, default_write_context(),
                          default_oracle())
    legs.append(("defaults switch OK, no new log (log_empty)",
                 out["result"].is_ok()
                 and not out["creating_new_log"]
                 and out["new_log_number"] == 0, None))
    legs.append(("defaults log-info line",
                 len(out["log"]) == 1
                 and out["log"][0]["message"]
                 == "[db/db_impl/db_impl_write.cc:2146] [default] "
                 "New memtable created with log file: #0. "
                 "Immutable memtables: 0.\n", None))
    legs.append(("defaults tail installs the new memtable",
                 cfd["mem"] is not None
                 and cfd["mem"]["id"] == 1
                 and cfd["mem"]["refs"] == 1
                 and cfd["mem"]["next_log_number"] == 0, None))
    legs.append(("plain loop sets creation seq even without a new log",
                 any("SetCreationSeq 100" in e for e in out["effects"])
                 and cfd["mem"]["creation_seq"] == 100, None))
    legs.append(("defaults preallocate 67108864/10 + 67108864",
                 out["preallocate_block_size"] == 73819750,
                 out["preallocate_block_size"]))
    # Creating a new log: new file number, WriteBuffer, log
    # recorded, alive_log_files_ updated.
    db = default_db_state()
    db["log_empty"] = False
    db["logs"] = [(3, {"file": {"seen_error": False}})]
    cfd = db["column_families"][0]
    out = switch_memtable(db, cfd, default_write_context(),
                          default_oracle())
    legs.append(("creating_new_log takes oracle file number 7",
                 out["result"].is_ok()
                 and out["creating_new_log"]
                 and out["new_log_number"] == 7, None))
    legs.append(("new log recorded in logs_ and alive_log_files_",
                 db["logfile_number"] == 7
                 and db["log_empty"]
                 and (7, out["db"]["logs"][-1][1]) in db["logs"]
                 and db["alive_log_files"] == [7], None))
    # Recoverable-state failure returns that status directly
    # (plain return at 0x5e8a914 -> epilogue, no SetBGError).
    oracle = default_oracle()
    oracle["recoverable_state"] = Status.error(
        "kIOError", "recover failed")
    out = switch_memtable(default_db_state(),
                          default_column_family(),
                          default_write_context(), oracle)
    legs.append(("recoverable-state failure returns its status",
                 out["result"].code == CODE["kIOError"]
                 and out["result"].state == "recover failed"
                 and "return WriteRecoverableState status"
                 in out["effects"], None))
    # CreateWAL failure -> error path -> GetBGError oracle.
    oracle = default_oracle()
    oracle["create_wal"] = (Status.error("kIOError", "wal failed"),
                            None)
    oracle["get_bg_error"] = Status.error("kIOError", "bg: wal failed")
    db = default_db_state()
    db["log_empty"] = False
    out = switch_memtable(db, default_column_family(),
                          default_write_context(), oracle)
    legs.append(("CreateWAL failure -> SetBGError(io_s), GetBGError",
                 out["result"].code == CODE["kIOError"]
                 and out["result"].state == "bg: wal failed"
                 and any("SetBGError(io_s, kMemTable)"
                         in e for e in out["effects"]), None))
    # WriteBuffer failure -> warn line, error path.
    oracle = default_oracle()
    oracle["write_buffer"] = Status.error("kIOError", "write failed")
    oracle["get_bg_error"] = Status.error("kIOError", "bg: write")
    db = default_db_state()
    db["log_empty"] = False
    db["logs"] = [(3, {"file": {"seen_error": False}})]
    out = switch_memtable(db, default_column_family(),
                          default_write_context(), oracle)
    legs.append(("WriteBuffer failure warns and goes to error path",
                 out["result"].code == CODE["kIOError"]
                 and out["result"].state == "bg: write"
                 and len(out["log"]) == 2
                 and "Failed to switch from #3 to #7  WAL file"
                 in out["log"][1]["message"], None))
    # Recycle: the front of log_recycle_files_ is reused and
    # popped after the relock.
    db = default_db_state()
    db["log_empty"] = False
    db["immutable"]["recycle_log_file_num"] = 1
    db["log_recycle_files"] = [5, 6]
    out = switch_memtable(db, default_column_family(),
                          default_write_context(), default_oracle())
    legs.append(("recycle reuses #5 and pops it",
                 out["result"].is_ok()
                 and out["recycle_log_number"] == 5
                 and out["new_log_number"] == 7
                 and db["log_recycle_files"] == [6], None))
    # Track-and-verify branch: the empty default CF contributes
    # the NEW log number (7) to the minimum, so min_wal 7 > 0
    # and LogAndApply runs; the CF is then updated.
    db = default_db_state()
    db["log_empty"] = False
    db["immutable"]["track_and_verify_wals_in_manifest"] = True
    out = switch_memtable(db, db["column_families"][0],
                          default_write_context(), default_oracle())
    legs.append(("empty CF contributes the new log number to min_wal",
                 out["result"].is_ok()
                 and any("min WAL with unflushed data: 7" in e
                         for e in out["effects"])
                 and any("LogAndApply(DeleteWalsBefore 7)" in e
                         for e in out["effects"])
                 and db["column_families"][0]["log_number"] == 7,
                 None))
    # A non-empty CF contributes its own log number instead.
    db = default_db_state()
    db["log_empty"] = False
    db["immutable"]["track_and_verify_wals_in_manifest"] = True
    busy = default_column_family(1, "busy", seq=5)
    busy["log_number"] = 3
    db["column_families"] = [busy, default_column_family()]
    out = switch_memtable(db, db["column_families"][0],
                          default_write_context(), default_oracle())
    legs.append(("non-empty CF contributes its log number (3)",
                 out["result"].is_ok()
                 and any("min WAL with unflushed data: 3" in e
                         for e in out["effects"]), None))
    # min_wal <= WalSet minimum -> plain loop, no LogAndApply.
    oracle = default_oracle()
    oracle["min_wal_to_keep"] = 7
    db = default_db_state()
    db["log_empty"] = False
    db["immutable"]["track_and_verify_wals_in_manifest"] = True
    out = switch_memtable(db, db["column_families"][0],
                          default_write_context(), oracle)
    legs.append(("min_wal <= WalSet min takes the plain loop",
                 out["result"].is_ok()
                 and not any("LogAndApply" in e
                             for e in out["effects"])
                 and db["column_families"][0]["log_number"] == 7,
                 None))
    # LogAndApply failure with an IOError versions status ->
    # SetBGError(manifest), result is the SetBGError oracle.
    oracle = default_oracle()
    oracle["log_and_apply"] = Status.error("kIOError", "manifest fail")
    oracle["versions_io_status"] = Status.error("kIOError", "io")
    oracle["set_bg_error"] = Status.error("kIOError", "bg: manifest")
    db = default_db_state()
    db["log_empty"] = False
    db["immutable"]["track_and_verify_wals_in_manifest"] = True
    out = switch_memtable(db, db["column_families"][0],
                          default_write_context(), oracle)
    legs.append(("LogAndApply IOError -> SetBGError(manifest)",
                 out["result"].code == CODE["kIOError"]
                 and out["result"].state == "bg: manifest"
                 and any("SetBGError(io_status, kManifestWrite)" in e
                         for e in out["effects"]), None))
    # Status ctor legs: state_ buffer is msg + NUL, alloc len+1.
    st = status_ctor(CODE["kInvalidArgument"], "bad input", "")
    legs.append(("ctor state_ buffer is msg + NUL",
                 st.state_buffer() == b"bad input\x00"
                 and st.state_alloc() == len("bad input") + 1, None))
    joined = status_ctor(CODE["kNotSupported"], "a", "b")
    legs.append(("ctor joins non-empty msg2 with ': '",
                 joined.state == "a: b", joined.state))
    # A throw through a landing pad with a bad canary becomes
    # StackCheckFailed after cleanup.
    try:
        switch_memtable(default_db_state(), default_column_family(),
                        default_write_context(), default_oracle(),
                        canary_ok=False, fail_at="create-wal")
        legs.append(("throw + bad canary -> StackCheckFailed",
                     False, "no exception"))
    except StackCheckFailed:
        legs.append(("throw + bad canary -> StackCheckFailed",
                     True, None))
    except Throw:
        legs.append(("throw + bad canary -> StackCheckFailed",
                     False, "CalleeThrew"))
    # A throw with no landing pad propagates with no canary
    # check, even with a bad canary (AssertHeld, pad None).
    try:
        switch_memtable(default_db_state(), default_column_family(),
                        default_write_context(), default_oracle(),
                        canary_ok=False, fail_at="assert-held")
        legs.append(("AssertHeld throw (no pad) -> CalleeThrew",
                     False, "no exception"))
    except Throw as err:
        legs.append(("AssertHeld throw (no pad) -> CalleeThrew",
                     err.kind == "CalleeThrew"
                     and err.pad is None, err.kind))
    except StackCheckFailed:
        legs.append(("AssertHeld throw (no pad) -> CalleeThrew",
                     False, "StackCheckFailed"))
    # A BadAlloc at an allocating site propagates as BadAlloc.
    try:
        switch_memtable(default_db_state(), default_column_family(),
                        default_write_context(), default_oracle(),
                        alloc_ok=False, fail_at="new-superversion")
        legs.append(("alloc failure at NewSuperVersion -> BadAlloc",
                     False, "no exception"))
    except BadAlloc:
        legs.append(("alloc failure at NewSuperVersion -> BadAlloc",
                     True, None))
    # A bad canary on a normal return raises StackCheckFailed.
    try:
        switch_memtable(default_db_state(), default_column_family(),
                        default_write_context(), default_oracle(),
                        canary_ok=False)
        legs.append(("normal return + bad canary -> StackCheckFailed",
                     False, "no exception"))
    except StackCheckFailed:
        legs.append(("normal return + bad canary -> StackCheckFailed",
                     True, None))
    failed = 0
    for name, ok, detail in legs:
        print("%s %s%s" % ("PASS" if ok else "FAIL", name,
                           (" (%s)" % detail) if detail is not None
                           else ""))
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
