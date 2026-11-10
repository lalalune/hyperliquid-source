#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::DBImpl::SetDBOptions.

Target: rocksdb::DBImpl::SetDBOptions(const unordered_map<string,
string>&) at 0x5d71fe0..0x5d72e50 (3696 B, main FDE) + its .cold
FDE 0x5d71eea..0x5d71fe0 (246 B) in node #115
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The DB options setter: it parses the options map into a new
MutableDBOptions (GetMutableDBOptionsFromStrings, oracle), defaults
bytes_per_sync to 1 MiB, short-circuits when nothing changed,
builds a new DBOptions (BuildDBOptions, oracle), validates it
(ValidateOptions 1-arg, oracle, open PR #6379) and every live
column family (ColumnFamilyData::ValidateOptions, oracle, open PR
#6449), grows the background thread pools when the new limits
increase, re-registers the periodic dump/persist-stats tasks,
stores the new max_total_wal_size, applies the new mutable
options, rebuilds the compaction FileOptions (with the base
FileSystem OptimizeForCompactionTableWrite/Read hooks),
switches the WAL when the log size or wal_bytes_per_sync changed,
and persists the options file. The returned Status is the parse /
validation / scheduler status, or IOError when the options file
could not be persisted and fail_if_options_file_error is set.
A SwitchWAL failure is only logged, never returned.

The caller census is empty on purpose: DB::SetDBOptions is a
virtual API reached through the DB vtable slot 0x248
(StackableDB::SetDBOptions 0x5d30750, census-bound, c.o, calls
the slot at 0x5d3081b after a devirtualization chain); there are
no direct E8 calls, E9 jumps or LEA refs in the whole .text.

Whole-FDE facts (verified live, see --live):
- Signature: Status by value (hidden sret out in rdi = r12),
  this in rsi = rbx, options_map in rdx. Stack canary used
  (stored 0xa48(%rsp), checked at the epilogue 0x5d720a1 and in
  the .cold chain at 0x5d71f1c before _Unwind_Resume).
- The FDE has a .cold FDE with a 22-entry LSDA (main LSDA at
  0x4092b8, 134 bytes; cold LSDA at 0x409343, 1 entry). All
  entries are cleanup-only (action 0); entry [0] (the
  empty-input Log + Status ctor) has NO landing pad. The 15
  landing-pad stubs at 0x5d72d9c..0x5d72e44 jump into the .cold
  FDE, which runs the destructor chain in order (string
  _M_dispose, WriteContext dtor, ColumnFamilyOptions /
  DBOptions dtors, FileOptions property_bag clear/dispose,
  FileSystemPtr release, Writer dtor, Mutex::Unlock) and then
  checks the canary before resuming -- so a throw with a bad
  canary becomes StackCheckFailed after cleanup, unlike the
  no-LSDA packets.
- 0x60d52f0 is port::Mutex::Unlock, not Lock: the census lists
  9 identical candidate symbols for that 149-byte body
  (Lock/Unlock/CondVar::Signal/...); the disassembly calls
  pthread_mutex_unlock (PLT 0x63f0b70). The Lock copy is
  0x60d5230, reached through the InstrumentedMutexLock wrapper
  0x606ca40.
- DBImpl/DBOptions layout: the vendored build's layout differs
  from a stock v8.1.1 compile after mutable_db_options_
  (mutex_ +0x700 vs +0x740, table_cache_ +0x750 vs +0x7d0,
  file_options_for_compaction_ +0x8d0 vs +0x950,
  write_controller_ +0x1120 vs +0x11b0, total_log_size_ +0xc28
  vs +0xcb8, max_total_wal_size_ +0x1860 vs +0x1978,
  periodic_task_scheduler_ +0x1748 vs +0x1858) and inside
  DBOptions (fail_if_options_file_error at +0x190 vs +0x210).
  The model follows the binary offsets; the stock-header
  offsets are recorded as the observation, not the ground
  truth. Early members match exactly (immutable_db_options_
  +0x330, mutable_db_options_ +0x5a0, versions_ +0x68,
  env_ +0x318), as do MutableDBOptions (0x70 B),
  ColumnFamilyOptions (+0xe8/+0x160/+0x2b8), ColumnFamilyData
  (dropped_ +0x3d, next_ +0x938), ColumnFamilySet
  (dummy_cfd_ +0x110) and VersionSet (column_family_set_
  +0x40), all verified by compiling offsetof() against the
  real v8.1.1 headers (g++).
- The FileOptions temp is built by EnvOptions::EnvOptions(const
  DBOptions&) (AssignEnvOptions + the base no-op
  SanitizeEnvOptions) with IOOptions defaults, temperature
  kUnknown and handoff checksum kCRC32c; the base FileSystem
  OptimizeForCompactionTableWrite sets use_direct_writes from
  use_direct_io_for_flush_and_compaction and
  OptimizeForCompactionTableRead sets use_direct_reads from
  use_direct_reads (PosixFileSystem does not override either).
- GetBGJobLimits is the static formula (flushes==-1 and
  compactions==-1: quarter of max_background_jobs to flushes;
  else max(1, flushes/compactions); parallelize=true here so
  the throttle arm never fires).
- GetMutableDBOptionsFromStrings restores the base options on
  a parse failure (its contract, options/db_options.cc:1049);
  the model takes the parse outcome as an oracle input.
- The per-CF loop walks the ColumnFamilySet circular list via
  dummy_cfd_->next_ (+0x938) and skips dropped CFs (byte
  +0x3d); a CF's options temp is destroyed after each
  iteration, and on the first failure the loop breaks through
  the 0x5d72d8d stub (ColumnFamilyOptions dtor, then the error
  tail).

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
START = 0x5D71FE0
END = 0x5D72E50
BODY_SHA256 = ("4e93a3e037558cb85400f83f221040af630bac0120a5f3ee7"
               "0a576a75c78e56b")
SOURCE_SHA256 = ("74c9d375bdd45799805a83045c527db5da3dd75711aa77"
                 "77586123b32c03d3aa")
RELOCATIONS = ("67:kind2;79:kind2;84:kind4;101:kind2;147:kind2;172:kind4;"
               "244:kind4;311:kind4;395:kind4;435:kind4;453:kind2;471:kind4;"
               "507:kind4;529:kind2;543:kind2;548:kind4;586:kind2;596:kind4;"
               "606:kind4;681:kind4;694:kind4;807:kind4;817:kind4;832:kind4;"
               "851:kind4;898:kind4;928:kind2;933:kind4;943:kind4;961:kind2;"
               "968:kind4;979:kind2;1017:kind4;1047:kind2;1062:kind4;"
               "1079:kind4;1121:kind4;1206:kind2;1219:kind4;1232:kind2;"
               "1250:kind4;1260:kind4;1276:kind4;1299:kind2;1309:kind4;"
               "1317:kind4;1334:kind2;1349:kind4;1357:kind4;1395:kind2;"
               "1422:kind4;1435:kind2;1453:kind4;1541:kind4;1559:kind4;"
               "1572:kind2;1590:kind4;1611:kind4;1659:kind4;1693:kind4;"
               "1789:kind4;1799:kind4;1839:kind4;1852:kind2;1870:kind4;"
               "1933:kind2;1960:kind4;1973:kind2;1991:kind4;2001:kind4;"
               "2238:kind4;2514:kind4;2559:kind4;2567:kind4;2591:kind4;"
               "2763:kind4;2801:kind4;2809:kind4;2827:kind4;2858:kind4;"
               "3020:kind4;3058:kind4;3066:kind4;3084:kind4;3121:kind4;"
               "3137:kind4;3152:kind4;3187:kind4;3219:kind4;3236:kind4;"
               "3254:kind2;3272:kind4;3283:kind4;3291:kind4;3314:kind2;"
               "3338:kind4;3364:kind4;3390:kind4;3414:kind2;3421:kind2;"
               "3431:kind4;3439:kind4;3482:kind2;3492:kind4;3502:kind4;"
               "3512:kind4;3524:kind2;3536:kind2;3548:kind2;3560:kind2;"
               "3572:kind2;3584:kind2;3596:kind2;3608:kind2;3620:kind2;"
               "3632:kind2;3644:kind2;3656:kind2;3668:kind2;3680:kind2;"
               "3692:kind2")
MEMBER = "4d429ab1cb2d8f8b-db_impl.o"
SYMBOL = ("_ZN7rocksdb6DBImpl12SetDBOptionsERKSt13unordered_mapINSt7__cxx"
          "1112basic_stringIcSt11char_traitsIcESaIcEEES7_St4hashIS7_ESt8"
          "equal_toIS7_ESaISt4pairIKS7_S7_EEE")
COLD_START = 0x5D71EEA
COLD_END = 0x5D71FE0
COLD_BODY_SHA256 = ("1e1c1fff1ddf5c8c7e159c22bd68242787554bc4f23c9898"
                    "b5ab60a8b3a2ea5e")
COLD_SOURCE_SHA256 = ("94db39e5dd3ba3f53236d5b0fb852b51b74e36eafbb47"
                      "c71f97dc1a9ff982cad")
COLD_RELOCATIONS = ("6:kind4;16:kind4;31:kind4;46:kind4;73:kind4;83:kind4;"
                    "93:kind4;103:kind4;110:kind4;118:kind4;136:kind4;"
                    "144:kind4;154:kind4;162:kind4;180:kind4;190:kind4;"
                    "198:kind4;216:kind4;229:kind4;237:kind4")
COLD_SYMBOL = SYMBOL + ".cold"
# FDE record in .eh_frame (section offset 0x7346d0): length 0x4c,
# range 0xe70, aug_len 4, LSDA at 0x4092b8 (22 entries, all
# cleanup, entry [0] has no landing pad).
FDE_SECTION_OFFSET = 0x7346D0
FDE_LENGTH = 0x4C
FDE_RANGE = 0xE70
FDE_LSDA = 0x4092B8
# .cold FDE record (section offset 0x734720): length 0x20, range
# 0xf6, aug_len 4, LSDA at 0x409343 (1 entry, no landing pad).
COLD_FDE_SECTION_OFFSET = 0x734720
COLD_FDE_LENGTH = 0x20
COLD_FDE_RANGE = 0xF6
COLD_FDE_LSDA = 0x409343
# Engine callees (census-bound unless noted).
STATUS_CTOR = 0x61CF670
STATUS_TOSTRING = 0x61CFED0
STACK_CHK_FAIL = 0x63F0D70
UNWIND_RESUME = 0x63F0A50
EMPTY_MSG2_ADDR = 0x4376FD
LOG_FILE_ADDR = 0x4451B9
LOG_FILE = "db/db_impl/db_impl.cc"
# DBImpl field offsets in the binary (see header note).
OFF_IMMUTABLE = 0x330
OFF_MUTABLE = 0x5A0
OFF_MUTEX = 0x700
OFF_VERSIONS = 0x68
OFF_ENV = 0x318
OFF_TABLE_CACHE = 0x750
OFF_WRITE_CONTROLLER = 0x1120
OFF_TOTAL_LOG_SIZE = 0xC28
OFF_MAX_TOTAL_WAL_SIZE = 0x1860
OFF_FILE_OPTIONS = 0x8D0
OFF_WRITE_THREAD = 0xD40
OFF_SCHEDULER = 0x1748
OFF_TASK_FUNCTIONS = 0x1780
# MutableDBOptions field offsets (verified against v8.1.1).
MUTABLE_FIELDS = ("max_background_jobs", "max_background_compactions",
                  "max_subcompactions", "avoid_flush_during_shutdown",
                  "writable_file_max_buffer_size", "delayed_write_rate",
                  "max_total_wal_size",
                  "delete_obsolete_files_period_micros",
                  "stats_dump_period_sec", "stats_persist_period_sec",
                  "stats_history_buffer_size", "max_open_files",
                  "bytes_per_sync", "wal_bytes_per_sync",
                  "strict_bytes_per_sync", "compaction_readahead_size",
                  "max_background_flushes")
K_INFINITE_CAPACITY = 0x400000

CODE = {"kOk": 0, "kNotFound": 1, "kCorruption": 2, "kNotSupported": 3,
        "kInvalidArgument": 4, "kIOError": 5, "kMergeInProgress": 6,
        "kIncomplete": 7, "kShutdownInProgress": 8, "kTimedOut": 9,
        "kAborted": 10, "kBusy": 11, "kExpired": 12, "kTryAgain": 13,
        "kCompactionTooLarge": 14, "kColumnFamilyDropped": 15}
CODE_NAME = {v: k for k, v in CODE.items()}

# (message, address, length) -- byte-verified against .rodata.
MESSAGES = {
    "empty-input": ("empty input", 0x43B417, 11),
    "log-empty-input": ("[%s:1212] SetDBOptions(), empty input.",
                        0x95EC48, 38),
    "log-not-changed": ("[%s:1232] SetDBOptions(), input option value "
                        "is not changed, skipping updating.",
                        0x95F650, 79),
    "log-purge-wal": ("[%s:1338] Unable to purge WAL files in "
                      "SetDBOptions() -- %s", 0x960198, 59),
    "log-inputs": ("[%s:1352] SetDBOptions(), inputs:", 0x964798, 33),
    "log-input-entry": ("[%s:1354] %s: %s\n", 0x43F81D, 17),
    "log-succeeded": ("[%s:1358] SetDBOptions() succeeded", 0x9669A8, 34),
    "log-persist": ("[%s:1366] Unable to persist options in "
                    "SetDBOptions() -- %s", 0x957910, 59),
    "log-failed": ("[%s:1371] SetDBOptions failed", 0x431FF4, 29),
    "ioerror-persist": ("SetDBOptions() succeeded, but unable to "
                        "persist options", 0x967DE8, 55),
}
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / "re-002-node115-rocksdb-dbimpl-set-db-options-115"
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
    normal return at the epilogue (0x5d720a1), or in the .cold
    chain (0x5d71f1c) after cleanup on a throw path."""

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


# ---------------------------------------------------------------- defaults

def default_mutable_db_options():
    """MutableDBOptions fields (upstream v8.1.1 defaults from
    options/db_options.h + include/rocksdb/options.h). They are
    model inputs, not binary claims; the binary reads them at the
    DBImpl+0x5a0 offsets verified by offsetof()."""
    return {
        # +0x00 max_background_jobs
        "max_background_jobs": 2,
        # +0x04 max_background_compactions
        "max_background_compactions": -1,
        # +0x08 max_subcompactions
        "max_subcompactions": 1,
        # +0x0c avoid_flush_during_shutdown
        "avoid_flush_during_shutdown": False,
        # +0x10 writable_file_max_buffer_size
        "writable_file_max_buffer_size": 1048576,
        # +0x18 delayed_write_rate
        "delayed_write_rate": 0,
        # +0x20 max_total_wal_size
        "max_total_wal_size": 0,
        # +0x28 delete_obsolete_files_period_micros (6h)
        "delete_obsolete_files_period_micros": 21600000000,
        # +0x30 stats_dump_period_sec
        "stats_dump_period_sec": 600,
        # +0x34 stats_persist_period_sec
        "stats_persist_period_sec": 600,
        # +0x38 stats_history_buffer_size
        "stats_history_buffer_size": 1048576,
        # +0x40 max_open_files
        "max_open_files": -1,
        # +0x48 bytes_per_sync
        "bytes_per_sync": 0,
        # +0x50 wal_bytes_per_sync
        "wal_bytes_per_sync": 0,
        # +0x58 strict_bytes_per_sync
        "strict_bytes_per_sync": False,
        # +0x60 compaction_readahead_size
        "compaction_readahead_size": 0,
        # +0x68 max_background_flushes
        "max_background_flushes": -1,
    }


def default_immutable_db_options():
    """DBOptions fields this FDE (and its FileOptions/Optimize
    callees) read. Defaults are the upstream v8.1.1 defaults;
    they are model inputs, not binary claims. `info_log_present`
    is the null check the Log calls perform (a null logger is
    skipped silently)."""
    return {
        # +0x30 info_log (shared_ptr<Logger>)
        "info_log_present": True,
        # +0x190 in the binary layout (stock v8.1.1: +0x210 --
        # see the header note): fail_if_options_file_error.
        "fail_if_options_file_error": False,
        # EnvOptions fields copied by FileOptions(new_db_options)
        # (AssignEnvOptions, env/env.cc:1067).
        "allow_mmap_reads": False,
        "allow_mmap_writes": False,
        "use_direct_reads": False,
        "is_fd_close_on_exec": True,
        "bytes_per_sync": 0,
        "compaction_readahead_size": 0,
        "random_access_max_buffer_size": 1048576,
        "writable_file_max_buffer_size": 1048576,
        "allow_fallocate": True,
        "strict_bytes_per_sync": False,
        # Read by the base FileSystem Optimize hooks.
        "use_direct_io_for_flush_and_compaction": False,
    }


def default_column_family(cf_id=0, name="default"):
    """One column family in versions_ iteration order. The
    per-CF ValidateOptions outcome is an oracle input (its
    status dict lives in `cf_statuses`); `cf_options` is the
    ColumnFamilyOptions temp GetLatestCFOptions builds, opaque
    here. `dropped` is the +0x3d byte the loop tests."""
    return {"id": cf_id, "name": name, "dropped": False,
            "cf_options": {}}


def default_db_state():
    """The DBImpl state this FDE reads or writes, keyed by the
    binary field offsets. `column_families` is the
    ColumnFamilySet list in iteration order (dummy_cfd_->next_
    chain). `periodic_tasks` maps kDumpStats (0) / kPersistStats
    (1) to the registered period in seconds, or None when
    unregistered."""
    return {
        "immutable": default_immutable_db_options(),
        "mutable": default_mutable_db_options(),
        # DBImpl+0x1860 max_total_wal_size_ (atomic<u64>)
        "max_total_wal_size": 0,
        # DBImpl+0xc28 total_log_size_
        "total_log_size": 0,
        # DBImpl+0x1120 WriteController: (max_delayed_write_rate_,
        # delayed_write_rate_) -- set_max_delayed_write_rate
        # writes both.
        "write_controller": {"max_delayed_write_rate": 0,
                             "delayed_write_rate": 0},
        # DBImpl+0x750 table_cache_ capacity (None = untouched).
        "table_cache_capacity": None,
        # DBImpl+0x8d0 file_options_for_compaction_ (None until
        # the FDE builds it).
        "file_options_for_compaction": None,
        # VersionSet file_options_.writable_file_max_buffer_size
        # (ChangeFileOptions, version_set.h:1458).
        "versions_file_options_writable_max_buffer_size": None,
        # DBImpl+0x1748 periodic_task_scheduler_ registrations.
        "periodic_tasks": {"dump": None, "persist": None},
        "column_families": [default_column_family()],
    }


def get_bg_job_limits(max_background_flushes,
                      max_background_compactions,
                      max_background_jobs,
                      parallelize_compactions=True):
    """DBImpl::GetBGJobLimits (static, db_impl_compaction_flush.cc:
    2649): flushes==-1 and compactions==-1 allocates a quarter
    of max_background_jobs to flushes; otherwise max(1, each);
    parallelize=false throttles compactions to 1. This FDE
    always passes parallelize=true (ecx=1), so the throttle arm
    never fires here."""
    if max_background_flushes == -1 and \
            max_background_compactions == -1:
        max_flushes = max(1, max_background_jobs // 4)
        max_compactions = max(1, max_background_jobs - max_flushes)
    else:
        max_flushes = max(1, max_background_flushes)
        max_compactions = max(1, max_background_compactions)
    if not parallelize_compactions:
        max_compactions = 1
    return {"max_flushes": max_flushes,
            "max_compactions": max_compactions}


def build_db_options(immutable, mutable):
    """BuildDBOptions (options/options_helper.cc:52) for the
    fields the FileOptions ctor reads: mutable fields override
    the immutable ones, the rest are copied from immutable."""
    out = dict(immutable)
    for field in ("max_open_files", "max_total_wal_size",
                  "delete_obsolete_files_period_micros",
                  "max_background_jobs", "max_background_compactions",
                  "bytes_per_sync", "wal_bytes_per_sync",
                  "strict_bytes_per_sync", "max_subcompactions",
                  "max_background_flushes"):
        out[field] = mutable[field]
    return out


def file_options_from_db_options(db_options):
    """FileOptions(new_db_options): EnvOptions ctor
    (AssignEnvOptions, env/env.cc:1067) + the base no-op
    SanitizeEnvOptions + IOOptions defaults + temperature
    kUnknown + handoff checksum kCRC32c. `property_bag` is the
    empty unordered_map (bucket_count 1, element_count 0)."""
    return {
        # EnvOptions (56 B)
        "use_mmap_reads": db_options["allow_mmap_reads"],
        "use_mmap_writes": db_options["allow_mmap_writes"],
        "use_direct_reads": db_options["use_direct_reads"],
        "set_fd_cloexec": db_options["is_fd_close_on_exec"],
        "bytes_per_sync": db_options["bytes_per_sync"],
        "compaction_readahead_size":
            db_options["compaction_readahead_size"],
        "random_access_max_buffer_size":
            db_options["random_access_max_buffer_size"],
        "rate_limiter": None,
        "writable_file_max_buffer_size":
            db_options["writable_file_max_buffer_size"],
        "allow_fallocate": db_options["allow_fallocate"],
        "strict_bytes_per_sync": db_options["strict_bytes_per_sync"],
        # IOOptions (88 B): timeout 0, prio kIOLow (0),
        # rate_limiter_priority IO_TOTAL (4), type kUnknown (7),
        # property_bag empty, force_dir_fsync false,
        # do_not_recurse false.
        "io_timeout_us": 0,
        "io_prio": 0,
        "io_rate_limiter_priority": 4,
        "io_type": 7,
        "property_bag": {},
        "force_dir_fsync": False,
        "do_not_recurse": False,
        # FileOptions tail
        "temperature": 0,  # kUnknown
        "handoff_checksum_type": 1,  # kCRC32c
    }


def optimize_for_compaction_table_write(file_options, db_options):
    """Base FileSystem::OptimizeForCompactionTableWrite
    (env/file_system.cc:157): a copy with use_direct_writes set
    from use_direct_io_for_flush_and_compaction. PosixFileSystem
    does not override it."""
    out = dict(file_options)
    out["use_direct_writes"] = \
        db_options["use_direct_io_for_flush_and_compaction"]
    return out


def optimize_for_compaction_table_read(file_options, db_options):
    """Base FileSystem::OptimizeForCompactionTableRead
    (env/file_system.cc:167): a copy with use_direct_reads set
    from use_direct_reads. PosixFileSystem does not override
    it."""
    out = dict(file_options)
    out["use_direct_reads"] = db_options["use_direct_reads"]
    return out


# ---------------------------------------------------------------- model

# .cold cleanup chains, in execution order. Each entry is a
# short label for one cleanup action the .cold FDE performs.
_CHAIN_EFE = ["delete[] persist_options_status.state_?",
              "delete[] s.state_?",
              "canary-check", "_Unwind_Resume"]
_CHAIN_EF4 = ["WriteContext dtor (Clean + delete memtables)"] + \
    _CHAIN_EFE
_CHAIN_F4B = ["Mutex::Unlock"] + _CHAIN_EF4
_CHAIN_F41 = ["DBOptions dtor (new_db_options)", "Mutex::Unlock"] + \
    _CHAIN_EF4
_CHAIN_F37 = ["ColumnFamilyOptions dtor (cf_options temp)"] + _CHAIN_F41
_CHAIN_EEA = ["string _M_dispose (ToString temp)"] + _CHAIN_EF4
_CHAIN_F5C = ["string _M_dispose (rbp temp)",
              "delete[] temp Status state_?",
              "WriteThread::Writer dtor"] + _CHAIN_F41
_CHAIN_F76 = ["WriteThread::Writer dtor"] + _CHAIN_F41
_CHAIN_F80 = ["hashtable clear (temp FileOptions property_bag)",
              "hashtable dispose",
              "FileSystemPtr _M_release?"] + _CHAIN_F41
_CHAIN_F90 = ["FileSystemPtr _M_release?"] + _CHAIN_F41
_CHAIN_FA4 = ["hashtable clear (temp FileOptions property_bag)",
              "hashtable dispose",
              "FileSystemPtr _M_release?"] + _CHAIN_F41
_CHAIN_FB4 = list(_CHAIN_FA4)
_CHAIN_FCB = ["hashtable clear (temp FileOptions property_bag)",
              "hashtable dispose"] + _CHAIN_F41
_CHAIN_F64 = ["delete[] temp Status state_?",
              "WriteThread::Writer dtor"] + _CHAIN_F41

# Throw sites: fail_at name -> (call address, LSDA pad or None,
# cleanup chain). The pad is the landing-pad stub address; the
# cleanup is the .cold chain that stub runs. pad None means the
# LSDA has no landing pad for that call (entry [0] and the
# LogFlush call): the exception propagates with no cleanup and
# no canary check.
THROW_SITES = {
    "status-ctor-empty-input": (0x5D7208B, None, []),
    "log-empty-input": (0x5D72033, None, []),
    "super-version-context-ctor": (0x5D72116, 0x5D72D9C, _CHAIN_EFE),
    "mutex-lock": (0x5D7216A, 0x5D72DA8, _CHAIN_EF4),
    "parse": (0x5D72192, 0x5D72DB4, _CHAIN_F4B),
    "log-not-changed": (0x5D721FC, 0x5D72DB4, _CHAIN_F4B),
    "build": (0x5D72361, 0x5D72DB4, _CHAIN_F4B),
    "log-inputs": (0x5D723A7, 0x5D72DA8, _CHAIN_EF4),
    "log-input-entry": (0x5D723D8, 0x5D72DA8, _CHAIN_EF4),
    "log-succeeded": (0x5D72405, 0x5D72DA8, _CHAIN_EF4),
    "dump": (0x5D72416, 0x5D72DA8, _CHAIN_EF4),
    "tostring-persist": (0x5D7243D, 0x5D72DA8, _CHAIN_EF4),
    "status-ctor-ioerror": (0x5D724A2, 0x5D72DD8, _CHAIN_EEA),
    "tostring-persist-2": (0x5D724DB, 0x5D72DA8, _CHAIN_EF4),
    "log-persist-warn": (0x5D724FC, 0x5D72DCC, _CHAIN_EEA),
    "log-failed": (0x5D72524, 0x5D72DA8, _CHAIN_EF4),
    "log-flush": (0x5D7252C, None, []),
    "validate1": (0x5D7256D, 0x5D72DE4, _CHAIN_F41),
    "get-latest-cf-options": (0x5D725DC, 0x5D72DE4, _CHAIN_F41),
    "validate-cf": (0x5D725F6, 0x5D72DC0, _CHAIN_F37),
    "bg-limits": (0x5D7265A, 0x5D72DE4, _CHAIN_F41),
    "inc-threads-flush": (0x5D726B9, 0x5D72DE4, _CHAIN_F41),
    "inc-threads-compactions": (0x5D726D3, 0x5D72DE4, _CHAIN_F41),
    "maybe-schedule": (0x5D726DC, 0x5D72DE4, _CHAIN_F41),
    "unregister-dump": (0x5D7270E, 0x5D72DE4, _CHAIN_F41),
    "register-dump": (0x5D72787, 0x5D72DE4, _CHAIN_F41),
    "mutex-relock": (0x5D727AB, 0x5D72DE4, _CHAIN_F41),
    "unregister-persist": (0x5D72D03, 0x5D72DE4, _CHAIN_F41),
    "register-persist": (0x5D72CE9, 0x5D72DE4, _CHAIN_F41),
    "file-options-ctor": (0x5D7289D, 0x5D72DE4, _CHAIN_F41),
    "hashtable-assign-write": (0x5D729B1, 0x5D72E44, _CHAIN_FCB),
    "optimize-write": (0x5D72A27, 0x5D72E20, _CHAIN_F90),
    "hashtable-assign-read": (0x5D72AAA, 0x5D72DFC, _CHAIN_F80),
    "optimize-read": (0x5D72B28, 0x5D72E14, _CHAIN_FB4),
    "hashtable-assign-read2": (0x5D72BAB, 0x5D72E08, _CHAIN_FA4),
    "enter-unbatched": (0x5D72C20, 0x5D72DF0, _CHAIN_F76),
    "switch-wal": (0x5D72C52, 0x5D72DF0, _CHAIN_F76),
    "write-options-file": (0x5D72C83, 0x5D72DF0, _CHAIN_F76),
    "exit-unbatched": (0x5D72CB2, 0x5D72DF0, _CHAIN_F76),
    "tostring-switchwal": (0x5D72D1D, 0x5D72E38, _CHAIN_F64),
    "log-switchwal-fail": (0x5D72D46, 0x5D72E2C, _CHAIN_F5C),
}


def _throw(name, fail_at, canary_ok, partial=None):
    """Raise the exception for throw site `name` when it is the
    armed fail_at. A throw with a landing pad runs the .cold
    cleanup chain and then the pad canary check, so a bad canary
    turns the throw into StackCheckFailed after cleanup. A
    throw with no pad propagates with no cleanup and no canary
    check."""
    if fail_at != name:
        return
    site, pad, cleanup = THROW_SITES[name]
    if pad is not None and not canary_ok:
        raise StackCheckFailed(site=site, pad=pad, cleanup=cleanup,
                               partial=partial)
    raise Throw("CalleeThrew", site=site, pad=pad, cleanup=cleanup,
                partial=partial)


def _log(db, log_lines, level, key, *args):
    """rocksdb::Log (0x5fcf060): level 1 = INFO, 2 = WARN. A
    null logger is skipped silently (the Log wrapper checks
    the shared_ptr first). The format strings carry the source
    line ([%s:line]) and the file argument is
    db/db_impl/db_impl.cc. Returns the rendered line, or None
    when the logger is null."""
    if not db["immutable"]["info_log_present"]:
        return None
    fmt = MESSAGES[key][0]
    line = fmt % ((LOG_FILE,) + args)
    log_lines.append({"level": level, "message": line})
    return line


def set_db_options(db, options_map, *, parse=None,
                   parse_new_options=None, validate1=None,
                   cf_statuses=None, new_db_options=None,
                   register_dump=None, register_persist=None,
                   switch_wal=None, write_options_file=None,
                   canary_ok=True, alloc_ok=True, fail_at=None):
    """The reconstructed DBImpl::SetDBOptions.

    `db` is a state dict from default_db_state(); `options_map`
    is the ordered list of (key, value) pairs (the unordered_map
    iteration order the binary logs is whatever the caller
    passed; the model preserves the given order). Oracle inputs
    are the statuses the FDE's callees return (each a dict with
    code/subcode/severity/state, or None for OK):
    - `parse`: GetMutableDBOptionsFromStrings, which also
      supplies the parsed new options via `parse_new_options`
      (on a parse failure the callee restores the base options,
      so the model ignores it then),
    - `validate1`: DBImpl::ValidateOptions (1-arg, 0x5e59cd0),
    - `cf_statuses`: ColumnFamilyData::ValidateOptions per live
      CF, in iteration order (the first non-OK status stops the
      loop),
    - `register_dump` / `register_persist`: the periodic-task
      Register statuses (Register returns a Status; Unregister
      returns void),
    - `switch_wal`: DBImpl::SwitchWAL,
    - `write_options_file`: DBImpl::WriteOptionsFile.
    `new_db_options` overrides BuildDBOptions' result.
    `canary_ok=False` corrupts the stack canary (a normal
    return then raises StackCheckFailed; a throw through a
    landing pad raises StackCheckFailed after cleanup).
    `alloc_ok=False` makes the Status ctor's `new char[]`
    fail (BadAlloc with the half-built status attached).
    `fail_at` arms one THROW_SITES entry: the named call throws
    instead of returning.
    Returns {"result": Status, "db": new state, "log": [...],
    "effects": [...]} where `effects` are the observable
    mutations in binary order. The input `db` is not mutated.
    """
    db = copy.deepcopy(db)
    log_lines = []
    effects = []
    out = None  # the sret out Status (r12)
    s = Status.ok()  # the local s Status (rsp+0x60)
    persist_options_status = Status.ok()  # rsp+0x70

    def epilogue():
        """The common epilogue (0x5d72238..0x5d72337 -> 0x5d72090):
        WriteContext::Clean + delete memtables, SuperVersion-
        Context dtor, delete[] persist/s state_ buffers (null
        after the moves), then the canary check at 0x5d720a1.
        `effects` records the cleanup; a bad canary raises
        StackCheckFailed. Returns the out Status."""
        effects.append("WriteContext::Clean + delete memtables "
                       "(0 free)")
        effects.append("SuperVersionContext dtor")
        # out = move(s) nulls s.state_ before this epilogue, so
        # s.state_ is always null here; persist_options_status
        # is never moved, so its state_ is deleted only when
        # WriteOptionsFile failed.
        effects.append("delete[] persist_options_status.state_"
                       if persist_options_status.state is not None
                       else "delete[] persist_options_status.state_ "
                       "(null)")
        effects.append("delete[] s.state_ (null after move)")
        if not canary_ok:
            raise StackCheckFailed(site=0x5D720A1)
        return out

    # --- empty input (no lock, no WriteContext) -------------
    if not options_map:
        _throw("log-empty-input", fail_at, canary_ok)
        _log(db, log_lines, 2, "log-empty-input")
        site, pad, cleanup = THROW_SITES["status-ctor-empty-input"]
        out = status_ctor(CODE["kInvalidArgument"],
                          MESSAGES["empty-input"][0], alloc_ok=alloc_ok,
                          site=site, pad=pad, cleanup=cleanup)
        if not canary_ok:
            raise StackCheckFailed(site=0x5D720A1)
        return {"result": out, "db": db, "log": log_lines,
                "effects": effects}

    # --- lock, parse -----------------------------------------
    _throw("super-version-context-ctor", fail_at, canary_ok)
    effects.append("SuperVersionContext ctor "
                   "(superversions_to_free=[], memtables_to_free=[])")
    _throw("mutex-lock", fail_at, canary_ok)
    effects.append("mutex Lock (0x606ca40)")
    _throw("parse", fail_at, canary_ok)
    s = status_from_dict(parse)
    new_options = copy.deepcopy(db["mutable"])
    if s.is_ok():
        if parse_new_options is not None:
            new_options = copy.deepcopy(parse_new_options)
    # GetMutableDBOptionsFromStrings restores the base options
    # on a parse failure, so new_options stays the old mutable.
    if new_options["bytes_per_sync"] == 0:
        new_options["bytes_per_sync"] = 1048576
        effects.append("bytes_per_sync 0 -> 1048576")
    if s.is_ok() and new_options == db["mutable"]:
        _throw("log-not-changed", fail_at, canary_ok)
        _log(db, log_lines, 1, "log-not-changed")
        out = Status(s.code, s.subcode, s.severity, s.state)
        s.state = None  # move-assign nulls the source
        effects.append("mutex Unlock (0x60d52f0)")
        return {"result": epilogue(), "db": db, "log": log_lines,
                "effects": effects}

    # --- build + validate ------------------------------------
    _throw("build", fail_at, canary_ok)
    built = build_db_options(db["immutable"], new_options)
    if new_db_options is not None:
        built = copy.deepcopy(new_db_options)
    effects.append("BuildDBOptions (0x60c2e20)")
    if s.is_ok():
        _throw("validate1", fail_at, canary_ok)
        s = status_from_dict(validate1)
        if s.is_ok():
            statuses = list(cf_statuses or [])
            live = [cf for cf in db["column_families"]
                    if not cf["dropped"]]
            for i, cf in enumerate(live):
                _throw("get-latest-cf-options", fail_at, canary_ok)
                effects.append("GetLatestCFOptions cf=%s" % cf["name"])
                _throw("validate-cf", fail_at, canary_ok)
                s = status_from_dict(statuses[i] if i < len(statuses)
                                     else None)
                effects.append("ColumnFamilyOptions temp dtor "
                               "(cf=%s)" % cf["name"])
                if not s.is_ok():
                    break

    # --- background threads + periodic tasks -----------------
    if s.is_ok():
        _throw("bg-limits", fail_at, canary_ok)
        old_limits = get_bg_job_limits(
            db["mutable"]["max_background_flushes"],
            db["mutable"]["max_background_compactions"],
            db["mutable"]["max_background_jobs"])
        new_limits = get_bg_job_limits(
            new_options["max_background_flushes"],
            new_options["max_background_compactions"],
            new_options["max_background_jobs"])
        flush_up = new_limits["max_flushes"] > \
            old_limits["max_flushes"]
        compaction_up = new_limits["max_compactions"] > \
            old_limits["max_compactions"]
        if flush_up or compaction_up:
            if flush_up:
                _throw("inc-threads-flush", fail_at, canary_ok)
                effects.append("Env::IncBackgroundThreads(HIGH, "
                               "%d)" % new_limits["max_flushes"])
            if compaction_up:
                _throw("inc-threads-compactions", fail_at, canary_ok)
                effects.append("Env::IncBackgroundThreads(LOW, %d)"
                               % new_limits["max_compactions"])
            _throw("maybe-schedule", fail_at, canary_ok)
            effects.append("MaybeScheduleFlushOrCompaction")
        effects.append("mutex Unlock (0x60d52f0)")
        if new_options["stats_dump_period_sec"] == 0:
            _throw("unregister-dump", fail_at, canary_ok)
            db["periodic_tasks"]["dump"] = None
            effects.append("UnregisterPeriodicTask(kDumpStats)")
        else:
            _throw("register-dump", fail_at, canary_ok)
            s = status_from_dict(register_dump)
            if s.is_ok():
                db["periodic_tasks"]["dump"] = \
                    new_options["stats_dump_period_sec"]
                effects.append("RegisterPeriodicTask(kDumpStats, "
                               "%d)" %
                               new_options["stats_dump_period_sec"])
            else:
                effects.append("RegisterPeriodicTask(kDumpStats) "
                               "-> %s" % status_tostring(s))
        if new_options["max_total_wal_size"] != \
                db["max_total_wal_size"]:
            db["max_total_wal_size"] = \
                new_options["max_total_wal_size"]
            effects.append("max_total_wal_size_ = %d" %
                           new_options["max_total_wal_size"])
        if s.is_ok():
            if new_options["stats_persist_period_sec"] == 0:
                _throw("unregister-persist", fail_at, canary_ok)
                db["periodic_tasks"]["persist"] = None
                effects.append("UnregisterPeriodicTask(kPersistStats)")
            else:
                _throw("register-persist", fail_at, canary_ok)
                s = status_from_dict(register_persist)
                if s.is_ok():
                    db["periodic_tasks"]["persist"] = \
                        new_options["stats_persist_period_sec"]
                    effects.append(
                        "RegisterPeriodicTask(kPersistStats, %d)"
                        % new_options["stats_persist_period_sec"])
                else:
                    effects.append(
                        "RegisterPeriodicTask(kPersistStats) -> %s"
                        % status_tostring(s))
        _throw("mutex-relock", fail_at, canary_ok)
        effects.append("mutex Lock (0x606ca40)")
        if not s.is_ok():
            out = Status(s.code, s.subcode, s.severity, s.state)
            s.state = None  # move-assign nulls the source
            effects.append("DBOptions dtor (new_db_options)")
            effects.append("mutex Unlock (0x60d52f0)")
            return {"result": epilogue(), "db": db,
                    "log": log_lines, "effects": effects}

        # --- apply the new options ---------------------------
        new_rate = max(1, new_options["delayed_write_rate"])
        db["write_controller"]["max_delayed_write_rate"] = new_rate
        db["write_controller"]["delayed_write_rate"] = new_rate
        effects.append("write_controller.set_max_delayed_write_rate"
                       "(%d) -> both fields" % new_rate)
        capacity = K_INFINITE_CAPACITY \
            if new_options["max_open_files"] == -1 else \
            new_options["max_open_files"] - 10
        db["table_cache_capacity"] = capacity
        effects.append("table_cache.SetCapacity(%d)" % capacity)
        wal_changed = db["mutable"]["wal_bytes_per_sync"] != \
            new_options["wal_bytes_per_sync"]
        db["mutable"] = copy.deepcopy(new_options)
        effects.append("mutable_db_options_ = new_options")
        _throw("file-options-ctor", fail_at, canary_ok)
        file_options = file_options_from_db_options(built)
        effects.append("FileOptions(new_db_options) "
                       "(EnvOptions ctor)")
        _throw("hashtable-assign-write", fail_at, canary_ok)
        effects.append("FileOptions.property_bag _M_assign_elements "
                       "(write)")
        _throw("optimize-write", fail_at, canary_ok)
        file_options = optimize_for_compaction_table_write(
            file_options, built)
        db["versions_file_options_writable_max_buffer_size"] = \
            new_options["writable_file_max_buffer_size"]
        effects.append("versions_->ChangeFileOptions"
                       "(writable_file_max_buffer_size=%d)" %
                       new_options["writable_file_max_buffer_size"])
        _throw("hashtable-assign-read", fail_at, canary_ok)
        effects.append("FileOptions.property_bag _M_assign_elements "
                       "(read)")
        _throw("optimize-read", fail_at, canary_ok)
        file_options = optimize_for_compaction_table_read(
            file_options, built)
        _throw("hashtable-assign-read2", fail_at, canary_ok)
        effects.append("FileOptions.property_bag _M_assign_elements "
                       "(read2)")
        file_options["compaction_readahead_size"] = \
            new_options["compaction_readahead_size"]
        db["file_options_for_compaction"] = file_options
        effects.append("file_options_for_compaction_ = FileOptions "
                       "(compaction_readahead_size=%d)" %
                       new_options["compaction_readahead_size"])

        # --- WAL switch + persist -----------------------------
        effects.append("WriteThread::Writer ctor")
        _throw("enter-unbatched", fail_at, canary_ok)
        effects.append("WriteThread::EnterUnbatched")
        if db["total_log_size"] > db["max_total_wal_size"] or \
                wal_changed:
            _throw("switch-wal", fail_at, canary_ok)
            purge = status_from_dict(switch_wal)
            if not purge.is_ok():
                _throw("tostring-switchwal", fail_at, canary_ok)
                purge_str = status_tostring(purge)
                _throw("log-switchwal-fail", fail_at, canary_ok)
                _log(db, log_lines, 2, "log-purge-wal", purge_str)
                effects.append("SwitchWAL failed (logged only) -> "
                               "%s" % purge_str)
            else:
                effects.append("SwitchWAL ok")
        _throw("write-options-file", fail_at, canary_ok)
        persist_options_status = status_from_dict(write_options_file)
        effects.append("WriteOptionsFile -> %s"
                       % status_tostring(persist_options_status))
        _throw("exit-unbatched", fail_at, canary_ok)
        effects.append("WriteThread::ExitUnbatched")
        effects.append("WriteThread::Writer dtor")
    else:
        effects.append("persist_options_status.PermitUncheckedError()")

    # --- tail: destroy new_db_options, unlock, log inputs -----
    effects.append("DBOptions dtor (new_db_options)")
    effects.append("mutex Unlock (0x60d52f0)")
    _throw("log-inputs", fail_at, canary_ok)
    _log(db, log_lines, 1, "log-inputs")
    for key, value in options_map:
        _throw("log-input-entry", fail_at, canary_ok)
        _log(db, log_lines, 1, "log-input-entry", key, value)
    if s.is_ok():
        _throw("log-succeeded", fail_at, canary_ok)
        _log(db, log_lines, 1, "log-succeeded")
        _throw("dump", fail_at, canary_ok)
        effects.append("MutableDBOptions::Dump(new_options)")
        if not persist_options_status.is_ok():
            if db["immutable"]["fail_if_options_file_error"]:
                _throw("tostring-persist", fail_at, canary_ok)
                persist_str = status_tostring(persist_options_status)
                site, pad, cleanup = \
                    THROW_SITES["status-ctor-ioerror"]
                s = status_ctor(CODE["kIOError"],
                                MESSAGES["ioerror-persist"][0],
                                msg2=persist_str, alloc_ok=alloc_ok,
                                site=site, pad=pad, cleanup=cleanup)
            # The WARN is logged whether or not fail_if is set;
            # its ToString temp is a separate call (0x5d724db).
            _throw("tostring-persist-2", fail_at, canary_ok)
            persist_str = status_tostring(persist_options_status)
            _throw("log-persist-warn", fail_at, canary_ok)
            _log(db, log_lines, 2, "log-persist", persist_str)
    else:
        _throw("log-failed", fail_at, canary_ok)
        _log(db, log_lines, 2, "log-failed")
    _throw("log-flush", fail_at, canary_ok)
    effects.append("LogFlush(info_log)")
    out = Status(s.code, s.subcode, s.severity, s.state)
    s.state = None  # move-assign nulls the source
    return {"result": epilogue(), "db": db, "log": log_lines,
            "effects": effects}



# ---------------------------------------------------------------- cases

# Engine call counts verified live (objdump, main FDE then .cold
# FDE). Keys are "call <target>" as objdump prints the address.
ENGINE_CALLS = {
    "main": {
        "call   63f0dc0": 10, "call   5d49b10": 10,
        "call   5fcf060": 8, "call   63f0db0": 3,
        "call   61cfed0": 3, "call   60d52f0": 3,
        "call   5d6cd90": 3, "call   5d5b4c0": 3,
        "call   5d5b300": 3, "call   63f0d80": 2,
        "call   61cf670": 2, "call   606ca40": 2,
        "call   5f22020": 2, "call   5f20a00": 2,
        "call   5dd5f00": 2, "call   5d50400": 2,
        "call   5d499b0": 2, "call   5d35770": 2,
        "call   5d354b0": 2, "call   5d350c0": 2,
        "call   63f0d70": 1, "call   60c2e20": 1,
        "call   60a2080": 1, "call   60a1d60": 1,
        "call   60a1640": 1, "call   60a1540": 1,
        "call   5fcf310": 1, "call   5fcf050": 1,
        "call   5fcbf90": 1, "call   5fcbda0": 1,
        "call   5f10d40": 1, "call   5e8c5e0": 1,
        "call   5e870c0": 1, "call   5e59cd0": 1,
        "call   5dd64b0": 1, "call   5d8e3b0": 1,
        "call   5d8bce0": 1, "call   5d713f0": 1,
        "call   5d5b0e0": 1, "call   5d51010": 1,
        "call   5d50de0": 1, "call   5d509c0": 1,
        "call   5d50930": 1,
        "call   *%rcx": 1, "call   *0x210(%rax)": 1,
        "call   *0x58(%rdx)": 1, "call   *0x1a8(%rax)": 1,
        "call   *0x1b0(%rax)": 1,
    },
    "cold": {
        "call   5d350c0": 2, "call   5d354b0": 1,
        "call   5d35770": 1, "call   5d509c0": 1,
        "call   5d519d0": 1, "call   5d5b300": 3,
        "call   5d5b4c0": 3, "call   60d52f0": 1,
        "call   63f0a50": 1, "call   63f0d70": 1,
        "call   63f0db0": 2, "call   63f0dc0": 3,
    },
}

# Landing-pad stub -> .cold target, verified live (each stub is
# endbr64 + mov %rax,%rbx + jmp rel32 at stub+7).
PAD_TO_COLD = {
    0x5D72D9C: 0x5D71EFE, 0x5D72DA8: 0x5D71EF4,
    0x5D72DB4: 0x5D71F4B, 0x5D72DC0: 0x5D71F37,
    0x5D72DCC: 0x5D71EEA, 0x5D72DD8: 0x5D71EEA,
    0x5D72DE4: 0x5D71F41, 0x5D72DF0: 0x5D71F76,
    0x5D72DFC: 0x5D71F80, 0x5D72E08: 0x5D71FA4,
    0x5D72E14: 0x5D71FB4, 0x5D72E20: 0x5D71F90,
    0x5D72E2C: 0x5D71F5C, 0x5D72E38: 0x5D71F64,
    0x5D72E44: 0x5D71FCB,
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


def _db_summary(db):
    fo = db["file_options_for_compaction"]
    return {
        "mutable": db["mutable"],
        "max_total_wal_size": db["max_total_wal_size"],
        "write_controller": db["write_controller"],
        "table_cache_capacity": db["table_cache_capacity"],
        "file_options_for_compaction": None if fo is None else {
            "use_direct_writes": fo["use_direct_writes"],
            "use_direct_reads": fo["use_direct_reads"],
            "compaction_readahead_size":
                fo["compaction_readahead_size"],
            "writable_file_max_buffer_size":
                fo["writable_file_max_buffer_size"],
            "bytes_per_sync": fo["bytes_per_sync"],
            "temperature": fo["temperature"],
            "handoff_checksum_type": fo["handoff_checksum_type"]},
        "versions_file_options_writable_max_buffer_size":
            db["versions_file_options_writable_max_buffer_size"],
        "periodic_tasks": db["periodic_tasks"],
    }


def _status_dict(status):
    return status.as_dict()


def _inputs_to_reach(site):
    """A base inputs dict that reaches throw site `site`
    (fail_at is added by the caller)."""
    base = {"group": "throw", "options_map": [["max_background_jobs",
                                               "4"]]}
    # A parse that changes max_background_jobs 2 -> 4.
    new_opts = default_mutable_db_options()
    new_opts["max_background_jobs"] = 4
    base["parse_new_options"] = new_opts
    if site in ("status-ctor-empty-input", "log-empty-input"):
        base["options_map"] = []
        return base
    if site in ("log-not-changed",):
        base["parse_new_options"] = default_mutable_db_options()
        return base
    if site in ("validate1", "get-latest-cf-options"):
        return base
    if site == "validate-cf":
        base["cf_statuses"] = [{"code": 4, "subcode": 0, "severity": 0,
                                "state": "bad cf"}]
        return base
    if site in ("bg-limits", "inc-threads-flush",
                "inc-threads-compactions", "maybe-schedule"):
        # jobs 2 -> 16: limits 1/1 -> 4/12, both increase.
        new_opts = default_mutable_db_options()
        new_opts["max_background_jobs"] = 16
        base["parse_new_options"] = new_opts
        return base
    if site == "unregister-dump":
        new_opts["stats_dump_period_sec"] = 0
        base["parse_new_options"] = new_opts
        return base
    if site == "register-dump":
        return base
    if site == "unregister-persist":
        new_opts["stats_persist_period_sec"] = 0
        base["parse_new_options"] = new_opts
        return base
    if site == "register-persist":
        return base
    if site in ("mutex-relock", "file-options-ctor",
                "hashtable-assign-write", "optimize-write",
                "hashtable-assign-read", "optimize-read",
                "hashtable-assign-read2", "enter-unbatched",
                "write-options-file", "exit-unbatched", "log-inputs",
                "log-input-entry", "log-succeeded", "dump",
                "log-flush"):
        return base
    if site == "switch-wal":
        base["db_overrides"] = {"total_log_size": 100}
        return base
    if site in ("tostring-switchwal", "log-switchwal-fail"):
        base["db_overrides"] = {"total_log_size": 100}
        base["switch_wal"] = {"code": 5, "subcode": 0, "severity": 0,
                              "state": "switch failed"}
        return base
    if site in ("tostring-persist", "status-ctor-ioerror",
                "tostring-persist-2", "log-persist-warn"):
        base["write_options_file"] = {
            "code": 5, "subcode": 0, "severity": 0,
            "state": "persist failed"}
        if site in ("tostring-persist", "status-ctor-ioerror",
                    "log-persist-warn"):
            base["db_overrides"] = {
                "immutable": {"fail_if_options_file_error": True}}
        return base
    if site == "log-failed":
        base["validate1"] = {"code": 4, "subcode": 0, "severity": 0,
                             "state": "bad options"}
        return base
    return base


def run_case(inputs):
    """Run one case and return the expected outputs."""
    group = inputs["group"]
    if group == "checks":
        db = default_db_state()
        _apply_overrides(db, inputs.get("db_overrides"))
        out = set_db_options(
            db, inputs.get("options_map", []),
            parse=inputs.get("parse"),
            parse_new_options=inputs.get("parse_new_options"),
            validate1=inputs.get("validate1"),
            cf_statuses=inputs.get("cf_statuses"),
            new_db_options=inputs.get("new_db_options"),
            register_dump=inputs.get("register_dump"),
            register_persist=inputs.get("register_persist"),
            switch_wal=inputs.get("switch_wal"),
            write_options_file=inputs.get("write_options_file"))
        return {"result": _status_dict(out["result"]),
                "log": [line["message"] for line in out["log"]],
                "effects": out["effects"],
                "db_summary": _db_summary(out["db"])}
    if group == "status":
        kind = inputs["kind"]
        if kind == "ok":
            return {"status": _status_dict(Status.ok())}
        if kind == "error-empty-input":
            st = status_ctor(CODE["kInvalidArgument"],
                             MESSAGES["empty-input"][0])
            return {"status": _status_dict(st)}
        if kind == "error-ioerror":
            st = status_ctor(CODE["kIOError"],
                             MESSAGES["ioerror-persist"][0],
                             msg2=inputs.get("msg2", "IOError: x"))
            return {"status": _status_dict(st),
                    "joined": st.state}
        if kind == "ctor-msg2":
            st = status_ctor(CODE["kNotSupported"],
                             inputs["message"], inputs["msg2"])
            return {"status": _status_dict(st),
                    "joined": st.state}
        if kind == "image":
            st = Status(inputs["code"], inputs["subcode"],
                        inputs["severity"], inputs.get("state"))
            return {"status": _status_dict(st)}
        if kind == "alloc-fail":
            try:
                status_ctor(CODE["kInvalidArgument"],
                            MESSAGES["empty-input"][0], alloc_ok=False,
                            site=0x5D7208B, pad=None, cleanup=[])
            except BadAlloc as err:
                return {"error": "BadAlloc",
                        "site": None if err.site is None else
                        hex(err.site),
                        "pad": None if err.pad is None else hex(err.pad),
                        "cleanup": err.cleanup,
                        "partial": None if err.partial is None else
                        _status_dict(err.partial),
                        "canary_checked": False}
            return {"error": None}
        raise ValueError("unknown status kind %r" % kind)
    if group == "throw":
        db = default_db_state()
        _apply_overrides(db, inputs.get("db_overrides"))
        try:
            out = set_db_options(
                db, inputs.get("options_map", []),
                parse=inputs.get("parse"),
                parse_new_options=inputs.get("parse_new_options"),
                validate1=inputs.get("validate1"),
                cf_statuses=inputs.get("cf_statuses"),
                new_db_options=inputs.get("new_db_options"),
                register_dump=inputs.get("register_dump"),
                register_persist=inputs.get("register_persist"),
                switch_wal=inputs.get("switch_wal"),
                write_options_file=inputs.get("write_options_file"),
                canary_ok=inputs.get("canary_ok", True),
                alloc_ok=inputs.get("alloc_ok", True),
                fail_at=inputs.get("fail_at"))
        except BadAlloc as err:
            return {"error": "BadAlloc",
                    "cause_message": str(err),
                    "site": None if err.site is None else hex(err.site),
                    "pad": None if err.pad is None else hex(err.pad),
                    "cleanup": err.cleanup,
                    "partial": None if err.partial is None else
                    _status_dict(err.partial),
                    "canary_checked": False}
        except StackCheckFailed as err:
            return {"error": "StackCheckFailed",
                    "message": str(err),
                    "site": None if err.site is None else hex(err.site),
                    "pad": None if err.pad is None else hex(err.pad),
                    "cleanup": err.cleanup,
                    "canary_checked": True}
        except Throw as err:
            return {"error": err.kind,
                    "site": None if err.site is None else hex(err.site),
                    "pad": None if err.pad is None else hex(err.pad),
                    "cleanup": err.cleanup,
                    "canary_checked": err.pad is not None}
        return {"error": None,
                "result": _status_dict(out["result"]),
                "canary_checked": True}
    if group == "bindings":
        db = default_db_state()
        _apply_overrides(db, inputs.get("db_overrides"))
        out = set_db_options(
            db, inputs.get("options_map", []),
            parse=inputs.get("parse"),
            parse_new_options=inputs.get("parse_new_options"),
            validate1=inputs.get("validate1"),
            cf_statuses=inputs.get("cf_statuses"),
            register_dump=inputs.get("register_dump"),
            register_persist=inputs.get("register_persist"),
            switch_wal=inputs.get("switch_wal"),
            write_options_file=inputs.get("write_options_file"))
        result = out["result"]
        return {
            "caller_site": inputs["caller_site"],
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
        }
    raise ValueError("unknown group %r" % group)


def _gen_group(rng, group, n):
    rows = []
    if group == "checks":
        modes = ["empty", "parse-fail", "unchanged",
                 "bytes-per-sync-default", "validate1-fail",
                 "cf-fail-first", "cf-fail-second",
                 "cf-dropped-skipped", "bg-flush-up",
                 "bg-compaction-up", "bg-both-up", "bg-none",
                 "scheduler-dump-0", "scheduler-dump-register-fail",
                 "scheduler-persist-0",
                 "scheduler-persist-register-fail",
                 "wal-switch-total", "wal-switch-changed",
                 "wal-switch-fail", "persist-fail-ignore",
                 "persist-fail-error", "mixed"]
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = modes[i % len(modes)]
            inputs = {"group": group, "case_id": case_id,
                      "options_map": [["max_background_jobs", "4"]]}
            new_opts = default_mutable_db_options()
            new_opts["max_background_jobs"] = 4
            inputs["parse_new_options"] = new_opts
            if mode == "empty":
                inputs["options_map"] = []
            elif mode == "parse-fail":
                inputs["parse"] = {"code": 4, "subcode": 0,
                                   "severity": 0,
                                   "state": "bad option"}
                inputs["parse_new_options"] = None
            elif mode == "unchanged":
                # The short-circuit compares the parsed options
                # AFTER the bytes_per_sync 1 MiB default against
                # the current mutable, so the db's mutable must
                # already carry bytes_per_sync=1048576 for the
                # guard to fire (a default db never short-circuits:
                # 0 vs 1048576).
                inputs["parse_new_options"] = \
                    default_mutable_db_options()
                inputs["db_overrides"] = {
                    "mutable": {"bytes_per_sync": 1048576}}
            elif mode == "bytes-per-sync-default":
                new_opts["bytes_per_sync"] = 0
                inputs["parse_new_options"] = new_opts
            elif mode == "validate1-fail":
                inputs["validate1"] = {"code": 4, "subcode": 0,
                                       "severity": 0,
                                       "state": "bad options"}
            elif mode == "cf-fail-first":
                inputs["cf_statuses"] = [
                    {"code": 4, "subcode": 0, "severity": 0,
                     "state": "bad cf"}]
            elif mode == "cf-fail-second":
                inputs["db_overrides"] = {
                    "column_families": [default_column_family(0),
                                        default_column_family(1, "cf1")]}
                inputs["cf_statuses"] = [
                    None,
                    {"code": 4, "subcode": 0, "severity": 0,
                     "state": "bad cf1"}]
            elif mode == "cf-dropped-skipped":
                dropped = default_column_family(0)
                dropped["dropped"] = True
                inputs["db_overrides"] = {
                    "column_families": [dropped,
                                        default_column_family(1, "cf1")]}
                inputs["cf_statuses"] = [
                    {"code": 4, "subcode": 0, "severity": 0,
                     "state": "bad cf1"}]
            elif mode == "bg-flush-up":
                new_opts["max_background_jobs"] = 16
                new_opts["max_background_flushes"] = 8
                inputs["parse_new_options"] = new_opts
            elif mode == "bg-compaction-up":
                new_opts["max_background_jobs"] = 16
                new_opts["max_background_compactions"] = 12
                inputs["parse_new_options"] = new_opts
            elif mode == "bg-both-up":
                new_opts["max_background_jobs"] = 16
                inputs["parse_new_options"] = new_opts
            elif mode == "bg-none":
                # Limits unchanged (1/1 vs 1/1) but the options
                # differ elsewhere, so the BG-limits code runs
                # with no IncBackgroundThreads call. The jobs
                # must stay at the db default (2): jobs 2->4
                # would grow compactions 1->3.
                new_opts["max_background_jobs"] = 2
                new_opts["stats_dump_period_sec"] = 601
                inputs["parse_new_options"] = new_opts
            elif mode == "scheduler-dump-0":
                new_opts["stats_dump_period_sec"] = 0
                inputs["parse_new_options"] = new_opts
            elif mode == "scheduler-dump-register-fail":
                inputs["register_dump"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "register failed"}
            elif mode == "scheduler-persist-0":
                new_opts["stats_persist_period_sec"] = 0
                inputs["parse_new_options"] = new_opts
            elif mode == "scheduler-persist-register-fail":
                inputs["register_persist"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "register failed"}
            elif mode == "wal-switch-total":
                inputs["db_overrides"] = {
                    "total_log_size": 100,
                    "max_total_wal_size": 50}
            elif mode == "wal-switch-changed":
                new_opts["wal_bytes_per_sync"] = 4096
                inputs["parse_new_options"] = new_opts
            elif mode == "wal-switch-fail":
                inputs["db_overrides"] = {"total_log_size": 100}
                inputs["switch_wal"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "switch failed"}
            elif mode == "persist-fail-ignore":
                inputs["write_options_file"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "persist failed"}
            elif mode == "persist-fail-error":
                inputs["db_overrides"] = {
                    "immutable": {"fail_if_options_file_error": True}}
                inputs["write_options_file"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "persist failed"}
            else:  # mixed
                new_opts["max_background_jobs"] = rng.choice(
                    [1, 2, 4, 8, 16])
                new_opts["max_background_flushes"] = rng.choice(
                    [-1, 1, 2, 4])
                new_opts["max_background_compactions"] = rng.choice(
                    [-1, 1, 4, 8])
                new_opts["stats_dump_period_sec"] = rng.choice(
                    [0, 60, 600])
                new_opts["stats_persist_period_sec"] = rng.choice(
                    [0, 60, 600])
                new_opts["delayed_write_rate"] = rng.choice(
                    [0, 1, 1048576])
                new_opts["max_open_files"] = rng.choice([-1, 100])
                new_opts["wal_bytes_per_sync"] = rng.choice(
                    [0, 4096])
                new_opts["bytes_per_sync"] = rng.choice([0, 4096])
                inputs["parse_new_options"] = new_opts
                inputs["db_overrides"] = {
                    "total_log_size": rng.choice([0, 50, 100]),
                    "max_total_wal_size": rng.choice([0, 50]),
                    "immutable": {
                        "fail_if_options_file_error":
                            rng.random() < 0.5}}
                if rng.random() < 0.2:
                    inputs["switch_wal"] = {
                        "code": 5, "subcode": 0, "severity": 0,
                        "state": "switch failed"}
                if rng.random() < 0.2:
                    inputs["write_options_file"] = {
                        "code": 5, "subcode": 0, "severity": 0,
                        "state": "persist failed"}
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    elif group == "status":
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = i % 6
            if mode == 0:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "ok"}
            elif mode == 1:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "error-empty-input"}
            elif mode == 2:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "error-ioerror",
                          "msg2": "IO error: no such file"}
            elif mode == 3:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "ctor-msg2", "message": "a",
                          "msg2": "b"}
            elif mode == 4:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "image",
                          "code": i % 16, "subcode": i % 4,
                          "severity": i % 3,
                          "state": None if i % 2 else "state %d" % i}
            else:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "alloc-fail"}
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    elif group == "throw":
        sites = sorted(THROW_SITES)
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = i % 5
            site = sites[i % len(sites)]
            inputs = _inputs_to_reach(site)
            inputs["case_id"] = case_id
            if mode == 0:
                inputs["fail_at"] = site
            elif mode == 1:
                # Throw + bad canary: a pad exists, so the .cold
                # chain checks the canary and the throw becomes
                # StackCheckFailed; no pad -> still CalleeThrew.
                inputs["fail_at"] = site
                inputs["canary_ok"] = False
            elif mode == 2:
                # BadAlloc in a Status ctor site + bad canary.
                if site == "status-ctor-empty-input":
                    inputs["alloc_ok"] = False
                    inputs["canary_ok"] = False
                elif site == "status-ctor-ioerror":
                    inputs["alloc_ok"] = False
                    inputs["canary_ok"] = False
                else:
                    inputs["fail_at"] = site
                    inputs["alloc_ok"] = False
            elif mode == 3:
                # Canary failure on a normal return (no throw).
                inputs["canary_ok"] = False
            else:
                # alloc_ok=False with no fail_at: the ctor fails
                # only when an error path runs it.
                inputs["alloc_ok"] = False
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    elif group == "bindings":
        callers = ["vtable:0x248 (StackableDB 0x5d30750)",
                   "vtable:0x248",
                   "no-direct-calls (0 sites)"]
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            inputs = {"group": group, "case_id": case_id,
                      "caller_site": callers[i % len(callers)],
                      "options_map": [["max_background_jobs", "4"]]}
            new_opts = default_mutable_db_options()
            new_opts["max_background_jobs"] = 4
            inputs["parse_new_options"] = new_opts
            if rng.random() < 0.3:
                inputs["write_options_file"] = {
                    "code": 5, "subcode": 0, "severity": 0,
                    "state": "persist failed"}
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    return rows


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
                     % (label, 16 if label == "main" else 0),
                     dis.count("endbr64") ==
                     (16 if label == "main" else 0),
                     dis.count("endbr64")))
        legs.append(("%s canary refs %%fs:0x28 x%d"
                     % (label, 2 if label == "main" else 1),
                     dis.count("%fs:0x28") ==
                     (2 if label == "main" else 1),
                     dis.count("%fs:0x28")))
    return legs


def _field_cmps(data, secs):
    legs = []
    dis = _disasm(data, secs, START, END)
    checks = [
        ("bytes_per_sync default 1 MiB",
         "movq   $0x100000,0xe8(%rsp)" in dis),
        ("fail_if_options_file_error at DBImpl+0x4c0",
         "cmpb   $0x0,0x4c0(%rbx)" in dis),
        ("CF next chain at ColumnFamilyData+0x938",
         "mov    0x938(%r13),%rbp" in dis
         and "mov    0x938(%rbp),%rbp" in dis),
        ("dropped CF byte at +0x3d",
         "movzbl 0x3d(%rbp),%eax" in dis),
        ("mutex at DBImpl+0x700",
         "lea    0x700(%rbx),%rax" in dis),
        ("mutable_db_options_ at DBImpl+0x5a0",
         "lea    0x5a0(%rbx),%rbp" in dis),
        ("immutable_db_options_ at DBImpl+0x330",
         "lea    0x330(%rbx),%rsi" in dis),
        ("max_total_wal_size_ store at DBImpl+0x1860",
         "mov    %rax,0x1860(%rbx)" in dis),
        ("table_cache_ at DBImpl+0x750",
         "mov    0x750(%rbx),%rdi" in dis),
        ("kInfiniteCapacity 0x400000",
         "mov    $0x400000,%eax" in dis),
        ("write_controller_ 16-byte store at DBImpl+0x1120",
         "movups %xmm0,0x1120(%rbx)" in dis),
        ("mutable_db_options_ 16-byte store",
         "movups %xmm1,0x5a0(%rbx)" in dis),
        ("file_options_for_compaction_ at DBImpl+0x8d0",
         "movups %xmm1,0x8d0(%rbx)" in dis),
        ("periodic_task_scheduler_ at DBImpl+0x1748",
         "lea    0x1748(%rbx),%r13" in dis),
        ("write_thread_ at DBImpl+0xd40",
         "lea    0xd40(%rbx),%r14" in dis),
        ("s.code checked (cmpb $0x0,0x60(%rsp))",
         dis.count("cmpb   $0x0,0x60(%rsp)") == 7,
         dis.count("cmpb   $0x0,0x60(%rsp)")),
        ("SetCapacity vtable slot 0x58",
         "call   *0x58(%rdx)" in dis),
        ("IncBackgroundThreadsIfNeeded slot 0x210",
         "call   *0x210(%rax)" in dis),
        ("IncBackgroundThreadsIfNeeded slot *%rcx",
         "call   *%rcx" in dis),
        ("OptimizeForCompactionTableWrite slot 0x1a8",
         "call   *0x1a8(%rax)" in dis),
        ("OptimizeForCompactionTableRead slot 0x1b0",
         "call   *0x1b0(%rax)" in dis),
        ("message file lea 0x4451b9 x4",
         dis.count("# 4451b9") == 4, dis.count("# 4451b9")),
        ("empty-input msg lea 0x43b417",
         "# 43b417" in dis),
        ("log-empty-input fmt lea 0x95ec48",
         "# 95ec48" in dis),
        ("log-not-changed fmt lea 0x95f650",
         "# 95f650" in dis),
        ("log-purge-wal fmt lea 0x960198",
         "# 960198" in dis),
        ("log-inputs fmt lea 0x964798",
         "# 964798" in dis),
        ("log-input-entry fmt lea 0x43f81d",
         "# 43f81d" in dis),
        ("log-succeeded fmt lea 0x9669a8",
         "# 9669a8" in dis),
        ("ioerror-persist msg lea 0x967de8",
         "# 967de8" in dis),
        ("log-persist fmt lea 0x957910",
         "# 957910" in dis),
        ("log-failed fmt lea 0x431ff4",
         "# 431ff4" in dis),
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
                 FDE_RANGE, FDE_LSDA, 22),
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
            legs.append(("main LSDA has 15 distinct landing pads",
                         len(pads) == 15, len(pads)))
            legs.append(("main LSDA pads are exactly the 15 stubs",
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
    legs.append(("caller census: 0 direct calls, 0 jumps, 0 lea refs",
                 sites == [], sites))
    # vtable slot: StackableDB::SetDBOptions 0x5d30750 calls the
    # slot at 0x5d3081b (mov rax,[rax+0x248]; call *0x248(%rax)).
    dis_stack = _disasm(data, secs, 0x5D30750, 0x5D3085C)
    legs.append(("StackableDB::SetDBOptions calls vtable slot 0x248",
                 "call   *0x248(%rax)" in dis_stack, None))
    # Model legs.
    legs.append(("defaults validate OK",
                 set_db_options(default_db_state(),
                                [["max_background_jobs", "4"]],
                                parse_new_options={**default_mutable_db_options(),
                                                   "max_background_jobs": 4})
                 ["result"].is_ok(), None))
    out = set_db_options(default_db_state(), [])
    legs.append(("empty input -> InvalidArgument 'empty input'",
                 out["result"].code == CODE["kInvalidArgument"]
                 and out["result"].state == "empty input"
                 and out["log"][0]["message"] ==
                 "[db/db_impl/db_impl.cc:1212] SetDBOptions(), "
                 "empty input.",
                 out["result"].state))
    new_opts = default_mutable_db_options()
    new_opts["max_background_jobs"] = 4
    db_unchanged = default_db_state()
    # The short-circuit compares the parsed options AFTER the
    # bytes_per_sync 1 MiB default, so the db's mutable must
    # already carry bytes_per_sync=1048576 and jobs=4.
    db_unchanged["mutable"]["bytes_per_sync"] = 1048576
    db_unchanged["mutable"]["max_background_jobs"] = 4
    out = set_db_options(db_unchanged,
                         [["max_background_jobs", "4"]],
                         parse_new_options=new_opts)
    legs.append(("unchanged options short-circuit OK",
                 out["result"].is_ok()
                 and any("not changed" in l["message"]
                         for l in out["log"]), None))
    out = set_db_options(default_db_state(),
                         [["max_background_jobs", "4"]],
                         parse={"code": 4, "subcode": 0, "severity": 0,
                                "state": "bad option"})
    legs.append(("parse failure returns the parse status",
                 out["result"].code == 4
                 and out["result"].state == "bad option", None))
    out = set_db_options(default_db_state(),
                         [["max_background_jobs", "4"]],
                         parse_new_options=new_opts,
                         validate1={"code": 4, "subcode": 0,
                                    "severity": 0,
                                    "state": "bad options"})
    legs.append(("validate1 failure returns its status",
                 out["result"].code == 4
                 and out["result"].state == "bad options", None))
    out = set_db_options(default_db_state(),
                         [["max_background_jobs", "4"]],
                         parse_new_options=new_opts,
                         cf_statuses=[{"code": 4, "subcode": 0,
                                       "severity": 0,
                                       "state": "bad cf"}])
    legs.append(("per-CF failure returns its status",
                 out["result"].code == 4
                 and out["result"].state == "bad cf", None))
    jobs16 = default_mutable_db_options()
    jobs16["max_background_jobs"] = 16
    out = set_db_options(default_db_state(),
                         [["max_background_jobs", "16"]],
                         parse_new_options=jobs16)
    legs.append(("jobs 2->16 grows both pools (4/12)",
                 "Env::IncBackgroundThreads(HIGH, 4)" in out["effects"]
                 and "Env::IncBackgroundThreads(LOW, 12)"
                 in out["effects"], None))
    out = set_db_options(default_db_state(),
                         [["max_background_jobs", "4"]],
                         parse_new_options=new_opts,
                         register_dump={"code": 5, "subcode": 0,
                                        "severity": 0,
                                        "state": "register failed"})
    legs.append(("register-dump failure returns its status",
                 out["result"].code == 5
                 and out["result"].state == "register failed", None))
    db = default_db_state()
    db["total_log_size"] = 100
    out = set_db_options(db, [["max_background_jobs", "4"]],
                         parse_new_options=new_opts,
                         switch_wal={"code": 5, "subcode": 0,
                                     "severity": 0,
                                     "state": "switch failed"})
    legs.append(("SwitchWAL failure is logged only, result OK",
                 out["result"].is_ok()
                 and any("Unable to purge WAL files" in l["message"]
                         for l in out["log"]), None))
    out = set_db_options(default_db_state(),
                         [["max_background_jobs", "4"]],
                         parse_new_options=new_opts,
                         write_options_file={"code": 5, "subcode": 0,
                                             "severity": 0,
                                             "state": "persist failed"})
    legs.append(("persist failure ignored when fail_if=false",
                 out["result"].is_ok()
                 and any("Unable to persist options" in l["message"]
                         for l in out["log"]), None))
    db = default_db_state()
    db["immutable"]["fail_if_options_file_error"] = True
    out = set_db_options(db, [["max_background_jobs", "4"]],
                         parse_new_options=new_opts,
                         write_options_file={"code": 5, "subcode": 0,
                                             "severity": 0,
                                             "state": "persist failed"})
    legs.append(("persist failure -> IOError when fail_if=true",
                 out["result"].code == CODE["kIOError"]
                 and out["result"].state ==
                 "SetDBOptions() succeeded, but unable to persist "
                 "options: IO error: persist failed",
                 out["result"].state))
    # Status ctor legs: state_ buffer is msg + NUL, alloc len+1.
    st = status_ctor(CODE["kInvalidArgument"],
                     MESSAGES["empty-input"][0], "")
    legs.append(("ctor state_ buffer is msg + NUL",
                 st.state_buffer() == MESSAGES["empty-input"][0].encode()
                 + b"\x00"
                 and st.state_alloc()
                 == len(MESSAGES["empty-input"][0]) + 1, None))
    joined = status_ctor(CODE["kNotSupported"], "a", "b")
    legs.append(("ctor joins non-empty msg2 with ': '",
                 joined.state == "a: b", joined.state))
    # A throw through a landing pad with a bad canary becomes
    # StackCheckFailed after cleanup.
    try:
        set_db_options(default_db_state(),
                       [["max_background_jobs", "4"]],
                       parse_new_options=new_opts,
                       canary_ok=False, fail_at="validate1")
        legs.append(("throw + bad canary -> StackCheckFailed",
                     False, "no exception"))
    except StackCheckFailed:
        legs.append(("throw + bad canary -> StackCheckFailed",
                     True, None))
    except Throw:
        legs.append(("throw + bad canary -> StackCheckFailed",
                     False, "CalleeThrew"))
    # A throw with no landing pad propagates with no canary
    # check, even with a bad canary.
    try:
        set_db_options(default_db_state(), [],
                       canary_ok=False, alloc_ok=False)
        legs.append(("BadAlloc + bad canary (no pad) -> BadAlloc",
                     False, "no exception"))
    except BadAlloc:
        legs.append(("BadAlloc + bad canary (no pad) -> BadAlloc",
                     True, None))
    except StackCheckFailed:
        legs.append(("BadAlloc + bad canary (no pad) -> BadAlloc",
                     False, "StackCheckFailed"))
    # A bad canary on a normal return raises StackCheckFailed.
    try:
        set_db_options(default_db_state(),
                       [["max_background_jobs", "4"]],
                       parse_new_options=new_opts, canary_ok=False)
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
