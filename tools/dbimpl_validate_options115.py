#!/usr/bin/env python3
"""Node #115 RocksDB DBImpl::ValidateOptions (two-argument overload):
reconstruction.

RE-002 work item. Reconstructs the per-column-family options validator
at 0x5e5a000..0x5e5a151 (337 B, main FDE) plus its .cold landing-pad
FDE at 0x5e59fd4..0x5e59fff (43 B): the gate DBImpl::Open runs before
it touches any column family -- it validates every requested column
family's options against the DB options, then validates the DB options
alone, and returns the first non-OK status. Its single validated
caller is DBImpl::Open 0x5e62c50 (site 0x5e62e52). Direct follow-up
to the open CreateWAL packet (PR #6222, 0x5e5c270, also called from
DBImpl::Open), the BuildDBOptions packet (open PR #6297, 0x60c2e20)
and the DBOptions ctor trio (open PRs #6337/#6338/#6341): Open
sanitizes the options, builds the DBOptions, validates them here,
and only then creates the WAL and the DBImpl.

  rocksdb::DBImpl::ValidateOptions  0x5e5a000 (337 B)
  rocksdb::DBImpl::ValidateOptions.cold  0x5e59fd4 (43 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The main FDE is vendor-census-bound (member
4d429ab1cb2d8f8b-db_impl_open.o, librocksdb-sys 0.11.0+8.1.1, symbol
_ZN7rocksdb6DBImpl15ValidateOptionsERKNS_9DBOptionsERKSt6vectorINS_22ColumnFamilyDescriptorESaIS5_EE):
the body hash 8b4ef727... and the source hash b3d3ffa3... were
recomputed from the binary, and the source hash was reproduced
exactly by zeroing the 8 census relocations (kinds 2/4, no
relaxation). The .cold FDE has NO vendor census record, so it is
bound by body hash only (9a82fbb2...), per the no-census convention.

What the binary does (whole-FDE disassembly, verbatim in the packet):

  Status DBImpl::ValidateOptions(const DBOptions& db_options,
      const std::vector<ColumnFamilyDescriptor>& column_families)
  -- the result is returned by value (hidden sret out in rdi = rbx),
  db_options in rsi (= r12), the descriptor vector in rdx
  (begin in rbp, end in r14). A stack canary IS used (%fs:0x28,
  stored at 0x18(%rsp), checked on the return path and in .cold).

  1. out = OK (0x5e5a028..0x5e5a043): code u32 at +0x0 = 0, subcode
     u16 at +0x4 = 0, state_ ptr at +0x8 = nullptr. Bytes +0x6..+0x7
     (the subcode padding) are never written -- the model zeroes
     them and records them as unwritten padding.
  2. The loop (0x5e5a044..0x5e5a0c3): p = begin; while (p != end):
     call ColumnFamilyData::ValidateOptions(db_options,
     p->options) -- 0x5d8e3b0, sret temp at (%rsp), db_options in
     rsi, &descriptor.options in rdx = p + 0x20 -- then MOVE the
     temp status into out (see 4) and test out.code: if non-zero,
     return out at once (first failure wins; later column families
     are never validated and the DB-options check never runs).
     Else p += 0x320 (the descriptor stride: name string 0x20 +
     ColumnFamilyOptions 0x300) and loop. The descriptor NAME is
     never read anywhere in this FDE -- only options at +0x20.
  3. After the loop -- including the empty-list case, which jumps
     straight here (0x5e5a049 -> 0x5e5a0e8): call
     DBImpl::ValidateOptions(db_options) -- 0x5e59cd0, the
     one-argument overload, sret temp at (%rsp) -- then MOVE the
     temp into out (see 4) and return out. The DB-options check
     runs exactly once, after every column family passed.
  4. The Status move (twice: 0x5e5a06f..0x5e5a0b9 after the per-CF
     call, 0x5e5a0f3..0x5e5a139 after the DB-options call): copy
     the temp's code u32 (+0x0) and subcode u16 (+0x4) into out,
     take the temp's state_ ptr (+0x8) into out, zero the temp's
     code/subcode/state_, then -- only if out's OLD state_ was
     non-null -- free it with operator delete[] (PLT 0x63f0dc0).
     The move transfers ownership: the old out state_ is freed,
     the new state_ is shared with no copy, and the temp is left
     as a null OK status. (The `movzwl (%rsp),%eax` at 0x5e5a076
     is dead -- its result is never used; the gate reads out.code
     fresh at 0x5e5a0be.)
  5. The gate (0x5e5a0be..0x5e5a0c3): `movzbl (%rbx),%eax; test
     %al,%al; je` -- only the code BYTE at out+0x0 is tested.
     Subcode and state_ never decide anything in this FDE.
  6. Epilogue (0x5e5a0c5..0x5e5a0e4): stack-canary check
     (`mov 0x18(%rsp),%rax; sub %fs:0x28,%rax; jne
     __stack_chk_fail`), add $0x20,%rsp; pop rbx/rbp/r12/r13/r14;
     ret rax = out.

  The LSDA call-site table (decoded from .gcc_except_table with
  the repo's tools/fde_extents.py FDE index -- main LSDA at
  0x40fa2d, 10 bytes, header ff ff 01 06 + 1 call-site entry;
  .cold LSDA at 0x40fa37, 8 bytes, header ff ff 01 04 + 1 entry).
  One guarded range in the main FDE:

    FDE+0x6a..+0xf3 (0x5e5a06a..0x5e5a0f3) -- both ValidateOptions
                      calls AND the four delete[] calls -> pad
                      0x5e5a145, action 0 (cleanup only, no catch)

  The pad (0x5e5a145..0x5e5a14f) is one endbr64 stub: `mov
  %rax,%rbp` (the exception object into rbp) then `jmp 0x5e59fd4`
  into .cold. .cold (0x5e59fd4..0x5e59fff) frees out.state_ if
  non-null (0x5e59fd4..0x5e59fdd, delete[] PLT 0x63f0dc0),
  checks the stack canary (0x5e59fe2..0x5e59ff0, __stack_chk_fail
  on mismatch) and resumes unwinding with _Unwind_Resume(%rbp)
  (0x5e59ff2..0x5e59ff9). It never touches the temp status on the
  stack -- the throwing call never completed its sret store -- and
  it never touches any descriptor. The .cold LSDA routes its own
  _Unwind_Resume call (FDE+0x21..+0x26) to NO pad (already inside
  the cleanup); the __stack_chk_fail call has no entry.

  The two callees are ORACLES in this packet (their bodies are not
  reconstructed here; the packet pins the dispatcher's loop, move,
  gate, LSDA and pad, and the call order/targets):

  * ColumnFamilyData::ValidateOptions 0x5d8e3b0 (1555 B,
    census-bound, member 4d429ab1cb2d8f8b-column_family.o):
    upstream (db/column_family.cc, read live this cycle via the
    rust-rocksdb mirror of the same-era source) runs, in order,
    CheckCompressionSupported, then -- only if the DB options
    allow concurrent memtable writes -- CheckConcurrentWritesSupported,
    then the unordered_write + max_successive_merges rule, then
    CheckCFPathsSupported, then the ttl / periodic-compaction
    table-factory rules. The reference oracle in this tool follows
    that check order; its message wordings are model wording except
    where quoted verbatim from the upstream read (see
    CF_VALIDATE_NOTES). The 0x5d8e3b0 body itself is an open
    follow-up candidate.
  * DBImpl::ValidateOptions(const DBOptions&) 0x5e59cd0 (771 B,
    census-bound, member 4d429ab1cb2d8f8b-db_impl_open.o, 21
    relocations): upstream db/db_impl/db_impl_open.cc:392-484, read
    live this cycle (meta/rocksdb v8.1.1), runs nine checks in
    order -- db_paths.size() > 4, allow_mmap_reads &&
    use_direct_reads, allow_mmap_writes &&
    use_direct_io_for_flush_and_compaction, keep_log_file_num == 0,
    unordered_write && !allow_concurrent_memtable_write,
    unordered_write && enable_pipelined_write, atomic_flush &&
    enable_pipelined_write, atomic_flush && best_efforts_recovery,
    use_direct_io_for_flush_and_compaction &&
    writable_file_max_buffer_size == 0 -- and returns OK otherwise.
    The reference oracle in this tool implements those nine checks
    with the upstream messages quoted verbatim. The 0x5e59cd0 body
    itself is an open follow-up candidate.

  Binary-vs-source observation (recorded, not hidden): the binary
  calls ColumnFamilyData::ValidateOptions per column family, NOT
  the free function rocksdb::ValidateOptions(DBOptions,
  ColumnFamilyOptions) 0x60b94c0 (options_helper.o) -- the
  anonymous-namespace ValidateOptionsByTable helper in
  db_impl_open.cc calls the free function, but DBImpl::ValidateOptions
  does not use that helper. The binary also returns the moved
  status directly (no extra copy), and the empty-list path skips
  the loop entirely by jumping to the DB-options call.
"""

import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
MAIN_START, MAIN_END = 0x5E5A000, 0x5E5A151
COLD_START, COLD_END = 0x5E59FD4, 0x5E59FFF
MAIN_BODY_SHA256 = "8b4ef72750b4932b47334802a85dd4030dab7985dc7cbf1a964e4f8490d1b7c7"
MAIN_SOURCE_SHA256 = "b3d3ffa353d65c669b904a080ecb7c57e809e43d76a77611456c4eeacb01dab8"
COLD_BODY_SHA256 = "9a82fbb229028dc489614db7989d2521b930301f6fda856b380bed01ed468da2"
MAIN_LSDA_VA = 0x40FA2D
MAIN_LSDA_HEX = "ffff01066a8901c50200"
COLD_LSDA_VA = 0x40FA37
COLD_LSDA_HEX = "ffff010421050000"
CF_VALIDATE_ADDR = 0x5D8E3B0
DB_VALIDATE_ADDR = 0x5E59CD0
CALLER_SITE = 0x5E62E52
CALLER_FDE = 0x5E62C50  # rocksdb::DBImpl::Open
DESCRIPTOR_STRIDE = 0x320
DESCRIPTOR_OPTIONS_OFF = 0x20
K_DEFAULT_TTL = 0xFFFFFFFFFFFFFFFE
K_MAX_UINT64 = 0xFFFFFFFFFFFFFFFF

PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / \
    "re-002-node115-rocksdb-dbimpl-validate-options-115"
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
# RocksDB Status::SubCode (v8.1.1); the dispatcher copies it opaquely.
SUBCODE = {
    "kNone": 0, "kMutexTimeout": 1, "kLockTimeout": 2, "kLockLimit": 3,
    "kNoSpace": 4, "kDeadlock": 5, "kStaleFile": 6, "kMemoryLimit": 7,
    "kSpaceLimit": 8, "kPathNotFound": 9, "kMergeOperandsInsufficient": 10,
}

# CompressionType names (include/rocksdb/types.h, v8.1.1).
COMPRESSION_TYPES = [
    "kNoCompression", "kSnappyCompression", "kZlibCompression",
    "kBZip2Compression", "kLZ4Compression", "kLZ4HCCompression",
    "kXpressCompression", "kZSTD", "kZSTDNotFinalCompression",
]
COMPACTION_STYLES = ["kCompactionStyleLevel", "kCompactionStyleUniversal",
                     "kCompactionStyleFIFO", "kCompactionStyleNone"]


class BadAlloc(Exception):
    """std::bad_alloc raised inside a callee (heap allocation failed)."""


class StackCheckFailed(Exception):
    """__stack_chk_fail: the stack canary did not match."""


class ValidateOptionsThrow(Exception):
    """An oracle raised while the dispatcher was inside the LSDA
    guarded range; `cleanup_freed` lists the state_ ids the .cold
    pad freed (out.state_, if non-null) before _Unwind_Resume."""

    def __init__(self, cause, cleanup_freed):
        super().__init__(str(cause))
        self.cause = cause
        self.cleanup_freed = cleanup_freed


def _state_id(message):
    """Deterministic heap id for a Status state_ buffer."""
    return "state:" + hashlib.sha256(message.encode()).hexdigest()[:16]


class Status:
    """A RocksDB Status as the binary lays it out (16 bytes):

    +0x0 code u32 (low byte is the Code enum), +0x4 subcode u16,
    +0x6 two padding bytes the binary never writes (modelled zero),
    +0x8 state_ (None = nullptr, else a heap message id)."""

    __slots__ = ("code", "subcode", "state")

    def __init__(self, code=0, subcode=0, state=None):
        self.code = code
        self.subcode = subcode
        self.state = state  # None, or a message string

    @classmethod
    def ok(cls):
        return cls(0, 0, None)

    @classmethod
    def error(cls, code_name, message, subcode=0):
        return cls(CODE[code_name], subcode, message)

    def is_ok(self):
        return self.code == 0

    def state_id(self):
        return None if self.state is None else _state_id(self.state)

    def image(self):
        buf = bytearray(16)
        struct.pack_into("<I", buf, 0, self.code)
        struct.pack_into("<H", buf, 4, self.subcode)
        struct.pack_into("<Q", buf, 8, 0 if self.state is None else
                         int(self.state_id()[6:], 16))
        return bytes(buf)

    def as_dict(self):
        return {"code": self.code,
                "code_name": CODE_NAME.get(self.code, "?"),
                "subcode": self.subcode, "state": self.state}

    def __eq__(self, other):
        return isinstance(other, Status) and \
            (self.code, self.subcode, self.state) == \
            (other.code, other.subcode, other.state)

    def __repr__(self):
        return "Status(%s, sub=%d, state=%r)" % (
            CODE_NAME.get(self.code, self.code), self.subcode, self.state)


def move_status(dst, src, freed):
    """The binary Status move (0x5e5a06f..0x5e5a0b9 and
    0x5e5a0f3..0x5e5a139): copy code u32 + subcode u16 + state_ ptr
    from src into dst, zero src, then delete[] dst's OLD state_ if
    it was non-null (recorded in `freed`)."""
    old_state = dst.state
    dst.code, dst.subcode, dst.state = src.code, src.subcode, src.state
    src.code, src.subcode, src.state = 0, 0, None
    if old_state is not None:
        freed.append(_state_id(old_state))
    return dst


# ---------------------------------------------------------------- oracles

def default_db_options():
    """DBOptions fields the 1-arg reference oracle reads. Defaults
    are the upstream v8.1.1 defaults for these fields (options.h);
    they are model inputs, not binary claims."""
    return {
        "db_paths": [],  # list of {"path": str, "target_size": int}
        "allow_mmap_reads": False,
        "use_direct_reads": False,
        "allow_mmap_writes": False,
        "use_direct_io_for_flush_and_compaction": False,
        "keep_log_file_num": 1000,
        "unordered_write": False,
        "allow_concurrent_memtable_write": False,
        "enable_pipelined_write": False,
        "atomic_flush": False,
        "best_efforts_recovery": False,
        "writable_file_max_buffer_size": 1048576,
    }


def default_cf_options():
    """ColumnFamilyOptions fields the per-CF reference oracle reads.
    Defaults are the upstream v8.1.1 defaults for these fields;
    they are model inputs, not binary claims."""
    return {
        "compression": "kSnappyCompression",
        "compression_per_level": [],
        "compression_opts": {
            "zstd_max_train_bytes": 0,
            "use_zstd_dict_trainer": False,
            "max_dict_bytes": 0,
        },
        "blob_compression_type": "kNoCompression",
        "inplace_update_support": False,
        "memtable_concurrent": True,
        "max_successive_merges": 0,
        "compaction_style": "kCompactionStyleLevel",
        "cf_paths": [],
        "ttl": 0,
        "table_factory": "BlockBasedTableFactory",
        "periodic_compaction_seconds": 0,
    }


def validate_db_options_reference(db_options):
    """Reference oracle for DBImpl::ValidateOptions(db_options)
    0x5e59cd0: the nine checks of upstream
    db/db_impl/db_impl_open.cc:392-484 (meta/rocksdb v8.1.1, read
    live this cycle), in order, with the upstream messages quoted
    verbatim. Returns a Status; never raises."""
    if len(db_options["db_paths"]) > 4:
        return Status.error(
            "kNotSupported",
            "More than four DB paths are not supported yet. ")
    if db_options["allow_mmap_reads"] and db_options["use_direct_reads"]:
        return Status.error(
            "kNotSupported",
            "If memory mapped reads (allow_mmap_reads) are enabled "
            "then direct I/O reads (use_direct_reads) must be disabled. ")
    if db_options["allow_mmap_writes"] and \
            db_options["use_direct_io_for_flush_and_compaction"]:
        return Status.error(
            "kNotSupported",
            "If memory mapped writes (allow_mmap_writes) are enabled "
            "then direct I/O writes "
            "(use_direct_io_for_flush_and_compaction) must be disabled. ")
    if db_options["keep_log_file_num"] == 0:
        return Status.error(
            "kInvalidArgument", "keep_log_file_num must be greater than 0")
    if db_options["unordered_write"] and \
            not db_options["allow_concurrent_memtable_write"]:
        return Status.error(
            "kInvalidArgument",
            "unordered_write is incompatible with "
            "!allow_concurrent_memtable_write")
    if db_options["unordered_write"] and \
            db_options["enable_pipelined_write"]:
        return Status.error(
            "kInvalidArgument",
            "unordered_write is incompatible with enable_pipelined_write")
    if db_options["atomic_flush"] and db_options["enable_pipelined_write"]:
        return Status.error(
            "kInvalidArgument",
            "atomic_flush is incompatible with enable_pipelined_write")
    if db_options["atomic_flush"] and db_options["best_efforts_recovery"]:
        return Status.error(
            "kInvalidArgument",
            "atomic_flush is currently incompatible with "
            "best-efforts recovery")
    if db_options["use_direct_io_for_flush_and_compaction"] and \
            db_options["writable_file_max_buffer_size"] == 0:
        return Status.error(
            "kInvalidArgument",
            "writes in direct IO require writable_file_max_buffer_size > 0")
    return Status.ok()


def _check_compression_supported(cf_options, supported,
                                 zstd_train_supported=True,
                                 zstd_finalize_supported=True):
    """Upstream CheckCompressionSupported (db/column_family.cc).
    `supported` is the set of linked compression types -- an
    explicit model input, not a binary claim. Messages quoted
    verbatim from the upstream read."""
    if cf_options["compression_per_level"]:
        for level in cf_options["compression_per_level"]:
            if level not in supported:
                return Status.error(
                    "kInvalidArgument",
                    "Compression type %s is not linked with the binary."
                    % level)
    elif cf_options["compression"] not in supported:
        return Status.error(
            "kInvalidArgument",
            "Compression type %s is not linked with the binary."
            % cf_options["compression"])
    opts = cf_options["compression_opts"]
    if opts["zstd_max_train_bytes"] > 0:
        if opts["use_zstd_dict_trainer"]:
            if not zstd_train_supported:
                return Status.error(
                    "kInvalidArgument",
                    "zstd dictionary trainer cannot be used because "
                    "ZSTD 1.1.3+ is not linked with the binary.")
        elif not zstd_finalize_supported:
            return Status.error(
                "kInvalidArgument",
                "zstd finalizeDictionary cannot be used because "
                "ZSTD 1.4.5+ is not linked with the binary.")
        if opts["max_dict_bytes"] == 0:
            return Status.error(
                "kInvalidArgument",
                "The dictionary size limit "
                "(`CompressionOptions::max_dict_bytes`) should be "
                "nonzero if we're using zstd's dictionary generator.")
    if cf_options["blob_compression_type"] not in supported:
        return Status.error(
            "kInvalidArgument",
            "The specified blob compression type %s is not available."
            % cf_options["blob_compression_type"])
    return Status.ok()


def _check_concurrent_writes_supported(cf_options):
    """Upstream CheckConcurrentWritesSupported (db/column_family.cc).
    The inplace-update message is quoted verbatim; the memtable
    message is model wording (the upstream read's rendering drops
    a word there)."""
    if cf_options["inplace_update_support"]:
        return Status.error(
            "kInvalidArgument",
            "In-place memtable updates (inplace_update_support) is "
            "not compatible with concurrent writes "
            "(allow_concurrent_memtable_write)")
    if not cf_options["memtable_concurrent"]:
        return Status.error(
            "kInvalidArgument",
            "Memtable does not support concurrent writes "
            "(allow_concurrent_memtable_write)")
    return Status.ok()


def _check_cf_paths_supported(db_options, cf_options):
    """Upstream CheckCFPathsSupported (db/column_family.cc); messages
    quoted verbatim."""
    style = cf_options["compaction_style"]
    if style not in ("kCompactionStyleUniversal", "kCompactionStyleLevel"):
        if len(cf_options["cf_paths"]) > 1:
            return Status.error(
                "kNotSupported",
                "More than one CF paths are only supported in "
                "universal and level compaction styles. ")
        if not cf_options["cf_paths"] and len(db_options["db_paths"]) > 1:
            return Status.error(
                "kNotSupported",
                "More than one DB paths are only supported in "
                "universal and level compaction styles. ")
    return Status.ok()


def validate_cf_options_reference(db_options, cf_options, supported=None,
                                  zstd_train_supported=True,
                                  zstd_finalize_supported=True):
    """Reference oracle for ColumnFamilyData::ValidateOptions
    0x5d8e3b0: the check order of upstream db/column_family.cc
    (read live this cycle via the rust-rocksdb mirror of the
    same-era source): compression, then concurrent writes (only
    when the DB options allow them), then the unordered_write +
    max_successive_merges rule, then CF paths, then the ttl and
    periodic-compaction table-factory rules. The ttl message is
    quoted verbatim; the unordered_write and periodic-compaction
    messages are model wording (the upstream read cut them off).
    Returns a Status; never raises."""
    if supported is None:
        supported = set(COMPRESSION_TYPES)
    s = _check_compression_supported(
        cf_options, supported, zstd_train_supported, zstd_finalize_supported)
    if s.is_ok() and db_options["allow_concurrent_memtable_write"]:
        s = _check_concurrent_writes_supported(cf_options)
    if s.is_ok() and db_options["unordered_write"] and \
            cf_options["max_successive_merges"] != 0:
        s = Status.error(
            "kInvalidArgument",
            "unordered_write is incompatible with max_successive_merges")
    if s.is_ok():
        s = _check_cf_paths_supported(db_options, cf_options)
    if s.is_ok() and cf_options["ttl"] > 0 and \
            cf_options["ttl"] != K_DEFAULT_TTL:
        if cf_options["table_factory"] != "BlockBasedTableFactory":
            s = Status.error(
                "kNotSupported",
                "TTL is only supported in Block-Based Table format. ")
    if s.is_ok() and cf_options["periodic_compaction_seconds"] > 0 and \
            cf_options["periodic_compaction_seconds"] < K_MAX_UINT64:
        if cf_options["table_factory"] != "BlockBasedTableFactory":
            s = Status.error(
                "kNotSupported",
                "Periodic compaction is only supported in "
                "Block-Based Table format. ")
    return s


CF_VALIDATE_NOTES = (
    "Reference oracle only: the 0x5d8e3b0 body (1555 B, census-bound) "
    "is NOT reconstructed in this packet; it is an open follow-up. "
    "The oracle follows the upstream check order; message wordings "
    "are model wording except CheckCompressionSupported, "
    "CheckConcurrentWritesSupported (inplace-update arm), "
    "CheckCFPathsSupported and the TTL arm, which are quoted verbatim "
    "from the upstream read."
)


# ---------------------------------------------------------------- dispatcher

class ColumnFamilyDescriptor:
    """A ColumnFamilyDescriptor as the binary walks it: name string
    at +0x00 (0x20 bytes, NEVER read by this FDE) and the
    ColumnFamilyOptions at +0x20; stride 0x320."""

    __slots__ = ("name", "options")

    def __init__(self, name, options):
        self.name = name
        self.options = options

    def as_dict(self):
        return {"name": self.name, "options": self.options}


def validate_options(db_options, descriptors,
                     cf_validate=None, db_validate=None,
                     canary_ok=True, trace=None):
    """The reconstructed dispatcher: DBImpl::ValidateOptions
    (0x5e5a000..0x5e5a151).

    `cf_validate(db_options, cf_options)` defaults to the reference
    oracle; `db_validate(db_options)` defaults to the 1-arg
    reference oracle. Either may raise (e.g. BadAlloc): the LSDA
    pad then frees out.state_ (if non-null) and re-raises, modelled
    as ValidateOptionsThrow. `canary_ok=False` models a stack-canary
    mismatch at the return path (__stack_chk_fail). `trace`, when
    given, records the freed state_ ids in order.
    Returns the resulting Status."""
    if cf_validate is None:
        cf_validate = validate_cf_options_reference
    if db_validate is None:
        db_validate = validate_db_options_reference
    freed = [] if trace is None else trace
    out = Status.ok()
    temp = Status()
    try:
        for desc in descriptors:
            # call 0x5d8e3b0: sret temp, db_options, &desc.options
            result = cf_validate(db_options, desc.options)
            temp.code, temp.subcode, temp.state = \
                result.code, result.subcode, result.state
            move_status(out, temp, freed)
            if out.code != 0:
                if not canary_ok:
                    raise StackCheckFailed("stack canary mismatch")
                return out
        # call 0x5e59cd0: sret temp, db_options
        result = db_validate(db_options)
        temp.code, temp.subcode, temp.state = \
            result.code, result.subcode, result.state
        move_status(out, temp, freed)
    except (BadAlloc, Exception) as err:
        if isinstance(err, StackCheckFailed):
            raise
        # LSDA pad 0x5e5a145 -> .cold 0x5e59fd4: free out.state_ if
        # non-null, check the canary, _Unwind_Resume.
        cleanup = []
        if out.state is not None:
            cleanup.append(_state_id(out.state))
            out.state = None
        if not canary_ok:
            raise StackCheckFailed("stack canary mismatch in .cold")
        raise ValidateOptionsThrow(err, cleanup)
    if not canary_ok:
        raise StackCheckFailed("stack canary mismatch")
    return out

# ---------------------------------------------------------------- cases

def _jsonable(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _unjsonable(value):
    if isinstance(value, dict) and set(value) == {"bytes_hex"}:
        return bytes.fromhex(value["bytes_hex"])
    if isinstance(value, dict):
        return {k: _unjsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unjsonable(v) for v in value]
    return value


# Scripted per-CF outcomes for the loop group: each entry is either
# {"ok": true} (reference oracle, default options), a failure
# produced by a crafted options override, or {"raise": "BadAlloc"}.
_CF_FAIL_VARIANTS = [
    # (label, cf_options overrides, expected code)
    ("bad-compression",
     {"compression": "kZSTDNotFinalCompression",
      "compression_per_level": []}, "kInvalidArgument"),
    ("bad-compression-level",
     {"compression_per_level": ["kSnappyCompression",
                                "kBZip2Compression", "kNoSuchType"]},
     "kInvalidArgument"),
    ("bad-blob-compression",
     {"blob_compression_type": "kNoSuchType"}, "kInvalidArgument"),
    ("cf-paths-many",
     {"compaction_style": "kCompactionStyleFIFO",
      "cf_paths": [{"path": "/a", "target_size": 1},
                   {"path": "/b", "target_size": 2}]}, "kNotSupported"),
    ("ttl-plain-table",
     {"ttl": 3600, "table_factory": "PlainTableFactory"}, "kNotSupported"),
    ("periodic-plain-table",
     {"periodic_compaction_seconds": 3600,
      "table_factory": "PlainTableFactory"}, "kNotSupported"),
]

_DB_FAIL_VARIANTS = [
    ("db-paths-5", {"db_paths": [{"path": "/p%d" % i, "target_size": 1}
                                 for i in range(5)]}, "kNotSupported"),
    ("mmap-direct-read", {"allow_mmap_reads": True, "use_direct_reads": True},
     "kNotSupported"),
    ("mmap-direct-write",
     {"allow_mmap_writes": True,
      "use_direct_io_for_flush_and_compaction": True}, "kNotSupported"),
    ("keep-log-zero", {"keep_log_file_num": 0}, "kInvalidArgument"),
    ("unordered-no-concurrent",
     {"unordered_write": True, "allow_concurrent_memtable_write": False},
     "kInvalidArgument"),
    ("unordered-pipelined",
     {"unordered_write": True, "allow_concurrent_memtable_write": True,
      "enable_pipelined_write": True}, "kInvalidArgument"),
    ("atomic-pipelined",
     {"atomic_flush": True, "enable_pipelined_write": True},
     "kInvalidArgument"),
    ("atomic-best-efforts",
     {"atomic_flush": True, "best_efforts_recovery": True},
     "kInvalidArgument"),
    ("direct-io-no-buffer",
     {"use_direct_io_for_flush_and_compaction": True,
      "writable_file_max_buffer_size": 0}, "kInvalidArgument"),
]


def _db_options_with(overrides):
    opts = default_db_options()
    opts.update(overrides)
    return opts


def _cf_options_with(overrides):
    opts = default_cf_options()
    opts.update(overrides)
    return opts


def _status_dict(status):
    return {"code": status.code, "code_name": CODE_NAME[status.code],
            "subcode": status.subcode, "state": status.state,
            "image_hex": status.image().hex()}


def run_case(inputs):
    """Run one case and return the expected outputs."""
    group = inputs["group"]
    if group == "loop":
        db_opts = _db_options_with(inputs.get("db_overrides", {}))
        descs = []
        for d in inputs["descriptors"]:
            descs.append(ColumnFamilyDescriptor(
                d["name"], _cf_options_with(d.get("overrides", {}))))
        supported = set(inputs.get("supported", COMPRESSION_TYPES))
        freed = []
        calls = {"cf": 0, "db": 0}

        def cf_validate(db_o, cf_o):
            calls["cf"] += 1
            return validate_cf_options_reference(db_o, cf_o, supported)

        def db_validate(db_o):
            calls["db"] += 1
            return validate_db_options_reference(db_o)

        result = validate_options(db_opts, descs, cf_validate, db_validate,
                                  trace=freed)
        return {"result": _status_dict(result), "cf_calls": calls["cf"],
                "db_calls": calls["db"], "freed": freed,
                "descriptors": len(descs)}
    if group == "move":
        dst = Status(inputs["dst"]["code"], inputs["dst"].get("subcode", 0),
                     inputs["dst"].get("state"))
        src = Status(inputs["src"]["code"], inputs["src"].get("subcode", 0),
                     inputs["src"].get("state"))
        freed = []
        move_status(dst, src, freed)
        return {"dst": _status_dict(dst), "src": _status_dict(src),
                "freed": freed}
    if group == "throw":
        db_opts = _db_options_with(inputs.get("db_overrides", {}))
        descs = [ColumnFamilyDescriptor(d["name"],
                                        _cf_options_with(d.get("overrides", {})))
                 for d in inputs["descriptors"]]
        fail_at = inputs["fail_at"]  # "cf:<index>" or "db"
        prior_state = inputs.get("prior_state")
        freed = []

        def cf_validate(db_o, cf_o, _idx=[0]):
            i = _idx[0]
            _idx[0] += 1
            if fail_at == "cf:%d" % i:
                raise BadAlloc("simulated BadAlloc in per-CF validation")
            return validate_cf_options_reference(db_o, cf_o)

        def db_validate(db_o):
            if fail_at == "db":
                raise BadAlloc("simulated BadAlloc in DB validation")
            return validate_db_options_reference(db_o)

        # Seed out with a prior non-OK status carrying a state_, by
        # validating one failing CF first when requested: the model
        # does this by pre-moving a status into out via a scripted
        # first call. Simpler: prior_state is modelled as the state_
        # of the status the previous loop iteration moved in -- the
        # throw cases that need it use a failing-then-throwing script.
        if prior_state is not None:
            # The first descriptor returns OK *with* a state_
            # (code 0, non-null state_): the dispatcher moves it
            # into out and keeps looping, so out holds a state_
            # when the second call throws and the pad must free it.
            # (A plain error return would make the dispatcher return
            # at once, so it can never seed the pad.)
            def cf_validate_seeded(db_o, cf_o, _idx=[0]):
                i = _idx[0]
                _idx[0] += 1
                if i == 0:
                    return Status(0, 0, prior_state)
                if fail_at == "cf:%d" % i:
                    raise BadAlloc(
                        "simulated BadAlloc in per-CF validation")
                return validate_cf_options_reference(db_o, cf_o)
            cf_validate = cf_validate_seeded
        try:
            result = validate_options(db_opts, descs, cf_validate,
                                      db_validate,
                                      canary_ok=inputs.get("canary_ok", True),
                                      trace=freed)
        except ValidateOptionsThrow as err:
            return {"error": "ValidateOptionsThrow",
                    "cause": type(err.cause).__name__,
                    "cause_message": str(err.cause),
                    "cleanup_freed": err.cleanup_freed,
                    "freed_before_throw": freed}
        except StackCheckFailed as err:
            return {"error": "StackCheckFailed", "message": str(err),
                    "freed_before_throw": freed}
        return {"error": None, "result": _status_dict(result),
                "freed": freed}
    if group == "bindings":
        db_opts = _db_options_with(inputs.get("db_overrides", {}))
        descs = [ColumnFamilyDescriptor(d["name"],
                                        _cf_options_with(d.get("overrides", {})))
                 for d in inputs["descriptors"]]
        result = validate_options(db_opts, descs)
        return {
            "caller_site": inputs["caller_site"],
            "result": _status_dict(result),
            "result_sha256": hashlib.sha256(
                result.image()).hexdigest(),
            "name_independent": True,
            "main_body_sha256": MAIN_BODY_SHA256,
            "main_source_sha256": MAIN_SOURCE_SHA256,
            "cold_body_sha256": COLD_BODY_SHA256,
            "main_lsda_hex": MAIN_LSDA_HEX,
            "cold_lsda_hex": COLD_LSDA_HEX,
        }
    raise ValueError("unknown group %r" % group)


_NAME_POOL = ["default", "cf-a", "cf-b", "user-cf-01", "x" * 32, ""]


def _gen_group(rng, group, n):
    rows = []
    for i in range(n):
        case_id = "%s-%03d" % (group, i)
        inputs = {"case_id": case_id, "group": group}
        if group == "loop":
            mode = i % 10
            n_desc = rng.choice([0, 1, 1, 2, 2, 3, 4, 5])
            descriptors = []
            fail_pos = None
            if mode in (1, 2, 3) and n_desc > 0:
                fail_pos = rng.randrange(n_desc)
            for j in range(n_desc):
                entry = {"name": rng.choice(_NAME_POOL)}
                if j == fail_pos:
                    label, overrides, _code = rng.choice(_CF_FAIL_VARIANTS)
                    entry["overrides"] = overrides
                    entry["fail_label"] = label
                descriptors.append(entry)
            inputs["descriptors"] = descriptors
            db_overrides = {}
            if mode in (4, 5):
                _label, overrides, _code = rng.choice(_DB_FAIL_VARIANTS)
                db_overrides = overrides
            elif mode == 6:
                # DB failure masked by an earlier CF failure.
                if n_desc == 0:
                    descriptors.append({"name": "default"})
                    n_desc = 1
                descriptors[0]["overrides"] = \
                    rng.choice(_CF_FAIL_VARIANTS)[1]
                _label, overrides, _code = rng.choice(_DB_FAIL_VARIANTS)
                db_overrides = overrides
            inputs["db_overrides"] = db_overrides
            if rng.random() < 0.2:
                supported = [c for c in COMPRESSION_TYPES
                             if rng.random() < 0.8]
                inputs["supported"] = supported
        elif group == "move":
            def _st():
                r = rng.random()
                if r < 0.35:
                    return {"code": 0, "subcode": 0, "state": None}
                code = rng.choice([1, 2, 3, 4, 5, 9, 15])
                state = None
                if rng.random() < 0.7:
                    state = rng.choice(
                        ["keep_log_file_num must be greater than 0",
                         "More than four DB paths are not supported yet. ",
                         "custom state message", "x"])
                return {"code": code,
                        "subcode": rng.choice([0, 0, 1, 9]),
                        "state": state}
            inputs["dst"] = _st()
            inputs["src"] = _st()
        elif group == "throw":
            n_desc = rng.choice([1, 2, 3, 4])
            descriptors = [{"name": rng.choice(_NAME_POOL)}
                           for _ in range(n_desc)]
            mode = i % 5
            if mode in (0, 1, 2):
                inputs["fail_at"] = "cf:%d" % rng.randrange(n_desc)
            elif mode == 3:
                inputs["fail_at"] = "db"
            else:
                # Throw after a prior failure moved a state_ into out.
                inputs["fail_at"] = "cf:%d" % (n_desc - 1 if n_desc > 1
                                               else 0)
                inputs["prior_state"] = rng.choice(
                    ["keep_log_file_num must be greater than 0",
                     "More than four DB paths are not supported yet. "])
                if n_desc < 2:
                    descriptors.append({"name": "second"})
                    inputs["fail_at"] = "cf:1"
            inputs["descriptors"] = descriptors
            if rng.random() < 0.15:
                inputs["canary_ok"] = False
        elif group == "bindings":
            n_desc = rng.choice([0, 1, 2, 3])
            descriptors = []
            for _ in range(n_desc):
                entry = {"name": rng.choice(_NAME_POOL)}
                if rng.random() < 0.3:
                    _label, overrides, _code = rng.choice(_CF_FAIL_VARIANTS)
                    entry["overrides"] = overrides
                descriptors.append(entry)
            inputs["descriptors"] = descriptors
            inputs["db_overrides"] = {}
            if rng.random() < 0.25:
                _label, overrides, _code = rng.choice(_DB_FAIL_VARIANTS)
                inputs["db_overrides"] = overrides
            inputs["caller_site"] = "0x%x" % CALLER_SITE
        expected = run_case(inputs)
        rows.append((group, case_id, inputs, expected))
    return rows


def write_cases():
    all_rows = []
    for gi, group in enumerate(["loop", "move", "throw", "bindings"]):
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
    print("verify: %d cases, %d mismatches" % (len(rows), mismatches))
    return mismatches == 0 and len(rows) == 2400


# ---------------------------------------------------------------- live

def _bin_path():
    for path in (Path(__file__).resolve().parents[1] / 'artifacts' / 'node' / '115' / 'hl-node',):
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
    main = _read_va(data, secs, MAIN_START, MAIN_END - MAIN_START)
    legs.append(("main body hash",
                 hashlib.sha256(main).hexdigest() == MAIN_BODY_SHA256,
                 hashlib.sha256(main).hexdigest()[:16]))
    cold = _read_va(data, secs, COLD_START, COLD_END - COLD_START)
    legs.append(("cold body hash",
                 hashlib.sha256(cold).hexdigest() == COLD_BODY_SHA256,
                 hashlib.sha256(cold).hexdigest()[:16]))
    import json as _json
    census = _json.load(open(
        Path(__file__).resolve().parents[1] / "research" / "work-items" /
        "RE-002-node115-vendor-census" / "census.json"))["records"]
    rec = {r["start"]: r for r in census}[MAIN_START]
    zeroed = bytearray(main)
    for rel in rec["relocations"]:
        o, w = rel["offset"], rel["width"]
        zeroed[o:o + w] = b"\x00" * w
    legs.append(("main source hash (8 relocations zeroed)",
                 hashlib.sha256(bytes(zeroed)).hexdigest()
                 == MAIN_SOURCE_SHA256,
                 hashlib.sha256(bytes(zeroed)).hexdigest()[:16]))
    legs.append(("main lsda bytes",
                 _read_va(data, secs, MAIN_LSDA_VA, 10).hex()
                 == MAIN_LSDA_HEX,
                 _read_va(data, secs, MAIN_LSDA_VA, 10).hex()))
    legs.append(("cold lsda bytes",
                 _read_va(data, secs, COLD_LSDA_VA, 8).hex()
                 == COLD_LSDA_HEX,
                 _read_va(data, secs, COLD_LSDA_VA, 8).hex()))
    return legs


def _disasm(data, secs, start, end):
    out = subprocess.check_output(
        ["objdump", "-d", "--start-address=0x%x" % start,
         "--stop-address=0x%x" % end, str(_bin_path())]).decode()
    return out


def _engine_calls():
    data = open(_bin_path(), "rb").read()
    secs = _sections(data)
    legs = []
    main_dis = _disasm(data, secs, MAIN_START, MAIN_END)
    cold_dis = _disasm(data, secs, COLD_START, COLD_END)
    legs.append(("cf-validate call 0x5d8e3b0 x1",
                 main_dis.count("call   5d8e3b0") == 1,
                 main_dis.count("call   5d8e3b0")))
    legs.append(("db-validate call 0x5e59cd0 x1",
                 main_dis.count("call   5e59cd0") == 1,
                 main_dis.count("call   5e59cd0")))
    legs.append(("operator delete[] PLT x4 in main",
                 main_dis.count("<_ZdaPv@plt>") == 4,
                 main_dis.count("<_ZdaPv@plt>")))
    legs.append(("__stack_chk_fail x1 in main",
                 main_dis.count("<__stack_chk_fail@plt>") == 1,
                 main_dis.count("<__stack_chk_fail@plt>")))
    legs.append(("delete[] + _Unwind_Resume + __stack_chk_fail in .cold",
                 cold_dis.count("<_ZdaPv@plt>") == 1 and
                 cold_dis.count("<_Unwind_Resume@plt>") == 1 and
                 cold_dis.count("<__stack_chk_fail@plt>") == 1,
                 "%d/%d/%d" % (cold_dis.count("<_ZdaPv@plt>"),
                               cold_dis.count("<_Unwind_Resume@plt>"),
                               cold_dis.count("<__stack_chk_fail@plt>"))))
    legs.append(("descriptor stride add $0x320,%rbp",
                 "add    $0x320,%rbp" in main_dis, None))
    legs.append(("options lea 0x20(%rbp),%rdx",
                 "lea    0x20(%rbp),%rdx" in main_dis, None))
    legs.append(("code-byte gate movzbl (%rbx) + test + je loop",
                 "movzbl (%rbx),%eax" in main_dis and
                 "test   %al,%al" in main_dis, None))
    legs.append(("canary load %fs:0x28 + two checks",
                 main_dis.count("%fs:0x28") == 2 and
                 cold_dis.count("%fs:0x28") == 1,
                 "%d/%d" % (main_dis.count("%fs:0x28"),
                            cold_dis.count("%fs:0x28"))))
    legs.append(("pad endbr64 + mov %rax,%rbp + jmp 0x5e59fd4",
                 "5e5a145:\tf3 0f 1e fa" in main_dis and
                 "mov    %rax,%rbp" in main_dis and
                 "jmp    5e59fd4" in main_dis, None))
    return legs


def _caller_scan():
    sys.path.insert(0, str(PACKET))
    import census as census_mod
    data = open(_bin_path(), "rb").read()
    text_va, _off, text = census_mod.load_text()
    fdes = census_mod.load_fdes()
    starts = sorted(fdes)
    rows = []
    for site, kind, target in census_mod.raw_scan(text_va, text):
        if target != MAIN_START:
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
    legs += _engine_calls()
    sites = _caller_scan()
    legs.append(("caller census: 1 call from DBImpl::Open 0x5e62e52",
                 sites == [(CALLER_SITE, "call")], sites))
    # Model end-to-end legs (reference oracles; dispatcher pinned).
    legs.append(("defaults validate OK",
                 validate_options(default_db_options(), []).is_ok(), None))
    bad = default_db_options()
    bad["keep_log_file_num"] = 0
    legs.append(("keep_log_file_num=0 -> InvalidArgument",
                 validate_options(bad, []).code
                 == CODE["kInvalidArgument"], None))
    bad5 = default_db_options()
    bad5["db_paths"] = [{"path": "/p", "target_size": 1}] * 5
    legs.append(("5 db_paths -> NotSupported",
                 validate_options(bad5, []).code
                 == CODE["kNotSupported"], None))
    cf_bad = ColumnFamilyDescriptor(
        "cf", _cf_options_with({"compression": "kNoSuchType"}))
    legs.append(("bad CF compression fails before db check",
                 validate_options(default_db_options(), [cf_bad]).code
                 == CODE["kInvalidArgument"], None))
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
