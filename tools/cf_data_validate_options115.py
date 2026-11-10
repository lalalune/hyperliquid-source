#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::ColumnFamilyData::ValidateOptions.

Target: rocksdb::ColumnFamilyData::ValidateOptions(const DBOptions&,
const ColumnFamilyOptions&) at 0x5d8e3b0..0x5d8e9c3 (1555 B, main
FDE) plus its .cold FDE at 0x5d8e356..0x5d8e3a5 (79 B), in node #115
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The validator runs the three helper oracles (CheckCompressionSupported,
CheckConcurrentWritesSupported, CheckCFPathsSupported) and seven
inline checks in the order of upstream RocksDB v8.1.1
db/column_family.cc:1364-1448, returning the first non-OK status.
The three helpers are modelled from the v8.1.1 source (their FDEs
are census-bound but their bodies are NOT reconstructed here -- the
model states which inputs each oracle reads and which messages it
can produce); the seven inline checks, the Status plumbing, the
move-assigns, the vector alloc/free and the LSDA pads are pinned
from the whole-FDE disassembly of this function.

Whole-FDE facts (verified live, see --live):
- Signature: Status by value (hidden sret out in rdi = rbp),
  db_options in rsi = r12, cf_options in rdx = rbx. Stack canary
  used (stored 0x78(%rsp), checked at the epilogue 0x5d8e457 and in
  every LSDA pad via the .cold FDE).
- Two stack temps: T1 at 0x40(%rsp) (helper-result temp, r13),
  T2 at 0x10(%rsp) (r14, shallow copy / move-assign target).
- Status byte layout (proved by the ctor 0x61cf670, same as the
  #6379 packet): code u8 +0x0, subcode u8 +0x1, severity u8 +0x2,
  padding +0x3..+0x7, state_ +0x8. Bytes +0x6..+0x7 are never
  written by any path in this FDE and are modelled zero.
- Main FDE LSDA at 0x40a30f (53 bytes): header ff ff 01, table
  length 0x31, 8 entries, all action 0 (cleanup only). Pads:
  0x607 generic (delete T2.state_ if non-null), 0x5fb dispose
  the "BlockBasedTable" string + generic (ttl IsInstanceOf),
  0x5e3 dispose the string + generic (periodic IsInstanceOf),
  0x5ef sized-delete the 20-byte vector + generic (memtable
  Status ctor). Cold FDE LSDA at 0x40a344 (8 bytes): 1 entry for
  the _Unwind_Resume call, pad 0.
- The ttl/periodic IsInstanceOf checks devirtualize: the
  table_factory vtable slot 16 function pointer is compared
  against the GOT slot 0x64eceb8 (R_X86_64_RELATIVE addend
  0x5d2e770 = Customizable::IsInstanceOf); if equal, the constprop
  clone 0x5d89e80 is called directly, else the virtual call.
- The memtable-protection check heap-allocates a 20-byte vector
  {0,1,2,4,8} (operator new(0x14), 16 B copied from .rodata
  0x4544c0, 5th int 8 stored at +0x10) and frees it with sized
  delete _ZdlPvm (0x14) on BOTH the error and the OK path.
- Blob GC range checks use comisd: NaN passes both (unordered
  sets ZF=1, so `ja` is not taken and `jbe` is taken) -- the same
  as the source `x < 0.0 || x > 1.0`, which is false for NaN.

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM. The
target binary is never executed. Status state_ buffers are
deterministic heap ids, not real pointers.
"""

import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

ARTIFACT_SHA256 = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f"
                   "249e98c3867b5301")
START = 0x5D8E3B0
END = 0x5D8E9C3
COLD_START = 0x5D8E356
COLD_END = 0x5D8E3A5
BODY_SHA256 = ("4c564ac336f94f2e9a06f9a725d47902a850a87162844c5"
               "ce7691f07672591d0")
SOURCE_SHA256 = ("7738e1c844bcbf2f687ce337478b114527447b1e9a53dc"
                 "2b8de6ca535251e564")
COLD_BODY_SHA256 = ("4df4d5cd1f379d7866ba92c9b18e0ea634492a6136623"
                    "aae87e50f435c93cd9c")
COLD_SOURCE_SHA256 = ("66b930753725447dcab71b3d141e053d0fdf2a3c43e"
                      "6a4e9e92fe0b60591d162")
RELOCATIONS = ("76:kind4;148:kind2;163:kind4;248:kind4;264:kind2;"
               "279:kind4;330:kind2;362:kind2;374:kind42;392:kind2;"
               "404:kind4;429:kind2;441:kind2;481:kind4;513:kind2;"
               "538:kind2;576:kind4;592:kind2;607:kind4;689:kind2;"
               "711:kind2;723:kind2;763:kind4;843:kind2;866:kind4;"
               "940:kind2;982:kind2;1001:kind4;1014:kind4;1067:kind2;"
               "1087:kind4;1103:kind2;1118:kind4;1170:kind2;1202:kind2;"
               "1214:kind42;1232:kind2;1244:kind4;1269:kind2;1281:kind2;"
               "1324:kind2;1336:kind2;1388:kind2;1400:kind2;1503:kind4;"
               "1515:kind2;1527:kind2;1539:kind2;1551:kind2")
COLD_RELOCATIONS = "5:kind4;20:kind4;44:kind4;57:kind4;64:kind4;73:kind4"
MEMBER = "25dac13516458d4d-column_family.o"
SYMBOL = ("_ZN7rocksdb16ColumnFamilyData15ValidateOptionsERKNS_"
          "9DBOptionsERKNS_19ColumnFamilyOptionsE")
LSDA_ADDR = 0x40A30F
COLD_LSDA_ADDR = 0x40A344
# LSDA call-site entries: (start, length, landing_pad, action).
LSDA_ENTRIES = [(75, 291, 1543, 0), (391, 5, 1531, 0),
                (480, 390, 1543, 0), (1000, 5, 1519, 0),
                (1086, 120, 1543, 0), (1231, 5, 1507, 0),
                (1367, 2, 1531, 0), (1495, 2, 1507, 0)]
COLD_LSDA_ENTRIES = [(43, 5, 0, 0)]
# Landing pads (FDE-relative) and what each pad's cleanup does.
# 0x607 generic: delete T2.state_ if non-null.
# 0x5fb ttl IsInstanceOf: dispose the "BlockBasedTable" string,
#   then generic. 0x5e3 periodic IsInstanceOf: same, via the
#   other .cold stub. 0x5ef memtable ctor: sized-delete the
#   20-byte vector, then generic.
PAD_CLEANUP = {
    0x607: ["delete_t2_state_if_nonnull"],
    0x5FB: ["dispose_block_based_table_string",
            "delete_t2_state_if_nonnull"],
    0x5E3: ["dispose_block_based_table_string",
            "delete_t2_state_if_nonnull"],
    0x5EF: ["sized_delete_vector_20B",
            "delete_t2_state_if_nonnull"],
}
# Engine callees (census-bound).
CHECK_COMPRESSION_SUPPORTED = 0x5D8DCC0
CHECK_CONCURRENT_WRITES_SUPPORTED = 0x5D8BA60
CHECK_CF_PATHS_SUPPORTED = 0x5D8BB50
STATUS_CTOR = 0x61CF670
STATUS_MOVE_ASSIGN = 0x5D89B20
STRING_CTOR = 0x5D89D40
ISINSTANCEOF_CONSTPROP = 0x5D89E80
ISINSTANCEOF_GOT_SLOT = 0x64ECEB8
ISINSTANCEOF_VTABLE_TARGET = 0x5D2E770
STACK_CHK_FAIL = 0x63F0D70
EMPTY_MSG2_ADDR = 0x4376FD

CODE = {"kOk": 0, "kNotFound": 1, "kCorruption": 2, "kNotSupported": 3,
        "kInvalidArgument": 4, "kIOError": 5, "kMergeInProgress": 6,
        "kIncomplete": 7, "kShutdownInProgress": 8, "kTimedOut": 9,
        "kAborted": 10, "kBusy": 11, "kExpired": 12, "kTryAgain": 13,
        "kCompactionTooLarge": 14, "kColumnFamilyDropped": 15}
CODE_NAME = {v: k for k, v in CODE.items()}

K_DEFAULT_TTL = 0xFFFFFFFFFFFFFFFE
K_DEFAULT_PERIODIC_COMP_SECS = 0xFFFFFFFFFFFFFFFE
MEMTABLE_PROTECTION_SUPPORTED = [0, 1, 2, 4, 8]

# The seven inline error messages, byte-verified against .rodata.
# (n, code_name, message, address, length, tail)
MESSAGES = {
    "unordered": ("max_successive_merges > 0 is incompatible with "
                  "unordered_write", 0x9601D8, 62),
    "ttl": ("TTL is only supported in Block-Based Table format. ",
            0x96B4C0, 51),
    "periodic": ("Periodic Compaction is only supported in "
                 "Block-Based Table format. ", 0x9669D0, 67),
    "age": ("The age cutoff for blob garbage collection should be "
            "in the range [0.0, 1.0].", 0x96BDE8, 77),
    "force": ("The garbage ratio threshold for forcing blob garbage "
              "collection should be in the range [0.0, 1.0].",
              0x958E00, 98),
    "fifo": ("FIFO compaction only supported with max_open_files = -1.",
             0x95B860, 56),
    "memtable": ("Memtable per key-value checksum protection only "
                 "supports 0, 1, 2, 4 or 8 bytes per key.",
                 0x96A950, 87),
}
# The ten checks in binary order: (n, kind, code_name, message_key).
# Oracle entries have message_key None: their message depends on
# the oracle inputs (see the oracle functions).
CHECKS = [
    (1, "oracle", "kInvalidArgument", None),   # CheckCompressionSupported
    (2, "oracle", "kInvalidArgument", None),   # CheckConcurrentWritesSupported
    (3, "inline", "kInvalidArgument", "unordered"),
    (4, "oracle", "kNotSupported", None),      # CheckCFPathsSupported
    (5, "inline", "kNotSupported", "ttl"),
    (6, "inline", "kNotSupported", "periodic"),
    (7, "inline", "kInvalidArgument", "age"),
    (8, "inline", "kInvalidArgument", "force"),
    (9, "inline", "kNotSupported", "fifo"),
    (10, "inline", "kNotSupported", "memtable"),
]
# Callers: (site, caller start, caller name, member).
CALLERS = [
    (0x5D69A9D, 0x5D69A00, "DBImpl::CreateColumnFamilyImpl",
     "4d429ab1cb2d8f8b-db_impl.o"),
    (0x5D725F6, 0x5D71FE0, "DBImpl::SetDBOptions",
     "4d429ab1cb2d8f8b-db_impl.o"),
    (0x5D8EB60, 0x5D8EA70, "ColumnFamilyData::SetOptions",
     "25dac13516458d4d-column_family.o"),
    (0x5E5A06A, 0x5E5A000, "DBImpl::ValidateOptions",
     "4d429ab1cb2d8f8b-db_impl_open.o"),
]
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-column-family-data-validate-options-115"
CASES = PACKET / "cases.tsv"


class BadAlloc(Exception):
    """std::bad_alloc raised inside the Status ctor (new char[]
    failed) or the vector operator new. `partial` is the
    half-built out Status for the ctor case: code/subcode/
    severity already written, state_ still nullptr. `site`,
    `pad` and `cleanup` name the throwing call, its LSDA pad
    and the cleanup the pad runs (before the canary check)."""

    def __init__(self, message="simulated BadAlloc"):
        super().__init__(message)
        self.partial = None
        self.site = None
        self.pad = None
        self.cleanup = []


class CalleeThrow(Exception):
    """An exception thrown by a callee (helper, string ctor, or
    IsInstanceOf). The binary never names the exception type;
    the model records the throwing site, its LSDA pad and the
    pad's cleanup."""

    def __init__(self, site, pad, cleanup):
        super().__init__("simulated throw at 0x%x" % site)
        self.site = site
        self.pad = pad
        self.cleanup = cleanup


class StackCheckFailed(Exception):
    """__stack_chk_fail: the stack canary did not match. When
    raised from an LSDA pad, `site`/`pad`/`cleanup` name the
    throwing call, its pad and the cleanup the pad ran before
    its canary check fired."""

    def __init__(self, message="stack canary mismatch"):
        super().__init__(message)
        self.site = None
        self.pad = None
        self.cleanup = []


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
                alloc_ok=True, site=None, pad=None, cleanup=None):
    """The Status ctor 0x61cf670 as the binary implements it.

    Writes code/subcode/severity into out, zeroes +0x3..+0x5 and
    state_, then allocates `new char[size+1]` (size = len(msg) +
    (len(msg2) ? len(msg2)+2 : 0)), copies msg, appends ": " + msg2
    when msg2 is non-empty, NUL-terminates, and stores the buffer
    as state_. If the allocation fails, raises BadAlloc with the
    half-built status attached (code/subcode/severity written,
    state_ still None); the LSDA pad for the call site then runs
    its cleanup and the exception propagates. The ctor's trailing
    delete[] of the old state_ is dead: state_ was zeroed before
    the read, so it never fires."""
    out = Status(code, subcode, severity, None)
    if not alloc_ok:
        err = BadAlloc()
        err.partial = out
        err.site = site
        err.pad = pad
        err.cleanup = list(cleanup or [])
        raise err
    if msg2:
        out.state = message + ": " + msg2
    else:
        out.state = message
    return out


def move_assign(dst, src):
    """Status::operator=(Status&&) 0x5d89b20 as the binary
    implements it (decoded from its disassembly; the function is
    NOT in the census): self-assign guard, copies the 6 bytes
    code/subcode/severity, moves state_ ptr, zeroes the source's
    6 bytes + state_, frees the destination's OLD state_ via
    operator delete[] tail-jump. Returns the (new-state, freed)
    pair: the moved status and the old state_ that was freed
    (None when the old state_ was nullptr)."""
    if dst is src:
        return dst, None
    old_state = dst.state
    dst.code, dst.subcode, dst.severity = \
        src.code, src.subcode, src.severity
    dst.state = src.state
    src.code = src.subcode = src.severity = 0
    src.state = None
    return dst, old_state


# ---------------------------------------------------------------- model

def default_db_options():
    """DBOptions fields this FDE reads. Defaults are the upstream
    v8.1.1 defaults for these fields (options.h, pinned by the
    default-ctor packet, open PR #6337); they are model inputs,
    not binary claims."""
    return {
        # +0x44 max_open_files (i32), default -1.
        "max_open_files": -1,
        # +0x1d1 unordered_write (bool).
        "unordered_write": False,
        # +0x1d2 allow_concurrent_memtable_write (bool).
        "allow_concurrent_memtable_write": True,
        # Number of db_paths entries (read only by the
        # CheckCFPathsSupported oracle, via db_paths.size()).
        "db_paths_count": 0,
    }


COMPRESSION_NAMES = {
    0: "NoCompression", 1: "Snappy", 2: "Zlib", 3: "BZip2",
    4: "LZ4", 5: "LZ4HC", 6: "Xpress", 7: "ZSTD",
    8: "ZSTDNotFinal", 9: "DisableOption",
}


def default_cf_options():
    """ColumnFamilyOptions fields this FDE (and its three helper
    oracles) reads. Defaults are the upstream v8.1.1 defaults
    (options.h / advanced_options.h, pinned by the field-offset
    layout computed this cycle); they are model inputs, not
    binary claims. `supported_compression` is the set of
    CompressionType values the build links (an oracle input:
    the binary's linked set is not pinned by this FDE)."""
    return {
        # Oracle inputs for CheckCompressionSupported 0x5d8dcc0.
        "compression_per_level": [],
        "compression": 1,  # kSnappyCompression
        "compression_opts": {"zstd_max_train_bytes": 0,
                             "use_zstd_dict_trainer": False,
                             "max_dict_bytes": 0},
        "blob_compression_type": 0,  # kNoCompression
        "supported_compression": [0, 1, 2, 3, 4, 5, 6, 7, 8],
        "zstd_train_supported": True,
        "zstd_finalize_supported": True,
        # Oracle inputs for CheckConcurrentWritesSupported 0x5d8ba60.
        "inplace_update_support": False,
        "memtable_insert_concurrently_supported": True,
        # Oracle inputs for CheckCFPathsSupported 0x5d8bb50.
        # compaction_style: 0 level, 1 universal, 2 fifo.
        "compaction_style": 0,
        "cf_paths_count": 0,
        # Inline-check fields (offsets verified this cycle).
        "max_successive_merges": 0,      # +0x150 u64
        "ttl": 0,                         # +0x160 u64
        "periodic_compaction_seconds": 0,  # +0x168 u64
        # IsInstanceOf oracle: table_factory->IsInstanceOf(
        # "BlockBasedTable"). The binary devirtualizes the call;
        # the model takes the outcome as an input.
        "table_factory_is_block_based": True,
        "enable_blob_garbage_collection": False,  # +0x1a9 bool
        "blob_garbage_collection_age_cutoff": 0.0,  # +0x1b0 double
        "blob_garbage_collection_force_threshold": 0.0,  # +0x1b8 double
        "memtable_protection_bytes_per_key": 0,  # +0x1e4 u32
        # Probe input (model only): when set, all three helpers
        # return OK carrying this state, exercising the
        # move-assign propagation of a code-0-with-state result.
        "helper_ok_state": None,
    }


def _num(value):
    """Normalize a case-file number: the string "nan" decodes to
    float NaN (cases.tsv is Python JSON, which round-trips NaN
    as the literal NaN; the string form keeps the file strict)."""
    if isinstance(value, str) and value == "nan":
        return float("nan")
    return value


def check_compression_supported(cf):
    """CheckCompressionSupported 0x5d8dcc0, modelled from upstream
    v8.1.1 db/column_family.cc:113-159 (read live this cycle).
    The helper's body is NOT reconstructed here; this oracle
    follows the source check order with the linked-codec set as
    an explicit input."""
    if cf.get("helper_ok_state") is not None:
        return Status(0, 0, 0, cf["helper_ok_state"])
    supported = set(cf["supported_compression"])
    per_level = cf["compression_per_level"]
    if per_level:
        for level in per_level:
            if level not in supported:
                return Status.error(
                    "kInvalidArgument",
                    "Compression type %s is not linked with the "
                    "binary." % COMPRESSION_NAMES.get(level, ""))
    elif cf["compression"] not in supported:
        return Status.error(
            "kInvalidArgument",
            "Compression type %s is not linked with the binary."
            % COMPRESSION_NAMES.get(cf["compression"], ""))
    opts = cf["compression_opts"]
    if opts["zstd_max_train_bytes"] > 0:
        if opts["use_zstd_dict_trainer"]:
            if not cf["zstd_train_supported"]:
                return Status.error(
                    "kInvalidArgument",
                    "zstd dictionary trainer cannot be used because "
                    "ZSTD 1.1.3+ is not linked with the binary.")
        elif not cf["zstd_finalize_supported"]:
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
    if cf["blob_compression_type"] not in supported:
        return Status.error(
            "kInvalidArgument",
            "The specified blob compression type %s is not "
            "available."
            % COMPRESSION_NAMES.get(cf["blob_compression_type"], ""))
    return Status.ok()


def check_concurrent_writes_supported(cf):
    """CheckConcurrentWritesSupported 0x5d8ba60, modelled from
    upstream v8.1.1 db/column_family.cc:161-171 (read live)."""
    if cf.get("helper_ok_state") is not None:
        return Status(0, 0, 0, cf["helper_ok_state"])
    if cf["inplace_update_support"]:
        return Status.error(
            "kInvalidArgument",
            "In-place memtable updates (inplace_update_support) is "
            "not compatible with concurrent writes "
            "(allow_concurrent_memtable_write)")
    if not cf["memtable_insert_concurrently_supported"]:
        return Status.error(
            "kInvalidArgument",
            "Memtable doesn't concurrent writes "
            "(allow_concurrent_memtable_write)")
    return Status.ok()


def check_cf_paths_supported(db, cf):
    """CheckCFPathsSupported 0x5d8bb50, modelled from upstream
    v8.1.1 db/column_family.cc:173-192 (read live)."""
    if cf.get("helper_ok_state") is not None:
        return Status(0, 0, 0, cf["helper_ok_state"])
    if cf["compaction_style"] not in (1, 0):  # universal, level
        if cf["cf_paths_count"] > 1:
            return Status.error(
                "kNotSupported",
                "More than one CF paths are only supported in "
                "universal and level compaction styles. ")
        if cf["cf_paths_count"] == 0 and db["db_paths_count"] > 1:
            return Status.error(
                "kNotSupported",
                "More than one DB paths are only supported in "
                "universal and level compaction styles. ")
    return Status.ok()


# Throw sites: (fail_at name, call address, LSDA pad, ctor site?).
# The pad is the landing pad the LSDA entry for the call names;
# the cleanup is PAD_CLEANUP[pad]. Ctor sites carry the partial
# status through BadAlloc; the other sites raise CalleeThrow.
THROW_SITES = {
    "compression-call": (0x5D8E3FB, 0x607, False),
    "concurrent-call": (0x5D8E7EE, 0x607, False),
    "cfpaths-call": (0x5D8E4A7, 0x607, False),
    "string-ctor-ttl": (0x5D8E519, 0x607, False),
    "string-ctor-periodic": (0x5D8E861, 0x607, False),
    "isinstanceof-ttl": (0x5D8E537, 0x5FB, False),
    "isinstanceof-ttl-virtual": (0x5D8E907, 0x5FB, False),
    "isinstanceof-periodic": (0x5D8E87F, 0x5E3, False),
    "isinstanceof-periodic-virtual": (0x5D8E987, 0x5E3, False),
    "status-ctor:unordered": (0x5D8E5EF, 0x607, True),
    "status-ctor:ttl": (0x5D8E590, 0x607, True),
    "status-ctor:periodic": (0x5D8E590, 0x607, True),
    "status-ctor:fifo": (0x5D8E590, 0x607, True),
    "status-ctor:age": (0x5D8E6AA, 0x607, True),
    "status-ctor:force": (0x5D8E6AA, 0x607, True),
    "status-ctor:memtable": (0x5D8E798, 0x5EF, True),
    "operator-new": (0x5D8E711, 0x607, False),
}


def _throw(site, t2, canary_ok=True):
    """Raise the exception for a throw at `site`, with the pad's
    cleanup resolved against the current T2 state (the generic
    cleanup deletes T2.state_ only when it is non-null). The pad
    runs its cleanup first, then its canary check: with a bad
    canary the pad raises StackCheckFailed instead of resuming."""
    addr, pad, _is_ctor = THROW_SITES[site]
    cleanup = _pad_cleanup(pad, t2)
    if not canary_ok:
        err = StackCheckFailed(
            "stack canary mismatch in LSDA pad 0x%x" % pad)
        err.site, err.pad, err.cleanup = addr, pad, cleanup
        raise err
    raise CalleeThrow(addr, pad, cleanup)


def _pad_cleanup(pad, t2):
    """The cleanup a pad runs, resolved against the current T2."""
    cleanup = []
    for action in PAD_CLEANUP[pad]:
        if action == "delete_t2_state_if_nonnull" and t2.state is None:
            continue
        cleanup.append(action)
    return cleanup


def _failing_check(db_options, cf_options):
    """The first failing check number (1-10), or 0 when all pass.
    Follows the binary's control flow exactly: helper 1, gated
    helper 2, inline unordered, helper 4, ttl, periodic, blob
    age, blob force, fifo, memtable protection."""
    if not check_compression_supported(cf_options).is_ok():
        return 1
    if db_options["allow_concurrent_memtable_write"]:
        if not check_concurrent_writes_supported(cf_options).is_ok():
            return 2
    if db_options["unordered_write"] and \
            cf_options["max_successive_merges"] != 0:
        return 3
    if not check_cf_paths_supported(db_options, cf_options).is_ok():
        return 4
    ttl = cf_options["ttl"]
    if ttl != 0 and ttl != K_DEFAULT_TTL and \
            not cf_options["table_factory_is_block_based"]:
        return 5
    periodic = cf_options["periodic_compaction_seconds"]
    if periodic != 0 and periodic != K_DEFAULT_PERIODIC_COMP_SECS and \
            not cf_options["table_factory_is_block_based"]:
        return 6
    if cf_options["enable_blob_garbage_collection"]:
        age = _num(cf_options["blob_garbage_collection_age_cutoff"])
        if age < 0.0 or age > 1.0:
            return 7
        force = _num(
            cf_options["blob_garbage_collection_force_threshold"])
        if force < 0.0 or force > 1.0:
            return 8
    if cf_options["compaction_style"] == 2 and \
            db_options["max_open_files"] != -1 and ttl != 0:
        return 9
    if cf_options["memtable_protection_bytes_per_key"] not in \
            MEMTABLE_PROTECTION_SUPPORTED:
        return 10
    return 0


def validate_options(db_options, cf_options, canary_ok=True,
                     alloc_ok=True, fail_at=None):
    """The reconstructed validator: ColumnFamilyData::ValidateOptions
    0x5d8e3b0..0x5d8e9c3.

    Runs the ten checks in binary order and returns the first
    non-OK status, or OK. T1/T2 follow the binary: T1 holds each
    helper result, T2 is the move-assign target; a helper error
    returns out = move(T2) via the shared error-return block
    (0x5d8e428); an inline error builds directly into out via
    the Status ctor and jumps to the epilogue; the OK path is
    out = move(T2). The memtable-protection vector is freed with
    sized delete on both the error and the OK path.

    `fail_at` names a throwing call (see THROW_SITES): the
    exception propagates with the pad's cleanup attached, after
    the pad's canary check -- so a throw with a bad canary raises
    StackCheckFailed instead. `alloc_ok=False` fails the Status
    ctor (or the vector operator new) with BadAlloc and the
    half-built status attached. A canary failure on a normal
    return raises StackCheckFailed; a throw never reaches the
    epilogue, so the throw is not masked by a canary failure --
    unless the pad's own canary check fires first.
    Returns the resulting Status."""
    t1 = Status.ok()
    t2 = Status.ok()
    out = Status.ok()

    def _check_throw(site):
        if fail_at == site:
            _throw(site, t2, canary_ok=canary_ok)

    def _ctor(code_name, message, site, pad):
        # The Status ctor at the given call site; on BadAlloc the
        # pad's cleanup runs (resolved against the current T2).
        if fail_at == site:
            cleanup = _pad_cleanup(pad, t2)
            if not canary_ok:
                err = StackCheckFailed(
                    "stack canary mismatch in LSDA pad 0x%x" % pad)
                err.site, err.pad = THROW_SITES[site][0], pad
                err.cleanup = cleanup
                raise err
            err = BadAlloc()
            err.partial = Status(CODE[code_name], 0, 0, None)
            err.site, err.pad = THROW_SITES[site][0], pad
            err.cleanup = cleanup
            raise err
        return status_ctor(CODE[code_name], message, "",
                           alloc_ok=alloc_ok, site=THROW_SITES[site][0],
                           pad=pad, cleanup=_pad_cleanup(pad, t2))

    def _epilogue(result):
        # delete[] T2.state_ if non-null (dead on every normal
        # path: T2 was zeroed by the final move-assign, or holds
        # the last helper's OK status), then the canary check.
        if not canary_ok:
            raise StackCheckFailed("stack canary mismatch")
        return result

    # 1. CheckCompressionSupported (0x5d8e3fb).
    _check_throw("compression-call")
    t1 = check_compression_supported(cf_options)
    move_assign(t2, t1)
    if not t2.is_ok():
        move_assign(out, t2)
        return _epilogue(out)
    # 2. CheckConcurrentWritesSupported (0x5d8e7ee), gated on
    # allow_concurrent_memtable_write (+0x1d2).
    if db_options["allow_concurrent_memtable_write"]:
        _check_throw("concurrent-call")
        t1 = check_concurrent_writes_supported(cf_options)
        move_assign(t2, t1)
        if not t2.is_ok():
            move_assign(out, t2)
            return _epilogue(out)
    # 3. unordered_write + max_successive_merges (inline).
    if db_options["unordered_write"] and \
            cf_options["max_successive_merges"] != 0:
        msg, _a, _l = MESSAGES["unordered"]
        t1 = _ctor("kInvalidArgument", msg, "status-ctor:unordered",
                   0x607)
        move_assign(t2, t1)
        if not t2.is_ok():
            move_assign(out, t2)
            return _epilogue(out)
    # 4. CheckCFPathsSupported (0x5d8e4a7).
    _check_throw("cfpaths-call")
    t1 = check_cf_paths_supported(db_options, cf_options)
    move_assign(t2, t1)
    if not t2.is_ok():
        move_assign(out, t2)
        return _epilogue(out)
    # 5. TTL: ttl != 0 and != kDefaultTtl -> BlockBasedTable.
    ttl = cf_options["ttl"]
    if ttl != 0 and ttl != K_DEFAULT_TTL:
        _check_throw("string-ctor-ttl")
        _check_throw("isinstanceof-ttl")
        _check_throw("isinstanceof-ttl-virtual")
        if not cf_options["table_factory_is_block_based"]:
            msg, _a, _l = MESSAGES["ttl"]
            out = _ctor("kNotSupported", msg, "status-ctor:ttl", 0x607)
            return _epilogue(out)
    # 6. Periodic: same gate with kDefaultPeriodicCompSecs.
    periodic = cf_options["periodic_compaction_seconds"]
    if periodic != 0 and periodic != K_DEFAULT_PERIODIC_COMP_SECS:
        _check_throw("string-ctor-periodic")
        _check_throw("isinstanceof-periodic")
        _check_throw("isinstanceof-periodic-virtual")
        if not cf_options["table_factory_is_block_based"]:
            msg, _a, _l = MESSAGES["periodic"]
            out = _ctor("kNotSupported", msg, "status-ctor:periodic",
                        0x607)
            return _epilogue(out)
    # 7-8. Blob GC cutoffs (comisd: NaN passes both range checks).
    if cf_options["enable_blob_garbage_collection"]:
        age = _num(cf_options["blob_garbage_collection_age_cutoff"])
        if age < 0.0 or age > 1.0:
            msg, _a, _l = MESSAGES["age"]
            out = _ctor("kInvalidArgument", msg, "status-ctor:age",
                        0x607)
            return _epilogue(out)
        force = _num(cf_options["blob_garbage_collection_force_threshold"])
        if force < 0.0 or force > 1.0:
            msg, _a, _l = MESSAGES["force"]
            out = _ctor("kInvalidArgument", msg, "status-ctor:force",
                        0x607)
            return _epilogue(out)
    # 9. FIFO + max_open_files != -1 + ttl != 0 (plain != 0: the
    # kDefaultTtl exclusion of check 5 does NOT apply here).
    if cf_options["compaction_style"] == 2 and \
            db_options["max_open_files"] != -1 and ttl != 0:
        msg, _a, _l = MESSAGES["fifo"]
        out = _ctor("kNotSupported", msg, "status-ctor:fifo", 0x607)
        return _epilogue(out)
    # 10. Memtable protection: heap vector {0,1,2,4,8} (operator
    # new(0x14) at 0x5d8e711), std::find constant-folded into a
    # switch; sized delete on both paths.
    _check_throw("operator-new")
    if not alloc_ok:
        cleanup = _pad_cleanup(0x607, t2)
        if not canary_ok:
            err = StackCheckFailed(
                "stack canary mismatch in LSDA pad 0x607")
            err.site, err.pad = THROW_SITES["operator-new"][0], 0x607
            err.cleanup = cleanup
            raise err
        err = BadAlloc("simulated BadAlloc in operator new(0x14)")
        err.site, err.pad = THROW_SITES["operator-new"][0], 0x607
        err.cleanup = cleanup
        raise err
    if cf_options["memtable_protection_bytes_per_key"] not in \
            MEMTABLE_PROTECTION_SUPPORTED:
        msg, _a, _l = MESSAGES["memtable"]
        out = _ctor("kNotSupported", msg, "status-ctor:memtable", 0x5EF)
        # Sized delete of the vector runs before the epilogue.
        return _epilogue(out)
    # OK path: out = move(T2) -- the last helper's OK status.
    move_assign(out, t2)
    return _epilogue(out)


# ---------------------------------------------------------------- cases

def _status_dict(status):
    return status.as_dict()


def _opts(inputs):
    db_opts = default_db_options()
    db_opts.update(inputs.get("db_overrides", {}))
    cf_opts = default_cf_options()
    cf_opts.update(inputs.get("cf_overrides", {}))
    return db_opts, cf_opts


def run_case(inputs):
    """Run one case and return the expected outputs."""
    group = inputs["group"]
    if group == "checks":
        db_opts, cf_opts = _opts(inputs)
        result = validate_options(db_opts, cf_opts)
        return {"result": _status_dict(result),
                "failed_check": _failing_check(db_opts, cf_opts)}
    if group == "status":
        kind = inputs["kind"]
        if kind == "ok":
            st = Status.ok()
            return {"status": _status_dict(st)}
        if kind == "error":
            n = inputs["check"]
            _n, _k, code_name, msg_key = CHECKS[n - 1]
            if msg_key is not None:
                msg, _a, _l = MESSAGES[msg_key]
            else:
                _m, overrides = _CHECK_FAIL_OVERRIDES[n - 1]
                db_opts, cf_opts = _opts(overrides)
                st = validate_options(db_opts, cf_opts)
                msg = st.state
            st = status_ctor(CODE[code_name], msg, "")
            return {"status": _status_dict(st),
                    "check": n, "message": msg}
        if kind == "ctor-msg2":
            st = status_ctor(CODE["kInvalidArgument"],
                             inputs["message"], inputs["msg2"])
            return {"status": _status_dict(st),
                    "joined": st.state}
        if kind == "move-assign":
            dst = Status.error("kNotSupported", "old-state")
            src = Status.error("kInvalidArgument", "new-state")
            _dst, freed = move_assign(dst, src)
            return {"dst": _status_dict(dst),
                    "src": _status_dict(src),
                    "freed_state": freed}
        if kind == "ok-with-state":
            db_opts, cf_opts = _opts(inputs)
            result = validate_options(db_opts, cf_opts)
            return {"result": _status_dict(result)}
        raise ValueError("unknown status kind %r" % kind)
    if group == "throw":
        db_opts, cf_opts = _opts(inputs)
        try:
            result = validate_options(
                db_opts, cf_opts,
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
                    "canary_checked": True}
        except CalleeThrow as err:
            return {"error": "CalleeThrow",
                    "site": hex(err.site), "pad": hex(err.pad),
                    "cleanup": err.cleanup,
                    "canary_checked": True}
        except StackCheckFailed as err:
            return {"error": "StackCheckFailed", "message": str(err),
                    "site": None if err.site is None else hex(err.site),
                    "pad": None if err.pad is None else hex(err.pad),
                    "cleanup": err.cleanup,
                    "canary_checked": True}
        return {"error": None, "result": _status_dict(result),
                "canary_checked": True}
    if group == "bindings":
        db_opts, cf_opts = _opts(inputs)
        result = validate_options(db_opts, cf_opts)
        return {
            "caller_site": inputs["caller_site"],
            "result": _status_dict(result),
            "result_sha256": hashlib.sha256(
                result.image()).hexdigest(),
            "result_independent_of_caller": True,
            "body_sha256": BODY_SHA256,
            "cold_body_sha256": COLD_BODY_SHA256,
            "source_sha256": SOURCE_SHA256,
            "cold_source_sha256": COLD_SOURCE_SHA256,
            "relocations": RELOCATIONS,
            "cold_relocations": COLD_RELOCATIONS,
            "lsda_entries": [list(e) for e in LSDA_ENTRIES],
            "cold_lsda_entries": [list(e) for e in COLD_LSDA_ENTRIES],
            "engine_calls": {"status_ctor_0x61cf670":
                             0 if result.is_ok() else 1,
                             "stack_chk_fail_0x63f0d70": 0},
        }
    raise ValueError("unknown group %r" % group)


# One failing variant per check, as db/cf overrides.
# (check number, {"db_overrides": ..., "cf_overrides": ...})
_CHECK_FAIL_OVERRIDES = [
    (1, {"cf_overrides": {"compression": 1,
                          "supported_compression": [0]}}),
    (2, {"db_overrides": {"allow_concurrent_memtable_write": True},
         "cf_overrides": {"inplace_update_support": True}}),
    (3, {"db_overrides": {"unordered_write": True},
         "cf_overrides": {"max_successive_merges": 1}}),
    (4, {"cf_overrides": {"compaction_style": 2,
                          "cf_paths_count": 2}}),
    (5, {"cf_overrides": {"ttl": 100,
                          "table_factory_is_block_based": False}}),
    (6, {"cf_overrides": {"periodic_compaction_seconds": 100,
                          "table_factory_is_block_based": False}}),
    (7, {"cf_overrides": {"enable_blob_garbage_collection": True,
                          "blob_garbage_collection_age_cutoff": 1.5}}),
    (8, {"cf_overrides": {"enable_blob_garbage_collection": True,
                          "blob_garbage_collection_force_threshold":
                              -0.5}}),
    (9, {"db_overrides": {"max_open_files": 0},
         "cf_overrides": {"compaction_style": 2, "ttl": 100}}),
    (10, {"cf_overrides": {"memtable_protection_bytes_per_key": 3}}),
]


def _gen_group(rng, group, n):
    rows = []
    if group == "checks":
        modes = ["each", "pair", "boundary", "mixed"]
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = modes[i % len(modes)]
            inputs = {"group": group, "case_id": case_id}
            if mode == "each":
                _n, overrides = _CHECK_FAIL_OVERRIDES[i % 10]
                inputs.update(overrides)
            elif mode == "pair":
                # Two failures: the earlier check must win.
                a = rng.randrange(10)
                b = rng.randrange(10)
                if a == b:
                    b = (b + 1) % 10
                first, second = min(a, b), max(a, b)
                _n, ov1 = _CHECK_FAIL_OVERRIDES[first]
                _n, ov2 = _CHECK_FAIL_OVERRIDES[second]
                for key in ("db_overrides", "cf_overrides"):
                    merged = dict(ov1.get(key, {}))
                    merged.update(ov2.get(key, {}))
                    if merged:
                        inputs[key] = merged
                # The pair must not cancel: the fifo override
                # sets ttl=100, which would trip check 5 first
                # when the table is not block-based -- keep the
                # table block-based in pairs unless check 5/6
                # is the earlier failure.
                if first not in (5, 6) and "cf_overrides" in inputs:
                    inputs["cf_overrides"].setdefault(
                        "table_factory_is_block_based", True)
            elif mode == "boundary":
                pick = rng.randrange(12)
                cf = {}
                db = {}
                if pick == 0:
                    cf["ttl"] = 1
                    cf["table_factory_is_block_based"] = False
                elif pick == 1:
                    cf["ttl"] = K_DEFAULT_TTL
                    cf["table_factory_is_block_based"] = False
                elif pick == 2:
                    cf["ttl"] = K_DEFAULT_TTL - 1
                    cf["table_factory_is_block_based"] = False
                elif pick == 3:
                    cf["periodic_compaction_seconds"] = 1
                    cf["table_factory_is_block_based"] = False
                elif pick == 4:
                    cf["periodic_compaction_seconds"] = \
                        K_DEFAULT_PERIODIC_COMP_SECS
                    cf["table_factory_is_block_based"] = False
                elif pick == 5:
                    cf["enable_blob_garbage_collection"] = True
                    cf["blob_garbage_collection_age_cutoff"] = 0.0
                    cf["blob_garbage_collection_force_threshold"] = 1.0
                elif pick == 6:
                    cf["enable_blob_garbage_collection"] = True
                    cf["blob_garbage_collection_age_cutoff"] = "nan"
                    cf["blob_garbage_collection_force_threshold"] = "nan"
                elif pick == 7:
                    cf["enable_blob_garbage_collection"] = True
                    cf["blob_garbage_collection_age_cutoff"] = -1e-9
                elif pick == 8:
                    cf["enable_blob_garbage_collection"] = True
                    cf["blob_garbage_collection_force_threshold"] = 1.0 + 1e-9
                elif pick == 9:
                    cf["memtable_protection_bytes_per_key"] = \
                        rng.choice([0, 1, 2, 4, 8])
                elif pick == 10:
                    cf["memtable_protection_bytes_per_key"] = \
                        rng.choice([3, 5, 9, 0xFFFFFFFF])
                else:
                    cf["compaction_style"] = 2
                    cf["ttl"] = K_DEFAULT_TTL
                    db["max_open_files"] = 0
                if db:
                    inputs["db_overrides"] = db
                if cf:
                    inputs["cf_overrides"] = cf
            else:  # mixed
                if rng.random() < 0.5:
                    inputs["db_overrides"] = {
                        "allow_concurrent_memtable_write":
                            rng.random() < 0.5,
                        "unordered_write": rng.random() < 0.3,
                        "max_open_files": rng.choice([-1, 0, 100]),
                        "db_paths_count": rng.choice([0, 1, 2, 5])}
                cf = {
                    "max_successive_merges": rng.choice([0, 1, 5]),
                    "ttl": rng.choice([0, 1, 100, K_DEFAULT_TTL]),
                    "periodic_compaction_seconds":
                        rng.choice([0, 1, 100, K_DEFAULT_PERIODIC_COMP_SECS]),
                    "table_factory_is_block_based":
                        rng.random() < 0.7,
                    "enable_blob_garbage_collection":
                        rng.random() < 0.3,
                    "compaction_style": rng.choice([0, 1, 2]),
                    "memtable_protection_bytes_per_key":
                        rng.choice([0, 1, 2, 3, 4, 8]),
                    "compression": rng.choice([0, 1, 7]),
                    "inplace_update_support": rng.random() < 0.2,
                    "cf_paths_count": rng.choice([0, 1, 2]),
                }
                if cf["enable_blob_garbage_collection"]:
                    cf["blob_garbage_collection_age_cutoff"] = \
                        rng.choice([0.0, 0.5, 1.0, 1.5, -0.5, "nan"])
                    cf["blob_garbage_collection_force_threshold"] = \
                        rng.choice([0.0, 0.5, 1.0, 1.5, -0.5, "nan"])
                inputs["cf_overrides"] = cf
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    elif group == "status":
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = i % 5
            if mode == 0:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "ok"}
            elif mode == 1:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "error", "check": (i % 10) + 1}
            elif mode == 2:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "ctor-msg2",
                          "message": "a", "msg2": "b"}
            elif mode == 3:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "move-assign"}
            else:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "ok-with-state",
                          "cf_overrides": {"helper_ok_state": "helper-state"}}
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    elif group == "throw":
        sites = list(THROW_SITES)
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = i % 6
            inputs = {"group": group, "case_id": case_id}
            if mode == 0:
                # BadAlloc in the Status ctor at each inline
                # error site (fail_at names the site; the
                # inputs must reach that error).
                check = (i // 6) % 7 + 1  # inline checks 3,5,6,7,8,9,10
                n = [3, 5, 6, 7, 8, 9, 10][check - 1]
                _m, overrides = _CHECK_FAIL_OVERRIDES[n - 1]
                inputs.update(overrides)
                site = {3: "status-ctor:unordered",
                        5: "status-ctor:ttl",
                        6: "status-ctor:periodic",
                        7: "status-ctor:age",
                        8: "status-ctor:force",
                        9: "status-ctor:fifo",
                        10: "status-ctor:memtable"}[n]
                inputs["fail_at"] = site
            elif mode == 1:
                # Callee throw at a helper / string / IsInstanceOf
                # / operator-new site. Status-ctor sites need the
                # error that reaches them; operator-new is reached
                # by the defaults (check 9 passes, check 10 runs
                # the vector alloc).
                site = sites[i % len(sites)]
                inputs["fail_at"] = site
                ctor_check = {"status-ctor:unordered": 3,
                              "status-ctor:ttl": 5,
                              "status-ctor:periodic": 6,
                              "status-ctor:age": 7,
                              "status-ctor:force": 8,
                              "status-ctor:fifo": 9,
                              "status-ctor:memtable": 10}.get(site)
                if ctor_check is not None:
                    _m, overrides = _CHECK_FAIL_OVERRIDES[ctor_check - 1]
                    inputs.update(overrides)
                if site in ("isinstanceof-ttl",
                            "isinstanceof-ttl-virtual"):
                    inputs["cf_overrides"] = {
                        "ttl": 100,
                        "table_factory_is_block_based": True}
                elif site in ("isinstanceof-periodic",
                              "isinstanceof-periodic-virtual"):
                    inputs["cf_overrides"] = {
                        "periodic_compaction_seconds": 100,
                        "table_factory_is_block_based": True}
            elif mode == 2:
                # Canary failure on a normal OK return.
                inputs["canary_ok"] = False
            elif mode == 3:
                # Canary failure on a normal error return.
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(10)]
                inputs.update(overrides)
                inputs["canary_ok"] = False
            elif mode == 4:
                # BadAlloc AND a bad canary: the throw wins at
                # the pad's canary check -- StackCheckFailed.
                # Only the inline checks have a Status-ctor site.
                n = rng.choice([3, 5, 6, 7, 8, 9, 10])
                _m, overrides = _CHECK_FAIL_OVERRIDES[n - 1]
                inputs.update(overrides)
                inputs["fail_at"] = {
                    3: "status-ctor:unordered",
                    5: "status-ctor:ttl",
                    6: "status-ctor:periodic",
                    7: "status-ctor:age",
                    8: "status-ctor:force",
                    9: "status-ctor:fifo",
                    10: "status-ctor:memtable"}[n]
                inputs["alloc_ok"] = False
                inputs["canary_ok"] = False
            else:
                # alloc_ok=False with no fail_at: the ctor fails
                # only when an error path runs it.
                check = rng.randrange(1, 11)
                _n, overrides = _CHECK_FAIL_OVERRIDES[check - 1]
                inputs.update(overrides)
                inputs["alloc_ok"] = False
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    elif group == "bindings":
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            inputs = {"group": group, "case_id": case_id,
                      "caller_site": "0x%x" % rng.choice(
                          [s for s, _k, _f, _n in CALLERS])}
            if rng.random() < 0.3:
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(10)]
                inputs.update(overrides)
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
    census = json.load(open(
        Path(__file__).resolve().parents[1] / "research" / "work-items" /
        "RE-002-node115-vendor-census" / "census.json"))["records"]
    rec = {r["start"]: r for r in census}
    for start, end, body_sha, src_sha, reloc_str, label in (
            (START, END, BODY_SHA256, SOURCE_SHA256, RELOCATIONS,
             "main"),
            (COLD_START, COLD_END, COLD_BODY_SHA256,
             COLD_SOURCE_SHA256, COLD_RELOCATIONS, "cold")):
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
                     hashlib.sha256(bytes(zeroed)).hexdigest() == src_sha,
                     hashlib.sha256(bytes(zeroed)).hexdigest()[:16]))
        legs.append(("%s relocation list matches census" % label,
                     ";".join("%d:kind%d" % (x["offset"], x["kind"])
                              for x in r["relocations"]) == reloc_str,
                     "%d relocations" % len(r["relocations"])))
        legs.append(("%s census symbol" % label,
                     r["symbol"] == SYMBOL + (".cold" if label == "cold"
                                              else ""),
                     r["symbol"][-24:]))
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
    dis = _disasm(data, secs, START, END)
    counts = [
        ("status ctor 0x61cf670 x4",
         dis.count("call   61cf670") == 4,
         dis.count("call   61cf670")),
        ("__stack_chk_fail x1",
         dis.count("<__stack_chk_fail@plt>") == 1,
         dis.count("<__stack_chk_fail@plt>")),
        ("operator delete[] x4",
         dis.count("<_ZdaPv@plt>") == 4,
         dis.count("<_ZdaPv@plt>")),
        ("sized delete _ZdlPvm x1",
         dis.count("<_ZdlPvm@plt>") == 1,
         dis.count("<_ZdlPvm@plt>")),
        ("endbr64 x5 (entry + 4 pad stubs)",
         dis.count("endbr64") == 5, dis.count("endbr64")),
        ("move-assign 0x5d89b20 x5",
         dis.count("call   5d89b20") == 5,
         dis.count("call   5d89b20")),
        ("CheckCompressionSupported 0x5d8dcc0 x1",
         dis.count("call   5d8dcc0") == 1,
         dis.count("call   5d8dcc0")),
        ("CheckConcurrentWritesSupported 0x5d8ba60 x1",
         dis.count("call   5d8ba60") == 1,
         dis.count("call   5d8ba60")),
        ("CheckCFPathsSupported 0x5d8bb50 x1",
         dis.count("call   5d8bb50") == 1,
         dis.count("call   5d8bb50")),
        ("string ctor 0x5d89d40 x2",
         dis.count("call   5d89d40") == 2,
         dis.count("call   5d89d40")),
        ("IsInstanceOf constprop 0x5d89e80 x2",
         dis.count("call   5d89e80") == 2,
         dis.count("call   5d89e80")),
        ("indirect IsInstanceOf call *%rcx x2",
         dis.count("call   *%rcx") == 2,
         dis.count("call   *%rcx")),
        ("canary stored once + checked once",
         dis.count("%fs:0x28") == 2, dis.count("%fs:0x28")),
        ("msg2 lea 0x4376fd x7 (one per error block)",
         dis.count("# 4376fd") == 7, dis.count("# 4376fd")),
        ("operator new(0x14) for the vector x1",
         "mov    $0x14,%edi" in dis, None),
        ("vector seed from .rodata 0x4544c0",
         "# 4544c0" in dis, None),
        ("GOT slot 0x64eceb8 for the vtable compare",
         "# 64eceb8" in dis, None),
    ]
    legs.extend(counts)
    cold = _disasm(data, secs, COLD_START, COLD_END)
    cold_counts = [
        ("cold: __stack_chk_fail x1",
         cold.count("<__stack_chk_fail@plt>") == 1,
         cold.count("<__stack_chk_fail@plt>")),
        ("cold: operator delete[] x1",
         cold.count("<_ZdaPv@plt>") == 1,
         cold.count("<_ZdaPv@plt>")),
        ("cold: sized delete _ZdlPvm x1",
         cold.count("<_ZdlPvm@plt>") == 1,
         cold.count("<_ZdlPvm@plt>")),
        ("cold: _Unwind_Resume x1",
         cold.count("<_Unwind_Resume@plt>") == 1,
         cold.count("<_Unwind_Resume@plt>")),
        ("cold: no endbr64 (cold entry has none)",
         cold.count("endbr64") == 0, cold.count("endbr64")),
        ("cold: canary checked once",
         cold.count("%fs:0x28") == 1, cold.count("%fs:0x28")),
    ]
    legs.extend(cold_counts)
    return legs


def _field_cmps(data, secs):
    legs = []
    dis = _disasm(data, secs, START, END)
    checks = [
        ("allow_concurrent cmpb +0x1d2 (%r12)",
         "cmpb   $0x0,0x1d2(%r12)" in dis),
        ("unordered_write cmpb +0x1d1 x2 (%r12)",
         dis.count("cmpb   $0x0,0x1d1(%r12)") == 2,
         dis.count("cmpb   $0x0,0x1d1(%r12)")),
        ("max_successive_merges cmpq +0x150",
         "cmpq   $0x0,0x150(%rbx)" in dis),
        ("ttl mov +0x160 + test + kDefaultTtl cmp",
         "mov    0x160(%rbx),%rax" in dis),
        ("kDefaultTtl cmp 0xfffffffffffffffe x2",
         dis.count("cmp    $0xfffffffffffffffe,%rax") == 2,
         dis.count("cmp    $0xfffffffffffffffe,%rax")),
        ("periodic mov +0x168 + test",
         "mov    0x168(%rbx),%rax" in dis),
        ("enable_blob_gc cmpb +0x1a9",
         "cmpb   $0x0,0x1a9(%rbx)" in dis),
        ("age cutoff movsd +0x1b0 + comisd pair",
         "movsd  0x1b0(%rbx),%xmm0" in dis
         and dis.count("comisd %xmm0,%xmm1") == 2
         and dis.count("comisd %xmm2,%xmm0") == 2),
        ("force threshold movsd +0x1b8",
         "movsd  0x1b8(%rbx),%xmm0" in dis),
        ("compaction_style cmpb +0xe8 == 2",
         "cmpb   $0x2,0xe8(%rbx)" in dis),
        ("max_open_files cmpl +0x44 != -1 (%r12)",
         "cmpl   $0xffffffff,0x44(%r12)" in dis),
        ("memtable_protection mov +0x1e4 + switch",
         "mov    0x1e4(%rbx),%eax" in dis
         and "cmp    $0x8,%eax" in dis),
    ]
    for name, ok, *rest in checks:
        legs.append((name, ok, rest[0] if rest else None))
    return legs


def _messages(data, secs):
    legs = []
    for key, (msg, addr, ln) in MESSAGES.items():
        raw = _read_va(data, secs, addr, ln)
        legs.append(("message %s byte-exact (%d B)" % (key, ln),
                     raw == msg.encode(), raw[:24].decode(errors="replace")))
    empty = _read_va(data, secs, EMPTY_MSG2_ADDR, 1)
    legs.append(("msg2 at 0x4376fd is the empty string",
                 empty == b"\x00", empty.hex()))
    return legs


def _uleb(data, i):
    result = 0
    shift = 0
    while True:
        byte = data[i]
        i += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return result, i


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


def _lsda(data, secs):
    legs = []
    for label, addr, entries, target, length, rng in (
            ("main", LSDA_ADDR, LSDA_ENTRIES, START, 0x4C, 0x613),
            ("cold", COLD_LSDA_ADDR, COLD_LSDA_ENTRIES, COLD_START,
             0x20, 0x4F)):
        raw = _read_va(data, secs, addr, 64)
        legs.append(("%s LSDA header ff ff 01" % label,
                     list(raw[:3]) == [0xFF, 0xFF, 0x01],
                     raw[:3].hex()))
        table_len = raw[3]
        want_len = 0x31 if label == "main" else 0x04
        legs.append(("%s LSDA table length 0x%x" % (label, want_len),
                     table_len == want_len, table_len))
        got = []
        j = 4
        end = 4 + table_len
        while j < end:
            st, j = _uleb(raw, j)
            ln, j = _uleb(raw, j)
            lp, j = _uleb(raw, j)
            ac, j = _uleb(raw, j)
            got.append((st, ln, lp, ac))
        legs.append(("%s LSDA %d entries, all action 0"
                     % (label, len(entries)),
                     got == entries and all(e[3] == 0 for e in got),
                     str(got)))
        sec_off, rec_len, rec_rng, aug_len, lsda = \
            _eh_frame_record(data, target)
        legs.append(("%s FDE record length 0x%x" % (label, length),
                     rec_len == length, hex(rec_len)))
        legs.append(("%s FDE range 0x%x" % (label, rng),
                     rec_rng == rng, hex(rec_rng)))
        legs.append(("%s FDE aug_len 4 (LSDA pointer present)"
                     % label,
                     aug_len == 4, aug_len))
        legs.append(("%s FDE LSDA pointer -> 0x%x" % (label, addr),
                     lsda == addr, None if lsda is None else hex(lsda)))
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
    legs += _lsda(data, secs)
    sites = _caller_scan()
    legs.append(("caller census: 4 calls, 0 jumps, 0 lea refs",
                 sites == [(0x5D69A9D, "call"), (0x5D725F6, "call"),
                           (0x5D8EB60, "call"), (0x5E5A06A, "call")],
                 sites))
    legs.append(("defaults validate OK",
                 validate_options(default_db_options(),
                                  default_cf_options()).is_ok(), None))
    for n, _k, _c, msg_key in CHECKS:
        if msg_key is None:
            _m, overrides = _CHECK_FAIL_OVERRIDES[n - 1]
            db_opts, cf_opts = _opts(overrides)
            st = validate_options(db_opts, cf_opts)
            legs.append(("check %d (oracle) fails" % n,
                         not st.is_ok() and st.state is not None,
                         "%s %r" % (CODE_NAME[st.code],
                                    (st.state or "")[:24])))
        else:
            _m, overrides = _CHECK_FAIL_OVERRIDES[n - 1]
            db_opts, cf_opts = _opts(overrides)
            st = validate_options(db_opts, cf_opts)
            msg, _a, _l = MESSAGES[msg_key]
            legs.append(("check %d fails with its message" % n,
                         st.code == CODE[_c] and st.state == msg,
                         "%s %r" % (CODE_NAME[st.code],
                                    (st.state or "")[:20])))
    # First failure wins: check 1 masks check 5; check 3 masks
    # check 10.
    db_opts, cf_opts = _opts(_CHECK_FAIL_OVERRIDES[0][1])
    cf_opts.update(_CHECK_FAIL_OVERRIDES[4][1].get("cf_overrides", {}))
    legs.append(("check 1 masks check 5",
                 validate_options(db_opts, cf_opts).state ==
                 "Compression type Snappy is not linked with the "
                 "binary.", None))
    db_opts = default_db_options()
    db_opts["unordered_write"] = True
    cf_opts = default_cf_options()
    cf_opts["max_successive_merges"] = 1
    cf_opts["memtable_protection_bytes_per_key"] = 3
    legs.append(("check 3 masks check 10",
                 validate_options(db_opts, cf_opts).state ==
                 MESSAGES["unordered"][0], None))
    # NaN passes the blob range checks (comisd semantics).
    cf_opts = default_cf_options()
    cf_opts["enable_blob_garbage_collection"] = True
    cf_opts["blob_garbage_collection_age_cutoff"] = float("nan")
    cf_opts["blob_garbage_collection_force_threshold"] = float("nan")
    legs.append(("NaN age/force cutoffs pass",
                 validate_options(default_db_options(), cf_opts).is_ok(),
                 None))
    # kDefaultTtl / kDefaultPeriodicCompSecs pass the table check.
    cf_opts = default_cf_options()
    cf_opts["ttl"] = K_DEFAULT_TTL
    cf_opts["periodic_compaction_seconds"] = K_DEFAULT_PERIODIC_COMP_SECS
    cf_opts["table_factory_is_block_based"] = False
    legs.append(("kDefaultTtl/kDefaultPeriodic pass",
                 validate_options(default_db_options(), cf_opts).is_ok(),
                 None))
    # FIFO fires even for kDefaultTtl (plain != 0, no exclusion).
    db_opts = default_db_options()
    db_opts["max_open_files"] = 0
    cf_opts = default_cf_options()
    cf_opts["compaction_style"] = 2
    cf_opts["ttl"] = K_DEFAULT_TTL
    legs.append(("FIFO fires for kDefaultTtl",
                 validate_options(db_opts, cf_opts).state ==
                 MESSAGES["fifo"][0], None))
    # OK-with-state helper result propagates via the final
    # move-assign into out.
    cf_opts = default_cf_options()
    cf_opts["helper_ok_state"] = "helper-state"
    st = validate_options(default_db_options(), cf_opts)
    legs.append(("helper OK-with-state propagates to out",
                 st.is_ok() and st.state == "helper-state", st.state))
    # Status ctor legs: state_ buffer is msg + NUL, alloc len+1.
    st = status_ctor(CODE["kInvalidArgument"], MESSAGES["age"][0], "")
    legs.append(("ctor state_ buffer is msg + NUL",
                 st.state_buffer() == MESSAGES["age"][0].encode() + b"\x00"
                 and st.state_alloc() == len(MESSAGES["age"][0]) + 1, None))
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
