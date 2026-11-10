#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::CheckCompressionSupported.

Target: rocksdb::CheckCompressionSupported(const ColumnFamilyOptions&)
at 0x5d8dcc0..0x5d8e356 (1686 B, main FDE) plus its .cold FDE at
0x5d8dc2c..0x5d8dcb5 (137 B), in node #115 (work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The helper ColumnFamilyData::ValidateOptions (open PR #6449) calls
once, at site 0x5d8e3fb, as its first check. This packet
supersedes the reference oracle for this function in the #6449
packet with the full reconstruction.

Whole-FDE facts (verified live, see --live):
- Signature: Status by value (hidden sret out in rdi = r12),
  cf_options in rsi = rbp. Stack canary used (stored 0x1e8(%rsp),
  checked at the epilogue 0x5d8ddee and in every LSDA pad via the
  .cold FDE; the two __throw_length_error paths check it too).
- Three stack strings: S1 at 0x30(%rsp) (rbp, the
  CompressionTypeToString result), S2 at 0x50(%rsp) (rbx, move of
  S1), S3 at 0x70(%rsp) (r13, move of S2) for the per-level and
  single-compression error paths; the blob error path reuses the
  0x70(%rsp) slot for the std::ostringstream (r13) and builds its
  message there instead. The Status ctor's Slices live at
  0x10/0x20(%rsp) (msg + the empty msg2 at 0x4376fd).
- Checks in binary order (upstream RocksDB v8.1.1
  db/column_family.cc:113-159, read live this cycle), first
  failure wins, else OK:
  1. compression_per_level (+0x70..+0x78) non-empty: every byte
     must be CompressionTypeSupported, else "Compression type <name>
     is not linked with the binary." (InvalidArgument); empty:
     the same test on compression (+0x220).
  2. compression_opts.zstd_max_train_bytes (+0x268, u32) > 0:
     use_zstd_dict_trainer (+0x280) and ZSTD < 1.1.3 ->
     "zstd dictionary trainer cannot be used because ZSTD 1.1.3+
     is not linked with the binary." (89 B); else (trainer off)
     ZSTD < 1.4.5 -> "zstd finalizeDictionary cannot be used
     because ZSTD 1.4.5+ is not linked with the binary." (89 B);
     then max_dict_bytes (+0x264, u32) == 0 -> "The dictionary
     size limit (`CompressionOptions::max_dict_bytes`) should be
     nonzero if we're using zstd's dictionary generator." (126 B).
  3. blob_compression_type (+0x1a8) must be
     CompressionTypeSupported, else (via std::ostringstream)
     "The specified blob compression type <name> is not
     available." (InvalidArgument).
  4. OK: out = {0, 0, nullptr} (movl/movw/movq at 0x5d8e10a).
- CompressionTypeSupported is inlined as a decision table over
  the byte (v8.1.1 util/compression.h:547-571, with SNAPPY/ZLIB/
  BZIP2/LZ4/ZSTD defined and XPRESS undefined in this build):
  0 NoCompression, 1 Snappy, 2 Zlib, 3 BZip2, 4 LZ4, 5 LZ4HC ->
  true (constant-folded, no call); 6 Xpress -> false; 7 ZSTD ->
  ZSTD_versionNumber() >= 800 (the linked ZSTD is 1.5.6, version
  number 10506 = 0x290a, from the 10-byte function at 0x620dd50:
  `mov $0x290a,%eax; ret`); 0x40 ZSTDNotFinal -> true; 0xff
  DisableOption and every other byte -> false (default:
  assert(false); return false).
- CompressionTypeToString (0x5d8b3c0, census-bound,
  column_family.o) names: 0 NoCompression, 1 Snappy, 2 Zlib,
  3 BZip2, 4 LZ4, 5 LZ4HC, 6 Xpress, 7 ZSTD, 0x40 ZSTDNotFinal,
  0xff DisableOption, anything else "" (empty). So an
  unsupported byte 8 reports "Compression type  is not linked
  with the binary." (empty name, double space), and 0xff
  reports "Compression type DisableOption is not linked with
  the binary."
- ZSTD_TrainDictionarySupported is ZSTD_versionNumber() >= 10103
  (binary: cmp $0x2776, error unless above); ZSTD_Finalize-
  DictionarySupported is >= 10405 (binary: cmp $0x28a4, error
  unless above); ZSTD_Supported is >= 800 (binary: cmp $0x31f,
  error unless above). All three thresholds match the v8.1.1
  source exactly.
- Main FDE LSDA at 0x40a2a0 (17 entries, all action 0, cleanup
  only). Pads: 0x61e dispose rbx-string + destroy ostringstream;
  0x62a same; 0x636 dispose r13/rbx/rbp strings; 0x642 dispose
  rbx-string + destroy ostringstream; 0x64e dispose rbx/rbp
  strings; 0x65a dispose r13/rbx/rbp strings; 0x666 same;
  0x672 dispose rbx/rbp strings; 0x67e destroy ostringstream;
  0x68a dispose rbp-string; pad 0 = no landing pad (the
  noexcept calls and the calls with nothing live). Cold FDE
  LSDA at 0x40a307 (1 entry (38,81,0,0) for the two
  _Unwind_Resume calls).
- Binary-vs-source observation (recorded, not hidden): the
  +1222 _M_replace call's LSDA entry names pad 0x636, whose
  .cold body disposes the r13 and rbx string slots -- but at
  that call site only the rbp string is constructed (r13/rbx
  are set up later, at +1288/+1235). The pad is shared with
  the Status ctor at +1347, where all three strings ARE live.
  The model follows the pad code literally; the quirk only
  matters if _M_replace throws at +1222 (a bad_alloc while
  inserting the 17-byte prefix), which no real input drives.
- Dead branch (recorded, not hidden): the blob path's
  _M_assign call at +1489 (0x5d8e291) runs only when the
  ostringstream's string is empty (r8 == 0 at 0x5d8dfcd); the
  composed message is never empty (36-byte prefix alone), so
  the branch is unreachable for real inputs. Its LSDA entry
  (1489,5,1578) and pad are still pinned.

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
START = 0x5D8DCC0
END = 0x5D8E356
COLD_START = 0x5D8DC2C
COLD_END = 0x5D8DCB5
BODY_SHA256 = ("cde4dcaa3d2f878a82348aeee686792e771a72cc82b3e4111"
               "cdc1fb0dfc7a670")
SOURCE_SHA256 = ("ba0cad22c9ce8ddce43a857113bfe5ba6099a9da1d03e2967"
                 "a52d25b4e5310de")
COLD_BODY_SHA256 = ("8b4d3b7883f7b077631b57b19b1d8cde3c18b6baec296a"
                    "75f79fd3b9f4e3795d")
COLD_SOURCE_SHA256 = ("8f60ab2cf74c433c225a0be9656a3598707e2ef3e87a"
                      "476bea2e06deb24d885d")
RELOCATIONS = ("102:kind2;124:kind4;141:kind2;149:kind4;165:kind4;"
               "202:kind2;210:kind4;226:kind4;274:kind4;282:kind4;"
               "290:kind4;298:kind4;353:kind4;423:kind4;460:kind2;"
               "472:kind2;514:kind4;598:kind4;610:kind2;618:kind4;"
               "638:kind4;656:kind4;671:kind2;676:kind4;683:kind42;"
               "690:kind42;724:kind4;731:kind2;834:kind4;882:kind4;"
               "890:kind4;925:kind4;932:kind42;954:kind4;961:kind42;"
               "998:kind42;1015:kind4;1025:kind4;1052:kind2;1064:kind2;"
               "1168:kind2;1198:kind4;1215:kind2;1223:kind4;1239:kind4;"
               "1276:kind2;1284:kind4;1300:kind4;1348:kind4;1361:kind4;"
               "1402:kind2;1414:kind2;1451:kind4;1490:kind4;1500:kind4;"
               "1526:kind2;1531:kind4;1557:kind2;1562:kind4;1574:kind2;"
               "1586:kind2;1598:kind2;1610:kind2;1622:kind2;1634:kind2;"
               "1646:kind2;1658:kind2;1670:kind2;1682:kind2")
COLD_RELOCATIONS = ("4:kind4;12:kind4;39:kind4;47:kind4;57:kind4;"
                    "65:kind4;73:kind4;97:kind4;105:kind4;115:kind4;"
                    "123:kind4;131:kind4")
MEMBER = "25dac13516458d4d-column_family.o"
SYMBOL = ("_ZN7rocksdb25CheckCompressionSupportedERKNS_"
          "19ColumnFamilyOptionsE")
LSDA_ADDR = 0x40A2A0
COLD_LSDA_ADDR = 0x40A307
# LSDA call-site entries: (start, length, landing_pad, action).
LSDA_ENTRIES = [(123, 5, 0, 0), (148, 5, 1674, 0), (209, 5, 1614, 0),
                (273, 5, 1626, 0), (352, 250, 0, 0), (617, 25, 1662, 0),
                (655, 25, 1602, 0), (833, 5, 1578, 0), (881, 5, 1566, 0),
                (1024, 178, 0, 0), (1222, 5, 1590, 0), (1283, 5, 1650, 0),
                (1347, 5, 1638, 0), (1360, 95, 0, 0), (1489, 5, 1578, 0),
                (1530, 5, 1650, 0), (1561, 5, 1614, 0)]
COLD_LSDA_ENTRIES = [(38, 81, 0, 0)]
# Landing pads (FDE-relative) and what each pad's .cold body does.
# 0x61e cold+0x0: dispose rbx-string, destroy r13-ostringstream.
# 0x62a cold+0x2b: dispose rbx-string, destroy r13-ostringstream.
# 0x636 cold+0x35: dispose r13/rbx/rbp strings.
# 0x642 cold+0x65: dispose rbx-string, destroy r13-ostringstream.
# 0x64e cold+0x7f: dispose rbx/rbp strings.
# 0x65a cold+0x77: dispose r13/rbx/rbp strings.
# 0x666 cold+0x35: dispose r13/rbx/rbp strings.
# 0x672 cold+0x3d: dispose rbx/rbp strings.
# 0x67e cold+0x8: destroy r13-ostringstream.
# 0x68a cold+0x45: dispose rbp-string.
# 0x000: no landing pad.
PAD_CLEANUP = {
    0x000: [],
    0x61E: ["dispose_rbx_string", "destroy_ostringstream"],
    0x62A: ["dispose_rbx_string", "destroy_ostringstream"],
    0x636: ["dispose_r13_string", "dispose_rbx_string",
            "dispose_rbp_string"],
    0x642: ["dispose_rbx_string", "destroy_ostringstream"],
    0x64E: ["dispose_rbx_string", "dispose_rbp_string"],
    0x65A: ["dispose_r13_string", "dispose_rbx_string",
            "dispose_rbp_string"],
    0x666: ["dispose_r13_string", "dispose_rbx_string",
            "dispose_rbp_string"],
    0x672: ["dispose_rbx_string", "dispose_rbp_string"],
    0x67E: ["destroy_ostringstream"],
    0x68A: ["dispose_rbp_string"],
}
# Engine callees (census-bound unless noted).
ZSTD_VERSION_NUMBER = 0x620DD50
COMPRESSION_TYPE_TO_STRING = 0x5D8B3C0
STATUS_CTOR = 0x61CF670
STACK_CHK_FAIL = 0x63F0D70
EMPTY_MSG2_ADDR = 0x4376FD

CODE = {"kOk": 0, "kNotFound": 1, "kCorruption": 2, "kNotSupported": 3,
        "kInvalidArgument": 4, "kIOError": 5, "kMergeInProgress": 6,
        "kIncomplete": 7, "kShutdownInProgress": 8, "kTimedOut": 9,
        "kAborted": 10, "kBusy": 11, "kExpired": 12, "kTryAgain": 13,
        "kCompactionTooLarge": 14, "kColumnFamilyDropped": 15}
CODE_NAME = {v: k for k, v in CODE.items()}

# The linked ZSTD version number (0x620dd50: mov $0x290a,%eax; ret).
ZSTD_VERSION_LINKED = 0x290A  # 10506 = ZSTD 1.5.6
ZSTD_SUPPORTED_MIN = 800      # ZSTD_Supported: >= 800 (cmp $0x31f)
ZSTD_TRAIN_MIN = 10103        # TrainDictionary: >= 10103 (cmp $0x2776)
ZSTD_FINALIZE_MIN = 10405     # FinalizeDictionary: >= 10405 (cmp $0x28a4)

# CompressionTypeToString (0x5d8b3c0) names, byte-verified against
# .rodata: 0x433f22 NoCompression, 0x43f864 Snappy, 0x4451eb Zlib,
# 0x43f86b BZip2, 0x44288c LZ4, 0x441919 LZ4HC, 0x449614 Xpress,
# 0x43304b ZSTD, 0x43a3d4 ZSTDNotFinal, 0x4350f0 DisableOption.
COMPRESSION_NAMES = {
    0: "NoCompression", 1: "Snappy", 2: "Zlib", 3: "BZip2",
    4: "LZ4", 5: "LZ4HC", 6: "Xpress", 7: "ZSTD",
    0x40: "ZSTDNotFinal", 0xFF: "DisableOption",
}

# The five error messages, byte-verified against .rodata.
# (message, address, length)
MESSAGES = {
    # "Compression type " (0x4408db, 17) + name +
    # " is not linked with the binary." (0x965df8, 31).
    "not_linked_prefix": ("Compression type ", 0x4408DB, 17),
    "not_linked_suffix": (" is not linked with the binary.",
                          0x965DF8, 31),
    "trainer": ("zstd dictionary trainer cannot be used because "
                "ZSTD 1.1.3+ is not linked with the binary.",
                0x9647E8, 89),
    "finalize": ("zstd finalizeDictionary cannot be used because "
                 "ZSTD 1.4.5+ is not linked with the binary.",
                 0x95E1A8, 89),
    "max_dict": ("The dictionary size limit "
                 "(`CompressionOptions::max_dict_bytes`) should be "
                 "nonzero if we're using zstd's dictionary "
                 "generator.", 0x967428, 126),
    # "The specified blob compression type " (0x95cd48, 36) + name +
    # " is not available." (0x43820b, 18).
    "blob_prefix": ("The specified blob compression type ",
                    0x95CD48, 36),
    "blob_suffix": (" is not available.", 0x43820B, 18),
}
# The checks in binary order: (n, kind, code_name).
CHECKS = [
    (1, "per_level_or_single", "kInvalidArgument"),
    (2, "trainer", "kInvalidArgument"),
    (3, "finalize", "kInvalidArgument"),
    (4, "max_dict", "kInvalidArgument"),
    (5, "blob", "kInvalidArgument"),
]
# Callers: (site, caller start, caller name, member).
CALLERS = [
    (0x5D8E3FB, 0x5D8E3B0, "ColumnFamilyData::ValidateOptions",
     "25dac13516458d4d-column_family.o"),
]
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-check-compression-supported-115"
CASES = PACKET / "cases.tsv"


class BadAlloc(Exception):
    """std::bad_alloc raised inside the Status ctor (new char[]
    failed). `partial` is the half-built out Status for the ctor
    case: code/subcode/severity already written, state_ still
    nullptr. `site`, `pad` and `cleanup` name the throwing call,
    its LSDA pad and the cleanup the pad runs (before the canary
    check)."""

    def __init__(self, message="simulated BadAlloc"):
        super().__init__(message)
        self.partial = None
        self.site = None
        self.pad = None
        self.cleanup = []


class CalleeThrow(Exception):
    """An exception thrown by a callee (CompressionTypeToString,
    a string op, an ostream insert, or __throw_length_error).
    The binary never names the exception type; the model records
    the throwing site, its LSDA pad and the pad's cleanup."""

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


def compression_type_to_string(value):
    """CompressionTypeToString 0x5d8b3c0: the name for a byte
    value, or "" for values with no case (the default arm)."""
    return COMPRESSION_NAMES.get(value & 0xFF, "")


def compression_type_supported(value, zstd_version):
    """The inlined CompressionTypeSupported switch
    (util/compression.h:547-571) as the binary implements it:
    0-5 and 0x40 are constant true; 6 Xpress is constant false;
    7 ZSTD is the version gate (>= 800); 0xff and every other
    byte are the default arm (false)."""
    value &= 0xFF
    if value in (0, 1, 2, 3, 4, 5, 0x40):
        return True
    if value == 6:
        return False
    if value == 7:
        return zstd_version >= ZSTD_SUPPORTED_MIN
    return False


def default_cf_options():
    """ColumnFamilyOptions fields this FDE reads. Defaults are the
    upstream v8.1.1 defaults (options.h / advanced_options.h,
    field offsets verified against the real headers this cycle
    with g++ offsetof); they are model inputs, not binary claims.
    `zstd_version` is the linked ZSTD_versionNumber() value
    (0x620dd50 returns 10506); the three version gates are
    testable by varying it."""
    return {
        # +0x70..+0x78 compression_per_level (vector begin/end).
        "compression_per_level": [],
        # +0x220 compression (CompressionType, 1 byte).
        "compression": 1,  # kSnappyCompression
        # +0x258 compression_opts.
        "compression_opts": {"zstd_max_train_bytes": 0,  # +0x268 u32
                             "use_zstd_dict_trainer": True,  # +0x280 bool
                             "max_dict_bytes": 0},  # +0x264 u32
        # +0x1a8 blob_compression_type (CompressionType, 1 byte).
        "blob_compression_type": 0,  # kNoCompression
        # Linked ZSTD_versionNumber() (0x620dd50).
        "zstd_version": ZSTD_VERSION_LINKED,
    }


# ---------------------------------------------------------------- model

# Throw sites: (fail_at name, call address, LSDA pad, ctor site?).
# The pad is the landing pad the LSDA entry for the call names;
# the cleanup is PAD_CLEANUP[pad]. Ctor sites carry the partial
# status through BadAlloc; the other sites raise CalleeThrow.
# The two __throw_length_error sites model the string length
# check failing (max_size - len <= 30): unreachable for real
# inputs (names are <= 13 bytes), exercised only via fail_at.
# The _M_assign site (+1489) is a dead branch for real inputs
# (the ostringstream string is never empty); it is recorded here
# with its pad but the model never reaches it.
THROW_SITES = {
    "compression-type-to-string:per-level": (0x5D8DD3B, 0x000, False),
    "string-replace:per-level": (0x5D8DD54, 0x68A, False),
    "string-append:per-level": (0x5D8DD91, 0x64E, False),
    "status-ctor:per-level": (0x5D8DDD1, 0x65A, True),
    "status-ctor:max-dict": (0x5D8DEC1, 0x000, True),
    "ostringstream-ctor": (0x5D8DF15, 0x000, False),
    "ostream-insert:blob-prefix": (0x5D8DF29, 0x67E, False),
    "compression-type-to-string:blob": (0x5D8DF3D, 0x67E, False),
    "ostream-insert:blob-name": (0x5D8DF4F, 0x642, False),
    "ostream-insert:blob-suffix": (0x5D8DF63, 0x642, False),
    "string-replace:blob": (0x5D8E001, 0x62A, False),
    "status-ctor:blob": (0x5D8E031, 0x61E, True),
    "compression-type-to-string:single": (0x5D8E16D, 0x000, False),
    "string-replace:single": (0x5D8E186, 0x636, False),
    "string-append:single": (0x5D8E1C3, 0x672, False),
    "status-ctor:single": (0x5D8E203, 0x666, True),
    "string-assign:blob-empty": (0x5D8E291, 0x62A, False),
    "throw-length-error:single": (0x5D8E2BA, 0x672, False),
    "throw-length-error:per-level": (0x5D8E2D9, 0x64E, False),
}


def _throw(site, canary_ok=True):
    """Raise the exception for a throw at `site`, with the pad's
    cleanup. The pad runs its cleanup first, then its canary
    check: with a bad canary the pad raises StackCheckFailed
    instead of resuming."""
    addr, pad, _is_ctor = THROW_SITES[site]
    cleanup = list(PAD_CLEANUP[pad])
    if not canary_ok:
        err = StackCheckFailed(
            "stack canary mismatch in LSDA pad 0x%x" % pad)
        err.site, err.pad, err.cleanup = addr, pad, cleanup
        raise err
    raise CalleeThrow(addr, pad, cleanup)


def _failing_check(cf_options):
    """The first failing check number (1-5), or 0 when all pass.
    Follows the binary's control flow exactly: the per-level
    loop (or the single compression test when the vector is
    empty), then the zstd trainer / finalize / max_dict_bytes
    gates, then the blob compression type."""
    zstd_version = cf_options["zstd_version"]
    per_level = cf_options["compression_per_level"]
    if per_level:
        for level in per_level:
            if not compression_type_supported(level, zstd_version):
                return 1
    elif not compression_type_supported(cf_options["compression"],
                                        zstd_version):
        return 1
    opts = cf_options["compression_opts"]
    if opts["zstd_max_train_bytes"] > 0:
        if opts["use_zstd_dict_trainer"]:
            if zstd_version < ZSTD_TRAIN_MIN:
                return 2
        elif zstd_version < ZSTD_FINALIZE_MIN:
            return 3
        if opts["max_dict_bytes"] == 0:
            return 4
    if not compression_type_supported(cf_options["blob_compression_type"],
                                      zstd_version):
        return 5
    return 0


def _not_linked_message(value):
    prefix, _a, _l = MESSAGES["not_linked_prefix"]
    suffix, _a, _l = MESSAGES["not_linked_suffix"]
    return prefix + compression_type_to_string(value) + suffix


def _blob_message(value):
    prefix, _a, _l = MESSAGES["blob_prefix"]
    suffix, _a, _l = MESSAGES["blob_suffix"]
    return prefix + compression_type_to_string(value) + suffix


def check_compression_supported(cf_options, canary_ok=True,
                                alloc_ok=True, fail_at=None):
    """The reconstructed helper: rocksdb::CheckCompressionSupported
    0x5d8dcc0..0x5d8e356.

    Runs the checks in binary order and returns the first non-OK
    status, or OK. The three stack strings (S1/S2/S3) and the
    ostringstream are modelled as live slots only where the
    binary builds them: S1 holds the CompressionTypeToString
    result, S2 the prefix-inserted string, S3 the final message
    (per-level/single paths); the blob path builds its message in
    the ostringstream at the S3 slot and copies it into S2.

    `fail_at` names a throwing call (see THROW_SITES): the
    exception propagates with the pad's cleanup attached, after
    the pad's canary check -- so a throw with a bad canary raises
    StackCheckFailed instead. `alloc_ok=False` fails the Status
    ctor with BadAlloc and the half-built status attached. A
    canary failure on a normal return raises StackCheckFailed; a
    throw never reaches the epilogue, so the throw is not masked
    by a canary failure -- unless the pad's own canary check
    fires first.
    Returns the resulting Status."""
    zstd_version = cf_options["zstd_version"]
    per_level = cf_options["compression_per_level"]

    def _check_throw(site):
        if fail_at == site:
            _throw(site, canary_ok=canary_ok)

    def _ctor(code_name, message, site, pad):
        # The Status ctor at the given call site; on BadAlloc the
        # pad's cleanup runs (resolved as the literal pad action
        # list) and the exception propagates.
        if fail_at == site:
            cleanup = list(PAD_CLEANUP[pad])
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
                           pad=pad, cleanup=list(PAD_CLEANUP[pad]))

    def _epilogue(result):
        # The canary check at 0x5d8ddee (and on the two
        # __throw_length_error paths).
        if not canary_ok:
            raise StackCheckFailed("stack canary mismatch")
        return result

    def _linked_error(value, site_prefix):
        # The shared per-level / single error path: S1 =
        # CompressionTypeToString(value); _M_replace inserts the
        # 17-byte prefix (length check: max_size - len <= 30
        # throws length_error); S2 = move(S1); _M_append adds the
        # 31-byte suffix (same length check); S3 = move(S2);
        # Status ctor into out; dispose S3, S2, S1; epilogue.
        _check_throw("compression-type-to-string:" + site_prefix)
        s1 = compression_type_to_string(value)
        _check_throw("string-replace:" + site_prefix)
        s2 = (MESSAGES["not_linked_prefix"][0] + s1)
        if fail_at == "throw-length-error:" + site_prefix:
            _throw("throw-length-error:" + site_prefix,
                   canary_ok=canary_ok)
        _check_throw("string-append:" + site_prefix)
        s3 = s2 + MESSAGES["not_linked_suffix"][0]
        out = _ctor("kInvalidArgument", s3,
                    "status-ctor:" + site_prefix,
                    {"per-level": 0x65A, "single": 0x666}[site_prefix])
        return _epilogue(out)

    # 1. Per-level loop, or the single compression test when the
    # vector is empty (0x5d8e130).
    if per_level:
        for level in per_level:
            if not compression_type_supported(level, zstd_version):
                return _linked_error(level, "per-level")
    elif not compression_type_supported(cf_options["compression"],
                                        zstd_version):
        return _linked_error(cf_options["compression"], "single")
    # 2. compression_opts.zstd_max_train_bytes (+0x268) > 0.
    opts = cf_options["compression_opts"]
    if opts["zstd_max_train_bytes"] > 0:
        if opts["use_zstd_dict_trainer"]:
            # ZSTD_TrainDictionarySupported: version >= 10103.
            if zstd_version < ZSTD_TRAIN_MIN:
                msg, _a, _l = MESSAGES["trainer"]
                out = _ctor("kInvalidArgument", msg,
                            "status-ctor:max-dict", 0x000)
                return _epilogue(out)
        elif zstd_version < ZSTD_FINALIZE_MIN:
            # ZSTD_FinalizeDictionarySupported: version >= 10405.
            msg, _a, _l = MESSAGES["finalize"]
            out = _ctor("kInvalidArgument", msg,
                        "status-ctor:max-dict", 0x000)
            return _epilogue(out)
        if opts["max_dict_bytes"] == 0:
            msg, _a, _l = MESSAGES["max_dict"]
            out = _ctor("kInvalidArgument", msg,
                        "status-ctor:max-dict", 0x000)
            return _epilogue(out)
    # 3. Blob compression type, via std::ostringstream.
    blob = cf_options["blob_compression_type"]
    if not compression_type_supported(blob, zstd_version):
        _check_throw("ostringstream-ctor")
        _check_throw("ostream-insert:blob-prefix")
        _check_throw("compression-type-to-string:blob")
        _check_throw("ostream-insert:blob-name")
        _check_throw("ostream-insert:blob-suffix")
        message = _blob_message(blob)
        # The ostringstream's str() is copied into S2 with
        # _M_replace (the _M_assign branch at +1489 runs only
        # for an empty string, which never happens here).
        _check_throw("string-replace:blob")
        out = _ctor("kInvalidArgument", message,
                    "status-ctor:blob", 0x61E)
        return _epilogue(out)
    # 4. OK path: out = {0, 0, nullptr} (0x5d8e10a).
    return _epilogue(Status.ok())


# ---------------------------------------------------------------- cases

def _status_dict(status):
    return status.as_dict()


def _opts(inputs):
    cf_opts = default_cf_options()
    cf_opts.update(inputs.get("cf_overrides", {}))
    return cf_opts


def run_case(inputs):
    """Run one case and return the expected outputs."""
    group = inputs["group"]
    if group == "checks":
        cf_opts = _opts(inputs)
        result = check_compression_supported(cf_opts)
        return {"result": _status_dict(result),
                "failed_check": _failing_check(cf_opts)}
    if group == "status":
        kind = inputs["kind"]
        if kind == "ok":
            st = Status.ok()
            return {"status": _status_dict(st)}
        if kind == "error":
            n = inputs["check"]
            _n, _k, code_name = CHECKS[n - 1]
            if n == 1:
                _m, overrides = _CHECK_FAIL_OVERRIDES[0]
                cf_opts = _opts(overrides)
                st = check_compression_supported(cf_opts)
                msg = st.state
            elif n == 2:
                msg = MESSAGES["trainer"][0]
            elif n == 3:
                msg = MESSAGES["finalize"][0]
            elif n == 4:
                msg = MESSAGES["max_dict"][0]
            else:
                _m, overrides = _CHECK_FAIL_OVERRIDES[4]
                cf_opts = _opts(overrides)
                st = check_compression_supported(cf_opts)
                msg = st.state
            st = status_ctor(CODE[code_name], msg, "")
            return {"status": _status_dict(st),
                    "check": n, "message": msg}
        if kind == "ctor-msg2":
            st = status_ctor(CODE["kInvalidArgument"],
                             inputs["message"], inputs["msg2"])
            return {"status": _status_dict(st),
                    "joined": st.state}
        if kind == "blob-error":
            # The blob error message, built via ostringstream.
            msg = _blob_message(6)
            st = status_ctor(CODE["kInvalidArgument"], msg, "")
            return {"status": _status_dict(st), "message": msg}
        if kind == "empty-name":
            # Byte 8 has no CompressionTypeToString case: the
            # message carries the empty name (double space).
            msg = _not_linked_message(8)
            st = status_ctor(CODE["kInvalidArgument"], msg, "")
            return {"status": _status_dict(st), "message": msg}
        if kind == "disable-option":
            # Byte 0xff names "DisableOption" in the message.
            msg = _not_linked_message(0xFF)
            st = status_ctor(CODE["kInvalidArgument"], msg, "")
            return {"status": _status_dict(st), "message": msg}
        raise ValueError("unknown status kind %r" % kind)
    if group == "throw":
        cf_opts = _opts(inputs)
        try:
            result = check_compression_supported(
                cf_opts,
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
        cf_opts = _opts(inputs)
        result = check_compression_supported(cf_opts)
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


# One failing variant per check, as cf overrides.
# (check number, {"cf_overrides": ...})
_CHECK_FAIL_OVERRIDES = [
    (1, {"cf_overrides": {"compression_per_level": [6]}}),
    (2, {"cf_overrides": {
        "compression_opts": {"zstd_max_train_bytes": 1,
                             "use_zstd_dict_trainer": True,
                             "max_dict_bytes": 1},
        "zstd_version": 10102}}),
    (3, {"cf_overrides": {
        "compression_opts": {"zstd_max_train_bytes": 1,
                             "use_zstd_dict_trainer": False,
                             "max_dict_bytes": 1},
        "zstd_version": 10404}}),
    (4, {"cf_overrides": {
        "compression_opts": {"zstd_max_train_bytes": 1,
                             "use_zstd_dict_trainer": False,
                             "max_dict_bytes": 0}}}),
    (5, {"cf_overrides": {"blob_compression_type": 6}}),
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
                _n, overrides = _CHECK_FAIL_OVERRIDES[i % 5]
                inputs.update(overrides)
            elif mode == "pair":
                # Two failures: the earlier check must win.
                a = rng.randrange(5)
                b = rng.randrange(5)
                if a == b:
                    b = (b + 1) % 5
                first, second = min(a, b), max(a, b)
                _n, ov1 = _CHECK_FAIL_OVERRIDES[first]
                _n, ov2 = _CHECK_FAIL_OVERRIDES[second]
                merged = dict(ov1.get("cf_overrides", {}))
                for key, value in ov2.get("cf_overrides", {}).items():
                    if key == "compression_opts" and \
                            "compression_opts" in merged:
                        sub = dict(merged["compression_opts"])
                        sub.update(value)
                        merged["compression_opts"] = sub
                    else:
                        merged[key] = value
                if merged:
                    inputs["cf_overrides"] = merged
                # The pair must not cancel: check 1's per-level
                # [6] masks everything, which is the point; check
                # 5's blob=6 is independent of the zstd gates.
            elif mode == "boundary":
                pick = rng.randrange(14)
                cf = {}
                if pick == 0:
                    cf["compression_per_level"] = []
                    cf["compression"] = 0
                elif pick == 1:
                    cf["compression_per_level"] = [0, 1, 2, 3, 4, 5,
                                                   0x40]
                elif pick == 2:
                    cf["compression_per_level"] = [7]
                    cf["zstd_version"] = 799
                elif pick == 3:
                    cf["compression_per_level"] = [7]
                    cf["zstd_version"] = 800
                elif pick == 4:
                    cf["compression_per_level"] = [8]
                elif pick == 5:
                    cf["compression_per_level"] = [0xFF]
                elif pick == 6:
                    cf["compression_per_level"] = [0, 1, 6, 7]
                elif pick == 7:
                    cf["compression_per_level"] = [0x40]
                    cf["zstd_version"] = 799
                elif pick == 8:
                    cf["compression_opts"] = {
                        "zstd_max_train_bytes": 1,
                        "use_zstd_dict_trainer": True,
                        "max_dict_bytes": 1}
                    cf["zstd_version"] = 10103
                elif pick == 9:
                    cf["compression_opts"] = {
                        "zstd_max_train_bytes": 1,
                        "use_zstd_dict_trainer": False,
                        "max_dict_bytes": 1}
                    cf["zstd_version"] = 10405
                elif pick == 10:
                    cf["compression_opts"] = {
                        "zstd_max_train_bytes": 0,
                        "use_zstd_dict_trainer": True,
                        "max_dict_bytes": 0}
                elif pick == 11:
                    cf["blob_compression_type"] = 0x40
                elif pick == 12:
                    cf["blob_compression_type"] = 0xFF
                else:
                    cf["compression_per_level"] = [7, 0x40, 5]
                    cf["blob_compression_type"] = 6
                if cf:
                    inputs["cf_overrides"] = cf
            else:  # mixed
                cf = {
                    "compression_per_level": rng.choice(
                        [[], [0], [1, 2], [7], [6], [0x40], [8],
                         [0xFF], [0, 7, 0x40], [5, 6]]),
                    "compression": rng.choice([0, 1, 6, 7, 0x40, 0xFF]),
                    "blob_compression_type": rng.choice(
                        [0, 1, 6, 7, 0x40, 0xFF, 9]),
                    "zstd_version": rng.choice(
                        [799, 800, 10102, 10103, 10404, 10405, 10506]),
                    "compression_opts": {
                        "zstd_max_train_bytes": rng.choice([0, 1, 100]),
                        "use_zstd_dict_trainer": rng.random() < 0.5,
                        "max_dict_bytes": rng.choice([0, 1, 4096])},
                }
                inputs["cf_overrides"] = cf
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
                          "kind": "error", "check": (i % 5) + 1}
            elif mode == 2:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "ctor-msg2",
                          "message": "a", "msg2": "b"}
            elif mode == 3:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "blob-error"}
            elif mode == 4:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "empty-name"}
            else:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "disable-option"}
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    elif group == "throw":
        # Reachable throw sites (the _M_assign site is a dead
        # branch for real inputs and is not rotated here).
        sites = [s for s in THROW_SITES
                 if s != "string-assign:blob-empty"]
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = i % 6
            inputs = {"group": group, "case_id": case_id}
            if mode == 0:
                # BadAlloc in the Status ctor at each error site
                # (fail_at names the site; the inputs must reach
                # that error).
                check = (i // 6) % 4 + 1  # ctor sites 1,2/3/4,5
                site = {1: "status-ctor:per-level",
                        2: "status-ctor:max-dict",
                        3: "status-ctor:blob",
                        4: "status-ctor:single"}[check]
                overrides = {
                    1: {"compression_per_level": [6]},
                    2: {"compression_opts": {
                        "zstd_max_train_bytes": 1,
                        "use_zstd_dict_trainer": False,
                        "max_dict_bytes": 0}},
                    3: {"blob_compression_type": 6},
                    4: {"compression": 6,
                        "compression_per_level": []},
                }[check]
                inputs["cf_overrides"] = overrides
                inputs["fail_at"] = site
            elif mode == 1:
                # Callee throw at a string / ostream / version /
                # length-error site. Each site needs the inputs
                # that reach it.
                site = sites[i % len(sites)]
                inputs["fail_at"] = site
                reach = {
                    "compression-type-to-string:per-level":
                        {"compression_per_level": [6]},
                    "string-replace:per-level":
                        {"compression_per_level": [6]},
                    "string-append:per-level":
                        {"compression_per_level": [6]},
                    "status-ctor:per-level":
                        {"compression_per_level": [6]},
                    "status-ctor:max-dict":
                        {"compression_opts": {
                            "zstd_max_train_bytes": 1,
                            "use_zstd_dict_trainer": False,
                            "max_dict_bytes": 0}},
                    "ostringstream-ctor":
                        {"blob_compression_type": 6},
                    "ostream-insert:blob-prefix":
                        {"blob_compression_type": 6},
                    "compression-type-to-string:blob":
                        {"blob_compression_type": 6},
                    "ostream-insert:blob-name":
                        {"blob_compression_type": 6},
                    "ostream-insert:blob-suffix":
                        {"blob_compression_type": 6},
                    "string-replace:blob":
                        {"blob_compression_type": 6},
                    "status-ctor:blob":
                        {"blob_compression_type": 6},
                    "compression-type-to-string:single":
                        {"compression": 6, "compression_per_level": []},
                    "string-replace:single":
                        {"compression": 6, "compression_per_level": []},
                    "string-append:single":
                        {"compression": 6, "compression_per_level": []},
                    "status-ctor:single":
                        {"compression": 6, "compression_per_level": []},
                    "throw-length-error:single":
                        {"compression": 6, "compression_per_level": []},
                    "throw-length-error:per-level":
                        {"compression_per_level": [6]},
                }[site]
                inputs["cf_overrides"] = reach
            elif mode == 2:
                # Canary failure on a normal OK return.
                inputs["canary_ok"] = False
            elif mode == 3:
                # Canary failure on a normal error return.
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(5)]
                inputs.update(overrides)
                inputs["canary_ok"] = False
            elif mode == 4:
                # BadAlloc AND a bad canary: the throw wins at
                # the pad's canary check -- StackCheckFailed.
                site = rng.choice(["status-ctor:per-level",
                                   "status-ctor:max-dict",
                                   "status-ctor:blob",
                                   "status-ctor:single"])
                overrides = {
                    "status-ctor:per-level":
                        {"compression_per_level": [6]},
                    "status-ctor:max-dict":
                        {"compression_opts": {
                            "zstd_max_train_bytes": 1,
                            "use_zstd_dict_trainer": False,
                            "max_dict_bytes": 0}},
                    "status-ctor:blob":
                        {"blob_compression_type": 6},
                    "status-ctor:single":
                        {"compression": 6,
                         "compression_per_level": []},
                }[site]
                inputs["cf_overrides"] = overrides
                inputs["fail_at"] = site
                inputs["alloc_ok"] = False
                inputs["canary_ok"] = False
            else:
                # alloc_ok=False with no fail_at: the ctor fails
                # only when an error path runs it.
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(5)]
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
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(5)]
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
        ("CompressionTypeToString 0x5d8b3c0 x3",
         dis.count("call   5d8b3c0") == 3,
         dis.count("call   5d8b3c0")),
        ("status ctor 0x61cf670 x4",
         dis.count("call   61cf670") == 4,
         dis.count("call   61cf670")),
        ("ZSTD_versionNumber 0x620dd50 x5",
         dis.count("call   620dd50") == 5,
         dis.count("call   620dd50")),
        ("_M_replace 0x63f0d90 x3",
         dis.count("call   63f0d90") == 3,
         dis.count("call   63f0d90")),
        ("_M_append 0x63f0f40 x2",
         dis.count("call   63f0f40") == 2,
         dis.count("call   63f0f40")),
        ("string move ctor 0x63f0eb0 x4",
         dis.count("call   63f0eb0") == 4,
         dis.count("call   63f0eb0")),
        ("_M_dispose 0x63f0db0 x6",
         dis.count("call   63f0db0") == 6,
         dis.count("call   63f0db0")),
        ("__ostream_insert 0x63f10f0 x3",
         dis.count("call   63f10f0") == 3,
         dis.count("call   63f10f0")),
        ("ostringstream ctor 0x63f10e0 x1",
         dis.count("call   63f10e0") == 1,
         dis.count("call   63f10e0")),
        ("_M_assign 0x63f0f00 x1",
         dis.count("call   63f0f00") == 1,
         dis.count("call   63f0f00")),
        ("locale dtor 0x63f1100 x1",
         dis.count("call   63f1100") == 1,
         dis.count("call   63f1100")),
        ("ios_base dtor 0x63f1110 x1",
         dis.count("call   63f1110") == 1,
         dis.count("call   63f1110")),
        ("__throw_length_error 0x63f0de0 x2",
         dis.count("call   63f0de0") == 2,
         dis.count("call   63f0de0")),
        ("__stack_chk_fail x1",
         dis.count("<__stack_chk_fail@plt>") == 1,
         dis.count("<__stack_chk_fail@plt>")),
        ("endbr64 x11 (entry + 10 pad stubs)",
         dis.count("endbr64") == 11, dis.count("endbr64")),
        ("canary refs %fs:0x28 x4 (store + 3 checks)",
         dis.count("%fs:0x28") == 4, dis.count("%fs:0x28")),
        ("msg2 lea 0x4376fd x6 (one per error message)",
         dis.count("# 4376fd") == 6, dis.count("# 4376fd")),
        ("length-check movabs 0x3fffffffffffffff x2",
         dis.count("movabs $0x3fffffffffffffff") == 2,
         dis.count("movabs $0x3fffffffffffffff")),
        ("total call lines 37",
         sum(1 for l in dis.splitlines() if "\tcall" in l) == 37,
         sum(1 for l in dis.splitlines() if "\tcall" in l)),
    ]
    legs.extend(counts)
    cold = _disasm(data, secs, COLD_START, COLD_END)
    cold_counts = [
        ("cold: _M_dispose x8",
         cold.count("call   63f0db0") == 8,
         cold.count("call   63f0db0")),
        ("cold: ostringstream dtor 0x63f1120 x1",
         cold.count("call   63f1120") == 1,
         cold.count("call   63f1120")),
        ("cold: _Unwind_Resume x2",
         cold.count("<_Unwind_Resume@plt>") == 2,
         cold.count("<_Unwind_Resume@plt>")),
        ("cold: __stack_chk_fail x1",
         cold.count("<__stack_chk_fail@plt>") == 1,
         cold.count("<__stack_chk_fail@plt>")),
        ("cold: no endbr64 (cold entry has none)",
         cold.count("endbr64") == 0, cold.count("endbr64")),
        ("cold: canary refs %fs:0x28 x2",
         cold.count("%fs:0x28") == 2, cold.count("%fs:0x28")),
        ("cold: total call lines 12",
         sum(1 for l in cold.splitlines() if "\tcall" in l) == 12,
         sum(1 for l in cold.splitlines() if "\tcall" in l)),
    ]
    legs.extend(cold_counts)
    # ZSTD_versionNumber body: mov $0x290a,%eax; ret (10 bytes).
    zstd = _disasm(data, secs, ZSTD_VERSION_NUMBER,
                   ZSTD_VERSION_NUMBER + 10)
    legs.append(("ZSTD_versionNumber returns 0x290a (10506)",
                 "mov    $0x290a,%eax" in zstd, None))
    return legs


def _field_cmps(data, secs):
    legs = []
    dis = _disasm(data, secs, START, END)
    checks = [
        ("compression_per_level begin/end +0x70/+0x78",
         "mov    0x70(%rsi),%rdx" in dis
         and "mov    0x78(%rsi),%rcx" in dis),
        ("loop byte load movzbl (%rdx,%rbx,1)",
         "movzbl (%rdx,%rbx,1),%eax" in dis),
        ("byte == 7 (kZSTD) x3",
         dis.count("cmp    $0x7,%al") == 3,
         dis.count("cmp    $0x7,%al")),
        ("byte == 6 (kXpress) x3",
         dis.count("cmp    $0x6,%al") == 3,
         dis.count("cmp    $0x6,%al")),
        ("byte == 0x40 (kZSTDNotFinal) x3",
         dis.count("cmp    $0x40,%al") == 3,
         dis.count("cmp    $0x40,%al")),
        ("ZSTD >= 800 cmp $0x31f x3",
         dis.count("cmp    $0x31f,%eax") == 3,
         dis.count("cmp    $0x31f,%eax")),
        ("trainer >= 10103 cmp $0x2776 x1",
         dis.count("cmp    $0x2776,%eax") == 1,
         dis.count("cmp    $0x2776,%eax")),
        ("finalize >= 10405 cmp $0x28a4 x1",
         dis.count("cmp    $0x28a4,%eax") == 1,
         dis.count("cmp    $0x28a4,%eax")),
        ("zstd_max_train_bytes mov +0x268 + test",
         "mov    0x268(%rbp),%ecx" in dis
         and "test   %ecx,%ecx" in dis),
        ("use_zstd_dict_trainer cmpb +0x280",
         "cmpb   $0x0,0x280(%rbp)" in dis),
        ("max_dict_bytes mov +0x264 + test",
         "mov    0x264(%rbp),%edx" in dis
         and "test   %edx,%edx" in dis),
        ("blob_compression_type movzbl +0x1a8",
         "movzbl 0x1a8(%rbp),%eax" in dis),
        ("compression movzbl +0x220 (empty-vector path)",
         "movzbl 0x220(%rsi),%eax" in dis),
        ("OK path writes out = {0,0,nullptr}",
         "movl   $0x0,(%r12)" in dis
         and "mov    %ax,0x4(%r12)" in dis
         and "movq   $0x0,0x8(%r12)" in dis),
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
            ("main", LSDA_ADDR, LSDA_ENTRIES, START, 0x40, 0x696),
            ("cold", COLD_LSDA_ADDR, COLD_LSDA_ENTRIES, COLD_START,
             0x1C, 0x89)):
        raw = _read_va(data, secs, addr, 128)
        legs.append(("%s LSDA header ff ff 01" % label,
                     list(raw[:3]) == [0xFF, 0xFF, 0x01],
                     raw[:3].hex()))
        table_len = raw[3]
        want_len = 0x63 if label == "main" else 0x04
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
    legs.append(("caller census: 1 call, 0 jumps, 0 lea refs",
                 sites == [(0x5D8E3FB, "call")],
                 sites))
    legs.append(("defaults validate OK",
                 check_compression_supported(
                     default_cf_options()).is_ok(), None))
    for n, _k, code_name in CHECKS:
        _m, overrides = _CHECK_FAIL_OVERRIDES[n - 1]
        cf_opts = _opts(overrides)
        st = check_compression_supported(cf_opts)
        if n == 1:
            msg = _not_linked_message(6)
        elif n == 2:
            msg = MESSAGES["trainer"][0]
        elif n == 3:
            msg = MESSAGES["finalize"][0]
        elif n == 4:
            msg = MESSAGES["max_dict"][0]
        else:
            msg = _blob_message(6)
        legs.append(("check %d fails with its message" % n,
                     st.code == CODE[code_name] and st.state == msg,
                     "%s %r" % (CODE_NAME[st.code],
                                (st.state or "")[:24])))
    # First failure wins: check 1 masks check 5; the trainer
    # gate masks the max_dict_bytes gate.
    cf_opts = default_cf_options()
    cf_opts["compression_per_level"] = [6]
    cf_opts["blob_compression_type"] = 6
    legs.append(("check 1 masks check 5",
                 check_compression_supported(cf_opts).state ==
                 _not_linked_message(6), None))
    cf_opts = default_cf_options()
    cf_opts["compression_opts"] = {"zstd_max_train_bytes": 1,
                                   "use_zstd_dict_trainer": True,
                                   "max_dict_bytes": 0}
    cf_opts["zstd_version"] = 10102
    legs.append(("trainer gate masks max_dict gate",
                 check_compression_supported(cf_opts).state ==
                 MESSAGES["trainer"][0], None))
    # Version boundaries: 799/800, 10102/10103, 10404/10405.
    for version, supported in ((799, False), (800, True)):
        cf_opts = default_cf_options()
        cf_opts["compression_per_level"] = [7]
        cf_opts["zstd_version"] = version
        legs.append(("ZSTD kZSTD supported at version %d: %s"
                     % (version, supported),
                     check_compression_supported(cf_opts).is_ok()
                     == supported, None))
    for version, train_ok in ((10102, False), (10103, True)):
        cf_opts = default_cf_options()
        cf_opts["compression_opts"] = {"zstd_max_train_bytes": 1,
                                       "use_zstd_dict_trainer": True,
                                       "max_dict_bytes": 1}
        cf_opts["zstd_version"] = version
        legs.append(("trainer supported at version %d: %s"
                     % (version, train_ok),
                     check_compression_supported(cf_opts).is_ok()
                     == train_ok, None))
    for version, fin_ok in ((10404, False), (10405, True)):
        cf_opts = default_cf_options()
        cf_opts["compression_opts"] = {"zstd_max_train_bytes": 1,
                                       "use_zstd_dict_trainer": False,
                                       "max_dict_bytes": 1}
        cf_opts["zstd_version"] = version
        legs.append(("finalize supported at version %d: %s"
                     % (version, fin_ok),
                     check_compression_supported(cf_opts).is_ok()
                     == fin_ok, None))
    # Byte 8 has no name: the message carries the empty name.
    cf_opts = default_cf_options()
    cf_opts["compression_per_level"] = [8]
    legs.append(("byte 8 message has the empty name",
                 check_compression_supported(cf_opts).state ==
                 "Compression type  is not linked with the binary.",
                 None))
    # Byte 0xff names DisableOption; 0x40 (ZSTDNotFinal) passes.
    cf_opts = default_cf_options()
    cf_opts["compression_per_level"] = [0xFF]
    legs.append(("byte 0xff message names DisableOption",
                 check_compression_supported(cf_opts).state ==
                 "Compression type DisableOption is not linked with "
                 "the binary.", None))
    cf_opts = default_cf_options()
    cf_opts["compression_per_level"] = [0x40]
    legs.append(("byte 0x40 (ZSTDNotFinal) passes",
                 check_compression_supported(cf_opts).is_ok(), None))
    # Status ctor legs: state_ buffer is msg + NUL, alloc len+1.
    st = status_ctor(CODE["kInvalidArgument"], MESSAGES["trainer"][0],
                     "")
    legs.append(("ctor state_ buffer is msg + NUL",
                 st.state_buffer() == MESSAGES["trainer"][0].encode()
                 + b"\x00"
                 and st.state_alloc() == len(MESSAGES["trainer"][0]) + 1,
                 None))
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
