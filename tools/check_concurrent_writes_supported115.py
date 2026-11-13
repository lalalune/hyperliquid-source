#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::CheckConcurrentWritesSupported.

Target: rocksdb::CheckConcurrentWritesSupported(const ColumnFamilyOptions&)
at 0x5d8ba60..0x5d8bb48 (232 B, single FDE) in node #115
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The helper ColumnFamilyData::ValidateOptions (open PR #6449) calls
once, at site 0x5d8e7ee, when allow_concurrent_memtable_write is
set, as its second check. This packet supersedes the reference
oracle for this function in the #6449 packet with the full
reconstruction.

Whole-FDE facts (verified live, see --live):
- Signature: Status by value (hidden sret out in rdi = rbx),
  cf_options in rsi. Stack canary used (stored 0x28(%rsp),
  checked at the epilogue 0x5d8baae; a failure calls
  __stack_chk_fail at 0x5d8bb43).
- Checks in binary order (upstream RocksDB v8.1.1
  db/column_family.cc:161-171, read live this cycle), first
  failure wins, else OK:
  1. inplace_update_support (+0x18, bool) != 0 -> InvalidArgument,
     "In-place memtable updates (inplace_update_support) is not
     compatible with concurrent writes
     (allow_concurrent_memtable_write)" (125 B, 0x95a210).
  2. memtable_factory (+0x128, shared_ptr<MemTableRepFactory>)
     -> IsInsertConcurrentlySupported() at vtable slot 0xa8
     (byte offset 168, slot 21) returns false -> InvalidArgument,
     "Memtable doesn't concurrent writes
     (allow_concurrent_memtable_write)" (68 B, 0x95e160).
  3. OK: out = {0, 0, nullptr} (movl/movw/movq at 0x5d8ba9c).
- Both error paths build their Slices on the stack (msg at
  (%rsp)/0x8(%rsp), msg2 = {0x4376fd, 0} at 0x10(%rsp)/0x18(%rsp))
  and share the single Status ctor call at 0x5d8bb0e
  (0x61cf670, census-bound, status.o): out, code 4, subcode 0,
  &msg, &msg2, severity 0. The OK path writes out directly (no
  move-assign is used anywhere in this FDE). Bytes +0x6..+0x7
  of out are never written by any path -- the model zeroes them
  and records them as unwritten padding.
- The FDE has NO .cold FDE and NO LSDA (the .eh_frame record at
  section offset 0x34ba04 has length 0x20, range 0xe8, aug_len 0):
  no landing pad, no catch, no cleanup. A throw from the Status
  ctor (bad_alloc) or from the virtual IsInsertConcurrently-
  Supported call propagates straight through; the canary is
  checked only on normal returns, so a throw is never masked by
  a canary failure -- unlike the LSDA packets, a BadAlloc with a
  bad canary still propagates as BadAlloc.
- The vtable slot is verified two ways: by hand-counting the
  MemTableRepFactory vtable (Configurable 14 slots, Customizable
  5 more, CreateMemTableRep x2, then IsInsertConcurrently-
  Supported at slot 21) and by compiling the pointer-to-member
  encoding with g++ (vtable byte offset 168 = 0xa8).
- The default memtable factory is SkipListFactory, whose
  IsInsertConcurrentlySupported returns true (memtablerep.h:354);
  the base MemTableRepFactory default returns false (:321). The
  model takes the factory's answer as an input.

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
START = 0x5D8BA60
END = 0x5D8BB48
BODY_SHA256 = ("a74c304849fb7d03189b349820271542e7cdbd92e18ce7dd14"
               "30a86244394de3")
SOURCE_SHA256 = ("c94795516f63b1c4286a0a69e1e9ba06b26a465fa9004a0e"
                 "77a4a36ca3394fb0")
RELOCATIONS = ("124:kind2;136:kind2;175:kind4;196:kind2;208:kind2;"
               "228:kind4")
MEMBER = "25dac13516458d4d-column_family.o"
SYMBOL = ("_ZN7rocksdb30CheckConcurrentWritesSupportedERKNS_"
          "19ColumnFamilyOptionsE")
# FDE record in .eh_frame (section offset 0x34ba04): length 0x20,
# range 0xe8, aug_len 0 -- no LSDA pointer, no landing pad.
FDE_SECTION_OFFSET = 0x34BA04
FDE_LENGTH = 0x20
FDE_RANGE = 0xE8
# Engine callees (census-bound unless noted).
STATUS_CTOR = 0x61CF670
STACK_CHK_FAIL = 0x63F0D70
EMPTY_MSG2_ADDR = 0x4376FD

CODE = {"kOk": 0, "kNotFound": 1, "kCorruption": 2, "kNotSupported": 3,
        "kInvalidArgument": 4, "kIOError": 5, "kMergeInProgress": 6,
        "kIncomplete": 7, "kShutdownInProgress": 8, "kTimedOut": 9,
        "kAborted": 10, "kBusy": 11, "kExpired": 12, "kTryAgain": 13,
        "kCompactionTooLarge": 14, "kColumnFamilyDropped": 15}
CODE_NAME = {v: k for k, v in CODE.items()}

# The two error messages, byte-verified against .rodata.
# (message, address, length)
MESSAGES = {
    "inplace": ("In-place memtable updates (inplace_update_support) "
                "is not compatible with concurrent writes "
                "(allow_concurrent_memtable_write)",
                0x95A210, 125),
    "memtable": ("Memtable doesn't concurrent writes "
                 "(allow_concurrent_memtable_write)",
                 0x95E160, 68),
}
# The checks in binary order: (n, kind, code_name).
CHECKS = [
    (1, "inplace", "kInvalidArgument"),
    (2, "memtable", "kInvalidArgument"),
]
# Callers: (site, caller start, caller name, member).
CALLERS = [
    (0x5D8E7EE, 0x5D8E3B0, "ColumnFamilyData::ValidateOptions",
     "25dac13516458d4d-column_family.o"),
]
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-check-concurrent-writes-supported-115"
CASES = PACKET / "cases.tsv"


class BadAlloc(Exception):
    """std::bad_alloc raised inside the Status ctor (new char[]
    failed). `partial` is the half-built out Status for the ctor
    case: code/subcode/severity already written, state_ still
    nullptr. This FDE has no LSDA, so there is no pad and no
    cleanup: the exception propagates straight through, and a
    bad canary never masks it (the canary is checked only on
    normal returns)."""

    def __init__(self, message="simulated BadAlloc"):
        super().__init__(message)
        self.partial = None
        self.site = None
        self.pad = None
        self.cleanup = []


class CalleeThrow(Exception):
    """An exception thrown by a callee (the virtual
    IsInsertConcurrentlySupported call). The binary never names
    the exception type; the model records the throwing site.
    No LSDA means no pad and no cleanup."""

    def __init__(self, site, pad, cleanup):
        super().__init__("simulated throw at 0x%x" % site)
        self.site = site
        self.pad = pad
        self.cleanup = cleanup


class StackCheckFailed(Exception):
    """__stack_chk_fail: the stack canary did not match on a
    normal return (the epilogue at 0x5d8baae). A throw never
    reaches the epilogue, so a throw is not masked by a canary
    failure in this FDE."""

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
    state_ still None); with no LSDA the exception propagates
    with no cleanup. The ctor's trailing delete[] of the old
    state_ is dead: state_ was zeroed before the read, so it
    never fires."""
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


def default_cf_options():
    """ColumnFamilyOptions fields this FDE reads. Defaults are the
    upstream v8.1.1 defaults (options.h / memtablerep.h, field
    offsets verified against the real headers this cycle with
    g++ offsetof); they are model inputs, not binary claims.
    `memtable_factory_concurrent` is the answer of the factory's
    virtual IsInsertConcurrentlySupported() (default true: the
    default factory is SkipListFactory)."""
    return {
        # +0x18 inplace_update_support (bool).
        "inplace_update_support": False,
        # +0x128 memtable_factory (shared_ptr<MemTableRepFactory>):
        # the vtable call at slot 0xa8 returns this.
        "memtable_factory_concurrent": True,
    }


# ---------------------------------------------------------------- model

# Throw sites: (fail_at name, call address, LSDA pad, ctor site?).
# This FDE has NO LSDA, so every pad is None and every cleanup is
# empty: a throw propagates straight through with no cleanup and
# no pad canary check.
THROW_SITES = {
    "virtual-call:is-insert-concurrently-supported":
        (0x5D8BA90, None, False),
    "status-ctor:inplace": (0x5D8BB0E, None, True),
    "status-ctor:memtable": (0x5D8BB0E, None, True),
}


def _throw(site, canary_ok=True):
    """Raise the exception for a throw at `site`. With no LSDA
    there is no pad cleanup and no pad canary check, so the
    exception propagates as-is even with a bad canary."""
    addr, pad, _is_ctor = THROW_SITES[site]
    raise CalleeThrow(addr, pad, [])


def _failing_check(cf_options):
    """The first failing check number (1-2), or 0 when all pass.
    Follows the binary's control flow exactly: the
    inplace_update_support gate first, then the virtual
    IsInsertConcurrentlySupported call."""
    if cf_options["inplace_update_support"]:
        return 1
    if not cf_options["memtable_factory_concurrent"]:
        return 2
    return 0


def check_concurrent_writes_supported(cf_options, canary_ok=True,
                                      alloc_ok=True, fail_at=None):
    """The reconstructed helper: rocksdb::CheckConcurrentWrites-
    Supported 0x5d8ba60..0x5d8bb48.

    Runs the checks in binary order and returns the first non-OK
    status, or OK.

    `fail_at` names a throwing call (see THROW_SITES): the
    exception propagates with no cleanup (no LSDA). `alloc_ok=False`
    fails the Status ctor with BadAlloc and the half-built status
    attached. A canary failure on a normal return raises
    StackCheckFailed; a throw never reaches the epilogue, so the
    throw is not masked by a canary failure -- and with no LSDA
    there is no pad canary check either, so BadAlloc + a bad
    canary still propagates as BadAlloc.
    Returns the resulting Status."""
    def _check_throw(site):
        if fail_at == site:
            _throw(site, canary_ok=canary_ok)

    def _ctor(code_name, message, site):
        # The Status ctor at the single call site 0x5d8bb0e; on
        # BadAlloc the exception propagates with no cleanup.
        if fail_at == site:
            err = BadAlloc()
            err.partial = Status(CODE[code_name], 0, 0, None)
            err.site, err.pad = THROW_SITES[site][0], None
            err.cleanup = []
            raise err
        return status_ctor(CODE[code_name], message, "",
                           alloc_ok=alloc_ok, site=THROW_SITES[site][0],
                           pad=None, cleanup=[])

    def _epilogue(result):
        # The canary check at 0x5d8baae.
        if not canary_ok:
            raise StackCheckFailed("stack canary mismatch")
        return result

    # 1. inplace_update_support (+0x18) != 0 (0x5d8ba7c).
    if cf_options["inplace_update_support"]:
        msg, _a, _l = MESSAGES["inplace"]
        out = _ctor("kInvalidArgument", msg, "status-ctor:inplace")
        return _epilogue(out)
    # 2. memtable_factory (+0x128) -> IsInsertConcurrentlySupported
    # at vtable slot 0xa8 (0x5d8ba90); false -> error (0x5d8bad0).
    _check_throw("virtual-call:is-insert-concurrently-supported")
    if not cf_options["memtable_factory_concurrent"]:
        msg, _a, _l = MESSAGES["memtable"]
        out = _ctor("kInvalidArgument", msg, "status-ctor:memtable")
        return _epilogue(out)
    # 3. OK path: out = {0, 0, nullptr} (0x5d8ba9c).
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
        result = check_concurrent_writes_supported(cf_opts)
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
            msg = MESSAGES["inplace" if n == 1 else "memtable"][0]
            st = status_ctor(CODE[code_name], msg, "")
            return {"status": _status_dict(st),
                    "check": n, "message": msg}
        if kind == "ctor-msg2":
            st = status_ctor(CODE["kInvalidArgument"],
                             inputs["message"], inputs["msg2"])
            return {"status": _status_dict(st),
                    "joined": st.state}
        if kind == "inplace-message":
            msg = MESSAGES["inplace"][0]
            st = status_ctor(CODE["kInvalidArgument"], msg, "")
            return {"status": _status_dict(st), "message": msg}
        if kind == "memtable-message":
            msg = MESSAGES["memtable"][0]
            st = status_ctor(CODE["kInvalidArgument"], msg, "")
            return {"status": _status_dict(st), "message": msg}
        raise ValueError("unknown status kind %r" % kind)
    if group == "throw":
        cf_opts = _opts(inputs)
        try:
            result = check_concurrent_writes_supported(
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
                    "canary_checked": False}
        except CalleeThrow as err:
            return {"error": "CalleeThrow",
                    "site": hex(err.site), "pad": None,
                    "cleanup": err.cleanup,
                    "canary_checked": False}
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
        result = check_concurrent_writes_supported(cf_opts)
        return {
            "caller_site": inputs["caller_site"],
            "result": _status_dict(result),
            "result_sha256": hashlib.sha256(
                result.image()).hexdigest(),
            "result_independent_of_caller": True,
            "body_sha256": BODY_SHA256,
            "source_sha256": SOURCE_SHA256,
            "relocations": RELOCATIONS,
            "engine_calls": {"status_ctor_0x61cf670":
                             0 if result.is_ok() else 1,
                             "stack_chk_fail_0x63f0d70": 0},
        }
    raise ValueError("unknown group %r" % group)


# One failing variant per check, as cf overrides.
# (check number, {"cf_overrides": ...})
_CHECK_FAIL_OVERRIDES = [
    (1, {"cf_overrides": {"inplace_update_support": True}}),
    (2, {"cf_overrides": {"memtable_factory_concurrent": False}}),
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
                _n, overrides = _CHECK_FAIL_OVERRIDES[(i // 4) % 2]
                inputs.update(overrides)
            elif mode == "pair":
                # Both failures: check 1 must win.
                inputs["cf_overrides"] = {
                    "inplace_update_support": True,
                    "memtable_factory_concurrent": False}
            elif mode == "boundary":
                pick = i % 4
                if pick == 0:
                    inputs["cf_overrides"] = {
                        "inplace_update_support": False,
                        "memtable_factory_concurrent": True}
                elif pick == 1:
                    inputs["cf_overrides"] = {
                        "inplace_update_support": True,
                        "memtable_factory_concurrent": True}
                elif pick == 2:
                    inputs["cf_overrides"] = {
                        "inplace_update_support": False,
                        "memtable_factory_concurrent": False}
                else:
                    inputs["cf_overrides"] = {
                        "inplace_update_support": True,
                        "memtable_factory_concurrent": False}
            else:  # mixed
                inputs["cf_overrides"] = {
                    "inplace_update_support": rng.random() < 0.5,
                    "memtable_factory_concurrent": rng.random() < 0.5}
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
                          "kind": "error", "check": (i % 2) + 1}
            elif mode == 2:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "ctor-msg2",
                          "message": "a", "msg2": "b"}
            elif mode == 3:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "inplace-message"}
            else:
                inputs = {"group": group, "case_id": case_id,
                          "kind": "memtable-message"}
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    elif group == "throw":
        for i in range(n):
            case_id = "%s-%04d" % (group, i)
            mode = i % 6
            inputs = {"group": group, "case_id": case_id}
            if mode == 0:
                # BadAlloc in the Status ctor at each error site
                # (fail_at names the site; the inputs must reach
                # that error).
                check = (i // 6) % 2 + 1
                site = {1: "status-ctor:inplace",
                        2: "status-ctor:memtable"}[check]
                overrides = {
                    1: {"inplace_update_support": True},
                    2: {"memtable_factory_concurrent": False},
                }[check]
                inputs["cf_overrides"] = overrides
                inputs["fail_at"] = site
            elif mode == 1:
                # Callee throw at the virtual call. It is reached
                # whenever check 1 passes (inplace off).
                site = "virtual-call:is-insert-concurrently-supported"
                inputs["fail_at"] = site
                inputs["cf_overrides"] = {
                    "inplace_update_support": False}
            elif mode == 2:
                # Canary failure on a normal OK return.
                inputs["canary_ok"] = False
            elif mode == 3:
                # Canary failure on a normal error return.
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(2)]
                inputs.update(overrides)
                inputs["canary_ok"] = False
            elif mode == 4:
                # BadAlloc AND a bad canary: with no LSDA there is
                # no pad canary check, so the throw still
                # propagates as BadAlloc (not StackCheckFailed).
                site = rng.choice(["status-ctor:inplace",
                                   "status-ctor:memtable"])
                overrides = {
                    "status-ctor:inplace":
                        {"inplace_update_support": True},
                    "status-ctor:memtable":
                        {"memtable_factory_concurrent": False},
                }[site]
                inputs["cf_overrides"] = overrides
                inputs["fail_at"] = site
                inputs["alloc_ok"] = False
                inputs["canary_ok"] = False
            else:
                # alloc_ok=False with no fail_at: the ctor fails
                # only when an error path runs it.
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(2)]
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
                _n, overrides = _CHECK_FAIL_OVERRIDES[rng.randrange(2)]
                inputs.update(overrides)
            expected = run_case(inputs)
            rows.append((group, case_id, inputs, expected))
    return rows


def write_cases():
    all_rows = []
    for gi, group in enumerate(["checks", "status", "throw", "bindings"]):
        rng = random.Random(115200 + gi)
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
    census = json.load(open(
        Path(__file__).resolve().parents[1] / "research" / "work-items" /
        "RE-002-node115-vendor-census" / "census.json"))["records"]
    rec = {r["start"]: r for r in census}
    body = _read_va(data, secs, START, END - START)
    legs.append(("body hash",
                 hashlib.sha256(body).hexdigest() == BODY_SHA256,
                 hashlib.sha256(body).hexdigest()[:16]))
    r = rec[START]
    zeroed = bytearray(body)
    for rel in r["relocations"]:
        o, w = rel["offset"], rel["width"]
        zeroed[o:o + w] = b"\x00" * w
    legs.append(("source hash (%d relocations zeroed)"
                 % len(r["relocations"]),
                 hashlib.sha256(bytes(zeroed)).hexdigest()
                 == SOURCE_SHA256,
                 hashlib.sha256(bytes(zeroed)).hexdigest()[:16]))
    legs.append(("relocation list matches census",
                 ";".join("%d:kind%d" % (x["offset"], x["kind"])
                          for x in r["relocations"]) == RELOCATIONS,
                 "%d relocations" % len(r["relocations"])))
    legs.append(("census symbol",
                 r["symbol"] == SYMBOL, r["symbol"][-24:]))
    legs.append(("census member",
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
        ("status ctor 0x61cf670 x1",
         dis.count("call   61cf670") == 1,
         dis.count("call   61cf670")),
        ("virtual call *0xa8(%rax) x1 (IsInsertConcurrentlySupported)",
         dis.count("call   *0xa8(%rax)") == 1,
         dis.count("call   *0xa8(%rax)")),
        ("__stack_chk_fail x1",
         dis.count("<__stack_chk_fail@plt>") == 1,
         dis.count("<__stack_chk_fail@plt>")),
        ("endbr64 x1",
         dis.count("endbr64") == 1, dis.count("endbr64")),
        ("canary refs %fs:0x28 x2 (store + epilogue check)",
         dis.count("%fs:0x28") == 2, dis.count("%fs:0x28")),
        ("msg2 lea 0x4376fd x2 (one per error path)",
         dis.count("# 4376fd") == 2, dis.count("# 4376fd")),
        ("total call lines 3",
         sum(1 for l in dis.splitlines() if "\tcall" in l) == 3,
         sum(1 for l in dis.splitlines() if "\tcall" in l)),
    ]
    legs.extend(counts)
    return legs


def _field_cmps(data, secs):
    legs = []
    dis = _disasm(data, secs, START, END)
    checks = [
        ("inplace_update_support cmpb +0x18(%rsi)",
         "cmpb   $0x0,0x18(%rsi)" in dis),
        ("memtable_factory mov +0x128(%rsi)",
         "mov    0x128(%rsi),%rdi" in dis),
        ("vtable load mov (%rdi),%rax",
         "mov    (%rdi),%rax" in dis),
        ("virtual call slot 0xa8",
         "call   *0xa8(%rax)" in dis),
        ("return test %al,%al",
         "test   %al,%al" in dis),
        ("OK path writes out = {0,0,nullptr}",
         "movl   $0x0,(%rbx)" in dis
         and "mov    %ax,0x4(%rbx)" in dis
         and "movq   $0x0,0x8(%rbx)" in dis),
        ("inplace error len 0x7d (125)",
         "movq   $0x7d,0x8(%rsp)" in dis),
        ("memtable error len 0x44 (68)",
         "movq   $0x44,0x8(%rsp)" in dis),
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


def _no_lsda(data, secs):
    legs = []
    sec_off, rec_len, rec_rng, aug_len, lsda = \
        _eh_frame_record(data, START)
    legs.append(("FDE record section offset 0x34ba04",
                 sec_off == FDE_SECTION_OFFSET, hex(sec_off)))
    legs.append(("FDE record length 0x20",
                 rec_len == FDE_LENGTH, hex(rec_len)))
    legs.append(("FDE range 0xe8",
                 rec_rng == FDE_RANGE, hex(rec_rng)))
    legs.append(("FDE aug_len 0 (no LSDA pointer)",
                 aug_len == 0, aug_len))
    legs.append(("no LSDA (throws propagate straight through)",
                 lsda is None, None if lsda is None else hex(lsda)))
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
    legs += _no_lsda(data, secs)
    sites = _caller_scan()
    legs.append(("caller census: 1 call, 0 jumps, 0 lea refs",
                 sites == [(0x5D8E7EE, "call")],
                 sites))
    legs.append(("defaults validate OK",
                 check_concurrent_writes_supported(
                     default_cf_options()).is_ok(), None))
    for n, _k, code_name in CHECKS:
        _m, overrides = _CHECK_FAIL_OVERRIDES[n - 1]
        cf_opts = _opts(overrides)
        st = check_concurrent_writes_supported(cf_opts)
        msg = MESSAGES["inplace" if n == 1 else "memtable"][0]
        legs.append(("check %d fails with its message" % n,
                     st.code == CODE[code_name] and st.state == msg,
                     "%s %r" % (CODE_NAME[st.code],
                                (st.state or "")[:24])))
    # First failure wins: check 1 masks check 2.
    cf_opts = default_cf_options()
    cf_opts["inplace_update_support"] = True
    cf_opts["memtable_factory_concurrent"] = False
    legs.append(("check 1 masks check 2",
                 check_concurrent_writes_supported(cf_opts).state ==
                 MESSAGES["inplace"][0], None))
    # Status ctor legs: state_ buffer is msg + NUL, alloc len+1.
    st = status_ctor(CODE["kInvalidArgument"], MESSAGES["memtable"][0],
                     "")
    legs.append(("ctor state_ buffer is msg + NUL",
                 st.state_buffer() == MESSAGES["memtable"][0].encode()
                 + b"\x00"
                 and st.state_alloc() == len(MESSAGES["memtable"][0]) + 1,
                 None))
    joined = status_ctor(CODE["kInvalidArgument"], "a", "b")
    legs.append(("ctor joins non-empty msg2 with ': '",
                 joined.state == "a: b", joined.state))
    # No-LSDA behavior: a BadAlloc with a bad canary still
    # propagates as BadAlloc (no pad canary check exists).
    try:
        check_concurrent_writes_supported(
            {"inplace_update_support": True,
             "memtable_factory_concurrent": True},
            canary_ok=False, fail_at="status-ctor:inplace")
        legs.append(("BadAlloc + bad canary propagates as BadAlloc",
                     False, "no exception"))
    except BadAlloc:
        legs.append(("BadAlloc + bad canary propagates as BadAlloc",
                     True, None))
    except StackCheckFailed:
        legs.append(("BadAlloc + bad canary propagates as BadAlloc",
                     False, "StackCheckFailed"))
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
