#!/usr/bin/env python3
"""Node #115 RocksDB DBImpl::CreateWAL: reconstruction.

RE-002 work item. Reconstructs the WAL-file creation routine at
0x5e5c270..0x5e5c9a3 (1843 B) plus its landing pad
``CreateWAL.cold`` at 0x5e5c1a0..0x5e5c26e (206 B):

  rocksdb::DBImpl::CreateWAL        0x5e5c270 (1843 B)
  rocksdb::DBImpl::CreateWAL.cold   0x5e5c1a0 (206 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
BOTH FDEs are census-bound (vendor census member
4d429ab1cb2d8f8b-db_impl_open.o, librocksdb-sys 0.11.0+8.1.1):
the main body hash matches target_body_sha256 exactly and its
source hash is reproduced by zeroing the recorded relocations
(52 relocations, kinds 2/4/42, with the GOTPCRELX mov-lea
opcode restored at the two relaxed sites -- see
gen_records.py); the .cold matches the same way (13 kind-4
relocations). Symbol from the vendor census:
``_ZN7rocksdb6DBImpl9CreateWALEmmmPPNS_3log6WriterE`` --
``IOStatus DBImpl::CreateWAL(uint64_t log_file_num, uint64_t
recycle_log_number, size_t preallocate_block_size, log::Writer**
new_log)``. This is the direct follow-up to open PR #6012
(log::Writer::EmitPhysicalRecord's caller note) and to the
WritableFileWriter engine family (#6041 Append, #6057 Flush,
#6070 Pad, #6088 WriteBuffered, #6094 WriteBufferedWithChecksum,
#6204 WriteDirect, #6215 WriteDirectWithChecksum), whose
constructors and members this routine wires together; it is
called from exactly two sites (whole-.text census):
``DBImpl::Open`` 0x5e62c50 (site 0x5e63ea0) and
``DBImpl::SwitchMemtable`` 0x5e8a890 (site 0x5e8a9c6).
Upstream v8.1.1: db/db_impl/db_impl_open.cc:1715-1759
(verified live this cycle; the repo has since moved to
meta/rocksdb).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  IOStatus CreateWAL(log_file_num, recycle_log_number,
                     preallocate_block_size, new_log)
  -- returns by value, so rdi is the hidden 16-byte sret
  out-pointer, rsi is the DBImpl*, rdx the log file number, rcx
  the recycle log number, r8 the preallocate block size, r9 the
  log::Writer** out-pointer. Steps, in binary order:

  1. BuildDBOptions (0x60c2e20) into a stack DBOptions temp
     (-0x2d0): (immutable_db_options_ at this+0x330,
     mutable_db_options_ at this+0x5a0). The temp is destroyed
     at the epilogue (DBOptions dtor 0x5d354b0); no field of it
     is observable downstream except through step 2.
  2. fs selection + OptimizeForLogWrite (0x5e5c2fd..0x5e5c379):
     the fs_ FileSystemPtr at this+0x570 is {shared_ptr fs
     +0x570/+0x578, shared_ptr io_tracer_ +0x580/+0x588,
     shared_ptr fs_with_tracer_ +0x590/+0x598} (pinned from
     the FileSystemPtr copy ctor 0x5d50400, which copies
     src+0x00 or src+0x20 by the same rule). If io_tracer_ is
     null, or the byte at +0x68 of the tracer object is 0, the
     raw fs_ is used; otherwise the tracer-wrapped fs at
     +0x590. The selected shared_ptr is copied (refcount++,
     plain or lock addl by the __gthread_active_p flag at
     0x64ed290) and released after the call
     (_Sp_counted_base::M_release 0x5d350c0). The virtual call
     is fs->OptimizeForLogWrite(&opt_file_options,
     &file_options_ [this+0x838], &db_options) through vtable
     slot 0x198; the returned FileOptions (stack, -0x3d0) is
     the options used for every later file call. The model
     passes the options through unchanged and records the
     call; the per-field tweaks OptimizeForLogWrite makes are
     NOT modelled (open unknown, recorded in the packet).
  3. wal_dir (0x5e5c379..0x5e5c3aa): GetWalDir (0x60a1500,
     not in the vendor census) on immutable_db_options_
     returns a pointer to a std::string: &wal_dir
     (immutable+0x98) when its size (+0xa0) is non-zero, else
     the string pointer stored at immutable+0x60 (the dbname
     string) -- exactly upstream ``wal_dir.empty() ? dbname :
     wal_dir``. The local wal_dir copy (-0x330) is built from
     the returned string's [ptr, ptr+size) by the libstdc++
     range helper 0x5e57bf0.
  4. log_fname (0x5e5c3af..0x5e5c3ca): LogFileName
     (0x603d050) into -0x310: MakeFileName (0x603cb70) formats
     "%06llu.%s" with the number and "log" (format string at
     0x4394a1, type string "log" at 0x44fd57) and joins
     ``wal_dir + "/" + that`` -- so ``<wal_dir>/000007.log``
     for log_file_num 7, and ``/000007.log`` when wal_dir is
     empty (the join is unconditional). Numbers >= 1000000
     print with more digits (%06llu never truncates).
  5. Recycle branch, only when recycle_log_number != 0
     (0x5e5c7c8..0x5e5c86f): ROCKS_LOG_INFO
     (0x5fcf060) on immutable_db_options_.info_log
     (this+0x360) with "reusing log %llu from recycle list";
     old_log_fname = LogFileName(wal_dir, recycle_log_number)
     (-0x2f0); then fs->ReuseWritableFile(log_fname,
     old_log_fname, opt_file_options, &lfile, nullptr) through
     vtable slot 0xc8, with the fs selected by a FileSystemPtr
     copy (0x5d50400 -- the census names it
     FileSystemPtr::operator->, but the body is the copy ctor:
     dest=rdi, src=rsi, copies src+0x00 or src+0x20 by the
     tracer rule, refcount++). NOTE: the two upstream
     TEST_SYNC_POINTs ("DBImpl::CreateWAL:
     BeforeReuseWritableFile1/2") have NO binary call in this
     FDE -- compiled out; the model records them as absent.
     The non-recycle branch (0x5e5c3f9..0x5e5c429) calls the
     free function NewWritableFile (0x6048500, census-bound):
     NewWritableFile(fs, log_fname, &lfile, opt_file_options).
  6. Status check (0x5e5c42e..0x5e5c497): the returned IOStatus
     is moved into the return slot (rbx); if not OK, return at
     once -- no writer is built and *new_log is never written.
  7. On OK (0x5e5c49d..0x5e5c535): lfile->SetWriteLifeTimeHint
     (vtable slot 0x70) with the constant 2 (WriteLifeTimeHint
     kWLTHShort) -- CalculateWALWriteHint() has no separate
     call site; its result is the constant 2 in this build --
     then lfile->SetPreallocationBlockSize
     (vtable slot 0x98) with preallocate_block_size.
  8. WritableFileWriter (0x5e5c4c6..0x5e5c535): operator new
     0xe0 bytes, then the ctor (0x5e5ba60, census-bound) with
     (std::move(lfile), log_fname, opt_file_options,
     immutable_db_options_.clock [this+0x540], io_tracer_
     [this+0x320], nullptr stats, listeners [this+0x470],
     nullptr checksum_gen, Contains(kWalFile),
     Contains(kWalFile)) -- the two trailing bools are the
     SAME value pushed twice: (this+0x520 & 1), the bit-0 test
     on checksum_handoff_file_types. The ctor stores bool 1
     into perform_data_verification_ (+0xd1) and bool 2 into
     buffered_data_with_checksum_ (+0xd8) -- verified in the
     ctor body (0x5e5bd3f..0x5e5bd5e). The model records both
     as ``checksum_handoff_kWalFile``.
  9. log::Writer (0x5e5c53e..0x5e5c58a): operator new 0x58
     bytes, then the ctor (0x5f04c00, census-bound) with
     (std::move(file_writer), log_file_num,
     recycle_log_file_num > 0 [this+0x400 != 0],
     manual_wal_flush [this+0x4c5 byte], wal_compression
     [this+0x4c6 byte]). NOTE the recycle flag comes from the
     IMMUTABLE option recycle_log_file_num, not from the
     recycle_log_number argument -- the two are independent.
     The ctor moves the file_writer pointer into its dest_
     and zeroes the source slot (0x5f04c2e: movq $0, (%rsi)).
 10. *new_log = the new log::Writer (0x5e5c58f..0x5e5c5a0),
     THEN io_s = (*new_log)->AddCompressionTypeRecord()
     (0x5f041d0, census-bound; sret into the io_s slot) --
     so on an AddCompressionTypeRecord failure the caller
     still receives the writer in *new_log and the failure
     status. The record bytes themselves are the subject of
     the sibling AddCompressionTypeRecord packet; this model
     scripts the call's status (default OK) and does not
     model the record bytes.
 11. Dead Close guard (0x5e5c60c..0x5e5c70e): after the status
     is copied to the return slot, the binary loads the
     file_writer slot (-0x3f0) and, if non-null, calls
     WritableFileWriter::Close (0x6052b80, census-bound) and
     then runs the inlined WritableFileWriter destructor
     (release checksum_generator_, clear listeners_, free
     buf_, tear down the FSWritableFile wrapper with
     devirtualization, dispose file_name_, operator delete
     0xe0). The slot is NULLED by the log::Writer ctor's move
     (step 9), so on the normal path the guard is false and
     the sequence is skipped; the Close result, if it ran,
     would land in the already-moved-from io_s slot and be
     discarded (the return value was already copied to rbx).
     The upstream v8.1.1 source has no Close call here. The
     model records close_guard_taken = False with this
     evidence and never takes the guard.
 12. Epilogue (0x5e5c713..0x5e5c79c): dispose the log_fname /
     wal_dir / old_log_fname strings, destroy the DBOptions
     temp, release the fs shared_ptr copy, check the stack
     canary, return the status in rbx. The .cold
     (0x5e5c1a0..0x5e5c26e) is unwind-only: the same
     destructions plus _Unwind_Resume.

Environment limits (stated honestly): no cargo/rustc/git-lfs/
Ghidra on this VM; the model is Python evidence, not a Rust
reconstruction; the FileSystem, clock, listeners and
OptimizeForLogWrite internals are modelled as opaque
recorded calls, not reimplemented.
"""
import hashlib
import json
import os
import random
import sys
import tempfile
from pathlib import Path

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / \
    "re-002-node115-dbimpl-createwal-115"
CASES = PACKET / "cases.tsv"

# Binary facts.
FDE_START = 0x5E5C270
FDE_END = 0x5E5C9A3
COLD_START = 0x5E5C1A0
COLD_END = 0x5E5C26E
WRITE_LIFETIME_HINT = 2  # kWLTHShort, the constant passed at 0x5e5c4a4
CHECKSUM_HANDOFF_KWALFILE_BIT = 0  # (this+0x520 & 1) at 0x5e5c4f0
K_NO_COMPRESSION = 0

# IOStatus codes (rocksdb/status.h, implicit 0-based).
CODE_OK = 0
CODE_NOT_FOUND = 1
CODE_CORRUPTION = 2
CODE_NOT_SUPPORTED = 3
CODE_INVALID_ARGUMENT = 4
CODE_IO_ERROR = 5


def log_file_name(wal_dir, number):
    """LogFileName: MakeFileName formats "%06llu.%s" and joins
    wal_dir + "/" + that (0x603cb70, format at 0x4394a1)."""
    return "%s/%06d.log" % (wal_dir, number)


def get_wal_dir(dbname, wal_dir):
    """GetWalDir (0x60a1500): wal_dir when non-empty, else dbname."""
    return wal_dir if wal_dir != "" else dbname


class IOStatus:
    """A 16-byte IOStatus: code (u16), subcode (u16), byte 5, state_ ptr."""

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


class FileHandle:
    """An FSWritableFile: records the hint/preallocation calls."""

    def __init__(self, path, fs):
        self.path = path
        self.fs = fs
        self.write_lifetime_hint = None
        self.preallocation_block_size = None
        self.calls = []

    def set_write_lifetime_hint(self, hint):
        self.write_lifetime_hint = hint
        self.calls.append({"op": "set_write_lifetime_hint",
                           "hint": hint})

    def set_preallocation_block_size(self, size):
        self.preallocation_block_size = size
        self.calls.append({"op": "set_preallocation_block_size",
                           "size": size})


class FakeFS:
    """In-memory FileSystem: files map path -> bytes."""

    def __init__(self, files=None, script=None):
        self.files = dict(files or {})
        self.script = script or {}
        self.calls = []

    def optimize_for_log_write(self, file_options, db_options):
        self.calls.append({"op": "optimize_for_log_write"})
        return dict(file_options)

    def new_writable_file(self, fname, options):
        self.calls.append({"op": "new_writable_file", "fname": fname})
        status = self.script.get("new_writable_file")
        if status is not None:
            return status, None
        self.files[fname] = b""
        return IOStatus.ok(), FileHandle(fname, self)

    def reuse_writable_file(self, new_fname, old_fname, options):
        self.calls.append({"op": "reuse_writable_file",
                           "new_fname": new_fname,
                           "old_fname": old_fname})
        status = self.script.get("reuse_writable_file")
        if status is not None:
            return status, None
        if old_fname not in self.files:
            return IOStatus.io_error(
                "reuse log file not found: %s" % old_fname), None
        self.files[new_fname] = self.files.pop(old_fname)
        return IOStatus.ok(), FileHandle(new_fname, self)


class RealFS:
    """A FileSystem backed by a real directory (for --live)."""

    def __init__(self, root, script=None):
        self.root = Path(root)
        self.script = script or {}
        self.calls = []

    def _p(self, fname):
        # The model passes wal_dir-relative names; the live root
        # stands in for the db dir, so strip a leading "/".
        return self.root / fname.lstrip("/")

    def optimize_for_log_write(self, file_options, db_options):
        self.calls.append({"op": "optimize_for_log_write"})
        return dict(file_options)

    def new_writable_file(self, fname, options):
        self.calls.append({"op": "new_writable_file", "fname": fname})
        status = self.script.get("new_writable_file")
        if status is not None:
            return status, None
        path = self._p(fname)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb"):
            pass
        return IOStatus.ok(), FileHandle(fname, self)

    def reuse_writable_file(self, new_fname, old_fname, options):
        self.calls.append({"op": "reuse_writable_file",
                           "new_fname": new_fname,
                           "old_fname": old_fname})
        status = self.script.get("reuse_writable_file")
        if status is not None:
            return status, None
        old, new = self._p(old_fname), self._p(new_fname)
        if not old.exists():
            return IOStatus.io_error(
                "reuse log file not found: %s" % old_fname), None
        os.rename(old, new)
        return IOStatus.ok(), FileHandle(new_fname, self)

    def image(self):
        out = {}
        for p in sorted(self.root.rglob("*")):
            if p.is_file():
                out[str(p.relative_to(self.root))] = p.read_bytes()
        return out


class LogWriter:
    """A log::Writer: holds the file_writer params; the
    AddCompressionTypeRecord call is scripted (default OK) --
    its record bytes are the sibling packet's subject."""

    def __init__(self, params, script=None):
        self.params = params
        self.script = script or {}
        self.calls = []

    def add_compression_type_record(self):
        self.calls.append({"op": "add_compression_type_record",
                           "compression":
                               self.params["wal_compression"]})
        status = self.script.get("add_compression_type_record")
        if status is not None:
            return status
        return IOStatus.ok()


class DBState:
    """The DBImpl fields CreateWAL reads (offsets in the docstring)."""

    def __init__(self, dbname="/tmp/db", wal_dir="", recycle_log_file_num=0,
                 manual_wal_flush=False, wal_compression=K_NO_COMPRESSION,
                 checksum_handoff_bits=0, listeners=None, clock="default",
                 io_tracer_present=False, io_tracer_enabled=False,
                 file_options=None, fs=None, script=None):
        self.dbname = dbname
        self.wal_dir = wal_dir
        self.recycle_log_file_num = recycle_log_file_num
        self.manual_wal_flush = manual_wal_flush
        self.wal_compression = wal_compression
        self.checksum_handoff_bits = checksum_handoff_bits
        self.listeners = list(listeners or [])
        self.clock = clock
        self.io_tracer_present = io_tracer_present
        self.io_tracer_enabled = io_tracer_enabled
        self.file_options = dict(file_options or {})
        self.fs = fs if fs is not None else FakeFS()
        self.script = script or {}
        self.trace = []
        self.new_log = [None]

    def contains_kwalfile(self):
        return bool(self.checksum_handoff_bits
                    & (1 << CHECKSUM_HANDOFF_KWALFILE_BIT))

    def select_fs(self):
        """Step 2: raw fs_ unless the tracer is present AND its
        +0x68 byte is set, in which case the wrapped fs."""
        if self.io_tracer_present and self.io_tracer_enabled:
            return "wrapped"
        return "raw"


def create_wal(state, log_file_num, recycle_log_number,
               preallocate_block_size):
    """The CreateWAL model. Returns the IOStatus; the writer (if
    built) is stored in state.new_log[0], exactly as *new_log."""
    trace = state.trace
    # 1. BuildDBOptions (opaque; destroyed at the epilogue).
    trace.append({"op": "build_db_options"})
    db_options = {"immutable": "immutable_db_options_",
                  "mutable": "mutable_db_options_"}
    # 2. fs selection + OptimizeForLogWrite.
    selected = state.select_fs()
    trace.append({"op": "select_fs", "selected": selected})
    opt_file_options = state.fs.optimize_for_log_write(
        state.file_options, db_options)
    trace.append({"op": "optimize_for_log_write",
                  "selected": selected})
    # 3. wal_dir.
    wal_dir = get_wal_dir(state.dbname, state.wal_dir)
    trace.append({"op": "get_wal_dir", "wal_dir": wal_dir})
    # 4. log_fname.
    log_fname = log_file_name(wal_dir, log_file_num)
    trace.append({"op": "log_file_name", "fname": log_fname})
    # 5. recycle vs new.
    if recycle_log_number:
        trace.append({"op": "log_info",
                      "msg": "reusing log %d from recycle list"
                             % recycle_log_number})
        old_fname = log_file_name(wal_dir, recycle_log_number)
        trace.append({"op": "log_file_name", "fname": old_fname,
                      "role": "old_log_fname"})
        # The two upstream TEST_SYNC_POINTs have no binary call.
        trace.append({"op": "sync_point",
                      "name": "DBImpl::CreateWAL:BeforeReuseWritableFile1",
                      "present_in_binary": False})
        trace.append({"op": "sync_point",
                      "name": "DBImpl::CreateWAL:BeforeReuseWritableFile2",
                      "present_in_binary": False})
        io_s, lfile = state.fs.reuse_writable_file(
            log_fname, old_fname, opt_file_options)
    else:
        io_s, lfile = state.fs.new_writable_file(
            log_fname, opt_file_options)
    trace.append({"op": "open_status", "code": io_s.code})
    # 6. Failure: return at once; *new_log untouched.
    if not io_s.is_ok():
        return io_s
    # 7. Lifetime hint (constant 2) + preallocation.
    lfile.set_write_lifetime_hint(WRITE_LIFETIME_HINT)
    trace.append({"op": "set_write_lifetime_hint", "hint": 2})
    lfile.set_preallocation_block_size(preallocate_block_size)
    trace.append({"op": "set_preallocation_block_size",
                  "size": preallocate_block_size})
    # 8. WritableFileWriter params.
    handoff = state.contains_kwalfile()
    writer_params = {
        "fname": log_fname,
        "clock": state.clock,
        "io_tracer_present": state.io_tracer_present,
        "stats": None,
        "listeners": list(state.listeners),
        "checksum_gen": None,
        "perform_data_verification": handoff,
        "buffered_data_with_checksum": handoff,
    }
    trace.append({"op": "writable_file_writer_new",
                  "params": writer_params})
    # 9. log::Writer params.
    log_params = {
        "log_number": log_file_num,
        "recycle": state.recycle_log_file_num > 0,
        "manual_wal_flush": state.manual_wal_flush,
        "wal_compression": state.wal_compression,
    }
    trace.append({"op": "log_writer_new", "params": log_params})
    writer = LogWriter(
        dict(writer_params, **log_params), script=state.script)
    # 10. *new_log is assigned BEFORE AddCompressionTypeRecord.
    state.new_log[0] = writer
    trace.append({"op": "assign_new_log"})
    io_s = writer.add_compression_type_record()
    trace.append({"op": "add_compression_type_record",
                  "code": io_s.code})
    # 11. Dead Close guard: the file_writer slot was nulled by
    # the log::Writer ctor's move, so the guard is never taken.
    trace.append({"op": "close_guard", "taken": False,
                  "reason": "file_writer slot nulled by the "
                            "log::Writer ctor move"})
    return io_s


def make_state(inputs):
    """Build a DBState from a case inputs dict."""
    fs = FakeFS(files={k: bytes.fromhex(v)
                       for k, v in inputs.get("fs_files", {}).items()},
                script={k: IOStatus.io_error(v) if v else None
                        for k, v in inputs.get("fs_script", {}).items()})
    db = inputs["db"]
    return DBState(
        dbname=db["dbname"], wal_dir=db["wal_dir"],
        recycle_log_file_num=db["recycle_log_file_num"],
        manual_wal_flush=db["manual_wal_flush"],
        wal_compression=db["wal_compression"],
        checksum_handoff_bits=db["checksum_handoff_bits"],
        listeners=db["listeners"], clock=db["clock"],
        io_tracer_present=db["io_tracer_present"],
        io_tracer_enabled=db["io_tracer_enabled"],
        file_options=db["file_options"], fs=fs,
        script={k: IOStatus.io_error(v) if v else None
                for k, v in inputs.get("script", {}).items()})


def run_case(inputs):
    """Run one case; returns the expected-output dict."""
    state = make_state(inputs)
    args = inputs["args"]
    status = create_wal(state, args["log_file_num"],
                        args["recycle_log_number"],
                        args["preallocate_block_size"])
    writer = state.new_log[0]
    files = {}
    if isinstance(state.fs, FakeFS):
        files = {k: v.hex() for k, v in state.fs.files.items()}
    return {
        "status": status.summary(),
        "new_log_assigned": writer is not None,
        "writer_params": (writer.params if writer is not None else None),
        "trace": state.trace,
        "files": files,
        "close_guard_taken": any(
            e.get("op") == "close_guard" and e.get("taken")
            for e in state.trace),
    }


def _rand_db(rng):
    return {
        "dbname": rng.choice(["/tmp/db", "/data/rocksdb", "db",
                              "/var/lib/hl"]),
        "wal_dir": rng.choice(["", "/tmp/wal", "/data/wal", "wal",
                               "/tmp/db"]),
        "recycle_log_file_num": rng.choice([0, 0, 1, 7, 42]),
        "manual_wal_flush": rng.choice([False, True]),
        "wal_compression": rng.choice([0, 0, 0, 1, 2]),
        "checksum_handoff_bits": rng.choice([0, 0, 1, 2, 3]),
        "listeners": rng.choice([[], ["L1"], ["L1", "L2"]]),
        "clock": "default",
        "io_tracer_present": rng.choice([False, False, True]),
        "io_tracer_enabled": rng.choice([False, True]),
        "file_options": {},
    }


def _gen_group(rng, group, n):
    rows = []
    for i in range(n):
        case_id = "%s-%03d" % (group, i)
        db = _rand_db(rng)
        args = {
            "log_file_num": rng.choice(
                [0, 1, 7, 123, 999999, 1000000, 1000001, 2**64 - 1]),
            "recycle_log_number": 0,
            "preallocate_block_size": rng.choice(
                [0, 4096, 1048576, 2**32 - 1]),
        }
        fs_files = {}
        fs_script = {}
        script = {}
        if group == "gate":
            args["recycle_log_number"] = rng.choice(
                [0, 0, 3, 9, 123456])
            if rng.random() < 0.35:
                fs_script["new_writable_file"] = "disk full"
            if rng.random() < 0.35:
                fs_script["reuse_writable_file"] = "rename failed"
            if rng.random() < 0.25:
                script["add_compression_type_record"] = \
                    "compression record failed"
            if args["recycle_log_number"]:
                fs_files[log_file_name(
                    get_wal_dir(db["dbname"], db["wal_dir"]),
                    args["recycle_log_number"])] = \
                    rng.randbytes(rng.choice([0, 11, 100]))
        elif group == "filenames":
            args["log_file_num"] = rng.choice(
                [0, 1, 9, 10, 99, 99999, 100000, 999999, 1000000,
                 123456789])
            args["recycle_log_number"] = rng.choice(
                [0, 0, 1, 999999, 1000000])
            if args["recycle_log_number"]:
                fs_files[log_file_name(
                    get_wal_dir(db["dbname"], db["wal_dir"]),
                    args["recycle_log_number"])] = b"old-wal-bytes"
        elif group == "writer_params":
            args["recycle_log_number"] = rng.choice([0, 5])
            if args["recycle_log_number"]:
                fs_files[log_file_name(
                    get_wal_dir(db["dbname"], db["wal_dir"]),
                    args["recycle_log_number"])] = b""
        elif group == "bindings":
            args["recycle_log_number"] = rng.choice([0, 0, 4, 77])
            if rng.random() < 0.3:
                fs_script["new_writable_file"] = "permission denied"
            if rng.random() < 0.3:
                script["add_compression_type_record"] = \
                    "compression record failed"
            if args["recycle_log_number"]:
                fs_files[log_file_name(
                    get_wal_dir(db["dbname"], db["wal_dir"]),
                    args["recycle_log_number"])] = \
                    rng.randbytes(rng.choice([0, 7, 4096]))
        inputs = {"case_id": case_id, "group": group, "db": db,
                  "args": args, "fs_files": {
                      k: v.hex() for k, v in fs_files.items()},
                  "fs_script": fs_script, "script": script}
        expected = run_case(inputs)
        rows.append((group, case_id, inputs, expected))
    return rows


def write_cases():
    all_rows = []
    for gi, group in enumerate(
            ["gate", "filenames", "writer_params", "bindings"]):
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
    """Drive real files through the model in a temp dir; the
    model file image must equal the real file bytes after every
    CreateWAL. 8 legs."""
    report = {"ok": False, "legs": []}
    try:
        # Leg 1: plain new WAL -- the file is created with the
        # LogFileName name, empty; the hint is 2, the
        # preallocation is recorded; *new_log is assigned.
        with tempfile.TemporaryDirectory() as root:
            fs = RealFS(root)
            state = DBState(dbname="db", wal_dir="",
                            fs=fs)
            s = create_wal(state, 7, 0, 1048576)
            assert s.is_ok(), s
            assert state.new_log[0] is not None
            img = fs.image()
            assert img == {"db/000007.log": b""}, img
            w = state.new_log[0]
            assert w.params["perform_data_verification"] is False
            assert w.params["buffered_data_with_checksum"] is False
            assert w.params["recycle"] is False
            report["legs"].append({"leg": "new_wal", "ok": True})
        # Leg 2: recycle -- the old file is renamed to the new
        # name, its bytes preserved; the old name is gone.
        with tempfile.TemporaryDirectory() as root:
            fs = RealFS(root)
            fs.files = {}
            old = Path(root) / "db" / "000003.log"
            old.parent.mkdir(parents=True, exist_ok=True)
            old.write_bytes(b"old-wal-bytes")
            state = DBState(dbname="db", wal_dir="", fs=fs)
            s = create_wal(state, 9, 3, 0)
            assert s.is_ok(), s
            assert fs.image() == {"db/000009.log": b"old-wal-bytes"}
            assert not old.exists()
            report["legs"].append({"leg": "recycle_rename", "ok": True})
        # Leg 3: empty wal_dir falls back to dbname.
        with tempfile.TemporaryDirectory() as root:
            fs = RealFS(root)
            state = DBState(dbname="mydb", wal_dir="wal", fs=fs)
            s = create_wal(state, 42, 0, 0)
            assert s.is_ok(), s
            assert fs.image() == {"wal/000042.log": b""}
            state = DBState(dbname="mydb", wal_dir="", fs=fs)
            s = create_wal(state, 43, 0, 0)
            assert s.is_ok(), s
            assert fs.image()["mydb/000043.log"] == b""
            report["legs"].append({"leg": "wal_dir_fallback",
                                  "ok": True})
        # Leg 4: NewWritableFile failure -- the status is
        # returned, no writer is built, *new_log stays None,
        # no file is created.
        with tempfile.TemporaryDirectory() as root:
            fs = RealFS(root, script={
                "new_writable_file": IOStatus.io_error("disk full")})
            state = DBState(dbname="db", wal_dir="", fs=fs)
            s = create_wal(state, 5, 0, 0)
            assert not s.is_ok() and s.code == 5, s
            assert state.new_log[0] is None
            assert fs.image() == {}
            report["legs"].append({"leg": "create_failure", "ok": True})
        # Leg 5: reuse of a missing old log -- IOError, nothing
        # created, *new_log untouched.
        with tempfile.TemporaryDirectory() as root:
            fs = RealFS(root)
            state = DBState(dbname="db", wal_dir="", fs=fs)
            s = create_wal(state, 8, 3, 0)
            assert not s.is_ok() and s.code == 5, s
            assert state.new_log[0] is None
            assert fs.image() == {}
            report["legs"].append({"leg": "reuse_missing_old",
                                  "ok": True})
        # Leg 6: AddCompressionTypeRecord failure -- the status
        # is returned BUT *new_log still holds the writer (the
        # assignment precedes the call in the binary); the
        # Close guard is not taken; the file exists.
        with tempfile.TemporaryDirectory() as root:
            fs = RealFS(root)
            state = DBState(dbname="db", wal_dir="", fs=fs,
                            script={"add_compression_type_record":
                                    IOStatus.io_error(
                                        "compression record failed")})
            s = create_wal(state, 11, 0, 0)
            assert not s.is_ok() and s.code == 5, s
            assert state.new_log[0] is not None
            assert fs.image() == {"db/000011.log": b""}
            assert not any(e.get("op") == "close_guard"
                           and e.get("taken")
                           for e in state.trace)
            report["legs"].append(
                {"leg": "compression_record_failure", "ok": True})
        # Leg 7: 7-digit log numbers print in full; the
        # preallocation size is recorded on the handle.
        with tempfile.TemporaryDirectory() as root:
            fs = RealFS(root)
            state = DBState(dbname="db", wal_dir="", fs=fs)
            s = create_wal(state, 1000001, 0, 4096)
            assert s.is_ok(), s
            assert fs.image() == {"db/1000001.log": b""}
            handle_calls = [c for c in state.trace
                            if c["op"] == "set_preallocation_block_size"]
            assert handle_calls == [
                {"op": "set_preallocation_block_size", "size": 4096}]
            report["legs"].append({"leg": "big_number", "ok": True})
        # Leg 8: checksum-handoff bit set -- both writer bools
        # follow it; recycle_log_file_num > 0 sets the
        # log::Writer recycle flag independently of the
        # recycle_log_number argument.
        with tempfile.TemporaryDirectory() as root:
            fs = RealFS(root)
            state = DBState(dbname="db", wal_dir="", fs=fs,
                            checksum_handoff_bits=1,
                            recycle_log_file_num=3,
                            manual_wal_flush=True, wal_compression=1)
            s = create_wal(state, 12, 0, 0)
            assert s.is_ok(), s
            w = state.new_log[0]
            assert w.params["perform_data_verification"] is True
            assert w.params["buffered_data_with_checksum"] is True
            assert w.params["recycle"] is True
            assert w.params["manual_wal_flush"] is True
            assert w.params["wal_compression"] == 1
            assert fs.image() == {"db/000012.log": b""}
            report["legs"].append({"leg": "writer_params", "ok": True})
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
