#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::WritableFileWriter::
SyncWithoutFlush.

Target: rocksdb::WritableFileWriter::SyncWithoutFlush(bool) at
0x604d500..0x604d6bd (445 B, main FDE) plus its .cold FDE at
0x604d4a8..0x604d4fe (86 B) in node #115 (work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c
3867b5301).

The direct sibling of the earlier RE-002 WritableFileWriter
packets (Append, Flush, Sync, UpdateFileChecksum, GetFileChecksum,
GetFileChecksumFuncName, DecideRateLimiterPriority): the sync
without a flush -- sync the underlying file while a concurrent
writer may still be appending. Upstream RocksDB v8.1.1 calls it
exactly as the binary behaves (file/writable_file_writer.cc:
455-474).

Whole-FDE facts (verified live, see --live):
- Signature: IOStatus SyncWithoutFlush(bool use_fsync); sret out
  in rdi, this in rsi, use_fsync in edx (kept in r12d). Stack
  frame 0x20, canary stored at rsp+0x18 and checked before every
  return (failure calls __stack_chk_fail at 0x604d6a0).
- Body hash matches the vendor census target_body_sha256 exactly;
  source hash reproduced exactly by zeroing the 15 census
  relocations (kinds 2/4, no relaxation); the .cold FDE matches
  its census record the same way (6 kind-4 relocations):
  member a895f7517936a0f7-writable_file_writer.o, librocksdb-sys
  0.11.0+8.1.1, symbol
  _ZN7rocksdb18WritableFileWriter16SyncWithoutFlushEb.
- Decision (105 instructions main, 20 cold): if seen_error_
  (this+0x89, std::atomic<bool>) is set, return
  AssertFalseAndGetStatusForPrevError() -- IOStatus::IOError
  ("Writer has previous error.", 26 chars, code 5) -- built fresh
  at 0x604d640 (the NDEBUG assert on sync_without_flush_called_
  is compiled out). Else resolve the file through
  FSWritableFilePtr::get() inlined: io_tracer_ is the shared_ptr
  at this+0x20, fs_tracer_ the unique_ptr at this+0x30; if
  io_tracer_ is non-null and its tracing_enabled byte at +0x68
  is set, the effective file is the tracing wrapper itself;
  otherwise it is fs_tracer_->target(), the wrapped file at
  wrapper+0x28 (FSWritableFileWrapper::target_, after the
  FSWritableFile base: vtable + two u64 + two int + bool + pad =
  0x28). Call IsSyncThreadSafe() on the effective file (vtable
  slot 11, *0x58(%rax): FSWritableFile's virtuals are dtor x2,
  Append x2, PositionedAppend x2, Truncate, Close, Flush, Sync,
  Fsync, then IsSyncThreadSafe; the default returns false,
  include/rocksdb/file_system.h:1048, and the tracing wrapper
  forwards to its target, :1683). If false, return
  IOStatus::NotSupported with the 94-char message "Can't
  WritableFileWriter::SyncWithoutFlush() because WritableFile::
  IsSyncThreadSafe() is false" (code 3). Else call SyncInternal
  (use_fsync) at 0x604c900 (FDE 0x604c900..0x604d4a7, .cold
  0x604c828..0x604c8f5) into a stack IOStatus; if its code is
  non-zero, set_seen_error() (this+0x89 = 1); return the copy of
  that status -- the IOStatus copy ctor (include/rocksdb/
  io_status.h:171) resets severity to kNoError, so the returned
  status always has sev_ 0, with code/subcode/retryable/data_loss/
  scope/state_ copied.
- Status byte layout (Status ctor init order, include/rocksdb/
  status.h): code u8 +0x0, subcode u8 +0x1, sev u8 +0x2,
  retryable bool +0x3, data_loss bool +0x4, scope u8 +0x5,
  padding +0x6..+0x7 (never written), state_ unique_ptr +0x8.
  The fresh error builders write code, zero the rest, then new
  char[len+1] and copy the message in 16-byte movdqa chunks
  (the 94-char message's last chunk starts at +0x4e, overlapping
  the previous chunk by 2 bytes; the 26-char message's second
  chunk starts at +0xa). A failed new throws BadAlloc into the
  .cold cleanup (delete the out state_ -- null at that point --
  check the canary, _Unwind_Resume); a throw from
  IsSyncThreadSafe or from SyncInternal has NO landing pad (LSDA
  entries [0] and [2]) and propagates with no cleanup of ours.
- Main LSDA at 0x41e76e (in .gcc_except_table): 4 call-site
  entries, all cleanup, action 0: [0] start 0x4e len 3 no pad
  (the IsSyncThreadSafe call), [1] start 0x72 len 5 pad 0x1b1
  (the NotSupported new -> stub 0x604d6b1 -> .cold 0x604d4ce),
  [2] start 0x102 len 5 no pad (the SyncInternal call), [3]
  start 0x159 len 5 pad 0x1a5 (the IOError new -> stub 0x604d6a5
  -> .cold 0x604d4a8). Cold LSDA at 0x41e786: 1 entry, start 0x21
  len 0x2b, no pad (the _Unwind_Resume/delete region propagates
  as-is). Both FDE records have aug_len 4 (LSDA pointer,
  encoding 0x9b indirect|pcrel|sdata4).
- Callers: exactly 1 direct call, 0 tail jumps, 0 LEA refs
  (whole-.text E8/E9/LEA scan, Capstone-validated):
  rocksdb::DBImpl::SyncWAL (site 0x5d7f657, FDE 0x5d7f3b0..
  0x5d7fb40, census-bound, db_impl.o). Upstream calls
  SyncWithoutFlush from DBImpl::SyncWAL as well
  (db_impl.cc, the WAL-sync path).

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM. The
target binary is never executed. The tool models the helper in
Python from its whole-FDE disassembly. SyncInternal is an oracle:
its result is an input to the model, not computed here.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ARTIFACT_SHA256 = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f"
                   "249e98c3867b5301")
START = 0x604D500
END = 0x604D6BD
BODY_SHA256 = ("6904e218743d50b49106216aa2edf1b408c832b9e228319c8fc"
               "2d7615385b3df")
SOURCE_SHA256 = ("3774816593878842e1b5f9d5e32ed6f7c3d3e7725906d13"
                 "da8db51a7cb28ce59")
# 15 census relocations: (offset, kind). Zeroing the 4-byte field
# at each offset reproduces source_body_sha256 exactly.
RELOCATIONS = [(115, 4), (123, 2), (138, 2), (150, 2), (162, 2),
               (174, 2), (186, 2), (208, 4), (259, 4), (346, 4),
               (354, 2), (369, 2), (417, 4), (429, 2), (441, 2)]
RELOCATIONS_DESC = ("15 relocations (offsets 115 k4, 123 k2, 138 k2, "
                    "150 k2, 162 k2, 174 k2, 186 k2, 208 k4, 259 k4, "
                    "346 k4, 354 k2, 369 k2, 417 k4, 429 k2, 441 k2)")
COLD_START = 0x604D4A8
COLD_END = 0x604D4FE
COLD_BODY_SHA256 = ("88100ca53220c63d8ba9c7e6f02b925acfa2fed83a3236f"
                    "8b78ed067ba719b10")
COLD_SOURCE_SHA256 = ("f8aefe2c541e7abfd9e06a08cccba5b16a16a56f7aca17"
                      "281c4d7b6629d1e336")
COLD_RELOCATIONS = [(10, 4), (34, 4), (48, 4), (72, 4), (77, 4),
                    (82, 4)]
COLD_RELOCATIONS_DESC = ("6 kind-4 relocations at offsets 10, 34, "
                         "48, 72, 77, 82")
MEMBER = "a895f7517936a0f7-writable_file_writer.o"
SYMBOL = "_ZN7rocksdb18WritableFileWriter16SyncWithoutFlushEb"
# FDE records in .eh_frame: main at section offset 0x759550
# (length 0x34, range 0x1bd, aug_len 4, LSDA at 0x41e76e);
# .cold at 0x759588 (length 0x1c, range 0x56, aug_len 4, LSDA at
# 0x41e786).
FDE_SECTION_OFFSET = 0x759550
FDE_LENGTH = 0x34
FDE_RANGE = 0x1BD
FDE_LSDA = 0x41E76E
COLD_FDE_SECTION_OFFSET = 0x759588
COLD_FDE_LENGTH = 0x1C
COLD_FDE_RANGE = 0x56
COLD_FDE_LSDA = 0x41E786
# Main LSDA call-site entries: (start, length, landing_pad, action).
# Landing pads are offsets from the FDE start (0x604d500): 0x1a5
# -> stub 0x604d6a5 -> .cold 0x604d4a8; 0x1b1 -> stub 0x604d6b1
# -> .cold 0x604d4ce. 0 means no landing pad.
LSDA_MAIN = [(0x4E, 3, 0, 0), (0x72, 5, 0x1B1, 0),
             (0x102, 5, 0, 0), (0x159, 5, 0x1A5, 0)]
LSDA_COLD = [(0x21, 0x2B, 0, 0)]
# The engine call: SyncInternal(bool) at 0x604c900 (FDE
# 0x604c900..0x604d4a7, .cold 0x604c828..0x604c8f5, census-bound
# .cold, member writable_file_writer.o).
SYNC_INTERNAL = 0x604C900
SYNC_INTERNAL_END = 0x604D4A7
SYNC_INTERNAL_COLD_START = 0x604C828
SYNC_INTERNAL_COLD_END = 0x604C8F5
NOT_SUPPORTED_MSG = ("Can't WritableFileWriter::SyncWithoutFlush() "
                     "because WritableFile::IsSyncThreadSafe() is "
                     "false")
PREV_ERROR_MSG = "Writer has previous error."
# The 94-char message's movdqa sources (whole .rodata, in order);
# the last chunk starts at buffer +0x4e, overlapping by 2 bytes.
NS_MSG_CHUNKS = [0x454BA0, 0x455630, 0x4541D0, 0x4532B0, 0x452C00,
                 0x450A90]
# The 26-char message: bytes 0..9 from 0x451480, bytes 10..25
# from 0x452bf0.
PE_MSG_CHUNKS = [(0x451480, 10), (0x452BF0, 16)]

# The 105 instructions of the main FDE, (address, mnemonic,
# op_str), in Capstone's Intel syntax (the .objdump.txt excerpt
# is the verbatim objdump rendering of the same bytes).
INSTRUCTIONS_MAIN = [
    (0x604D500, "endbr64", ""),
    (0x604D504, "push", "r12"),
    (0x604D506, "push", "rbp"),
    (0x604D507, "push", "rbx"),
    (0x604D508, "mov", "rbx, rdi"),
    (0x604D50B, "sub", "rsp, 0x20"),
    (0x604D50F, "mov", "rax, qword ptr fs:[0x28]"),
    (0x604D518, "mov", "qword ptr [rsp + 0x18], rax"),
    (0x604D51D, "xor", "eax, eax"),
    (0x604D51F, "movzx", "eax, byte ptr [rsi + 0x89]"),
    (0x604D526, "test", "al, al"),
    (0x604D528, "jne", "0x604d640"),
    (0x604D52E, "mov", "rax, qword ptr [rsi + 0x20]"),
    (0x604D532, "mov", "rdi, qword ptr [rsi + 0x30]"),
    (0x604D536, "mov", "rbp, rsi"),
    (0x604D539, "mov", "r12d, edx"),
    (0x604D53C, "test", "rax, rax"),
    (0x604D53F, "je", "0x604d547"),
    (0x604D541, "cmp", "byte ptr [rax + 0x68], 0"),
    (0x604D545, "jne", "0x604d54b"),
    (0x604D547, "mov", "rdi, qword ptr [rdi + 0x28]"),
    (0x604D54B, "mov", "rax, qword ptr [rdi]"),
    (0x604D54E, "call", "qword ptr [rax + 0x58]"),
    (0x604D551, "test", "al, al"),
    (0x604D553, "jne", "0x604d5f8"),
    (0x604D559, "xor", "eax, eax"),
    (0x604D55B, "mov", "dword ptr [rbx], 3"),
    (0x604D561, "mov", "edi, 0x5f"),
    (0x604D566, "mov", "word ptr [rbx + 4], ax"),
    (0x604D56A, "mov", "qword ptr [rbx + 8], 0"),
    (0x604D572, "call", "0x63f0e30"),
    (0x604D577, "movdqa", "xmm0, xmmword ptr [rip - 0x5bf89df]"),
    (0x604D57F, "mov", "byte ptr [rax + 0x5e], 0"),
    (0x604D583, "movups", "xmmword ptr [rax], xmm0"),
    (0x604D586, "movdqa", "xmm0, xmmword ptr [rip - 0x5bf7f5e]"),
    (0x604D58E, "movups", "xmmword ptr [rax + 0x10], xmm0"),
    (0x604D592, "movdqa", "xmm0, xmmword ptr [rip - 0x5bf93ca]"),
    (0x604D59A, "movups", "xmmword ptr [rax + 0x20], xmm0"),
    (0x604D59E, "movdqa", "xmm0, xmmword ptr [rip - 0x5bfa2f6]"),
    (0x604D5A6, "movups", "xmmword ptr [rax + 0x30], xmm0"),
    (0x604D5AA, "movdqa", "xmm0, xmmword ptr [rip - 0x5bfa9b2]"),
    (0x604D5B2, "movups", "xmmword ptr [rax + 0x40], xmm0"),
    (0x604D5B6, "movdqa", "xmm0, xmmword ptr [rip - 0x5bfcb2e]"),
    (0x604D5BE, "movups", "xmmword ptr [rax + 0x4e], xmm0"),
    (0x604D5C2, "mov", "rdi, qword ptr [rbx + 8]"),
    (0x604D5C6, "mov", "qword ptr [rbx + 8], rax"),
    (0x604D5CA, "test", "rdi, rdi"),
    (0x604D5CD, "je", "0x604d5d4"),
    (0x604D5CF, "call", "0x63f0dc0"),
    (0x604D5D4, "mov", "rax, qword ptr [rsp + 0x18]"),
    (0x604D5D9, "sub", "rax, qword ptr fs:[0x28]"),
    (0x604D5E2, "jne", "0x604d6a0"),
    (0x604D5E8, "add", "rsp, 0x20"),
    (0x604D5EC, "mov", "rax, rbx"),
    (0x604D5EF, "pop", "rbx"),
    (0x604D5F0, "pop", "rbp"),
    (0x604D5F1, "pop", "r12"),
    (0x604D5F3, "ret", ""),
    (0x604D5F4, "nop", "dword ptr [rax]"),
    (0x604D5F8, "movzx", "edx, r12b"),
    (0x604D5FC, "mov", "rdi, rsp"),
    (0x604D5FF, "mov", "rsi, rbp"),
    (0x604D602, "call", "0x604c900"),
    (0x604D607, "movzx", "edx, byte ptr [rsp]"),
    (0x604D60B, "test", "dl, dl"),
    (0x604D60D, "jne", "0x604d690"),
    (0x604D613, "movzx", "eax, dl"),
    (0x604D616, "mov", "ah, byte ptr [rsp + 1]"),
    (0x604D61A, "mov", "byte ptr [rbx + 2], 0"),
    (0x604D61E, "mov", "word ptr [rbx], ax"),
    (0x604D621, "movzx", "eax, word ptr [rsp + 3]"),
    (0x604D626, "mov", "word ptr [rbx + 3], ax"),
    (0x604D62A, "movzx", "eax, byte ptr [rsp + 5]"),
    (0x604D62F, "mov", "byte ptr [rbx + 5], al"),
    (0x604D632, "mov", "rax, qword ptr [rsp + 8]"),
    (0x604D637, "mov", "qword ptr [rbx + 8], rax"),
    (0x604D63B, "jmp", "0x604d5d4"),
    (0x604D63D, "nop", "dword ptr [rax]"),
    (0x604D640, "xor", "edx, edx"),
    (0x604D642, "mov", "dword ptr [rdi], 5"),
    (0x604D648, "mov", "word ptr [rdi + 4], dx"),
    (0x604D64C, "mov", "qword ptr [rdi + 8], 0"),
    (0x604D654, "mov", "edi, 0x1b"),
    (0x604D659, "call", "0x63f0e30"),
    (0x604D65E, "movdqa", "xmm0, xmmword ptr [rip - 0x5bfc1e6]"),
    (0x604D666, "mov", "byte ptr [rax + 0x1a], 0"),
    (0x604D66A, "movups", "xmmword ptr [rax], xmm0"),
    (0x604D66D, "movdqa", "xmm0, xmmword ptr [rip - 0x5bfaa85]"),
    (0x604D675, "movups", "xmmword ptr [rax + 0xa], xmm0"),
    (0x604D679, "mov", "rdi, qword ptr [rbx + 8]"),
    (0x604D67D, "mov", "qword ptr [rbx + 8], rax"),
    (0x604D681, "test", "rdi, rdi"),
    (0x604D684, "jne", "0x604d5cf"),
    (0x604D68A, "jmp", "0x604d5d4"),
    (0x604D68F, "nop", ""),
    (0x604D690, "mov", "byte ptr [rbp + 0x89], 1"),
    (0x604D697, "movzx", "edx, byte ptr [rsp]"),
    (0x604D69B, "jmp", "0x604d613"),
    (0x604D6A0, "call", "0x63f0d70"),
    (0x604D6A5, "endbr64", ""),
    (0x604D6A9, "mov", "rbp, rax"),
    (0x604D6AC, "jmp", "0x604d4a8"),
    (0x604D6B1, "endbr64", ""),
    (0x604D6B5, "mov", "rbp, rax"),
    (0x604D6B8, "jmp", "0x604d4ce"),
]
# The 20 instructions of the .cold FDE, same format.
INSTRUCTIONS_COLD = [
    (0x604D4A8, "mov", "rdi, qword ptr [rbx + 8]"),
    (0x604D4AC, "test", "rdi, rdi"),
    (0x604D4AF, "je", "0x604d4b6"),
    (0x604D4B1, "call", "0x63f0dc0"),
    (0x604D4B6, "mov", "rax, qword ptr [rsp + 0x18]"),
    (0x604D4BB, "sub", "rax, qword ptr fs:[0x28]"),
    (0x604D4C4, "jne", "0x604d4f4"),
    (0x604D4C6, "mov", "rdi, rbp"),
    (0x604D4C9, "call", "0x63f0a50"),
    (0x604D4CE, "mov", "rdi, qword ptr [rbx + 8]"),
    (0x604D4D2, "test", "rdi, rdi"),
    (0x604D4D5, "je", "0x604d4dc"),
    (0x604D4D7, "call", "0x63f0dc0"),
    (0x604D4DC, "mov", "rax, qword ptr [rsp + 0x18]"),
    (0x604D4E1, "sub", "rax, qword ptr fs:[0x28]"),
    (0x604D4EA, "jne", "0x604d4f9"),
    (0x604D4EC, "mov", "rdi, rbp"),
    (0x604D4EF, "call", "0x63f0a50"),
    (0x604D4F4, "call", "0x63f0d70"),
    (0x604D4F9, "call", "0x63f0d70"),
]
# Callers: (site, caller start, caller end, caller name, member, kind).
CALLERS = [
    (0x5D7F657, 0x5D7F3B0, 0x5D7FB40,
     "rocksdb::DBImpl::SyncWAL",
     "4d429ab1cb2d8f8b-db_impl.o", "call"),
]
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-sync-without-flush-115"
CASES = PACKET / "cases.tsv"


class IsSyncThreadSafeThrew(Exception):
    """The effective file's IsSyncThreadSafe threw (no pad)."""


class SyncInternalThrew(Exception):
    """SyncInternal threw (no pad)."""


class BadAlloc(Exception):
    """operator new[] threw (lands in the .cold cleanup)."""


class StackCheckFailed(Exception):
    """The canary check failed (__stack_chk_fail)."""


def _ok_status():
    return {"code": 0, "subcode": 0, "sev": 0, "retryable": False,
            "data_loss": False, "scope": 0, "state": None}


def _fresh_error(code, message):
    """The Status ctor used by the two fresh-error builders:
    code, subcode 0, sev kNoError, retryable/data_loss/scope 0,
    state_ = message + NUL (a fresh char[len+1] buffer)."""
    return {"code": code, "subcode": 0, "sev": 0, "retryable": False,
            "data_loss": False, "scope": 0, "state": message}


def _copy_status(s):
    """The IOStatus copy ctor (io_status.h:171): code, subcode,
    retryable, data_loss, scope and a fresh copy of state_ are
    copied; severity is reset to kNoError."""
    return {"code": s["code"], "subcode": s["subcode"], "sev": 0,
            "retryable": s["retryable"], "data_loss": s["data_loss"],
            "scope": s["scope"],
            "state": None if s["state"] is None else str(s["state"])}


def resolve_file(writer):
    """FSWritableFilePtr::get() inlined (file_system_tracer.h:
    365-373). writer: {"io_tracer": None | {"tracing_enabled":
    bool}, "fs_tracer": None | {"target": file}}. Returns
    ("wrapper"|"target", file): the tracing wrapper itself when
    tracing is enabled, else the wrapped file -- and the file
    whose IsSyncThreadSafe result decides. (The wrapper's
    IsSyncThreadSafe forwards to its target, file_system.h:1683,
    so the deciding file is the target either way; the model
    records which object the call lands on.)"""
    io_tracer = writer["io_tracer"]
    fs_tracer = writer["fs_tracer"]
    if io_tracer is not None and io_tracer["tracing_enabled"]:
        return ("wrapper",
                fs_tracer["target"] if fs_tracer else None)
    if fs_tracer is None:
        return ("target", None)
    return ("target", fs_tracer["target"])


def sync_without_flush(writer, use_fsync, sync_result=None,
                       is_sync_throws=False, sync_throws=False,
                       new_throws=None, canary_ok=True):
    """The binary's decision, on the writer state.

    writer: {"seen_error": bool, "io_tracer": None | {"tracing_enabled":
    bool}, "fs_tracer": None | {"target": {"sync_thread_safe": bool}}}.
    sync_result: the IOStatus SyncInternal returns (None when it is
    never reached), as a status dict.
    new_throws: None, "not_supported" or "prev_error" -- the
    operator new[] in that error path throws BadAlloc.
    Returns {"status": status, "seen_error": bool, "effective":
    "wrapper"|"target", "sync_internal_called": bool}.
    Raises IsSyncThreadSafeThrew / SyncInternalThrew (no landing
    pad: out untouched, seen_error unchanged), BadAlloc (lands in
    the .cold cleanup: the out state_ is null at that point, the
    canary is checked, then _Unwind_Resume) or StackCheckFailed
    (bad canary at the return check, or in the .cold cleanup
    instead of resuming).
    """
    seen_error = writer["seen_error"]
    if seen_error:
        if new_throws == "prev_error":
            raise BadAlloc("prev_error new[]")
        if not canary_ok:
            raise StackCheckFailed("return canary")
        return {"status": _fresh_error(5, PREV_ERROR_MSG),
                "seen_error": True, "effective": None,
                "sync_internal_called": False}
    effective, f = resolve_file(writer)
    if f is None:
        # fs_tracer_ null: [rdi+0x28] faults in the binary; the
        # source's get() returns nullptr and the virtual call
        # faults the same way. Not a reachable writer state.
        raise ValueError("fs_tracer is null (unreachable state)")
    if is_sync_throws:
        raise IsSyncThreadSafeThrew()
    if not f["sync_thread_safe"]:
        if new_throws == "not_supported":
            raise BadAlloc("not_supported new[]")
        if not canary_ok:
            raise StackCheckFailed("return canary")
        return {"status": _fresh_error(3, NOT_SUPPORTED_MSG),
                "seen_error": False, "effective": effective,
                "sync_internal_called": False}
    if sync_throws:
        raise SyncInternalThrew()
    s = _copy_status(sync_result)
    if s["code"] != 0:
        seen_error = True
    if not canary_ok:
        raise StackCheckFailed("return canary")
    return {"status": s, "seen_error": seen_error,
            "effective": effective, "sync_internal_called": True}


def run_case(inputs):
    """Run one case. Inputs carry the writer state, use_fsync,
    the SyncInternal oracle result, the throw/new/canary flags,
    and optionally an invariant."""
    writer = {"seen_error": inputs["seen_error"],
              "io_tracer": inputs["io_tracer"],
              "fs_tracer": inputs["fs_tracer"]}
    sync_result = inputs.get("sync_result")
    try:
        out = sync_without_flush(
            writer, inputs["use_fsync"], sync_result=sync_result,
            is_sync_throws=inputs.get("is_sync_throws", False),
            sync_throws=inputs.get("sync_throws", False),
            new_throws=inputs.get("new_throws"),
            canary_ok=inputs.get("canary_ok", True))
        out = {"outcome": "ok", "status": out["status"],
               "seen_error": out["seen_error"],
               "effective": out["effective"],
               "sync_internal_called": out["sync_internal_called"]}
    except IsSyncThreadSafeThrew:
        out = {"outcome": "throw_is_sync_thread_safe",
               "seen_error": writer["seen_error"],
               "effective": None, "sync_internal_called": False}
    except SyncInternalThrew:
        out = {"outcome": "throw_sync_internal",
               "seen_error": writer["seen_error"],
               "effective": None, "sync_internal_called": True}
    except BadAlloc:
        out = {"outcome": "throw_bad_alloc",
               "seen_error": writer["seen_error"],
               "effective": None, "sync_internal_called": False}
    except StackCheckFailed:
        out = {"outcome": "stack_check_failed",
               "seen_error": writer["seen_error"],
               "effective": None, "sync_internal_called": False}
    if "invariant" in inputs:
        out["invariant"] = inputs["invariant"]
        out["invariant_expected"] = invariant_value(inputs["invariant"])
    return out


def invariant_value(name):
    """The recorded expected value of a binding invariant."""
    if name == "body_sha256":
        return BODY_SHA256
    if name == "source_sha256":
        return SOURCE_SHA256
    if name == "fde_record":
        return {"main": {"section_offset": hex(FDE_SECTION_OFFSET),
                         "length": FDE_LENGTH, "range": FDE_RANGE,
                         "aug_len": 4, "lsda": hex(FDE_LSDA),
                         "call_sites": len(LSDA_MAIN)},
                "cold": {"section_offset":
                         hex(COLD_FDE_SECTION_OFFSET),
                         "length": COLD_FDE_LENGTH,
                         "range": COLD_FDE_RANGE, "aug_len": 4,
                         "lsda": hex(COLD_FDE_LSDA),
                         "call_sites": len(LSDA_COLD)}}
    if name == "caller_census":
        return {"calls": 1, "jumps": 0, "lea_refs": 0}
    raise ValueError(name)

# Case inputs: the writer state is (seen_error, io_tracer,
# fs_tracer). io_tracer: None | {"tracing_enabled": bool};
# fs_tracer: {"target": {"sync_thread_safe": bool}} -- the
# tracing wrapper object; its own IsSyncThreadSafe forwards to
# the target, so the target's flag decides either way.
def _writer(seen_error, tracer, safe):
    return {"seen_error": seen_error,
            "io_tracer": tracer,
            "fs_tracer": {"target": {"sync_thread_safe": safe}}}


def _status(code, subcode=0, message=None, retryable=False,
            data_loss=False, scope=0):
    return {"code": code, "subcode": subcode, "sev": 0,
            "retryable": retryable, "data_loss": data_loss,
            "scope": scope, "state": message}


# 50 deterministic check combos: tracer state x thread-safety x
# use_fsync x SyncInternal result (ok / IOError / NotSupported /
# NotFound, with a subcode and a message on some). With
# seen_error False the SyncInternal result only matters when the
# file is thread-safe; with it True the early return wins.
_TRACERS = [None, {"tracing_enabled": False},
            {"tracing_enabled": True}]
_SYNC_RESULTS = [
    _ok_status(),
    _status(5, message="Sync failed: I/O error"),
    _status(3, message="Not supported"),
    _status(1, subcode=9, message="Path not found"),
    _status(5, subcode=4, message="No space", retryable=True),
    _status(5, message="Timed out", scope=1),
    _status(5, subcode=6, message="Stale file", data_loss=True),
    _status(2, message="Corruption"),
    _status(5, message=""),
    _status(10, message="Aborted"),
]
CHECK_COMBOS = []
for i in range(50):
    CHECK_COMBOS.append((
        _TRACERS[i % 3],
        (i // 3) % 2 == 0,
        (i // 6) % 2 == 0,
        _SYNC_RESULTS[i % len(_SYNC_RESULTS)],
    ))

# Edge conditions: (is_sync_throws, sync_throws, new_throws,
# canary_ok). A throw from IsSyncThreadSafe or SyncInternal has
# no landing pad; a new[] failure lands in the .cold cleanup; a
# bad canary becomes StackCheckFailed at the return check.
EDGE_CONDITIONS = [
    (False, False, None, True),          # normal
    (True, False, None, True),           # IsSyncThreadSafe throws
    (False, True, None, True),           # SyncInternal throws
    (False, False, "not_supported", True),  # new[] in NotSupported
    (False, False, "prev_error", True),  # new[] in IOError path
    (False, False, None, False),         # bad canary on return
    (True, False, None, False),          # throw, canary moot
    (False, True, None, False),          # throw, canary moot
    (False, False, "not_supported", False),  # new[] + bad canary
    (False, False, None, True),          # normal, empty sync msg
]


def gen_cases():
    """300 deterministic cases: 100 checks + 100 edge + 100 bindings."""
    rows = []
    # checks: 50 combos x 2 seen_error states.
    for seen_error in (False, True):
        for tracer, safe, use_fsync, sync_result in CHECK_COMBOS:
            inputs = {"case_id": f"checks-{len(rows):04d}",
                      "group": "checks",
                      "seen_error": seen_error,
                      "io_tracer": tracer,
                      "fs_tracer": {"target":
                                    {"sync_thread_safe": safe}},
                      "use_fsync": use_fsync,
                      "sync_result": sync_result}
            rows.append(("checks", inputs["case_id"], inputs,
                         run_case(inputs)))
    assert len(rows) == 100, len(rows)
    # edge: 10 base combos x 10 conditions.
    edge_bases = CHECK_COMBOS[::5]
    assert len(edge_bases) == 10, len(edge_bases)
    for tracer, safe, use_fsync, sync_result in edge_bases:
        for is_throws, sy_throws, new_throws, canary_ok in \
                EDGE_CONDITIONS:
            inputs = {"case_id": f"edge-{len(rows) - 100:04d}",
                      "group": "edge",
                      "seen_error": False,
                      "io_tracer": tracer,
                      "fs_tracer": {"target":
                                    {"sync_thread_safe": safe}},
                      "use_fsync": use_fsync,
                      "sync_result": (None if sy_throws else
                                      sync_result),
                      "is_sync_throws": is_throws,
                      "sync_throws": sy_throws,
                      "new_throws": new_throws,
                      "canary_ok": canary_ok}
            # The last condition pins the empty-message sync
            # result: an OK SyncInternal with a null state_.
            if (is_throws, sy_throws, new_throws, canary_ok) == \
                    EDGE_CONDITIONS[-1]:
                inputs["sync_result"] = _status(5, message="")
            rows.append(("edge", inputs["case_id"], inputs,
                         run_case(inputs)))
    assert len(rows) == 200, len(rows)
    # bindings: 25 (writer, use_fsync) pairs x 4 invariants.
    bind_pairs = []
    for seen_error in (False, True):
        for tracer, safe, use_fsync, sync_result in CHECK_COMBOS[:13]:
            bind_pairs.append((seen_error, tracer, safe, use_fsync,
                               sync_result))
    bind_pairs = bind_pairs[:25]
    invariants = ["body_sha256", "source_sha256", "fde_record",
                  "caller_census"]
    for seen_error, tracer, safe, use_fsync, sync_result in bind_pairs:
        for inv in invariants:
            inputs = {"case_id": f"bindings-{len(rows) - 200:04d}",
                      "group": "bindings", "invariant": inv,
                      "seen_error": seen_error,
                      "io_tracer": tracer,
                      "fs_tracer": {"target":
                                    {"sync_thread_safe": safe}},
                      "use_fsync": use_fsync,
                      "sync_result": sync_result}
            rows.append(("bindings", inputs["case_id"], inputs,
                         run_case(inputs)))
    assert len(rows) == 300, len(rows)
    return rows


def write_cases(path=CASES):
    rows = gen_cases()
    with open(path, "w") as fh:
        fh.write("group\tcase_id\tinputs_json\texpected_json\n")
        for group, case_id, inputs, expected in rows:
            fh.write(f"{group}\t{case_id}\t"
                     f"{json.dumps(inputs, separators=(',', ':'))}\t"
                     f"{json.dumps(expected, separators=(',', ':'))}\n")
    print(f"wrote {len(rows)} cases to {path}")
    return rows


def verify_cases(path=CASES):
    rows = gen_cases()
    by_id = {r[1]: r for r in rows}
    mismatches = []
    with open(path) as fh:
        header = fh.readline()
        assert header.startswith("group\tcase_id\t"), header
        for line in fh:
            group, case_id, inputs_json, expected_json = \
                line.rstrip("\n").split("\t")
            inputs = json.loads(inputs_json)
            expected = json.loads(expected_json)
            if case_id not in by_id:
                mismatches.append((case_id, "unknown case id"))
                continue
            got = run_case(inputs)
            if got != expected:
                mismatches.append((case_id, f"got {got} want {expected}"))
    if mismatches:
        for m in mismatches[:10]:
            print("MISMATCH", m, file=sys.stderr)
        print(f"{len(mismatches)} mismatches / {len(rows)} cases",
              file=sys.stderr)
        return 1
    print(f"{len(rows)} cases, 0 mismatches")
    return 0


def _bin_path():
    for candidate in (Path(__file__).resolve().parents[1] / "work" /
                      "hl-node-115.bin",
                      Path(__file__).resolve().parents[1] / "artifacts" /
                      "node" / "115" / "hl-node"):
        data = open(candidate, "rb").read()
        if hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256:
            return candidate
    raise RuntimeError("node #115 artifact not materialized")


def _load_text():
    BIN = _bin_path()
    out = subprocess.check_output(["readelf", "-SW", str(BIN)]).decode()
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
                  r"([0-9a-f]+)", out)
    va, off, size = (int(m.group(i), 16) for i in (1, 2, 3))
    data = open(BIN, "rb").read()
    return va, off, data[off:off + size]


def _load_eh_frame():
    BIN = _bin_path()
    out = subprocess.check_output(["readelf", "-SW", str(BIN)]).decode()
    m = re.search(r"\.eh_frame\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)"
                  r"\s+([0-9a-f]+)", out)
    va, off, size = (int(m.group(i), 16) for i in (1, 2, 3))
    data = open(BIN, "rb").read()
    return va, off, data[off:off + size]


def _uleb(data, pos):
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return result, pos


def _lsda_at(addr):
    """Parse the LSDA at a .gcc_except_table address (file offset
    == VA for that section). Returns the call-site entries as
    (start, length, landing_pad, action) tuples."""
    BIN = _bin_path()
    data = open(BIN, "rb").read()
    pos = addr
    lpstart_enc = data[pos]
    pos += 1
    assert lpstart_enc == 0xFF, hex(lpstart_enc)  # omit
    ttype_enc = data[pos]
    pos += 1
    assert ttype_enc == 0xFF, hex(ttype_enc)  # omit
    cs_enc = data[pos]
    pos += 1
    assert cs_enc == 0x01, hex(cs_enc)  # uleb128
    cs_len, pos = _uleb(data, pos)
    end = pos + cs_len
    entries = []
    while pos < end:
        start, pos = _uleb(data, pos)
        length, pos = _uleb(data, pos)
        pad, pos = _uleb(data, pos)
        action, pos = _uleb(data, pos)
        entries.append((start, length, pad, action))
    assert pos == end, (pos, end)
    return entries


def _fde_lsda_addr(fde_section_offset):
    """Resolve an FDE's LSDA pointer: the augmentation data holds
    a 4-byte indirect|pcrel|sdata4 (encoding 0x9b) offset from the
    field to the LSDA start in .gcc_except_table (file offset ==
    VA for that section). Returns (lsda_address, fde_length)."""
    eh_va, eh_off, eh = _load_eh_frame()
    pos = fde_section_offset
    (length,) = struct.unpack_from("<I", eh, pos)
    aug_len = eh[pos + 16]
    assert aug_len == 4, aug_len
    field_va = eh_va + pos + 17
    (raw,) = struct.unpack_from("<i", eh, pos + 17)
    target = field_va + raw
    return target, length

def live_check():
    """Decisive legs only: hashes, FDE records, LSDA tables,
    instruction facts, message bytes, caller census, model
    end-to-end. Returns exit code."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    legs = []

    def leg(ok, label):
        legs.append((bool(ok), label))
        print(("PASS " if ok else "FAIL ") + label)
        return ok

    BIN = _bin_path()
    data = open(BIN, "rb").read()
    leg(hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256,
        "artifact digest")
    text_va, text_off, text = _load_text()
    body = data[text_off + (START - text_va):
                text_off + (END - text_va)]
    leg(len(body) == 445, "body length 445")
    leg(hashlib.sha256(body).hexdigest() == BODY_SHA256, "body hash")
    src = bytearray(body)
    for off, _kind in RELOCATIONS:
        src[off:off + 4] = b"\x00\x00\x00\x00"
    leg(hashlib.sha256(bytes(src)).hexdigest() == SOURCE_SHA256,
        "source hash (zero 15 census relocations)")
    cold = data[text_off + (COLD_START - text_va):
                text_off + (COLD_END - text_va)]
    leg(len(cold) == 86, "cold body length 86")
    leg(hashlib.sha256(cold).hexdigest() == COLD_BODY_SHA256,
        "cold body hash")
    csrc = bytearray(cold)
    for off, _kind in COLD_RELOCATIONS:
        csrc[off:off + 4] = b"\x00\x00\x00\x00"
    leg(hashlib.sha256(bytes(csrc)).hexdigest() ==
        COLD_SOURCE_SHA256, "cold source hash (zero 6 relocations)")
    # FDE records: parse .eh_frame for the records at the two
    # section offsets.
    eh_va, eh_off, eh = _load_eh_frame()

    def fde_record(offset):
        (length,) = struct.unpack_from("<I", eh, offset)
        (init4,) = struct.unpack_from("<i", eh, offset + 8)
        (rng,) = struct.unpack_from("<I", eh, offset + 12)
        pc = eh_va + offset + 8 + init4
        return length, pc, rng, eh[offset + 16]

    length, pc, rng, aug = fde_record(FDE_SECTION_OFFSET)
    leg(length == FDE_LENGTH, f"main FDE length 0x{length:x}")
    leg(pc == START, f"main FDE initial_location 0x{pc:x}")
    leg(rng == FDE_RANGE, f"main FDE range 0x{rng:x}")
    leg(aug == 4, "main FDE aug_len 4 (LSDA pointer)")
    lsda_addr, _ = _fde_lsda_addr(FDE_SECTION_OFFSET)
    leg(lsda_addr == FDE_LSDA, f"main LSDA at 0x{lsda_addr:x}")
    leg(_lsda_at(lsda_addr) == LSDA_MAIN,
        "main LSDA: 4 call-site entries (pads 0x1b1/0x1a5)")
    length, pc, rng, aug = fde_record(COLD_FDE_SECTION_OFFSET)
    leg(length == COLD_FDE_LENGTH, f"cold FDE length 0x{length:x}")
    leg(pc == COLD_START, f"cold FDE initial_location 0x{pc:x}")
    leg(rng == COLD_FDE_RANGE, f"cold FDE range 0x{rng:x}")
    leg(aug == 4, "cold FDE aug_len 4 (LSDA pointer)")
    cold_lsda, _ = _fde_lsda_addr(COLD_FDE_SECTION_OFFSET)
    leg(cold_lsda == COLD_FDE_LSDA, f"cold LSDA at 0x{cold_lsda:x}")
    leg(_lsda_at(cold_lsda) == LSDA_COLD,
        "cold LSDA: 1 call-site entry, no pad")
    # Instruction facts via Capstone over the FDE bytes.
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    insns = list(md.disasm(body, START))
    got = [(i.address, i.mnemonic, i.op_str) for i in insns]
    leg(got == INSTRUCTIONS_MAIN,
        f"105 main instructions verbatim ({len(insns)} decoded)")
    cold_insns = list(md.disasm(cold, COLD_START))
    got_cold = [(i.address, i.mnemonic, i.op_str)
                for i in cold_insns]
    leg(got_cold == INSTRUCTIONS_COLD,
        f"20 cold instructions verbatim ({len(cold_insns)} decoded)")
    calls = [i for i in insns if i.mnemonic == "call"]
    direct = [i for i in calls if i.op_str.startswith("0x")]
    leg(len(calls) == 6 and len(direct) == 5,
        f"6 calls in main: 5 direct + 1 indirect "
        f"({len(calls)} found)")
    leg([i for i in calls if i.op_str == "0x604c900"] != [],
        "direct call to SyncInternal 0x604c900")
    leg([i for i in calls if i.op_str == "0x63f0e30"] != [] and
        len([i for i in calls if i.op_str == "0x63f0e30"]) == 2,
        "2 operator new[] calls (0x63f0e30)")
    leg([i for i in insns if i.mnemonic == "call" and
         i.op_str == "qword ptr [rax + 0x58]"] != [],
        "indirect call to vtable slot 11 (IsSyncThreadSafe)")
    leg(sum(1 for i in insns if i.mnemonic == "ret") == 1, "1 ret")
    leg(all(START <= int(i.op_str, 16) < END
            for i in insns if i.mnemonic in ("je", "jne")
            and i.op_str.startswith("0x")),
        "all conditional jumps stay inside the main FDE")
    leg(sorted(int(i.op_str, 16) for i in insns
               if i.mnemonic == "jmp"
               and i.op_str.startswith("0x")
               and not (START <= int(i.op_str, 16) < END)) ==
        [COLD_START, 0x604D4CE],
        "the only out-of-FDE jumps are the two LSDA stubs to .cold")
    # Message bytes: rebuild both messages from the .rodata
    # chunks the binary copies with movdqa/movups.
    m2 = re.search(r"\.rodata\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)"
                   r"\s+([0-9a-f]+)", subprocess.check_output(
                       ["readelf", "-SW", str(BIN)]).decode())
    rva, roff, _rsize = (int(m2.group(i), 16) for i in (1, 2, 3))
    ns = b"".join(data[roff + (a - rva):roff + (a - rva) + 16]
                  for a in NS_MSG_CHUNKS[:5])[:78] + \
        data[roff + (NS_MSG_CHUNKS[5] - rva):
             roff + (NS_MSG_CHUNKS[5] - rva) + 16]
    leg(ns == NOT_SUPPORTED_MSG.encode(),
        "94-char NotSupported message bytes")
    pe = data[roff + (PE_MSG_CHUNKS[0][0] - rva):
              roff + (PE_MSG_CHUNKS[0][0] - rva) + 10] + \
        data[roff + (PE_MSG_CHUNKS[1][0] - rva):
             roff + (PE_MSG_CHUNKS[1][0] - rva) + 16]
    leg(pe == PREV_ERROR_MSG.encode(),
        "26-char prev-error message bytes")
    # Caller census: raw whole-.text scan for E8/E9/LEA landing on
    # START, validated by decoding from the enclosing FDE start.
    out2 = subprocess.check_output(
        ["readelf", "--debug-dump=frames-interp", str(BIN)]).decode()
    fdes = {}
    for line in out2.splitlines():
        mm = re.search(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if mm:
            fdes[int(mm.group(1), 16)] = int(mm.group(2), 16)
    import bisect
    starts = sorted(fdes)

    def fde_containing(v):
        i = bisect.bisect_right(starts, v) - 1
        if i < 0:
            return None
        s = starts[i]
        return (s, fdes[s]) if s <= v < fdes[s] else None

    def validate(site, kind):
        fde = fde_containing(site)
        if fde is None:
            return None
        start, end = fde
        o = start - text_va
        for insn in md.disasm(text[o:o + (end - start)], start):
            if insn.address == site:
                if kind == "call" and insn.mnemonic == "call":
                    return insn
                if kind == "jmp" and insn.mnemonic == "jmp":
                    return insn
                if kind == "lea" and insn.mnemonic == "lea":
                    return insn
                return None
            if insn.address > site:
                return None
        return None

    sites = []
    n = len(text)
    for opcode, kind, width in ((0xE8, "call", 5), (0xE9, "jmp", 5)):
        i = 0
        while True:
            i = text.find(bytes([opcode]), i)
            if i < 0 or i + 5 > n:
                break
            disp = struct.unpack_from("<i", text, i + 1)[0]
            site = text_va + i
            if site + width + disp == START:
                if validate(site, kind) is not None:
                    sites.append((site, kind))
            i += 1
    i = 0
    while True:
        i = text.find(b"\x48\x8d", i)
        if i < 0 or i + 7 > n:
            break
        modrm = text[i + 2]
        if modrm & 0xC7 == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            site = text_va + i
            if site + 7 + disp == START:
                if validate(site, "lea") is not None:
                    sites.append((site, "lea"))
        i += 1
    leg(sorted(sites) == sorted(
        (s, kind) for s, _, _, _, _, kind in CALLERS),
        f"caller census: 1 direct call, 0 jumps, 0 LEA refs "
        f"({len(sites)} validated)")
    # Model end-to-end legs.
    ok = True
    w = _writer(False, None, True)
    ok = ok and sync_without_flush(
        w, False, sync_result=_ok_status())["status"] == _ok_status()
    ok = ok and sync_without_flush(
        _writer(False, None, False), True)["status"] == \
        _fresh_error(3, NOT_SUPPORTED_MSG)
    ok = ok and sync_without_flush(
        _writer(True, None, True), False)["status"] == \
        _fresh_error(5, PREV_ERROR_MSG)
    ok = ok and sync_without_flush(
        _writer(False, {"tracing_enabled": True}, True), False,
        sync_result=_status(5, message="x"))["seen_error"] is True
    ok = ok and sync_without_flush(
        _writer(False, {"tracing_enabled": True}, True), False,
        sync_result=_status(5, message="x"))["status"]["sev"] == 0
    ok = ok and sync_without_flush(
        _writer(False, None, True), False,
        sync_result=_status(5, message="x"))["effective"] == "target"
    ok = ok and sync_without_flush(
        _writer(False, {"tracing_enabled": True}, True), False,
        sync_result=_ok_status())["effective"] == "wrapper"
    try:
        sync_without_flush(_writer(False, None, True), False,
                           is_sync_throws=True)
        ok = False
    except IsSyncThreadSafeThrew:
        pass
    try:
        sync_without_flush(_writer(False, None, True), False,
                           sync_throws=True)
        ok = False
    except SyncInternalThrew:
        pass
    try:
        sync_without_flush(_writer(False, None, False), False,
                           new_throws="not_supported")
        ok = False
    except BadAlloc:
        pass
    try:
        sync_without_flush(_writer(False, None, True), False,
                           sync_result=_ok_status(), canary_ok=False)
        ok = False
    except StackCheckFailed:
        pass
    leg(ok, "model end-to-end (prev-error / not-supported / ok / "
            "seen_error set / sev reset / wrapper-vs-target / "
            "throws / bad-alloc / bad-canary)")
    failed = [label for passed, label in legs if not passed]
    print(f"{len(legs) - len(failed)}/{len(legs)} live legs pass")
    return 0 if not failed else 1


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--live":
        return live_check()
    if len(sys.argv) > 1 and sys.argv[1] == "--write-cases":
        write_cases()
        return verify_cases()
    if len(sys.argv) > 1 and sys.argv[1] == "--verify-cases":
        return verify_cases()
    print("usage: sync_without_flush115.py "
          "[--live | --write-cases | --verify-cases]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
