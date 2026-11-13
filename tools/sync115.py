#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::WritableFileWriter::Sync.

Target: rocksdb::WritableFileWriter::Sync(bool) at
0x6052800..0x60529ee (494 B, main FDE) plus its .cold FDE at
0x60527a6..0x60527fd (87 B) in node #115 (work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c
3867b5301).

The direct sibling of the earlier RE-002 WritableFileWriter
packets (Append, Flush, UpdateFileChecksum, GetFileChecksum,
GetFileChecksumFuncName, DecideRateLimiterPriority,
SyncWithoutFlush): the sync that flushes first, then syncs the
underlying file only when there is pending data and the file does
not use direct I/O. Upstream RocksDB v8.1.1 calls it exactly as
the binary behaves (file/writable_file_writer.cc:432-453).

Whole-FDE facts (verified live, see --live):
- Signature: IOStatus Sync(bool use_fsync); sret out in rdi,
  this in rsi, use_fsync in edx (kept in r12d). Stack frame
  0x30, canary stored at rsp+0x28 and checked before every
  return (failure calls __stack_chk_fail at 0x60529d1).
- Body hash matches the vendor census target_body_sha256 exactly;
  source hash reproduced exactly by zeroing the 11 census
  relocations (kinds 2/4, no relaxation); the .cold FDE matches
  its census record the same way (6 kind-4 relocations):
  member a895f7517936a0f7-writable_file_writer.o, librocksdb-sys
  0.11.0+8.1.1, symbol _ZN7rocksdb18WritableFileWriter4SyncEb.
- Decision (116 instructions main, 20 cold): if seen_error_
  (this+0x89, std::atomic<bool>) is set, return
  AssertFalseAndGetStatusForPrevError() -- IOStatus::IOError
  ("Writer has previous error.", 26 chars, code 5) -- built fresh
  at 0x605282a (the same 26-char message, copied from the same
  two .rodata chunks 0x451480/0x452bf0 as SyncWithoutFlush).
  Else call Flush(IO_TOTAL) -- the public Flush at 0x6051a20
  (FDE 0x6051a20..0x605257c, open PR #6057), the default argument
  (writable_file_writer.h:244) inlined as the constant 4 -- into
  the stack-local status at rsp; if its code is non-zero,
  set_seen_error() (this+0x89 = 1) and return the copy. Else
  resolve the file through FSWritableFilePtr::get() inlined:
  io_tracer_ is the shared_ptr at this+0x20, fs_tracer_ the
  unique_ptr at this+0x30; if io_tracer_ is non-null and its
  tracing_enabled byte at +0x68 is set, the effective file is
  the tracing wrapper itself; otherwise it is
  fs_tracer_->target(), the wrapped file at wrapper+0x28
  (FSWritableFileWrapper::target_, after the FSWritableFile
  base: vtable + two u64 + two int + bool + pad = 0x28). Call
  use_direct_io() on the effective file (vtable slot 12,
  *0x60(%rax): FSWritableFile's virtuals are dtor x2, Append x2,
  PositionedAppend x2, Truncate, Close, Flush, Sync, Fsync,
  IsSyncThreadSafe (slot 11), then use_direct_io (slot 12),
  include/rocksdb/file_system.h:1052; the tracing wrapper
  forwards to its target, :1685; WritableFileWriter's own
  use_direct_io() is writable_file_writer.h:273). If it returns
  true, skip the sync: clear pending_sync_ (this+0x88) and
  return OK. Else if pending_sync_ is clear, return OK the same
  way. Else call SyncInternal(use_fsync) at 0x604c900 (FDE
  0x604c900..0x604d4a7, .cold 0x604c828..0x604c8f5) into a second
  stack IOStatus at rsp+0x10, move-assign it into the local
  status at rsp (code/subcode, bytes +3..+5 and state_ moved
  over; the destination's severity byte is never written, so it
  stays 0 from the OK Flush result), then if its code is
  non-zero, set_seen_error() and return the copy; else clear
  pending_sync_ and return OK. The OK return frees the local
  status's state_ buffer (the SyncInternal message, when any)
  and leaves out a fresh OK; the Flush/SyncInternal failure
  copies return the copy of the local status with severity reset
  to kNoError by the IOStatus copy ctor (io_status.h:171).
- Status byte layout (Status ctor init order, include/rocksdb/
  status.h): code u8 +0x0, subcode u8 +0x1, sev u8 +0x2,
  retryable bool +0x3, data_loss bool +0x4, scope u8 +0x5,
  padding +0x6..+0x7 (never written), state_ unique_ptr +0x8.
  The fresh error builder writes code, zeroes the rest, then new
  char[len+1] and copies the 26-char message in two movdqa
  chunks (bytes 0..9 from 0x451480, bytes 10..25 from 0x452bf0).
  A failed new throws BadAlloc into the .cold cleanup (delete
  the out state_ -- null at that point -- check the canary,
  _Unwind_Resume); a throw from Flush has NO landing pad (LSDA
  entry [1]) and propagates with no cleanup of ours; a throw
  from use_direct_io or from SyncInternal shares the second
  landing pad (LSDA entry [2], stub 0x60529e2 -> .cold
  0x60527cc), which deletes the local status's state_ (null
  after the OK Flush), checks the canary, and resumes.
- Main LSDA at 0x41ea39 (in .gcc_except_table): 3 call-site
  entries, all cleanup, action 0: [0] start 0x43 len 5 pad
  0x1d6 (the prev-error new -> stub 0x60529d6 -> .cold
  0x60527a6), [1] start 0xa6 len 5 no pad (the Flush call),
  [2] start 0xd3 len 0x21 pad 0x1e2 (the use_direct_io call at
  0xd3 and the SyncInternal call at 0xef, sharing the stub
  0x60529e2 -> .cold 0x60527cc). Cold LSDA at 0x41ea4d: 1 entry,
  start 0x21 len 0x2c, no pad. Both FDE records have aug_len 4
  (LSDA pointer, encoding 0x9b indirect|pcrel|sdata4).
- Callers: exactly 11 direct calls, 0 tail jumps, 0 LEA refs
  (whole-.text E8/E9/LEA scan, Capstone-validated):
  rocksdb::DBImpl::SyncClosedLogs (site 0x5ddd278, FDE
  0x5ddd080..0x5ddd673, census-bound, db_impl_compaction_flush.o),
  rocksdb::CompactionOutputs::WriterSyncClose (site 0x5e1881a,
  FDE 0x5e183f0..0x5e18b3b, census-bound, compaction_outputs.o),
  rocksdb::BuildTable (site 0x5e1eed6, FDE 0x5e1b9c0..0x5e20481;
  the main FDE has no census record, its .cold is census-bound
  as BuildTable, builder.o), rocksdb::BlobLogWriter::Sync (site
  0x5e261ac, FDE 0x5e26110..0x5e262c4, census-bound,
  blob_log_writer.o), rocksdb::DBImpl::Open (sites 0x5e63cce and
  0x5e650c7, FDE 0x5e62c50..0x5e65462, census-bound,
  db_impl_open.o), rocksdb::DBImpl::WriteToWAL (site 0x5e8a1d2,
  FDE 0x5e89c90..0x5e8a4a9, census-bound, db_impl_write.o),
  rocksdb::CreateFile (site 0x603a9aa, FDE 0x603a5a0..0x603ad3e,
  census-bound, file_util.o), rocksdb::CopyFile (site 0x603bcda,
  FDE 0x603ae70..0x603bfd6, census-bound, file_util.o),
  rocksdb::SyncManifest (site 0x603fb3d, FDE 0x603fa00..0x603ff25,
  census-bound, filename.o), rocksdb::PersistRocksDBOptions
  (site 0x60d43ff, FDE 0x60d2820..0x60d49d3, census-bound,
  options_parser.o). Upstream calls Sync from the same paths
  (Flush in DBImpl::Open, WriteToWAL, SyncManifest and the
  options persist path; the full Sync in the file-utility and
  compaction-output paths).

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM. The
target binary is never executed. The tool models the helper in
Python from its whole-FDE disassembly. Flush and SyncInternal are
oracles: their results are inputs to the model, not computed here
(Flush is open PR #6057; SyncInternal has no packet yet).
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
START = 0x6052800
END = 0x60529EE
BODY_SHA256 = ("6de1b149335b8aaa0377bd4d0f9a72fe688304c740725e6e449"
               "0fea4308fd9d9")
SOURCE_SHA256 = ("5f209027a09cc64b90340fcbd0403a4f13ccebfa761c4133"
                 "e632736813846a72")
# 11 census relocations: (offset, kind). Zeroing the 4-byte field
# at each offset reproduces source_body_sha256 exactly.
RELOCATIONS = [(68, 4), (76, 2), (99, 2), (113, 4), (167, 4),
               (240, 4), (314, 4), (329, 4), (466, 4), (478, 2),
               (490, 2)]
RELOCATIONS_DESC = ("11 relocations (offsets 68 k4, 76 k2, 99 k2, "
                    "113 k4, 167 k4, 240 k4, 314 k4, 329 k4, 466 k4, "
                    "478 k2, 490 k2)")
COLD_START = 0x60527A6
COLD_END = 0x60527FD
COLD_BODY_SHA256 = ("0f2e32ed5e4030a260198ce167722a997238f3b40fda5d"
                    "19aae8cc13c3980f7e")
COLD_SOURCE_SHA256 = ("7b132dd1a9e41436bcc39b053f5abcd1d198696c1eab"
                      "abf14c77bdeb17c2d78b")
COLD_RELOCATIONS = [(10, 4), (34, 4), (49, 4), (73, 4), (78, 4),
                    (83, 4)]
COLD_RELOCATIONS_DESC = ("6 kind-4 relocations at offsets 10, 34, "
                         "49, 73, 78, 83")
MEMBER = "a895f7517936a0f7-writable_file_writer.o"
SYMBOL = "_ZN7rocksdb18WritableFileWriter4SyncEb"
# FDE records in .eh_frame: main at section offset 0x7598bc
# (length 0x34, range 0x1ee, aug_len 4, LSDA at 0x41ea39);
# .cold at 0x7598f4 (length 0x1c, range 0x57, aug_len 4, LSDA at
# 0x41ea4d).
FDE_SECTION_OFFSET = 0x7598BC
FDE_LENGTH = 0x34
FDE_RANGE = 0x1EE
FDE_LSDA = 0x41EA39
COLD_FDE_SECTION_OFFSET = 0x7598F4
COLD_FDE_LENGTH = 0x1C
COLD_FDE_RANGE = 0x57
COLD_FDE_LSDA = 0x41EA4D
# Main LSDA call-site entries: (start, length, landing_pad, action).
# Landing pads are offsets from the FDE start (0x6052800): 0x1d6
# -> stub 0x60529d6 -> .cold 0x60527a6; 0x1e2 -> stub 0x60529e2
# -> .cold 0x60527cc. 0 means no landing pad.
LSDA_MAIN = [(0x43, 5, 0x1D6, 0), (0xA6, 5, 0, 0),
             (0xD3, 0x21, 0x1E2, 0)]
LSDA_COLD = [(0x21, 0x2C, 0, 0)]
# The engine calls: Flush(Env::IOPriority) at 0x6051a20 (FDE
# 0x6051a20..0x605257c, open PR #6057); SyncInternal(bool) at
# 0x604c900 (FDE 0x604c900..0x604d4a7, .cold 0x604c828..0x604c8f5).
FLUSH = 0x6051A20
FLUSH_END = 0x605257C
SYNC_INTERNAL = 0x604C900
SYNC_INTERNAL_END = 0x604D4A7
SYNC_INTERNAL_COLD_START = 0x604C828
SYNC_INTERNAL_COLD_END = 0x604C8F5
PREV_ERROR_MSG = "Writer has previous error."
# The 26-char message: bytes 0..9 from 0x451480, bytes 10..25
# from 0x452bf0 (the same chunks as SyncWithoutFlush).
PE_MSG_CHUNKS = [(0x451480, 10), (0x452BF0, 16)]

# The 116 instructions of the main FDE, (address, mnemonic,
# op_str), in Capstone's Intel syntax (the .objdump.txt excerpt
# is the verbatim objdump rendering of the same bytes).
INSTRUCTIONS_MAIN = [
    (0x6052800, "endbr64", ""),
    (0x6052804, "push", "r12"),
    (0x6052806, "push", "rbp"),
    (0x6052807, "push", "rbx"),
    (0x6052808, "mov", "rbx, rdi"),
    (0x605280B, "sub", "rsp, 0x30"),
    (0x605280F, "mov", "rax, qword ptr fs:[0x28]"),
    (0x6052818, "mov", "qword ptr [rsp + 0x28], rax"),
    (0x605281D, "xor", "eax, eax"),
    (0x605281F, "movzx", "eax, byte ptr [rsi + 0x89]"),
    (0x6052826, "test", "al, al"),
    (0x6052828, "je", "0x6052898"),
    (0x605282A, "xor", "ecx, ecx"),
    (0x605282C, "mov", "dword ptr [rdi], 5"),
    (0x6052832, "mov", "word ptr [rdi + 4], cx"),
    (0x6052836, "mov", "qword ptr [rdi + 8], 0"),
    (0x605283E, "mov", "edi, 0x1b"),
    (0x6052843, "call", "0x63f0e30"),
    (0x6052848, "movdqa", "xmm0, xmmword ptr [rip - 0x5c013d0]"),
    (0x6052850, "mov", "rdi, qword ptr [rbx + 8]"),
    (0x6052854, "mov", "byte ptr [rax + 0x1a], 0"),
    (0x6052858, "mov", "qword ptr [rbx + 8], rax"),
    (0x605285C, "movups", "xmmword ptr [rax], xmm0"),
    (0x605285F, "movdqa", "xmm0, xmmword ptr [rip - 0x5bffc77]"),
    (0x6052867, "movups", "xmmword ptr [rax + 0xa], xmm0"),
    (0x605286B, "test", "rdi, rdi"),
    (0x605286E, "je", "0x6052875"),
    (0x6052870, "call", "0x63f0dc0"),
    (0x6052875, "mov", "rax, qword ptr [rsp + 0x28]"),
    (0x605287A, "sub", "rax, qword ptr fs:[0x28]"),
    (0x6052883, "jne", "0x60529d1"),
    (0x6052889, "add", "rsp, 0x30"),
    (0x605288D, "mov", "rax, rbx"),
    (0x6052890, "pop", "rbx"),
    (0x6052891, "pop", "rbp"),
    (0x6052892, "pop", "r12"),
    (0x6052894, "ret", ""),
    (0x6052895, "nop", "dword ptr [rax]"),
    (0x6052898, "mov", "r12d, edx"),
    (0x605289B, "mov", "rdi, rsp"),
    (0x605289E, "mov", "edx, 4"),
    (0x60528A3, "mov", "rbp, rsi"),
    (0x60528A6, "call", "0x6051a20"),
    (0x60528AB, "cmp", "byte ptr [rsp], 0"),
    (0x60528AF, "jne", "0x60529a0"),
    (0x60528B5, "mov", "rax, qword ptr [rbp + 0x20]"),
    (0x60528B9, "mov", "rdi, qword ptr [rbp + 0x30]"),
    (0x60528BD, "test", "rax, rax"),
    (0x60528C0, "je", "0x6052990"),
    (0x60528C6, "cmp", "byte ptr [rax + 0x68], 0"),
    (0x60528CA, "je", "0x6052990"),
    (0x60528D0, "mov", "rax, qword ptr [rdi]"),
    (0x60528D3, "call", "qword ptr [rax + 0x60]"),
    (0x60528D6, "test", "al, al"),
    (0x60528D8, "jne", "0x6052958"),
    (0x60528DA, "cmp", "byte ptr [rbp + 0x88], 0"),
    (0x60528E1, "je", "0x6052958"),
    (0x60528E3, "lea", "rdi, [rsp + 0x10]"),
    (0x60528E8, "movzx", "edx, r12b"),
    (0x60528EC, "mov", "rsi, rbp"),
    (0x60528EF, "call", "0x604c900"),
    (0x60528F4, "xor", "edx, edx"),
    (0x60528F6, "movzx", "eax, word ptr [rsp + 0x10]"),
    (0x60528FB, "mov", "rdi, qword ptr [rsp + 8]"),
    (0x6052900, "mov", "word ptr [rsp + 0x10], dx"),
    (0x6052905, "movzx", "edx, word ptr [rsp + 0x13]"),
    (0x605290A, "mov", "word ptr [rsp], ax"),
    (0x605290E, "mov", "word ptr [rsp + 3], dx"),
    (0x6052913, "movzx", "edx, byte ptr [rsp + 0x15]"),
    (0x6052918, "mov", "byte ptr [rsp + 0x15], 0"),
    (0x605291D, "mov", "byte ptr [rsp + 5], dl"),
    (0x6052921, "mov", "rdx, qword ptr [rsp + 0x18]"),
    (0x6052926, "mov", "qword ptr [rsp + 0x18], 0"),
    (0x605292F, "mov", "qword ptr [rsp + 8], rdx"),
    (0x6052934, "test", "rdi, rdi"),
    (0x6052937, "je", "0x6052951"),
    (0x6052939, "call", "0x63f0dc0"),
    (0x605293E, "mov", "rdi, qword ptr [rsp + 0x18]"),
    (0x6052943, "test", "rdi, rdi"),
    (0x6052946, "je", "0x605294d"),
    (0x6052948, "call", "0x63f0dc0"),
    (0x605294D, "movzx", "eax, byte ptr [rsp]"),
    (0x6052951, "test", "al, al"),
    (0x6052953, "jne", "0x60529a0"),
    (0x6052955, "nop", "dword ptr [rax]"),
    (0x6052958, "mov", "rdi, qword ptr [rsp + 8]"),
    (0x605295D, "xor", "eax, eax"),
    (0x605295F, "mov", "byte ptr [rbp + 0x88], 0"),
    (0x6052966, "mov", "dword ptr [rbx], 0"),
    (0x605296C, "mov", "word ptr [rbx + 4], ax"),
    (0x6052970, "mov", "qword ptr [rbx + 8], 0"),
    (0x6052978, "test", "rdi, rdi"),
    (0x605297B, "jne", "0x6052870"),
    (0x6052981, "jmp", "0x6052875"),
    (0x6052986, "nop", "word ptr cs:[rax + rax]"),
    (0x6052990, "mov", "rdi, qword ptr [rdi + 0x28]"),
    (0x6052994, "jmp", "0x60528d0"),
    (0x6052999, "nop", "dword ptr [rax]"),
    (0x60529A0, "mov", "byte ptr [rbp + 0x89], 1"),
    (0x60529A7, "mov", "byte ptr [rbx + 2], 0"),
    (0x60529AB, "movzx", "eax, word ptr [rsp]"),
    (0x60529AF, "mov", "word ptr [rbx], ax"),
    (0x60529B2, "movzx", "eax, word ptr [rsp + 3]"),
    (0x60529B7, "mov", "word ptr [rbx + 3], ax"),
    (0x60529BB, "movzx", "eax, byte ptr [rsp + 5]"),
    (0x60529C0, "mov", "byte ptr [rbx + 5], al"),
    (0x60529C3, "mov", "rax, qword ptr [rsp + 8]"),
    (0x60529C8, "mov", "qword ptr [rbx + 8], rax"),
    (0x60529CC, "jmp", "0x6052875"),
    (0x60529D1, "call", "0x63f0d70"),
    (0x60529D6, "endbr64", ""),
    (0x60529DA, "mov", "rbp, rax"),
    (0x60529DD, "jmp", "0x60527a6"),
    (0x60529E2, "endbr64", ""),
    (0x60529E6, "mov", "rbx, rax"),
    (0x60529E9, "jmp", "0x60527cc"),
]
# The 20 instructions of the .cold FDE, same format.
INSTRUCTIONS_COLD = [
    (0x60527A6, "mov", "rdi, qword ptr [rbx + 8]"),
    (0x60527AA, "test", "rdi, rdi"),
    (0x60527AD, "je", "0x60527b4"),
    (0x60527AF, "call", "0x63f0dc0"),
    (0x60527B4, "mov", "rax, qword ptr [rsp + 0x28]"),
    (0x60527B9, "sub", "rax, qword ptr fs:[0x28]"),
    (0x60527C2, "jne", "0x60527f3"),
    (0x60527C4, "mov", "rdi, rbp"),
    (0x60527C7, "call", "0x63f0a50"),
    (0x60527CC, "mov", "rdi, qword ptr [rsp + 8]"),
    (0x60527D1, "test", "rdi, rdi"),
    (0x60527D4, "je", "0x60527db"),
    (0x60527D6, "call", "0x63f0dc0"),
    (0x60527DB, "mov", "rax, qword ptr [rsp + 0x28]"),
    (0x60527E0, "sub", "rax, qword ptr fs:[0x28]"),
    (0x60527E9, "jne", "0x60527f8"),
    (0x60527EB, "mov", "rdi, rbx"),
    (0x60527EE, "call", "0x63f0a50"),
    (0x60527F3, "call", "0x63f0d70"),
    (0x60527F8, "call", "0x63f0d70"),
]
# Callers: (site, caller start, caller end, caller name, member, kind).
CALLERS = [
    (0x5DDD278, 0x5DDD080, 0x5DDD673,
     "rocksdb::DBImpl::SyncClosedLogs",
     "4d429ab1cb2d8f8b-db_impl_compaction_flush.o", "call"),
    (0x5E1881A, 0x5E183F0, 0x5E18B3B,
     "rocksdb::CompactionOutputs::WriterSyncClose",
     "e7c8f0e01ce23ae2-compaction_outputs.o", "call"),
    (0x5E1EED6, 0x5E1B9C0, 0x5E20481,
     "rocksdb::BuildTable",
     "25dac13516458d4d-builder.o", "call"),
    (0x5E261AC, 0x5E26110, 0x5E262C4,
     "rocksdb::BlobLogWriter::Sync",
     "ae4e8abb3e2e5bbe-blob_log_writer.o", "call"),
    (0x5E63CCE, 0x5E62C50, 0x5E65462,
     "rocksdb::DBImpl::Open",
     "4d429ab1cb2d8f8b-db_impl_open.o", "call"),
    (0x5E650C7, 0x5E62C50, 0x5E65462,
     "rocksdb::DBImpl::Open",
     "4d429ab1cb2d8f8b-db_impl_open.o", "call"),
    (0x5E8A1D2, 0x5E89C90, 0x5E8A4A9,
     "rocksdb::DBImpl::WriteToWAL",
     "4d429ab1cb2d8f8b-db_impl_write.o", "call"),
    (0x603A9AA, 0x603A5A0, 0x603AD3E,
     "rocksdb::CreateFile",
     "a895f7517936a0f7-file_util.o", "call"),
    (0x603BCDA, 0x603AE70, 0x603BFD6,
     "rocksdb::CopyFile",
     "a895f7517936a0f7-file_util.o", "call"),
    (0x603FB3D, 0x603FA00, 0x603FF25,
     "rocksdb::SyncManifest",
     "a895f7517936a0f7-filename.o", "call"),
    (0x60D43FF, 0x60D2820, 0x60D49D3,
     "rocksdb::PersistRocksDBOptions",
     "d7ece8bd5f9dc186-options_parser.o", "call"),
]
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-sync-115"
CASES = PACKET / "cases.tsv"


class FlushThrew(Exception):
    """Flush threw (no landing pad: out untouched, seen_error
    unchanged)."""


class UseDirectIoThrew(Exception):
    """The effective file's use_direct_io threw (lands in the
    .cold cleanup at 0x60527cc)."""


class SyncInternalThrew(Exception):
    """SyncInternal threw (lands in the .cold cleanup at
    0x60527cc)."""


class BadAlloc(Exception):
    """operator new[] threw (lands in the .cold cleanup at
    0x60527a6)."""


class StackCheckFailed(Exception):
    """The canary check failed (__stack_chk_fail)."""


def _ok_status():
    return {"code": 0, "subcode": 0, "sev": 0, "retryable": False,
            "data_loss": False, "scope": 0, "state": None}


def _fresh_error(code, message):
    """The Status ctor used by the prev-error builder: code,
    subcode 0, sev kNoError, retryable/data_loss/scope 0, state_
    = message + NUL (a fresh char[len+1] buffer)."""
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


def _move_status(s):
    """The move-assign of the SyncInternal result into the local
    status (0x60528f4..0x6052934): code, subcode, bytes +3..+5
    and state_ move over; the destination's severity byte is
    never written, so it stays 0 from the OK Flush result."""
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
    whose use_direct_io result decides. (The wrapper's
    use_direct_io forwards to its target, file_system.h:1685,
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


def sync(writer, use_fsync, flush_result=None, sync_result=None,
         flush_throws=False, use_direct_io_throws=False,
         sync_throws=False, new_throws=None, canary_ok=True):
    """The binary's decision, on the writer state.

    writer: {"seen_error": bool, "pending_sync": bool,
    "io_tracer": None | {"tracing_enabled": bool},
    "fs_tracer": {"target": {"use_direct_io": bool}}}.
    flush_result: the IOStatus Flush(IO_TOTAL) returns (None when
    it is never reached); sync_result: the IOStatus
    SyncInternal returns (None when it is never reached), as
    status dicts.
    new_throws: None or "prev_error" -- the operator new[] in
    that error path throws BadAlloc.
    Returns {"status": status, "seen_error": bool,
    "pending_sync": bool, "effective": "wrapper"|"target"|None,
    "flush_called": bool, "sync_internal_called": bool}.
    Raises FlushThrew (no landing pad: out untouched, seen_error
    unchanged), UseDirectIoThrew / SyncInternalThrew (landing
    pad at .cold 0x60527cc: the local status's state_ -- null
    after the OK Flush -- is deleted, the canary is checked,
    then _Unwind_Resume), BadAlloc (landing pad at .cold
    0x60527a6: the out state_ is null at that point, the canary
    is checked, then _Unwind_Resume) or StackCheckFailed (bad
    canary at the return check, or in the .cold cleanup instead
    of resuming).
    """
    seen_error = writer["seen_error"]
    pending_sync = writer["pending_sync"]
    if seen_error:
        if new_throws == "prev_error":
            if not canary_ok:
                raise StackCheckFailed("cold canary")
            raise BadAlloc("prev_error new[]")
        if not canary_ok:
            raise StackCheckFailed("return canary")
        return {"status": _fresh_error(5, PREV_ERROR_MSG),
                "seen_error": True, "pending_sync": pending_sync,
                "effective": None, "flush_called": False,
                "sync_internal_called": False}
    if flush_throws:
        raise FlushThrew()
    s = flush_result
    if s["code"] != 0:
        if not canary_ok:
            raise StackCheckFailed("return canary")
        return {"status": _copy_status(s),
                "seen_error": True, "pending_sync": pending_sync,
                "effective": None, "flush_called": True,
                "sync_internal_called": False}
    effective, f = resolve_file(writer)
    if f is None:
        # fs_tracer_ null: [rdi+0x28] faults in the binary; the
        # source's get() returns nullptr and the virtual call
        # faults the same way. Not a reachable writer state.
        raise ValueError("fs_tracer is null (unreachable state)")
    if use_direct_io_throws:
        if not canary_ok:
            raise StackCheckFailed("cold canary")
        raise UseDirectIoThrew()
    if f["use_direct_io"]:
        if not canary_ok:
            raise StackCheckFailed("return canary")
        return {"status": _ok_status(), "seen_error": False,
                "pending_sync": False, "effective": effective,
                "flush_called": True, "sync_internal_called": False}
    if not pending_sync:
        if not canary_ok:
            raise StackCheckFailed("return canary")
        return {"status": _ok_status(), "seen_error": False,
                "pending_sync": False, "effective": effective,
                "flush_called": True, "sync_internal_called": False}
    if sync_throws:
        if not canary_ok:
            raise StackCheckFailed("cold canary")
        raise SyncInternalThrew()
    local = _move_status(sync_result)
    if local["code"] != 0:
        if not canary_ok:
            raise StackCheckFailed("return canary")
        return {"status": _copy_status(local),
                "seen_error": True, "pending_sync": pending_sync,
                "effective": effective, "flush_called": True,
                "sync_internal_called": True}
    if not canary_ok:
        raise StackCheckFailed("return canary")
    return {"status": _ok_status(), "seen_error": False,
            "pending_sync": False, "effective": effective,
            "flush_called": True, "sync_internal_called": True}


def run_case(inputs):
    """Run one case. Inputs carry the writer state, use_fsync,
    the Flush/SyncInternal oracle results, the throw/new/canary
    flags, and optionally an invariant."""
    writer = {"seen_error": inputs["seen_error"],
              "pending_sync": inputs["pending_sync"],
              "io_tracer": inputs["io_tracer"],
              "fs_tracer": inputs["fs_tracer"]}
    try:
        out = sync(
            writer, inputs["use_fsync"],
            flush_result=inputs.get("flush_result"),
            sync_result=inputs.get("sync_result"),
            flush_throws=inputs.get("flush_throws", False),
            use_direct_io_throws=inputs.get(
                "use_direct_io_throws", False),
            sync_throws=inputs.get("sync_throws", False),
            new_throws=inputs.get("new_throws"),
            canary_ok=inputs.get("canary_ok", True))
        out = {"outcome": "ok", "status": out["status"],
               "seen_error": out["seen_error"],
               "pending_sync": out["pending_sync"],
               "effective": out["effective"],
               "flush_called": out["flush_called"],
               "sync_internal_called": out["sync_internal_called"]}
    except FlushThrew:
        out = {"outcome": "throw_flush",
               "seen_error": writer["seen_error"],
               "pending_sync": writer["pending_sync"],
               "effective": None, "flush_called": True,
               "sync_internal_called": False}
    except UseDirectIoThrew:
        out = {"outcome": "throw_use_direct_io",
               "seen_error": writer["seen_error"],
               "pending_sync": writer["pending_sync"],
               "effective": None, "flush_called": True,
               "sync_internal_called": False}
    except SyncInternalThrew:
        out = {"outcome": "throw_sync_internal",
               "seen_error": writer["seen_error"],
               "pending_sync": writer["pending_sync"],
               "effective": None, "flush_called": True,
               "sync_internal_called": True}
    except BadAlloc:
        out = {"outcome": "throw_bad_alloc",
               "seen_error": writer["seen_error"],
               "pending_sync": writer["pending_sync"],
               "effective": None, "flush_called": False,
               "sync_internal_called": False}
    except StackCheckFailed:
        out = {"outcome": "stack_check_failed",
               "seen_error": writer["seen_error"],
               "pending_sync": writer["pending_sync"],
               "effective": None, "flush_called": False,
               "sync_internal_called": False}
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
        return {"calls": 11, "jumps": 0, "lea_refs": 0}
    raise ValueError(name)

# Case inputs: the writer state is (seen_error, pending_sync,
# io_tracer, fs_tracer). io_tracer: None | {"tracing_enabled":
# bool}; fs_tracer: {"target": {"use_direct_io": bool}} -- the
# tracing wrapper object; its own use_direct_io forwards to the
# target, so the target's flag decides either way.
def _writer(seen_error, pending_sync, tracer, direct_io):
    return {"seen_error": seen_error, "pending_sync": pending_sync,
            "io_tracer": tracer,
            "fs_tracer": {"target": {"use_direct_io": direct_io}}}


def _status(code, subcode=0, message=None, retryable=False,
            data_loss=False, scope=0, sev=0):
    return {"code": code, "subcode": subcode, "sev": sev,
            "retryable": retryable, "data_loss": data_loss,
            "scope": scope, "state": message}


# 50 deterministic check combos: tracer state x direct-I/O x
# pending_sync x Flush result x SyncInternal result x use_fsync.
# With seen_error False the Flush result decides first; with it
# True the early return wins. With direct I/O or a clear
# pending_sync the SyncInternal result is never reached.
_TRACERS = [None, {"tracing_enabled": False},
            {"tracing_enabled": True}]
_FLUSH_RESULTS = [
    _ok_status(),
    _status(5, message="Flush failed: I/O error"),
    _status(3, message="Not supported"),
    _status(1, subcode=9, message="Path not found"),
    _status(5, subcode=4, message="No space", retryable=True),
    _status(2, message="Corruption"),
]
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
        _FLUSH_RESULTS[i % len(_FLUSH_RESULTS)],
        _SYNC_RESULTS[i % len(_SYNC_RESULTS)],
        (i // 12) % 2 == 0,
    ))

# Edge conditions: (flush_throws, use_direct_io_throws,
# sync_throws, new_throws, canary_ok). A throw from Flush has no
# landing pad; a throw from use_direct_io or SyncInternal lands
# in the .cold cleanup; a new[] failure lands in the .cold
# cleanup; a bad canary becomes StackCheckFailed at the return
# check (or in the .cold cleanup instead of resuming).
EDGE_CONDITIONS = [
    (False, False, False, None, True),    # normal
    (True, False, False, None, True),     # Flush throws
    (False, True, False, None, True),     # use_direct_io throws
    (False, False, True, None, True),     # SyncInternal throws
    (False, False, False, "prev_error", True),  # new[] in IOError
    (False, False, False, None, False),   # bad canary on return
    (True, False, False, None, False),    # Flush throw, canary moot
    (False, False, True, None, False),    # SyncInternal throw + bad canary
    (False, False, False, "prev_error", False),  # new[] + bad canary
    (False, False, False, None, True),    # normal, empty sync msg
]


def gen_cases():
    """300 deterministic cases: 100 checks + 100 edge + 100 bindings."""
    rows = []
    # checks: 50 combos x 2 seen_error states.
    for seen_error in (False, True):
        for tracer, direct_io, pending_sync, flush_result, \
                sync_result, use_fsync in CHECK_COMBOS:
            inputs = {"case_id": f"checks-{len(rows):04d}",
                      "group": "checks",
                      "seen_error": seen_error,
                      "pending_sync": pending_sync,
                      "io_tracer": tracer,
                      "fs_tracer": {"target":
                                    {"use_direct_io": direct_io}},
                      "use_fsync": use_fsync,
                      "flush_result": flush_result,
                      "sync_result": sync_result}
            rows.append(("checks", inputs["case_id"], inputs,
                         run_case(inputs)))
    assert len(rows) == 100, len(rows)
    # edge: 10 base combos x 10 conditions.
    edge_bases = CHECK_COMBOS[::5]
    assert len(edge_bases) == 10, len(edge_bases)
    for tracer, direct_io, pending_sync, flush_result, \
            sync_result, use_fsync in edge_bases:
        for fl_throws, dio_throws, sy_throws, new_throws, \
                canary_ok in EDGE_CONDITIONS:
            # The new[] in the IOError path only runs when
            # seen_error_ is set (the early return); the other
            # conditions run with a clear seen_error_.
            inputs = {"case_id": f"edge-{len(rows) - 100:04d}",
                      "group": "edge",
                      "seen_error": new_throws is not None,
                      "pending_sync": pending_sync,
                      "io_tracer": tracer,
                      "fs_tracer": {"target":
                                    {"use_direct_io": direct_io}},
                      "use_fsync": use_fsync,
                      "flush_result": (None if fl_throws else
                                       flush_result),
                      "sync_result": (None if sy_throws else
                                      sync_result),
                      "flush_throws": fl_throws,
                      "use_direct_io_throws": dio_throws,
                      "sync_throws": sy_throws,
                      "new_throws": new_throws,
                      "canary_ok": canary_ok}
            # The last condition pins the empty-message sync
            # result: an OK SyncInternal with a null state_.
            if (fl_throws, dio_throws, sy_throws, new_throws,
                    canary_ok) == EDGE_CONDITIONS[-1]:
                inputs["sync_result"] = _status(5, message="")
            rows.append(("edge", inputs["case_id"], inputs,
                         run_case(inputs)))
    assert len(rows) == 200, len(rows)
    # bindings: 25 (writer, use_fsync) pairs x 4 invariants.
    bind_pairs = []
    for seen_error in (False, True):
        for tracer, direct_io, pending_sync, flush_result, \
                sync_result, use_fsync in CHECK_COMBOS[:13]:
            bind_pairs.append((seen_error, pending_sync, tracer,
                               direct_io, use_fsync, flush_result,
                               sync_result))
    bind_pairs = bind_pairs[:25]
    invariants = ["body_sha256", "source_sha256", "fde_record",
                  "caller_census"]
    for seen_error, pending_sync, tracer, direct_io, use_fsync, \
            flush_result, sync_result in bind_pairs:
        for inv in invariants:
            inputs = {"case_id": f"bindings-{len(rows) - 200:04d}",
                      "group": "bindings", "invariant": inv,
                      "seen_error": seen_error,
                      "pending_sync": pending_sync,
                      "io_tracer": tracer,
                      "fs_tracer": {"target":
                                    {"use_direct_io": direct_io}},
                      "use_fsync": use_fsync,
                      "flush_result": flush_result,
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
    leg(len(body) == 494, "body length 494")
    leg(hashlib.sha256(body).hexdigest() == BODY_SHA256, "body hash")
    src = bytearray(body)
    for off, _kind in RELOCATIONS:
        src[off:off + 4] = b"\x00\x00\x00\x00"
    leg(hashlib.sha256(bytes(src)).hexdigest() == SOURCE_SHA256,
        "source hash (zero 11 census relocations)")
    cold = data[text_off + (COLD_START - text_va):
                text_off + (COLD_END - text_va)]
    leg(len(cold) == 87, "cold body length 87")
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
        "main LSDA: 3 call-site entries (pads 0x1d6/0x1e2)")
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
        f"116 main instructions verbatim ({len(insns)} decoded)")
    cold_insns = list(md.disasm(cold, COLD_START))
    got_cold = [(i.address, i.mnemonic, i.op_str)
                for i in cold_insns]
    leg(got_cold == INSTRUCTIONS_COLD,
        f"20 cold instructions verbatim ({len(cold_insns)} decoded)")
    calls = [i for i in insns if i.mnemonic == "call"]
    direct = [i for i in calls if i.op_str.startswith("0x")]
    leg(len(calls) == 8 and len(direct) == 7,
        f"8 calls in main: 7 direct + 1 indirect "
        f"({len(calls)} found)")
    leg([i for i in calls if i.op_str == "0x6051a20"] != [],
        "direct call to Flush 0x6051a20")
    leg([i for i in calls if i.op_str == "0x604c900"] != [],
        "direct call to SyncInternal 0x604c900")
    leg([i for i in calls if i.op_str == "0x63f0e30"] != [] and
        len([i for i in calls if i.op_str == "0x63f0e30"]) == 1,
        "1 operator new[] call (0x63f0e30)")
    leg([i for i in calls if i.op_str == "0x63f0dc0"] != [] and
        len([i for i in calls if i.op_str == "0x63f0dc0"]) == 3,
        "3 operator delete[] calls (0x63f0dc0)")
    leg([i for i in insns if i.mnemonic == "call" and
         i.op_str == "qword ptr [rax + 0x60]"] != [],
        "indirect call to vtable slot 12 (use_direct_io)")
    leg(sum(1 for i in insns if i.mnemonic == "ret") == 1, "1 ret")
    leg(all(START <= int(i.op_str, 16) < END
            for i in insns if i.mnemonic in ("je", "jne")
            and i.op_str.startswith("0x")),
        "all conditional jumps stay inside the main FDE")
    leg(sorted(int(i.op_str, 16) for i in insns
               if i.mnemonic == "jmp"
               and i.op_str.startswith("0x")
               and not (START <= int(i.op_str, 16) < END)) ==
        [COLD_START, 0x60527CC],
        "the only out-of-FDE jumps are the two LSDA stubs to .cold")
    # Message bytes: rebuild the 26-char message from the
    # .rodata chunks the binary copies with movdqa/movups.
    m2 = re.search(r"\.rodata\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)"
                   r"\s+([0-9a-f]+)", subprocess.check_output(
                       ["readelf", "-SW", str(BIN)]).decode())
    rva, roff, _rsize = (int(m2.group(i), 16) for i in (1, 2, 3))
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
        f"caller census: 11 direct calls, 0 jumps, 0 LEA refs "
        f"({len(sites)} validated)")
    # Model end-to-end legs.
    ok = True
    w = _writer(False, True, None, False)
    ok = ok and sync(
        w, False, flush_result=_ok_status(),
        sync_result=_ok_status())["status"] == _ok_status()
    ok = ok and sync(
        w, False, flush_result=_ok_status(),
        sync_result=_ok_status())["pending_sync"] is False
    ok = ok and sync(
        _writer(False, True, None, False), True,
        flush_result=_status(5, message="x"))["seen_error"] is True
    ok = ok and sync(
        _writer(False, True, None, False), True,
        flush_result=_status(5, message="x"))["status"]["sev"] == 0
    ok = ok and sync(
        _writer(True, True, None, False), False)["status"] == \
        _fresh_error(5, PREV_ERROR_MSG)
    ok = ok and sync(
        _writer(False, True, None, True), False,
        flush_result=_ok_status(),
        sync_result=_ok_status())["status"] == _ok_status()
    ok = ok and sync(
        _writer(False, True, None, True), False,
        flush_result=_ok_status(),
        sync_result=_status(5, message="x"))["sync_internal_called"] \
        is False
    ok = ok and sync(
        _writer(False, False, None, False), False,
        flush_result=_ok_status(),
        sync_result=_status(5, message="x"))["sync_internal_called"] \
        is False
    ok = ok and sync(
        _writer(False, True, {"tracing_enabled": True}, False), False,
        flush_result=_ok_status(),
        sync_result=_ok_status())["effective"] == "wrapper"
    ok = ok and sync(
        _writer(False, True, None, False), False,
        flush_result=_ok_status(),
        sync_result=_status(5, message="x", sev=2))["status"]["sev"] \
        == 0
    try:
        sync(_writer(False, True, None, False), False,
             flush_throws=True)
        ok = False
    except FlushThrew:
        pass
    try:
        sync(_writer(False, True, None, False), False,
             flush_result=_ok_status(),
             use_direct_io_throws=True)
        ok = False
    except UseDirectIoThrew:
        pass
    try:
        sync(_writer(False, True, None, False), False,
             flush_result=_ok_status(), sync_throws=True)
        ok = False
    except SyncInternalThrew:
        pass
    try:
        sync(_writer(True, True, None, False), False,
             new_throws="prev_error")
        ok = False
    except BadAlloc:
        pass
    try:
        sync(_writer(True, True, None, False), False,
             canary_ok=False)
        ok = False
    except StackCheckFailed:
        pass
    try:
        sync(_writer(False, True, None, False), False,
             flush_result=_ok_status(), sync_throws=True,
             canary_ok=False)
        ok = False
    except StackCheckFailed:
        pass
    leg(ok, "model end-to-end (prev-error / flush-fail / "
            "direct-io skip / pending_sync clear / ok / seen_error "
            "set / sev reset / wrapper-vs-target / throws / "
            "bad-alloc / bad-canary)")
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
    print("usage: sync115.py "
          "[--live | --write-cases | --verify-cases]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
