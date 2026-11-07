#!/usr/bin/env python3
"""Regenerate records.json for the RE-001-logger-vtable-full-map-115 packet.

Run from the repository root:
  python3 research/work-items/RE-001-logger-vtable-full-map-115/gen_records.py

The JSON holds semantic records only -- vtable slot -> function
bindings, object layouts, gate and delegation rules, literal records,
guard records and caller counts.  Instruction-level detail lives only
in the verbatim whole-function excerpts in excerpts/; there is no
per-instruction mnemonic list here.  Vtable slot values are read from
the binary's .rela.dyn entries (see census.py); literals are read from
.rodata.
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"

sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from census import (parse_rela_dyn, slot_value, read_rodata_str,  # noqa: E402
                    direct_callers_all, CALLER_TARGETS)

ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def vtable_slots(rela, vt, slots):
    out = {}
    for i in slots:
        out[str(i)] = slot_value(rela, vt + i * 8)
    return out


def main():
    data = BIN.read_bytes()
    rela = parse_rela_dyn(data)

    records = {
        "task": "RE-001",
        "work_item": "RE-001-logger-vtable-full-map-115",
        "artifact": {
            "node": 115,
            "file": "work/hl-node-115.bin",
            "sha256": ARTIFACT_SHA256,
        },
        "question": (
            "Pin, for node #115, the complete Logger and AutoRollLogger "
            "vtable maps: every slot's C++ name and body, the shared "
            "log-write path, the rollover path, and the object layouts "
            "the slots read and write."
        ),
        "resolves": (
            "#4315 open unknowns: Logger slots 4/6/7/10 and AutoRollLogger "
            "slots 3/4/6/7/9/10 named by header position or shape only; "
            "Logger slots 11+ tail unresolved; the +0x98/+0x130 size "
            "fields; the AutoRollLogger level-gate discrepancy (slot-5 "
            "gate reads the own +0x11 while slot 8 returns the wrapped "
            "logger's level)."
        ),
        "source_basis": (
            "RocksDB v8.1.1 headers (env.h, env_logger.h) for declaration "
            "order and the Logger/AutoRollLogger class shapes; every slot "
            "name below is additionally confirmed by the function body in "
            "the binary.  The binary's source line numbers differ from "
            "the v8.1.1 tag (see open_unknowns)."
        ),
        "logger": {
            "vtable_envlogger": "0x64cda68",
            "vtable_autoroll": "0x64d1f00",
            "typeinfo_envlogger": "N7rocksdb9EnvLoggerE",
            "typeinfo_autoroll": "N7rocksdb14AutoRollLoggerE",
            "typeinfo_logger_base": "N7rocksdb6LoggerE",
            "only_two_logger_classes": True,
            "note": "No PosixLogger vtable exists in the binary.",
            "slots_envlogger": {
                "0": {"fn": "0x5fcfb90", "name": "~EnvLogger (D0)",
                      "shape": "installs own vtable; if closed_ (+0x10) "
                               "is clear, closes first via the worker "
                               "0x5fce770, then tears down; ends with "
                               "operator delete"},
                "1": {"fn": "0x5fcfde0", "name": "~EnvLogger (D1)",
                      "shape": "same teardown as D0 without operator "
                               "delete"},
                "2": {"fn": "0x5fcc410", "name": "Close()",
                      "shape": "Status by value (sret); idempotent via "
                               "closed_ (+0x10); delegates to slot 10 "
                               "(CloseImpl) into the same sret",
                      "shared": "EnvLogger and AutoRollLogger"},
                "3": {"fn": "0x5fcc200", "name": "LogHeader(const char*, va_list)",
                      "shape": "forwards to slot 5 with level 1 "
                               "(INFO_LEVEL); AutoRollLogger overrides at "
                               "0x6057000 (rollover-aware, queues the "
                               "header)"},
                "4": {"fn": "0x5fce280", "name": "Logv(const char*, va_list)",
                      "shape": "formats the timestamped line, locks the "
                               "mutex at +0x108, appends via the writer at "
                               "+0x28, refreshes the cached file size at "
                               "+0x98/+0x130; AutoRollLogger overrides at "
                               "0x6058770"},
                "5": {"fn": "0x5fcd400", "name": "Logv(InfoLogLevel, const char*, va_list)",
                      "shape": "gate: return iff level < log_level_ "
                               "(+0x11); else jump to the core 0x5fcd2c0, "
                               "which routes level 5 (HEADER) through slot "
                               "3 and other levels through the formatter",
                      "shared": "EnvLogger and AutoRollLogger"},
                "6": {"fn": "0x5fcced0", "name": "GetLogFileSize() const",
                      "shape": "locks the mutex at +0x108, returns the "
                               "cached size at +0x98, unlocks; "
                               "AutoRollLogger overrides at 0x6057590"},
                "7": {"fn": "0x5fce130", "name": "Flush()",
                      "shape": "locks the mutex at +0x108; if the dirty "
                               "flag at +0x138 is set, clears it and calls "
                               "the writer Flush/Sync 0x6051a20; refreshes "
                               "+0x130 from the file slot 0x98; "
                               "AutoRollLogger overrides at 0x6057440"},
                "8": {"fn": "0x5fcc220", "name": "GetInfoLogLevel() const",
                      "shape": "movzbl 0x11(%rdi),%eax; ret; returns the "
                               "own log_level_; AutoRollLogger overrides "
                               "at 0x60552e0 (delegates to the wrapped "
                               "logger when present)"},
                "9": {"fn": "0x5fcc230", "name": "SetInfoLogLevel(InfoLogLevel)",
                      "shape": "mov %sil,0x11(%rdi); ret; stores the "
                               "level at +0x11; AutoRollLogger overrides "
                               "at 0x6055280 (also forwards to the wrapped "
                               "logger)"},
                "10": {"fn": "0x5fceae0", "name": "CloseImpl()",
                       "shape": "forwards (out, this) to the worker "
                                "0x5fce770 and returns out; AutoRollLogger "
                                "overrides at 0x60551d0 (delegates to the "
                                "wrapped logger's Close, slot 2)"},
            },
            "slots_autoroll": {
                "0": {"fn": "0x60576b0", "name": "~AutoRollLogger (D0)",
                      "shape": "installs own vtable; if the wrapped "
                               "logger is non-null and closed_ is clear, "
                               "closes first, then tears down; ends with "
                               "operator delete"},
                "1": {"fn": "0x6057d00", "name": "~AutoRollLogger (D1)",
                      "shape": "calls D0, then operator delete of 0x290 "
                               "bytes"},
                "2": {"fn": "0x5fcc410", "name": "Close()",
                      "note": "shared with EnvLogger (same function)"},
                "3": {"fn": "0x6057000", "name": "LogHeader(const char*, va_list)",
                      "shape": "if the wrapped logger is null, returns; "
                               "formats the message, locks the mutex at "
                               "+0x268, appends a copy to the queued-header "
                               "list at +0xf0 (count at +0x100), forwards "
                               "to the wrapped logger's slot 4 (Logv), "
                               "unlocks"},
                "4": {"fn": "0x6058770", "name": "Logv(const char*, va_list)",
                      "shape": "if the wrapped logger is null, returns; "
                               "locks the mutex at +0x268; rolls (0x6058110) "
                               "when the time check 0x6057310 says so or "
                               "when log_max_size (+0xd8) is non-zero and "
                               "the wrapped size is >= +0xd8; re-logs the "
                               "queued headers (0x60572a0) after a roll; "
                               "then forwards to the wrapped logger's slot "
                               "4 with a refcounted copy of the wrapped "
                               "shared_ptr"},
                "5": {"fn": "0x5fcd400", "name": "Logv(InfoLogLevel, const char*, va_list)",
                      "note": "shared with EnvLogger; the gate reads the "
                              "AutoRollLogger's OWN +0x11, not the wrapped "
                              "logger's level"},
                "6": {"fn": "0x6057590", "name": "GetLogFileSize() const",
                      "shape": "if the wrapped logger is null, returns 0; "
                               "else copies the wrapped shared_ptr under "
                               "the mutex at +0x268, calls the wrapped "
                               "logger's slot 6, releases the copy"},
                "7": {"fn": "0x6057440", "name": "Flush()",
                      "shape": "same shared_ptr-copy pattern; if the "
                               "wrapped logger is non-null, calls the "
                               "wrapped logger's slot 7 (Flush)"},
                "8": {"fn": "0x60552e0", "name": "GetInfoLogLevel() const",
                      "shape": "locks the mutex at +0x268; if the wrapped "
                               "logger is non-null, returns the wrapped "
                               "logger's slot 8; else returns the own "
                               "+0x11.  This is the resolution of #4315's "
                               "level-gate discrepancy: slot 8 reports the "
                               "wrapped level, while the shared slot-5 gate "
                               "reads the own +0x11 -- the two can disagree "
                               "by design"},
                "9": {"fn": "0x6055280", "name": "SetInfoLogLevel(InfoLogLevel)",
                      "shape": "locks the mutex at +0x268; stores the "
                               "level at the own +0x11; if the wrapped "
                               "logger is non-null, forwards the same level "
                               "to the wrapped logger's slot 9; unlocks"},
                "10": {"fn": "0x60551d0", "name": "CloseImpl()",
                       "shape": "if the wrapped logger is null, out = OK "
                                "status (code 0); else calls the wrapped "
                                "logger's slot 2 (Close, NOT CloseImpl) "
                                "with (out, wrapped) and returns out"},
            },
            "vtable_slots_from_rela": {
                "EnvLogger": vtable_slots(rela, 0x64CDA68, range(0, 11)),
                "AutoRollLogger": vtable_slots(rela, 0x64D1F00, range(0, 11)),
            },
            "level_enum": {
                "0": "DEBUG_LEVEL",
                "1": "INFO_LEVEL",
                "2": "WARN_LEVEL",
                "3": "ERROR_LEVEL",
                "4": "FATAL_LEVEL",
                "5": "HEADER_LEVEL",
            },
            "level_gate": {
                "rule": "a message at level L is written iff L >= log_level_ (+0x11)",
                "header_forward_level": 1,
                "factory_default_level": 3,
                "factory_default_note": (
                    "the EnvLogger factory 0x5fd0de0 hardcodes the WORD "
                    "0x300 at EnvLogger+0x10: closed_ = 0, log_level_ = 3 "
                    "(ERROR_LEVEL).  The AutoRollLogger ctor instead takes "
                    "its level from a stack argument."
                ),
            },
            "envlogger_layout": {
                "object_size": "0x140 (inside a 0x150-byte "
                               "_Sp_counted_ptr_inplace<EnvLogger> control "
                               "block; EnvLogger at control+0x10)",
                "0x00": "vtable",
                "0x08": "u64, set to -1 by the factory (field identity open)",
                "0x10": "closed_ (byte)",
                "0x11": "log_level_ (byte)",
                "0x18": "Env* (thread id via slot 0x288)",
                "0x20": "file object pointer (size via slot 0x98)",
                "0x28": "writer object start AND std::string fname_ (SSO buffer at +0x38) -- the exact object boundary is an open unknown",
                "0x50": "shared_ptr control-block release site",
                "0x58": "pointer to a 0x70-byte heap object (type checked via D1 == 0x5dfdf90)",
                "0x70": "heap buffer (freed with _ZdaPv)",
                "0x98": "cached log file size (returned by GetLogFileSize under the mutex)",
                "0x108": "pthread_mutex_t (40 bytes)",
                "0x130": "last-refreshed file size",
                "0x138": "dirty / needs-flush flag (byte)",
                "0xd8": "vector<shared_ptr> (begin/end/cap at +0xd8/+0xe0/+0xe8)",
                "0xf0": "heap object deleted via D1 in the destructor",
            },
            "autoroll_layout": {
                "object_size": "0x290 (operator delete of 0x290 in D1)",
                "0x00": "vtable",
                "0x08": "u64, set to -1 by the ctor (field identity open)",
                "0x10": "closed_ (byte)",
                "0x11": "log_level_ (byte, own copy)",
                "0x18": "self-pointer (&this+0x28)",
                "0x20": "0",
                "0x28": "byte 0",
                "0x38": "std::string (fname part, SSO buffer at +0x48)",
                "0x58": "std::string (SSO buffer at +0x68)",
                "0x78": "std::string, empty (SSO buffer at +0x88)",
                "0x98": "shared_ptr member (16 bytes, role open)",
                "0xa8": "shared_ptr member (16 bytes, role open)",
                "0xb8": "shared_ptr<Logger> logger_ (wrapped logger; null until filled after construction)",
                "0xc8": "DWORD 0 + WORD 0 at +0xcc",
                "0xd0": "0",
                "0xd8": "log_max_size (u64; 0 = no size roll)",
                "0xe0": "time-to-roll (u64; 0 = no time roll)",
                "0xe8": "from a stack argument",
                "0xf0": "std::list<std::string> anchor of queued header lines (list node 0x30 bytes, string at node+0x10)",
                "0x100": "queued-header count (u64)",
                "0x108": "container initialized by 0x6057d70 (capacity 8, 0x40-byte buffer, 0x200-byte elements; exact type open)",
                "0x158": "FileOptions-like struct (copied from 0x452220)",
                "0x178": "0",
                "0x180": "byte 0",
                "0x184": "DWORD 4",
                "0x188": "byte 7",
                "0x190": "pointer = &this+0x1c0",
                "0x198": "1",
                "0x1a0": "0",
                "0x1a8": "0",
                "0x1b0": "DWORD 1.0f",
                "0x1b8": "0",
                "0x1c0": "0",
                "0x1c8": "WORD 0",
                "0x1d0": "std::string (ptr = &this+0x1e0)",
                "0x1d8": "0",
                "0x1e0": "byte 0",
                "0x1f8": "DWORD 0",
                "0x200": "list head (nodes 0x48 bytes, next at +0x10, string at +0x20/+0x30)",
                "0x208": "&this+0x1f8",
                "0x210": "&this+0x1f8",
                "0x218": "0",
                "0x220": "std::string (SSO buffer +0x230)",
                "0x228": "0",
                "0x230": "byte 0",
                "0x240": "std::string (SSO buffer +0x250)",
                "0x248": "0",
                "0x250": "byte 0",
                "0x268": "pthread_mutex_t (40 bytes)",
            },
            "logv_envlogger": {
                "fn": "0x5fce280",
                "perf_level": {
                    "values": "0=kDisable, 1=kEnableCount, "
                              "2=kEnableTimeExceptForMutex, 3=kEnableTime, "
                              "4=kEnableTimeAndCPUTime",
                    "timing_active": "perf_level > 2",
                    "start": "samples NowMicros via the default SystemClock singleton 0x5fe2680 slot 0xa0 when timing is active, else skips",
                    "during_write": "sets perf_level = 1 (suppresses nested perf timing) and the TLS byte at (fs:0-0x3f8)+0x98 = 1 for the duration of the write",
                    "accumulate": "adds (end - start) into the TLS u64 at (fs:0-0x3f8)+0x50 when perf_level > 2",
                },
                "timestamp_format": "%04d/%02d/%02d-%02d:%02d:%02d.%06d %llu ",
                "timestamp_format_addr": "0x968038",
                "timestamp_sources": "gettimeofday + localtime_r; thread id via Env slot 0x288 (Env::GetThreadID)",
                "stack_buffer": "0x1f4 bytes; a 0x10000-byte heap buffer is used via __vsnprintf_chk when the message does not fit",
                "trailing_newline": "a trailing \\n is ensured",
                "size_refresh": {
                    "threshold": "0x4c4b3f (4,999,999)",
                    "rule": "after the write, calls the file slot 0x98 (GetFileSize); iff (size - [+0x130]) > 0x4c4b3f, refreshes [+0x130] = current size; if the dirty flag +0x138 was set, it is cleared and the writer Flush/Sync 0x6051a20 is called first",
                },
                "dirty_flag": "set to 1 (xchg) after each append; cleared by Flush",
                "write_call": "writer Append 0x6054680 (out Status, writer@+0x28, Slice{buf,len}, 0, 4)",
            },
            "flush_envlogger": {
                "fn": "0x5fce130",
                "shape": "saves perf_level, sets it to 1, sets the TLS byte +0x98 = 1, locks the mutex at +0x108, calls the no-op stub 0x60d5390; if +0x138 != 0 clears it and calls 0x6051a20 (out, writer@+0x28, 4); then refreshes [+0x130] = GetFileSize via slot 0x98; unlocks, restores perf_level, clears the TLS byte",
                "note": "Flush does NOT do the perf-timing accumulation Logv does",
            },
            "close_impl": {
                "fn": "0x5fceae0",
                "worker": "0x5fce770",
                "worker_shape": "locks the mutex at +0x108, sets the TLS byte +0x98 = 1, sets perf_level = 1, calls the writer Close 0x6052b80 (out, writer@+0x28); on writer-Close OK builds an OK status in out; else builds kIOError (code 5) via the Status ctor 0x61cf670 with message 'Close of log file failed with error:' (0x966d00, 36 chars) + the writer's error string; unlocks, restores perf_level, clears the TLS byte",
            },
            "writer_contract": {
                "methods": {
                    "append": "0x6054680",
                    "flush_sync": "0x6051a20",
                    "close": "0x6052b80",
                },
                "signature": "(out 16-byte IOStatus-style value, writer@logger+0x28, ...)",
                "previous_error": {
                    "flag": "writer byte +0x89",
                    "rule": "if +0x89 != 0, Append returns kIOError (code 5) with message 'Writer has previous error.' (26 chars: 16 bytes from 0x451480 'Writer has previ' + 16 bytes from 0x452bf0 ' previous error.')",
                },
                "buffer": "std::string buffer at writer+0x50/+0x58/+0x68 with doubling growth; writes via the file slot 0xc0 after a type check vs GOT 0x64ecf30 (= 0x5df6e90)",
                "note": "generic WritableFileWriter methods with ~35/~12/~25 direct call sites binary-wide, NOT logger-specific; their full internal buffer/layout dissection is an open unknown",
            },
            "rollover": {
                "size_gate": "log_max_size (+0xd8) != 0 and the wrapped logger's GetLogFileSize >= +0xd8",
                "time_gate": "time-to-roll (+0xe0) != 0 and the time check 0x6057310 returns nonzero",
                "roll_fn": "0x6058110",
                "roll_shape": "reads [this+0xa8] (a shared_ptr), walks +0x20-linked objects doing slot-0x98 type checks vs the function 0x5d4d490 (compiler-unrolled GetFileSize devirtualization guard chain), then builds new filename strings from +0x38/+0x58/+0x78 (fname parts); the full roll mechanics (close old file, rename, open new) are an open unknown beyond the characterized head",
                "relog_after_roll": "0x60572a0 re-logs the queued headers into the new file",
                "filename_helpers": ["0x6056790", "0x6056ba0"],
                "format_helper": "0x6056e50",
            },
            "construction": {
                "factory": {
                    "fn": "0x5fd0de0",
                    "shape": "allocates a 0x150-byte _Sp_counted_ptr_inplace<EnvLogger> control block via operator new(0x150); installs the control-block vtable 0x64cdf00 at +0x0 and the EnvLogger vtable at +0x10; sets the counts from the qword at 0x459b20, [control+0x18] = -1, WORD [control+0x20] = 0x300 (closed_ = 0, log_level_ = 3); calls the helper 0x5fcf8c0 first (builds DBOptions on the stack via the default ctor 0x60b2db0, copies 8 fields out); opens the file via Env slot 0xb8 (NewWritableFile) with a stack FileOptions (writable_file_max_buffer_size 0x100000, bytes_per_sync 0x400000000, 7, 1, 1.0f); fname handling via find_last_of; stores factory arg3 (rdx) at EnvLogger+0x18 and [arg3+0x38] at EnvLogger+0x20",
                },
                "autoroll_ctor": {
                    "fn": "0x605a210",
                    "shape": "installs the vtable, initializes the fields above; calls 0x6057d70 (this+0x108); then a chain of GetFileSize slot-0x98 type checks (comparing vtable slot 0x98 vs GOT 0x64ecf80) walking +0x20-linked objects (compiler-unrolled loop, exact purpose open); computes a double from the file size (unsigned->double, times the constant at 0x459130, compare vs 0x459360) -- likely the initial roll-time computation; initializes the +0x158 FileOptions struct and the +0x190/+0x1d0/+0x200 lists/strings",
                },
                "sharedptr_dispose": {
                    "fn": "0x5fcf660",
                    "shape": "for _Sp_counted_ptr_inplace<EnvLogger>; verifies the embedded object's slot-0 == EnvLogger D0 (compares [vtable] vs GOT 0x64ed970 = 0x5fcfb90), installs the EnvLogger vtable at +0x10, if closed_ == 0 closes first via the worker 0x5fce770, then the same teardown at +0x10-shifted offsets, tail-jumps to the no-op 0x5fcc400 (the empty base Logger::~Logger())",
                },
            },
            "tls_perf_context": {
                "init": "0x606d9f0 (once-per-thread: if the byte at fs:0-0x400 is 0, sets it to 1 and zeroes (fs:0-0x3f8)+0x98)",
                "set_1_sites": ["0x5fce191 (Flush)", "0x5fce48a (Logv)", "0x5fce7e0 (CloseImpl worker)"],
                "set_0_sites": ["0x5fce11a", "0x5fce1fa", "0x5fce554", "0x5fce903", "0x606da24 (init)"],
                "readers": "28 cmp sites of [rax+0x98] binary-wide (0x5e8e879, 0x6043294, 0x604359a, 0x60435df, 0x60436c2, 0x6043707, 0x604378a, 0x60437cf, 0x6044535, 0x6044fef, 0x604503e, 0x604535f, 0x60453ae, 0x6045437, 0x6045486, 0x60479ea, 0x6047a94, 0x6047ae3, 0x6047cbf, 0x6047d0e, 0x6047d9f, 0x6047dee, 0x6048ede, 0x604e786, 0x604f618, 0x60507aa, 0x60513ad, 0x60d4e51)",
                "open": "the +0x98 byte's exact field name is an open unknown (a per-thread byte in the perf-context TLS block, set for the duration of log writes)",
            },
            "destructor_teardown": {
                "shape": "mutex destroy 0x60d5170 at +0x108; writer Close 0x6052b80 (+0x28); free [rsp+0x8]; D1 call on the object at +0xf0; vector<shared_ptr> teardown loop at +0xd8/+0xe0 (shared_ptr dispose 0x5d35070, control release 0x5d350c0); _ZdaPv on the buffer at +0x70; teardown of the 0x70-byte object at +0x58 (type check D1 vs GOT 0x64ecf88 = 0x5dfdf90; installs vtables 0x64d0b58+0x10 / 0x64ca720+0x10; string _M_dispose at +0x50; 0x5d350c0 on +0x40; D1 on +0x30; _ZdlPvm(obj, 0x70)); 0x5d350c0 on [logger+0x50]; std::string dispose on fname_ (+0x28/+0x38 SSO check); tail-jump to the no-op 0x5fcc400",
                "d1_differs": "D1 differs from D0 only in that D0 ends with operator delete (D1 returns without it)",
                "autoroll_teardown": "destroy the mutex at +0x268; destroy the strings at +0x240/+0x220; destroy the list at +0x200 (0x48-byte nodes, 0x6055350 on [node+0x18], string at [node+0x20]/[node+0x30], _ZdlPvm(node, 0x48), follow [node+0x10]); destroy the string at +0x1d0; destroy the list at +0x1a0 (nodes with a string at +0x28/+0x38)",
            },
            "literals": {
                "timestamp_format": {
                    "addr": "0x968038",
                    "text": read_rodata_str(data, 0x968038),
                },
                "writer_error_part_1": {
                    "addr": "0x451480",
                    "text": read_rodata_str(data, 0x451480, 16),
                },
                "writer_error_part_2": {
                    "addr": "0x452bf0",
                    "text": read_rodata_str(data, 0x452BF0, 16),
                },
                "writer_error_full": "Writer has previous error.",
                "close_error": {
                    "addr": "0x966d00",
                    "text": read_rodata_str(data, 0x966D00),
                },
                "typeinfo_envlogger": {
                    "addr": "0x972160",
                    "text": read_rodata_str(data, 0x972160),
                },
                "typeinfo_autoroll": {
                    "addr": "0x974e10",
                    "text": read_rodata_str(data, 0x974E10),
                },
                "empty_string_addr": "0x4376fd",
            },
            "guards": [
                {
                    "guard": "shared_ptr dispose checks EnvLogger D0",
                    "cmp_addr": "0x5fcf689",
                    "got_slot": "0x64ed970",
                    "got_addend": slot_value(rela, 0x64ED970),
                    "expected": "0x5fcfb90",
                },
                {
                    "guard": "AutoRollLogger ctor checks GetFileSize slot",
                    "cmp_addr": "0x605a487",
                    "got_slot": "0x64ecf80",
                    "got_addend": slot_value(rela, 0x64ECF80),
                    "expected": "0x5d4d490",
                },
                {
                    "guard": "roll path checks GetFileSize slot",
                    "cmp_addr": "0x6058153",
                    "got_slot": None,
                    "compared_fn": "0x5d4d490 (lea at 0x605814c)",
                    "expected": "0x5d4d490",
                },
            ],
            "caller_counts": {
                f"{target:#x}": len(sites)
                for target, sites in direct_callers_all(
                    data, [t for t, _n in CALLER_TARGETS]).items()
            },
            "vtable_tail_raw": {
                "EnvLogger": {
                    str(i): slot_value(rela, 0x64CDA68 + i * 8)
                    for i in range(11, 17)
                },
                "AutoRollLogger": {
                    str(i): slot_value(rela, 0x64D1F00 + i * 8)
                    for i in range(11, 17)
                },
            },
        },
        "open_unknowns": [
            "Logger+0x28: the writer object starting at +0x28 vs the fname_ std::string also at +0x28 (callees address it as writer@+0x28; D0 disposes a string at +0x28/+0x38) -- the exact object boundary/layout needs the writer's own dissection; the writer's internal field layout (buffer +0x50/+0x58/+0x68, flags +0x88/+0x89) is only partially pinned.",
            "Identity of the object at Logger+0xf0 (D1-deleted in the destructor) and of the 0x70-byte object at +0x58; the factory arg3 type and [arg3+0x38] -> Logger+0x20.",
            "TLS perf-context byte at +0x98 and u64 counter at +0x50: exact field names (the timing counter is the log-write-time metric, gated on perf_level > 2 -- the name is not verified from the binary).",
            "EnvLogger+0x08 (-1) and AutoRollLogger+0x08 (-1) field identities; AutoRollLogger +0x98/+0xa8 shared_ptr members' roles; the +0x108 container's exact type; the +0x190/+0x1d0/+0x200 list/string members' roles; the roll 0x6058110 full mechanics (rename/open sequence) beyond the characterized head.",
            "Logger vtable slots 11+ tail (EnvLogger slots 11/13/14 have no relocation and read as zero; slot 12 points at data 0x64cd8d0; the tail holds the shared Configurable GetOption/AreEquivalent 0x609d760/0x609dc40 at 0x78/0x80; the AutoRollLogger tail holds 0x6055240 bare ret, 0x6055260/0x6055270 deleting dtors for 0x18-byte objects, 0x6057d20 dtor-shaped calling D0) -- unresolved whether Logger carries additional virtuals past CloseImpl.",
            "The two ColumnFamilyData ctor callers 0x5d96cf8 / 0x5d972ab C++ names (from #4315, still open).",
        ],
    }

    (HERE / "records.json").write_text(
        json.dumps(records, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote records.json ({len(json.dumps(records))} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
