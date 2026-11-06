"""Generate records.json for RE-001-optiontypeinfo-systemclock-115.

Run from the repository root:
    python3 research/work-items/RE-001-optiontypeinfo-systemclock-115/gen_records.py

Merges the hand-derived semantic records below with the live caller
census (census.py) so the census block in records.json is always a
fresh reproduction of the binary. The semantic records are the
packet's claims; verify.py re-checks them against the excerpts,
the relocations and the model. The per-site containing FDE is
derived from objdump --dwarf=frames (same helper as the neighbouring
RE packets).
"""

import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")
sys.path.insert(0, HERE)
import census as census_mod

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

SEMANTIC = {
    "task_id": "RE-001",
    "bounded_question": (
        "How does node #115 build the OptionTypeInfo record for a "
        "custom shared_ptr SystemClock option, and how do the record's "
        "two create hooks resolve that option by name?"
    ),
    "artifact": "artifacts/node/115/hl-node",
    "artifact_sha256": DIGEST,
    "node": 115,
    "objdump": "GNU objdump (GNU Binutils for Ubuntu) 2.42",
    "builder": {
        "address": "0x5fd0180",
        "fde": "0x5fd0180..0x5fd02f2",
        "bytes": 370,
        "symbol": (
            "rocksdb::OptionTypeInfo::AsCustomSharedPtr<rocksdb::SystemClock>"
            "(int, OptionVerificationType, OptionTypeFlags)"
        ),
        "args": {
            "out": "rdi",
            "offset": "esi",
            "verification": "edx",
            "flags": "ecx",
        },
        "record_size": "0xb8",
        "fields": [
            {"offset": "+0x00", "name": "offset", "source": "esi (int)"},
            {"offset": "+0x04", "name": "padding",
             "note": "never written by the builder or by the copy helper; "
                     "its content is indeterminate"},
            {"offset": "+0x08..+0x18", "name": "reserved", "value": 0},
            {"offset": "+0x18", "name": "create_hook_manager",
             "value": "0x5fcc660", "via": "GOT slot 0x64ed8d0 (RELATIVE)"},
            {"offset": "+0x20", "name": "create_hook_invoker",
             "value": "0x5fd4c30", "via": "GOT slot 0x64ed958 (RELATIVE)"},
            {"offset": "+0x28..+0xa8", "name": "reserved", "value": 0},
            {"offset": "+0xa8", "name": "type", "value": 22,
             "note": "the custom-shared-ptr kind this builder writes"},
            {"offset": "+0xac", "name": "verification", "source": "edx"},
            {"offset": "+0xb0", "name": "flags", "source": "ecx"},
        ],
        "stack_temp": (
            "The builder first fills an identical 0xb8-byte record as "
            "a stack temporary at rsp+0x20 (offset at temp+0x00, hooks "
            "at temp+0x18, type 22 at temp+0xa8, verification at "
            "temp+0xac, flags at temp+0xb0) and then installs it into "
            "out with the record-copy helper 0x5e332c0 (site 0x5fd0266, "
            "args (out, temp)). The hook pair is also staged at "
            "rsp+0x10 (temp-0x10) as the temporary's std::function "
            "object, whose manager the builder destroys after the "
            "copy."
        ),
        "temp_cleanup": {
            "manager_destroy": {
                "site": "0x5fd0280",
                "target": "0x5fcc660",
                "args": "(rsp, rsp, op 3)",
                "effect": (
                    "No-op: op 3 is destroy_functor and the lambda "
                    "captures nothing, so the manager returns 0 without "
                    "touching memory. Skipped when the manager pointer "
                    "at rsp+0x10 is null."
                ),
            },
            "record_dtor": {
                "site": "0x5fd0285",
                "target": "0x5d3f950",
                "args": "(temp)",
                "effect": (
                    "No-op for the freshly built record: the destructor "
                    "destroys the functor members at record+0x58/+0x78/"
                    "+0x98 via their managers with op 3 when non-null, "
                    "and all three are zero here. Cited by contract "
                    "(FDE 0x5d3f950..0x5d3f9d3); not excerpted."
                ),
            },
        },
        "returns": "rax = out",
    },
    "copy_helper": {
        "address": "0x5e332c0",
        "fde": "0x5e332c0..0x5e3354f",
        "bytes": 655,
        "role": (
            "OptionTypeInfo copy-assignment: copies a 0xb8-byte record "
            "from rsi into rdi. The record holds five std::function "
            "members at +0x08/+0x28/+0x48/+0x68/+0x88 (each 0x20 bytes: "
            "functor storage at +0x00, manager at +0x10, invoker at "
            "+0x18)."
        ),
        "args": {"out": "rdi", "src": "rsi"},
        "steps": [
            "Copy the 4-byte offset at +0x00; zero out+0x08..+0x18 and "
            "out+0x18/+0x20.",
            "For each of the five members (in order +0x08, +0x28, "
            "+0x48, +0x68, +0x88): zero the member in out; when the "
            "source member's manager (at member+0x10) is non-null, "
            "call manager(out+member, src+member, op 2 = clone_functor) "
            "and then copy the manager+invoker pair (16 bytes) from the "
            "source member.",
            "Copy the 8 bytes at +0xa8 (type + verification) and the 4 "
            "bytes at +0xb0 (flags) verbatim.",
        ],
        "landing_pads": (
            "The five endbr64 stubs at 0x5e33438..0x5e3354d each save "
            "%rax and destroy the already-copied members in reverse "
            "order via their managers with op 3, then resume unwinding "
            "via _Unwind_Resume; not decoded beyond that shape."
        ),
        "note": (
            "Shared by every OptionTypeInfo installer in the binary "
            "(85 direct call sites, including the SliceTransform "
            "sibling builder's site 0x6083b76). The Statistics sibling "
            "builder 0x6071520 (open PR #3685) does NOT call it: it "
            "copies field-wise and calls the manager directly instead. "
            "For this builder only the first member is non-empty (the "
            "create hooks); the other four members are all zero, so "
            "their clones are skipped."
        ),
    },
    "manager": {
        "address": "0x5fcc660",
        "fde": "0x5fcc660..0x5fcc68d",
        "bytes": 45,
        "role": (
            "std::function manager (_Function_handler manager) for the "
            "AsCustomSharedPtr<SystemClock> lambda. Reached only "
            "through the GOT slot 0x64ed8d0 and the copy helper's "
            "indirect manager call; it has no direct call site."
        ),
        "args": {
            "out": "rdi",
            "functor_storage": "rsi",
            "op": "edx",
        },
        "ops": [
            {"op": 0, "name": "get_type_info",
             "effect": (
                 "*(out) = 0x64cda00, the address of the lambda "
                 "typeinfo object (vtable "
                 "__cxxabiv1::__class_type_info + 0x10, name string at "
                 "0x972460)")},
            {"op": 1, "name": "get_functor_ptr",
             "effect": "*(out) = *(functor_storage)"},
            {"op": 2, "name": "clone_functor",
             "effect": "no-op, returns 0 (empty lambda: nothing to copy)"},
            {"op": 3, "name": "destroy_functor",
             "effect": "no-op, returns 0 (empty lambda: nothing to free)"},
            {"op": "other",
             "effect": "no-op, returns 0"},
        ],
        "returns": "0 (eax) in every path",
    },
    "invoker": {
        "address": "0x5fd4c30",
        "fde": "0x5fd4c30..0x5fd4cc1",
        "bytes": 145,
        "role": (
            "std::function _M_invoke for the AsCustomSharedPtr<SystemClock> "
            "lambda: Status (const ConfigOptions&, const std::string&, "
            "const std::string&, void*), returned through a hidden "
            "sret pointer in rdi. Reached only through the GOT slot "
            "0x64ed958; it has no direct call site."
        ),
        "args": {
            "sret_status": "rdi (also returned in rax)",
            "functor": "rsi (discarded: the lambda is empty)",
            "config_options": "rdx (passed to the create host as its 2nd arg)",
            "id_string": "rcx (std::string: data at +0x00, length at +0x08)",
            "name_string": "r8 (std::string: data at +0x00, length at +0x08)",
            "dest_slot": "r9 (pointer to the destination shared_ptr slot)",
        },
        "id_fast_path": {
            "condition": (
                "id_string length == 2 and its first two bytes are "
                "'id' (word 0x6469) and name_string length == 0"
            ),
            "effect": (
                "Release the shared_ptr at *(dest_slot): zero the "
                "16-byte slot, then call _M_release 0x5d350c0 (site "
                "0x5fd4ca1) on the old control block when non-null "
                "(the packed use/weak fast path and the use-count "
                "decrement live inside _M_release itself, pinned by "
                "open PR #3674 — unlike the Statistics invoker, this "
                "invoker does not inline them). Then write an empty "
                "Status (code 0, subcode 0, state null) to out and "
                "return out."
            ),
        },
        "forward_path": {
            "condition": "otherwise",
            "call": {
                "site": "0x5fd4c60",
                "target": "0x5fd46c0",
                "args": "(out, config_options, name_string, *(dest_slot))",
            },
            "effect": "returns out (the host fills it)",
        },
    },
    "create_host": {
        "address": "0x5fd46c0",
        "fde": "0x5fd46c0..0x5fd4c2e",
        "bytes": 1390,
        "role": (
            "Create-by-name host for the SystemClock option: resolves "
            "the name against the current clock, adopting it when it "
            "matches, and otherwise creates the default clock through "
            "the registry translator. Pinned here for the first time."
        ),
        "args": {
            "out": "rdi",
            "config_options": "rsi",
            "name_string": "rdx",
            "dest_slot": "rcx (pointer to the 16-byte shared_ptr storage)",
        },
        "current_clock": {
            "accessor": "0x5fe2680 (site 0x5fd46f4)",
            "load": (
                "r15 = *(control+0x00) = the clock object (object+0x10 "
                "of the combined allocation); rbp = *(control+0x08) = "
                "the control block (the allocation base)."
            ),
            "use_count_bump": (
                "The use count at control+0x08 is bumped by 1: lock "
                "addl when the global byte at 0x64ed290 is 0, plain "
                "addl otherwise (sites 0x5fd4715 / 0x5fd4978)."
            ),
        },
        "name_dispatch": [
            {
                "step": "slot 0x80 predicate",
                "detail": (
                    "Read vtable slot 0x80 of the current clock's table "
                    "(0x64ce930) and compare it with the global at "
                    "0x64eceb8 (RELATIVE -> 0x5d2e770, the default "
                    "implementation, FDE 0x5d2e770..0x5d2e832). When "
                    "they differ, call slot 0x80 (current, name); a "
                    "false result goes to the default path. When they "
                    "are equal, the predicate is skipped and the host "
                    "does the same matching inline (steps below). The "
                    "default predicate itself is verified by reading "
                    "its body: it returns false for an empty input "
                    "name; otherwise it returns true when the input "
                    "equals the slot-0x70 name (strlen + memcmp) or, "
                    "failing that, the slot-0x90 name (null -> false; "
                    "strlen + memcmp); otherwise false."
                ),
            },
            {
                "step": "empty name",
                "detail": (
                    "When name_string length is 0, go to the default path."
                ),
            },
            {
                "step": "slot 0x70 name",
                "detail": (
                    "Call vtable slot 0x70 (current) for its name string; "
                    "when strlen(name) == name_string length and memcmp "
                    "is 0, adopt the current clock. Otherwise fall "
                    "through to the slot 0x90 check."
                ),
            },
            {
                "step": "slot 0x90 name",
                "detail": (
                    "Read vtable slot 0x90 and compare it with the "
                    "global at 0x64eceb0 (RELATIVE -> 0x5d2ca10, the "
                    "default implementation, FDE 0x5d2ca10..0x5d2ca1c: "
                    "7 bytes, lea of the empty string at 0x4376fd and "
                    "ret — the default second name is empty). When "
                    "they are equal, go to the default path. When they "
                    "differ, call slot 0x90 (current) for a second name "
                    "string; when it is non-null and strlen(name) == "
                    "name_string length and memcmp is 0, adopt the "
                    "current clock; otherwise go to the default path."
                ),
            },
        ],
        "adopt_path": {
            "site": "0x5fd4998",
            "effect": (
                "Install the current clock into *dest_slot: write the "
                "object pointer at dest+0x00 and the control block at "
                "dest+0x08; when the old control differs from the new "
                "one, bump the new control's use count (same 0x64ed290 "
                "selector rule) and release the old control via "
                "_M_release 0x5d350c0 (site 0x5fd49c3). Then write an "
                "empty Status to out."
            ),
        },
        "default_path": {
            "site": "0x5fd4783",
            "once_init": (
                "pthread_once with the once control at 0x6504b68, the "
                "initializer 0x5fd20d0 (passed by lea at 0x5fd47c1) and "
                "the TLS slots 0x64ed818/0x64ed820/0x64ed828; on "
                "pthread_once failure the host throws a system error "
                "(site 0x5fd4beb)."
            ),
            "translator": (
                "Call the registry translator 0x609e510 (site 0x5fd489a; "
                "by contract, open PR #3440) with a stack-built options "
                "struct (Status out at rsp+0x20, config_options, "
                "*dest_slot object, name_string, translated-name string "
                "at rsp+0x90, once-arg at rsp+0x50). The translator "
                "writes a Status at rsp+0x20, the translated name into "
                "the string at rsp+0x90 (length at rsp+0x98) and an "
                "error out-param at rsp+0x68."
            ),
            "outcomes": [
                {
                    "condition": "translator Status code != 0",
                    "effect": (
                        "out = move(translator Status) via the Status "
                        "move helper 0x5fcdf70 (site 0x5fd48c6)."
                    ),
                },
                {
                    "condition": (
                        "translator Status code == 0 and the translated "
                        "name is non-empty"
                    ),
                    "effect": (
                        "Call the name-to-clock factory helper 0x5fd4080 "
                        "(site 0x5fd4aa3; by contract, FDE "
                        "0x5fd4080..0x5fd4627) with (Status out at "
                        "rsp+0x40, config_options+0x40, the translated "
                        "name string, dest_slot), then normalize the "
                        "resulting Status (see status_normalization) and "
                        "move it to out."
                    ),
                },
                {
                    "condition": (
                        "translator Status code == 0, translated name "
                        "empty, error out-param (rsp+0x68) non-null"
                    ),
                    "effect": (
                        "Build an error Status via the Status builder "
                        "0x61cf670 (site 0x5fd4bc9; by contract, open PR "
                        "#3440) with code 3 and the message at 0x433f9f "
                        "(\"Cannot reset object \") plus the name at "
                        "0x4376fd, then move it to out."
                    ),
                },
                {
                    "condition": (
                        "translator Status code == 0, translated name "
                        "empty, error out-param null"
                    ),
                    "effect": (
                        "Release *dest_slot (zero the 16-byte slot, "
                        "_M_release the old control via site 0x5fd4955) "
                        "and write an empty Status to out."
                    ),
                },
            ],
        },
        "status_normalization": {
            "input": "the factory helper's Status, moved to rsp+0x30",
            "rules": [
                "code == 3 (NotSupported, per RocksDB's Status code "
                "table — inference) and config_options+1 != 0: reset "
                "the intermediate Status to empty; out = empty.",
                "code == 0: call the second translator 0x609e2d0 (site "
                "0x5fd4b76; by contract) with (rsp+0x40, "
                "config_options, *dest_slot object, current clock), "
                "then move the Status at rsp+0x40 to rsp+0x30 and out.",
                "any other code: out = the factory Status unchanged.",
            ],
            "note": (
                "The config_options+1 byte's meaning and the 0x609e2d0 "
                "contract are open; only the branch structure is pinned."
            ),
        },
        "cleanup": {
            "site": "0x5fd48cb",
            "effect": (
                "Free the array at rsp+0x28 (operator delete[] when "
                "non-null); call the once-arg cleanup helper 0x5d36110 "
                "(site 0x5fd48dd; by contract, FDE "
                "0x5d36110..0x5d361d5) on rsp+0x50; dispose the "
                "translated-name string via _M_dispose (site "
                "0x5fd48e7); release the local current-clock reference "
                "via _M_release 0x5d350c0 when non-null (site "
                "0x5fd48f4); stack-canary check; return out."
            ),
        },
        "returns": "rax = out",
    },
    "accessor": {
        "address": "0x5fe2680",
        "fde": "0x5fe2680..0x5fe2756",
        "bytes": 214,
        "role": (
            "Function-local-static accessor for the current SystemClock "
            "shared_ptr (guard byte at 0x6504c98, static at 0x6504ca0). "
            "Called from ~190 sites across the node; only the create "
            "host's use is pinned in detail here."
        ),
        "fast_path": (
            "When the guard byte is set, return the static's value "
            "(the control-block pointer)."
        ),
        "slow_path": [
            "__cxa_guard_acquire on the guard; when another thread is "
            "initializing, return the static's value.",
            "Allocate the 0x10-byte control block (operator new) and "
            "the 0x30-byte combined allocation (operator new).",
            "Combined allocation layout: control block at +0x00..+0x10 "
            "(table 0x64ced00, packed counts qword 0x100000001 at "
            "+0x08, copied from the global at 0x459b20) and the "
            "PosixClock object at +0x10..+0x30 (table 0x64ce930 at "
            "+0x00, zeroes at +0x08/+0x10/+0x18).",
            "Control block at +0x00: object+0x10; at +0x08: the "
            "allocation base. Store the control block in the static "
            "at 0x6504ca0; __cxa_guard_release; return the control "
            "block.",
        ],
        "clock_identity": (
            "The object table 0x64ce930 resolves (via the RELATIVE "
            "record at 0x64ce928) to the typeinfo at 0x64ce870, whose "
            "name string at 0x972c00 is "
            "rocksdb::(anonymous)::PosixClock; the control table "
            "0x64ced00 resolves (via the RELATIVE record at 0x64cecf8) "
            "to the typeinfo at 0x64ce8b8, "
            "std::_Sp_counted_ptr_inplace<PosixClock, ...>. The "
            "packed counts 0x100000001 mean use 1, weak 1. The "
            "vtable-header cells in this binary carry the typeinfo "
            "pointer at base-0x08 (verified on five vtables: "
            "StatisticsImpl, HistogramImpl, SystemClockWrapper, "
            "PosixClock, _Sp_counted_ptr_inplace<PosixClock>); slot "
            "numbers in this packet are relative to the stored table "
            "base, as the code reads them."
        ),
        "control_vtable_slots": (
            "Read at the stored control-table base 0x64ced00: slot "
            "+0x10 is _M_dispose 0x5fe1860, slot +0x18 is _M_destroy "
            "0x5fe1590 (operator delete, size 0x30), slot +0x20 is "
            "_M_get_deleter 0x5fe15a0 — the slots _M_release calls."
        ),
    },
    "default_init": {
        "address": "0x5fd20d0",
        "fde": "0x5fd20d0..0x5fd241d",
        "bytes": 333,
        "role": (
            "pthread_once initializer for the default SystemClock "
            "registry entry (the routine the create host passes to "
            "pthread_once by lea at 0x5fd47c1). It has no direct call "
            "site; it is reached only through pthread_once."
        ),
        "steps": [
            "Build a stack string via the string helper 0x5fcd890 (by "
            "contract) from the literal \"TimeEmulatedSystemClock\" "
            "at 0x4372ae.",
            "Fetch the registry mutex via 0x61f8b60 (by contract; "
            "returns the mutex pointer, saved to r12).",
            "Build a second stack object at rsp+0x60 via 0x5fcd890 "
            "with the table references 0x5fcd550 / 0x5fcc630 (by "
            "contract).",
            "Allocate the 0x30-byte registry entry (operator new) and "
            "the 0x70-byte clock object (operator new, table "
            "0x64d8ec0+0x10, byte +0x48 = 1); link the entry to the "
            "clock object.",
            "Lock the registry mutex; insert the entry into the "
            "mutex-guarded registry under the name \"SystemClock\" "
            "(literal at 0x438369) via the registry helper 0x5fd1da0 "
            "(site 0x5fd22b4; by contract); unlock; dispose the "
            "temporaries.",
        ],
        "note": (
            "The registry structure and the 0x5fcd890 / 0x61f8b60 / "
            "0x5fcd6f0 / 0x5fd1da0 / 0x61f8700 contracts are open; only "
            "the allocation sizes, the table pointers, the two name "
            "literals and the lock/insert/unlock shape are pinned. "
            "pthread_mutex_lock failure throws a system error; the "
            "landing pads are shared rethrow blocks (not decoded)."
        ),
    },
    "status_move": {
        "address": "0x5fcdf70",
        "fde": "0x5fcdf70..0x5fcdfdf",
        "bytes": 111,
        "role": (
            "rocksdb::Status move-assignment (dst = std::move(src)). "
            "A shared helper (17 direct call sites); the create host "
            "uses it four times."
        ),
        "args": {"dst": "rdi", "src": "rsi"},
        "steps": [
            "When dst == src, return dst at once.",
            "Copy bytes 0..5 from src to dst; zero src bytes 1..5 "
            "(src byte 0, the code, is left intact).",
            "Move the state qword at +0x08 from src to dst, freeing "
            "dst's old state via operator delete[] when non-null; "
            "src state becomes null.",
            "Return dst.",
        ],
        "note": (
            "The 0x10-byte Status layout pinned here is: code byte at "
            "+0x00, subcode and severity bytes at +0x01..+0x05, state "
            "pointer (char*) at +0x08. An empty Status is all zeros."
        ),
    },
    "factory_helper_contract": {
        "address": "0x5fd4080",
        "fde": "0x5fd4080..0x5fd4627",
        "bytes": 1447,
        "role": (
            "Name-to-clock factory helper: takes (Status out, "
            "config_options+0x40, translated-name string, dest_slot) "
            "and writes a Status to out. Its sole caller is the create "
            "host (site 0x5fd4aa3). Cited by contract only; its "
            "internals are not pinned here."
        ),
        "args": {
            "out": "rdi (a stack Status at rsp+0x40 in the host)",
            "config_field": "rsi (config_options+0x40)",
            "name": "rdx (the translated-name string)",
            "dest_slot": "rcx",
        },
    },
    "installer": {
        "site": "0x5fd1a14",
        "kind": "direct_call",
        "containing_fde": "0x5fd19a0..0x5fd1c56",
        "args": {
            "out": "rbp-0x1c0 (a stack record)",
            "offset": 0,
            "verification": 1,
            "flags": 0x2000,
        },
        "note": (
            "The containing function (0x5fd19a0..0x5fd1c56) is a static "
            "initializer: it registers __cxa_atexit for the global at "
            "0x6504bc0, installs the record with the builder, then "
            "assigns the string \"target\" (literal at 0x44a390) via "
            "0x5fcd890. It is NOT pinned here; only this call site and "
            "its arguments are. It is the builder's sole direct caller "
            "in the binary."
        ),
    },
    "sibling_note": {
        "claim": (
            "The SystemClock builder shares the record field map with "
            "the Statistics builder 0x6071520 (open PR #3685) — same "
            "0xb8-byte record, same type 22, same hook-pair layout — "
            "but installs it differently: this builder copies through "
            "the record-copy helper 0x5e332c0, while the Statistics "
            "builder copies field-wise and calls the manager directly. "
            "The GOT-resolved hooks prove SystemClock, not Statistics "
            "or FileSystem: the manager 0x5fcc660 is the SystemClock "
            "lambda manager (its kind-0 typeinfo name at 0x972460 is "
            "the AsCustomSharedPtr<SystemClock> lambda) and the "
            "invoker 0x5fd4c30 calls the SystemClock create host "
            "0x5fd46c0."
        ),
        "other_sibling": (
            "The SliceTransform sibling builder 0x6083a90 shares this "
            "builder's install shape (it also calls the copy helper "
            "0x5e332c0 — census site 0x6083b76) and resolves its own "
            "hooks through its own GOT slots (manager 0x607d190, "
            "invoker 0x60809e0; typeinfo name at 0x976100 is the "
            "AsCustomSharedPtr<const SliceTransform> lambda). It is a "
            "separate work item."
        ),
        "copies_in_binary": 1,
    },
    "literals": [
        {"value": 22, "where": "builder 0x5fd023a", "role": "type field"},
        {"value": "0x5fcc660", "where": "GOT 0x64ed8d0",
         "role": "manager hook"},
        {"value": "0x5fd4c30", "where": "GOT 0x64ed958",
         "role": "invoker hook"},
        {"value": "0x64cda00", "where": "manager 0x5fcc680",
         "role": "lambda typeinfo object (kind 0)"},
        {"value": "0x972460", "where": "reloc at 0x64cda08",
         "role": "lambda typeinfo name string"},
        {"value": "0x6469", "where": "invoker 0x5fd4c83",
         "role": "\"id\" word in the fast-path check"},
        {"value": "0x64ed290", "where": "host 0x5fd4705",
         "role": "atomicity selector byte for the counted use-count bump"},
        {"value": "0x100000001", "where": "global at 0x459b20",
         "role": "packed use/weak counts for the new control block"},
        {"value": "0x5d2e770", "where": "global 0x64eceb8",
         "role": "default slot-0x80 name predicate (FDE 0x5d2e770..0x5d2e832)"},
        {"value": "0x5d2ca10", "where": "global 0x64eceb0",
         "role": "default slot-0x90 name getter, returns the empty string"},
        {"value": "SystemClock", "where": "literal 0x438369",
         "role": "name under which the default clock is registered"},
        {"value": "TimeEmulatedSystemClock", "where": "literal 0x4372ae",
         "role": "name string built by the default initializer"},
        {"value": "Cannot reset object ", "where": "literal 0x433f9f",
         "role": "error Status message built by the host error path"},
        {"value": "target", "where": "literal 0x44a390",
         "role": "string assigned by the installer after the builder call"},
    ],
    "unknowns": [
        "The OptionVerificationType / OptionTypeFlags enum spellings "
        "for the raw values verification 1 / flags 0x2000 used by the "
        "sole installing call site; only the raw values are pinned.",
        "The semantic names of the invoker's two string args beyond "
        "their observed roles (rcx is the string compared to \"id\", "
        "r8 is the name string the create host dispatches on); the "
        "lambda's mangled type only fixes their C++ types.",
        "The exact vtable-base/header attribution of the PosixClock "
        "tables: the typeinfo-bearing cells sit at the stored base "
        "minus 0x08 in this binary (verified on five vtables), so slot "
        "numbers here are relative to the stored base as the code "
        "reads them; the -0x10 cell's role (0, except 0x7 for the "
        "PosixClock object table) is open.",
        "The registry structure built by the default initializer "
        "(0x5fcd890 / 0x61f8b60 / 0x5fcd6f0 / 0x5fd1da0 / 0x61f8700 by "
        "contract) and the roles of the 0x5fcd550 / 0x5fcc630 table "
        "references inside it.",
        "The factory helper 0x5fd4080's internals (by contract only).",
        "The translator 0x609e510's stack struct layout beyond the "
        "pinned out-params (translated-name string at rsp+0x90, error "
        "out-param at rsp+0x68) and the second translator 0x609e2d0's "
        "contract.",
        "The config_options+1 byte's meaning in the Status "
        "normalization branch.",
        "Whether the \"id\" fast path means \"reset to the default "
        "object\" or \"release and return empty\" in the caller's "
        "terms; the binary only shows the release + empty Status.",
        "The \"target\" string's role in the installer (assigned after "
        "the builder call).",
        "The host's landing-pad stubs (FDE 0x5fd4c22..0x5fd4c2e region "
        "and the jumps to 0x5fd4646/0x5fd4680) are shared rethrow "
        "blocks, not decoded; the LSDA call-site tables are not "
        "decoded.",
    ],
}

# Caller roles, read from objdump around each census site. Sites
# without an explicit role get "consumer in FDE <start> (exact use
# open)". The accessor is called from ~190 sites across the node;
# only the create host's use is role-annotated here.
CALLER_ROLES = {
    0x5FD1A14: "the static initializer (FDE 0x5fd19a0..0x5fd1c56) "
               "installing the SystemClock record with offset 0, "
               "verification 1, flags 0x2000",
    0x5FD4C60: "the invoker 0x5fd4c30: forwards (out, config_options, "
               "name_string, *(dest_slot))",
    0x5FD46F4: "the create host: loads the current clock",
    0x5FD0266: "the builder: copies the stack record into out",
    0x5FD4AA3: "the create host: factory helper for a translated name",
    0x5FD48C6: "the create host: out = move(translator Status)",
    0x5FD4AB5: "the create host: move(factory Status, rsp+0x40 -> rsp+0x30)",
    0x5FD4B01: "the create host: move(Status rsp+0x40 -> rsp+0x30)",
    0x5FD4B2F: "the create host: out = move(Status rsp+0x30)",
    0x6083B76: "the SliceTransform sibling builder 0x6083a90: copies "
               "its stack record into out (separate work item)",
}

# In-packet call sites of the generic helpers (libstdc++/RocksDB-wide;
# full caller lists are 1273+25 sites for _M_release and add no RE
# value, so only the sites this behaviour uses are pinned here).
# Each is verified as a real call in its FDE.
PACKET_INTERNAL_SITES = {
    "0x5d350c0": [
        (0x5FD4CA1, "invoker: release the old control in the id fast path"),
        (0x5FD49C3, "host adopt path: release the old control"),
        (0x5FD4955, "host default path: release the old control when the "
                    "translator found no name"),
        (0x5FD48F4, "host cleanup: release the local current-clock reference"),
    ],
    "0x5d3f950": [
        (0x5FD0285, "builder: destroy the temporary record's functors"),
    ],
    "0x609e510": [
        (0x5FD489A, "host default path: registry translator"),
    ],
    "0x609e2d0": [
        (0x5FD4B76, "host Status normalization: second translator"),
    ],
    "0x61cf670": [
        (0x5FD4BC9, "host error path: build the error Status"),
    ],
    "0x5d36110": [
        (0x5FD48DD, "host cleanup: once-arg cleanup helper"),
    ],
}


def fde_table():
    out = subprocess.run(
        ["objdump", "--dwarf=frames", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    fdes = []
    for m in re.finditer(
            r"^([0-9a-f]{8}) \S+ \S+ FDE cie=([0-9a-f]+) "
            r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", out, re.M):
        fdes.append((int(m.group(3), 16), int(m.group(4), 16),
                     m.group(1), m.group(2)))
    return fdes


def containing(fdes, va):
    for s, e, off, cie in fdes:
        if s <= va < e:
            return (hex(s), hex(e))
    return (None, None)


def build():
    data = open(BIN, "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        print("binary digest mismatch")
        sys.exit(1)
    calls, tails, hits, slots = census_mod.scan(BIN)
    fdes = fde_table()
    records = dict(SEMANTIC)
    records["census"] = {}
    for t in census_mod.TARGETS:
        records["census"][hex(t)] = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
    callers = {}
    for t in census_mod.TARGETS:
        rows = []
        for site in calls[t]:
            fs, fe = containing(fdes, site)
            role = CALLER_ROLES.get(site)
            if role is None:
                role = "consumer in FDE %s (exact use open)" % fs
            rows.append({
                "site": hex(site), "kind": "direct_call",
                "containing_fde": [fs, fe],
                "role": role,
            })
        for site in tails[t]:
            fs, fe = containing(fdes, site)
            role = CALLER_ROLES.get(site)
            if role is None:
                role = "consumer in FDE %s (exact use open)" % fs
            rows.append({
                "site": hex(site), "kind": "tail_jump",
                "containing_fde": [fs, fe],
                "role": role,
            })
        callers[hex(t)] = rows
    internal_sites = {}
    for t_hex, sites in PACKET_INTERNAL_SITES.items():
        rows = []
        for site, role in sites:
            fs, fe = containing(fdes, site)
            rows.append({
                "site": hex(site), "kind": "direct_call",
                "containing_fde": [fs, fe],
                "role": role,
            })
        internal_sites[t_hex] = rows
    records["callers"] = callers
    records["packet_internal_sites"] = internal_sites
    return records, callers


def main():
    records, callers = build()
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1)
        fh.write("\n")
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("target\tsite\tkind\tcontaining_fde_start\tcontaining_fde_end\trole\n")
        for t in census_mod.TARGETS:
            for row in callers[hex(t)]:
                fs, fe = row["containing_fde"]
                fh.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (
                    hex(t), row["site"], row["kind"], fs, fe, row["role"]))
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write("Relocations touching this packet (readelf -r -W "
                 "work/hl-node-115.bin; .rela.dyn parsed directly).\n\n")
        fh.write("The two create hooks are GOT slots filled by "
                 "R_X86_64_RELATIVE relocations, so their values are "
                 "link-time constants, not computed by the builder:\n")
        fh.write("  0x64ed8d0  R_X86_64_RELATIVE  addend 0x5fcc660 "
                 "(the manager)\n")
        fh.write("  0x64ed958  R_X86_64_RELATIVE  addend 0x5fd4c30 "
                 "(the invoker)\n")
        fh.write("The builder copies the pair from these slots into the "
                 "record at +0x18/+0x20 (movq 0x64ed8d0 -> xmm0 low, "
                 "movhps 0x64ed958 -> xmm0 high, movaps/movups into the "
                 "stack temporary, then the copy helper installs them "
                 "into out+0x18). The file bytes at both slots are zero; "
                 "the values exist only after relocation.\n\n")
        fh.write("The manager's kind-0 path returns the address of the "
                 "lambda typeinfo object:\n")
        fh.write("  0x64cda00  R_X86_64_64  "
                 "_ZTVN10__cxxabiv117__class_type_infoE@CXXABI_1.3 + 0x10\n")
        fh.write("  0x64cda08  R_X86_64_RELATIVE  addend 0x972460 "
                 "(the typeinfo name)\n")
        fh.write("The name string at 0x972460 is\n")
        fh.write("\"ZN7rocksdb14OptionTypeInfo17AsCustomSharedPtrINS_11SystemClockEEES0_iNS_22OptionVerificationTypeENS_15OptionTypeFlagsEEUlRKNS_13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESF_PvE_\",\n")
        fh.write("i.e. the AsCustomSharedPtr<SystemClock> lambda. This is "
                 "the relocation evidence behind the sibling note in "
                 "records.json.\n\n")
        fh.write("The default clock's tables resolve the same way "
                 "(typeinfo pointer at table base - 0x08 in this binary, "
                 "verified on five vtables):\n")
        fh.write("  0x64ce928  R_X86_64_RELATIVE  addend 0x64ce870 "
                 "(PosixClock typeinfo; name at 0x972c00)\n")
        fh.write("  0x64cecf8  R_X86_64_RELATIVE  addend 0x64ce8b8 "
                 "(_Sp_counted_ptr_inplace<PosixClock> typeinfo; name at "
                 "0x972d00)\n")
        fh.write("The control table's dispose/destroy slots read at the "
                 "stored base are 0x5fe1860 (+0x10) and 0x5fe1590 (+0x18).\n\n")
        fh.write("The host's name-dispatch sentinels are RELATIVE-resolved "
                 "globals:\n")
        fh.write("  0x64eceb8  R_X86_64_RELATIVE  addend 0x5d2e770 "
                 "(default slot-0x80 name predicate, FDE "
                 "0x5d2e770..0x5d2e832)\n")
        fh.write("  0x64eceb0  R_X86_64_RELATIVE  addend 0x5d2ca10 "
                 "(default slot-0x90 name getter, FDE "
                 "0x5d2ca10..0x5d2ca1c)\n")
        fh.write("The default slot-0x80 predicate 0x5d2e770 was read "
                 "in full: empty input name -> false; else true when "
                 "the input equals the slot-0x70 name (strlen + "
                 "memcmp) or the slot-0x90 name (null -> false; "
                 "strlen + memcmp). The host inlines exactly this "
                 "logic when slot 0x80 is the default. The default "
                 "slot-0x90 getter 0x5d2ca10 is 7 bytes (endbr64, lea "
                 "of the empty string at 0x4376fd, ret).\n\n")
        fh.write("The only R_X86_64_RELATIVE entries in .rela.dyn whose "
                 "addend is a packet window start are exactly the two "
                 "hook GOT slots above (0x64ed8d0 -> 0x5fcc660, "
                 "0x64ed958 -> 0x5fd4c30); no other RELATIVE entry points "
                 "at a window, and no RELATIVE slot lives inside any "
                 "window's byte range. The windows are entered only by "
                 "direct call (builder, host, accessor, copy helper, "
                 "status move, factory helper) or through those GOT slots "
                 "(manager, invoker) or by pthread_once (default init).\n\n")
        fh.write("The atomicity selector 0x64ed290 (the global byte "
                 "choosing the lock-xadd vs plain decrement in the "
                 "counted use-count bump) is read by RIP-relative movs in "
                 "the host excerpt (no relocation). The packed counts "
                 "qword 0x100000001 lives at 0x459b20 in .rodata (no "
                 "relocation).\n")
    manifest = {}
    for name in sorted(os.listdir(HERE)):
        if name == "MANIFEST.sha256" or name == "__pycache__":
            continue
        path = os.path.join(HERE, name)
        if os.path.isfile(path):
            manifest[name] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    with open(os.path.join(HERE, "MANIFEST.sha256"), "w") as fh:
        for name in sorted(manifest):
            fh.write("%s  %s\n" % (manifest[name], name))
    print("wrote records.json, callers.tsv, relocations.txt, MANIFEST.sha256")
    return 0


if __name__ == "__main__":
    sys.exit(main())
