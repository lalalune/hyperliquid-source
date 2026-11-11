#!/usr/bin/env python3
"""Generate records.json + vtables.tsv for RE-001-delegate-vtable-115.

Derives the delegate (Customizable) vtable family from the node #115
binary's own relocation table, so the packet's claims are
reproducible without trusting this script's embedded constants:

  * typeinfo objects: R_X86_64_64 relocs (type 1) with symbol 260
    (_ZTVN10__cxxabiv117__class_type_infoE) or 261
    (_ZTVN10__cxxabiv120__si_class_type_infoE) at the object's +0x00
    slot. The name is the C string at the R_X86_64_RELATIVE target of
    the +0x08 slot; the base class is the RELATIVE target of the
    +0x10 slot (single-inheritance typeinfos only). 701 objects.
  * strict vtables: a RELATIVE reloc at B-0x8 whose addend is a
    typeinfo, with no reloc at B-0x10 (the offset-to-top slot).
    406 tables.
  * family extents: a table's slots run from its base while each slot
    is a RELATIVE reloc into .text (a concrete function), a type-1
    reloc with symbol 263 (__cxa_pure_virtual, addend 0), or a NULL
    slot (no reloc, file content 0); the table ends at the first slot
    that is none of those, capped by the next strict vtable's base
    minus 0x10.

The semantic records (slot contracts, call sites, literals) are the
author's readings of the verbatim excerpts in excerpts/; the
instruction-level detail lives only in those excerpt files, never in
records.json.

Usage (from the repository root, after census.py has run):
    python3 research/work-items/RE-001-delegate-vtable-115/gen_records.py

Writes records.json and vtables.tsv next to this script.
"""

import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# The 19 delegate-family vtable bases (from the strict-vtable census).
FAMILY_BASES = [
    0x64CDA68, 0x64CDAD0, 0x64CDD88, 0x64CE2D8, 0x64CE590,
    0x64CE930, 0x64CEA10, 0x64D1398, 0x64D1650, 0x64D1940,
    0x64D1980, 0x64D19A0, 0x64D1F00, 0x64D2D88, 0x64D3138,
    0x64D31B8, 0x64D3430, 0x64D3638, 0x64D36B8,
]

# Slot contracts for the Customizable delegate interface (offsets
# 0x10..0x98), read off the verbatim excerpts. "shared" is the
# function most family tables use; "overrides" maps a class name to
# its own implementation. Callees marked (unmodeled) are real
# functions whose bodies are NOT in this packet's excerpts.
SLOT_CONTRACTS = {
    0x10: {
        "role": "GetOption",
        "shared": 0x609D760,
        "contract": "If the option name is exactly \"id\" (length 2, "
                    "bytes 0x6469), return the delegate's own name "
                    "(its slot-0x78 string) and a zeroed Status; "
                    "otherwise forward to Configurable's slot 0x10 "
                    "(0x6099030).",
        "callees": ["0x6099030", "slot 0x78 (delegate Name)"],
        "overrides": {
            "Configurable": 0x6099030,
            "Logger": 0x5FCC410,
        },
    },
    0x18: {
        "role": "ConfigureOption",
        "shared": 0x609DC40,
        "contract": "Return 1 when the value's +0x2c byte is <= 1, "
                    "when out == delegate, or (return 0) when the "
                    "delegate is null. Otherwise compare the "
                    "delegate's name with this object's name via "
                    "slot 0x78; on mismatch rewrite the option name "
                    "to \"id\" (0x441b15), then forward to "
                    "Configurable's slot 0x18 (0x60996a0) when the "
                    "value's +0x2c byte is > 2, else return 1.",
        "callees": ["0x60996a0", "slot 0x78 (delegate Name)"],
        "overrides": {"Configurable": 0x60996A0},
    },
    0x20: {
        "role": "init string field",
        "shared": 0x5D32560,
        "contract": "Initialize a std::string at rdi: pointer "
                    "rdi+0x10, length 0, NUL at +0x10. Returns rdi.",
        "callees": [],
        "overrides": {},
    },
    0x28: {
        "role": "parse/apply a list of (name, value) records",
        "shared": 0x6095E70,
        "contract": "Walk 0x30-byte records from the range in rsi. "
                    "For each record copy the name (SSO-aware) and "
                    "the 0x20-byte value struct, then walk its +0x18 "
                    "entry chain; for each entry materialize five "
                    "sub-values through the +0x40/+0x60/+0x80/+0xa0/"
                    "+0xc0 copy function pointers (tag 2). When the "
                    "HIGH dword of the entry's +0xd0 qword, minus 4, "
                    "is > 1 (unsigned; a high dword of 0..3 wraps "
                    "and also passes) and the 0x40 bit of the byte "
                    "at +0xd9 is clear and (the materialized +0xa0 "
                    "sub-value's first qword is non-null or the LOW "
                    "dword of the +0xd0 qword, minus 0x15, is <= 1 "
                    "unsigned), call worker 0x60b9e00 (unmodeled) "
                    "with the built value and copy the returned "
                    "Status to the out parameter; then tear down the "
                    "sub-values through their slot-0x00 pointers "
                    "with code 3. When +0xc0 is null the binary "
                    "skips materializing that sub-value and jumps to "
                    "a second, identical gate site.",
        "callees": ["0x60b9e00 (unmodeled)"],
        "overrides": {
            "SystemClockWrapper": 0x5FCF590,
            "CompositeEnvWrapper": 0x5FD7560,
        },
    },
    0x30: {
        "role": "parse/apply a list of (name, value) records (worker 2)",
        "shared": 0x6096790,
        "contract": "Same record walk and sub-value materialization "
                    "as slot 0x28, but the worker is 0x60b9f50 "
                    "(unmodeled, six arguments) and the kind gate "
                    "has no 0x40 flag-byte check: the worker fires "
                    "when (HIGH dword of the +0xd0 qword - 4) > 1 "
                    "unsigned and (the raw +0xc0 function pointer "
                    "is non-null or (LOW dword of the +0xd0 qword "
                    "- 0x15) <= 1 unsigned). When +0xc0 is null the "
                    "binary skips materializing it and jumps to a "
                    "second gate site that runs the same predicate "
                    "without the +0xc0 branch.",
        "callees": ["0x60b9f50 (unmodeled)"],
        "overrides": {},
    },
    0x38: {
        "role": "resolve an option name to a field",
        "shared": 0x5D2E090,
        "contract": "Call the shared resolver 0x60958c0: it scans the "
                    "0x30-byte (name, +0x20 field) record array at "
                    "*(rdi+0x08)..*(rdi+0x10) for the name in rsi "
                    "(length then memcmp, SSO-aware) and returns the "
                    "matching record's +0x20 field, or null. If the "
                    "resolver returns non-null, return it. Otherwise "
                    "call this object's slot 0x88 (the wrapped "
                    "object) and, when non-null, tail-jump to the "
                    "wrapped object's slot 0x38; return null when "
                    "there is no wrapped object.",
        "callees": ["0x60958c0", "slot 0x88 (wrapped)"],
        "overrides": {
            "ConfigurableCFOptions": 0x607DD50,
            "DBOptionsConfigurable": 0x60A0240,
        },
    },
    0x40: {
        "role": "zero Status",
        "shared": 0x60956F0,
        "contract": "Write a zeroed 16-byte Status (u32 0, u16 0, "
                    "u64 0) into *(rdi) and return rdi. Byte-"
                    "identical copies at 0x5fcc0e0 and 0x5fcc100.",
        "callees": [],
        "overrides": {},
    },
    0x48: {
        "role": "merge/apply host",
        "shared": 0x609D0E0,
        "contract": "The merge host every slot-0x48 override calls "
                    "first (see RE-001-find-family-merge-115, "
                    "#3560). It returns a Status in *(rdi); the "
                    "overrides return early when its first byte is "
                    "non-zero.",
        "callees": [],
        "overrides": {
            "ConfigurableMutableCFOptions": 0x607E420,
            "DBOptionsConfigurable": 0x60A2470,
        },
    },
    0x50: {
        "role": "SetOption (string value)",
        "shared": 0x60986B0,
        "contract": "When the value kind byte (+0x04) is 0, forward "
                    "(name, value) to worker 0x60bedc0 (unmodeled). "
                    "When kind != 0 and the changeable flag at "
                    "name+0xb1 is set, copy the value struct "
                    "(shared_ptr refcounted) and call 0x60bedc0. "
                    "When kind != 0 and the flag is clear, build "
                    "the error string \"Option not changeable: \" "
                    "(0x4341c2) + name and report it through "
                    "0x61cf670 (unmodeled) with code 4. Always "
                    "returns the out Status.",
        "callees": ["0x60bedc0 (unmodeled)", "0x61cf670 (unmodeled)"],
        "overrides": {"TestMemLogger": 0x5FCC480},
    },
    0x58: {
        "role": "validate (name, value)",
        "shared": 0x6095710,
        "contract": "Call kind validator 0x60bf980 (unmodeled); if "
                    "it accepts, return 1. Otherwise call "
                    "0x60bf7c0 (unmodeled); if it rejects too, "
                    "blank the target name string (replace with "
                    "\"\"). Always returns 1.",
        "callees": ["0x60bf980 (unmodeled)", "0x60bf7c0 (unmodeled)"],
        "overrides": {
            "ConfigurableCFOptions": 0x6086B70,
            "MutableDBConfigurable": 0x60A7420,
        },
    },
    0x60: {
        "role": "serialize options to a string",
        "shared": 0x609DE80,
        "contract": "Call the delegate's slot 0x78 for its name. "
                    "When the value kind (+0x28) is 1 or the "
                    "delegate name is empty, compose the out string "
                    "as <options name> + \"id\" + \"=\" + <delegate "
                    "name> + <value name>; when the delegate name "
                    "string is also empty, assign the delegate name "
                    "directly. Otherwise forward to Configurable's "
                    "slot 0x60 (0x60985e0) and copy its output.",
        "callees": ["0x60985e0", "slot 0x78 (delegate Name)"],
        "overrides": {
            "Configurable": 0x60985E0,
            "SystemClockWrapper": 0x5FCDAE0,
            "CompositeEnvWrapper": 0x5FD5E00,
        },
    },
    0x68: {
        "role": "dotted-name lookup",
        "shared": 0x609D980,
        "contract": "Call the delegate's slot 0x70 (Name()); if "
                    "the input name starts with that name followed "
                    "by '.', strip the prefix (name + '.') and "
                    "return the remainder as the out string; if "
                    "Name() is null, throw std::logic_error. "
                    "Otherwise fall back to Configurable's slot "
                    "0x68 (0x6095a60), a std::string copy into the "
                    "out string.",
        "callees": ["0x6095a60", "slot 0x70 (delegate Name)"],
        "overrides": {"Configurable": 0x6095A60},
    },
    0x70: {
        "role": "Name()",
        "shared": 0x5FCC0D0,
        "contract": "Return the class's name as a const char*: \"\" "
                    "for Env, \"BasicStatistics\" for "
                    "StatisticsImpl, \"CompositeEnv\" for "
                    "CompositeEnvWrapper, \"DefaultClock\" for "
                    "PosixClock, \"PosixEnv\" for PosixEnv, "
                    "\"MockEnv\" for MockEnv, "
                    "\"TimeEmulatedSystemClock\" for "
                    "EmulatedSystemClock. SystemClockWrapper's "
                    "slot 0x70 is NULL: calling Name() on it would "
                    "crash.",
        "callees": [],
        "overrides": {
            "StatisticsImpl": 0x606FA20,
            "CompositeEnvWrapper": 0x5FD4E60,
            "PosixClock": 0x5FE0FE0,
            "PosixEnv": 0x5FE1000,
            "MockEnv": 0x6025790,
            "EmulatedSystemClock": 0x60257A0,
        },
    },
    0x78: {
        "role": "name as std::string",
        "shared": 0x5D32A30,
        "contract": "Call the delegate's slot 0x70 (Name()) and "
                    "assign the returned C string into the sret "
                    "std::string at rdi through 0x5d32940 "
                    "(unmodeled). Returns rdi.",
        "callees": ["0x5d32940 (unmodeled)", "slot 0x70 (Name)"],
        "overrides": {},
    },
    0x80: {
        "role": "IsInstanceOf(name)",
        "shared": 0x5D2E770,
        "contract": "Return 1 when the input string matches this "
                    "object's Name() (slot 0x70) or its NickName() "
                    "(slot 0x90) by length then memcmp; else 0. "
                    "MockEnv and CompositeEnvWrapper override it "
                    "(0x5fd6240): return 1 when the input is exactly "
                    "\"CompositeEnv\" (length 12), else tail-jump to "
                    "the canonical 0x5d2e770.",
        "callees": ["slot 0x70 (Name)", "slot 0x90 (NickName)"],
        "overrides": {"MockEnv": 0x5FD6240,
                      "CompositeEnvWrapper": 0x5FD6240},
    },
    0x88: {
        "role": "wrapped/parent object",
        "shared": 0x5D2CA00,
        "contract": "Env returns 0 (no wrapped object). "
                    "SystemClockWrapper returns *(obj+0x20); "
                    "MockEnv returns *(obj+0x48); StatisticsImpl "
                    "returns *(obj+0x28). Slot 0x38 forwards "
                    "through this object's slot 0x38.",
        "callees": [],
        "overrides": {
            "SystemClockWrapper": 0x5FCC3F0,
            "MockEnv": 0x5FD4E70,
            "StatisticsImpl": 0x606FA30,
        },
    },
    0x90: {
        "role": "NickName()",
        "shared": 0x5D2CA10,
        "contract": "Return the class's nickname as a const char*: "
                    "\"\" for Env, \"PosixClock\" for PosixClock, "
                    "\"DefaultEnv\" for PosixEnv.",
        "callees": [],
        "overrides": {
            "PosixClock": 0x5FE0FF0,
            "PosixEnv": 0x5FE1010,
        },
    },
    0x98: {
        "role": "unwrap / status / time",
        "shared": 0x5FD5A00,
        "contract": "CompositeEnv/PosixEnv/MockEnv (0x5fd5a00): "
                    "take the object at the 2nd argument's +0x28; "
                    "when its slot-0x98 is the terminal stub "
                    "0x5fcc240 (GOT 0x64ed8b0) write a zeroed "
                    "Status into *(rdi), else call that slot-0x98. "
                    "SystemClockWrapper (0x5d4d490): walk the +0x20 "
                    "chain, comparing each level's slot-0x98 "
                    "against the GOT slot 0x64ecf80 (0x5d4d490 "
                    "itself), 10 levels unrolled, then tail-jump "
                    "to the innermost slot-0x98. Env (0x5fcc0e0): "
                    "zeroed Status. StatisticsImpl (0x6070490): run "
                    "the +0x38 field's pre-hook 0x60d5230 "
                    "(unmodeled), call core 0x6070430 (unmodeled), "
                    "run the +0x38 post-hook 0x60d52f0 (unmodeled), "
                    "return the core result. PosixClock (0x5fe1540): "
                    "gettimeofday, return tv_sec * 1000000 + "
                    "tv_usec (microseconds since the epoch). "
                    "EmulatedSystemClock (0x60259e0): when the flag "
                    "byte at +0x48 is clear, call the wrapped "
                    "clock's (at +0x20) slot 0x98; return that "
                    "result plus the offset at +0x40 (0 when the "
                    "flag is set).",
        "callees": [],
        "overrides": {
            "SystemClockWrapper": 0x5D4D490,
            "Env": 0x5FCC0E0,
            "StatisticsImpl": 0x6070490,
            "PosixClock": 0x5FE1540,
            "EmulatedSystemClock": 0x60259E0,
        },
    },
}

# Per-class override contracts that need more than a line.
OVERRIDE_NOTES = {
    "SystemClockWrapper/0x28": "0x5fcf590: when *(rsi+0x20) is null, "
        "create the wrapped PosixClock through 0x5fe2680 (unmodeled; "
        "it installs the PosixClock vtable 0x64ce930) and store it at "
        "+0x20 with shared_ptr refcounting, then call the shared "
        "slot-0x28 (0x6095e70).",
    "CompositeEnvWrapper/0x28": "0x5fd7560 (MockEnv's slot 0x28; "
        "CompositeEnvWrapper shares the MockEnv override): when "
        "*(rsi+0x50) is null, take *(rsi+0x48), creating the wrapped "
        "PosixEnv through 0x5fe2860 (unmodeled; installs the PosixEnv "
        "vtable 0x64cea10) when that is null too; when *(rsi+0x28) is "
        "null, create it through 0x5fcf390 (unmodeled); when "
        "*(rsi+0x38) is null, create it through 0x5fcf430 (unmodeled) "
        "applied to the wrapped env; then call the shared slot-0x28 "
        "(0x6095e70).",
    "ConfigurableCFOptions/0x38": "0x607dd50: compare the input name "
        "against the .bss string at 0x6506ac0 (runtime-built; its "
        "value is not recoverable from the static binary); on a "
        "match return this+0x330, else tail-jump to the shared "
        "resolver 0x60958c0 (linear scan over the 0x30-byte record "
        "array, returns the matching record's +0x20 field).",
    "DBOptionsConfigurable/0x38": "0x60a0240: the DBOptions variant: "
        "compare the input name against the .bss string at 0x6506d60 "
        "(runtime-built); on a match return this+0x2d8 (the start of "
        "the DBOptions snapshot block that slot 0x48 copies into), "
        "else tail-jump to the shared resolver 0x60958c0.",
    "ConfigurableMutableCFOptions/0x48": "0x607e420: call host A "
        "(0x609d0e0); return early when its Status is non-zero; "
        "call 0x60c0580 (unmodeled) with (this+0x20, this+0x330) and "
        "0x60c2a10 (unmodeled) with (this+0x218, this+0x330); then "
        "call the delegate's slot 0x28 and copy its Status out.",
    "DBOptionsConfigurable/0x48": "0x60a2470: call host A "
        "(0x609d0e0); return early when its Status is non-zero; "
        "read the DBOptions snapshot through 0x60c2e20 (unmodeled) "
        "into a local struct and copy it field-by-field into "
        "this+0x2d8..+0x560 (shared_ptr refcount management, old "
        "vector<string> teardown at +0x348); call finalize helper "
        "0x5d354b0 (unmodeled); then call the delegate's slot 0x28 "
        "and copy its Status out.",
    "ConfigurableCFOptions/0x58": "0x6086b70 (twin A) and "
        "0x60a7420 (twin B, MutableDBConfigurable): byte-identical "
        "after address normalization except the holder-map loads "
        "(0x630 vs 0x90); see RE-001-default-name-115 (#3563).",
    "SystemClockWrapper/0x60": "0x5fcdae0: run the shared slot-0x60 "
        "(0x609de80); then, when the value kind (+0x28) is not 1 "
        "and a wrapped clock is installed at +0x20, check whether "
        "the wrapped clock's IsInstanceOf (slot 0x80) is the "
        "canonical 0x5d2e770 (GOT 0x64eceb8) and whether its Name() "
        "/ NickName() (slots 0x70/0x90) equal \"DefaultClock\"; when "
        "the wrapped clock is not the default clock, append "
        "\"target=\" (0x4496d1) + the wrapped clock's serialization "
        "(helpers 0x5fcd890/0x5fcd6f0/0x61d13e0/0x61d1390/0x60971c0, "
        "unmodeled).",
    "CompositeEnvWrapper/0x60": "0x5fd5e00 (MockEnv's slot 0x60): "
        "run the shared slot-0x60 (0x609de80); then, when the "
        "wrapped PosixEnv at +0x48 is non-null and differs from the "
        "default PosixEnv returned by 0x5fe2860 (unmodeled), append "
        "\"target=\" (0x4496d1) + the wrapped env's serialization "
        "(helpers 0x5fd5cc0/0x60971c0, unmodeled).",
    "Logger/0x10": "0x5fcc410: a one-shot gate shared by EnvLogger, "
        "TestMemLogger and AutoRollLogger: when *(rsi+0x10) is 0, "
        "set it to 1 and call the delegate's slot 0x50; later calls "
        "write a zeroed Status into *(rdi) and return. TestMemLogger's "
        "slot 0x50 (0x5fcc480) returns Status code 3 (kNotSupported).",
    "Configurable/0x10": "0x6099030: resolve the option name through "
        "the delegate's slot 0x68 (dotted-name lookup) into a local "
        "string, then call worker 0x6098ad0 (unmodeled) and return "
        "its Status.",
    "Configurable/0x18": "0x60996a0: the Configurable configure "
        "worker; the Env slot-0x18 (0x609dc40) tail-jumps here after "
        "its name check. The worker's own callee 0x6099100 is "
        "unmodeled.",
    "Configurable/0x60": "0x60985e0: initialize a 16-byte struct at "
        "rdi, then call worker 0x6097630 (unmodeled) over the "
        "object; the shared slot-0x60 forwards here when the value "
        "kind is not 1 and the delegate name is non-empty.",
    "Configurable/0x68": "0x6095a60: a std::string copy (SSO-aware) "
        "of the string at *(rdx) into the string at this; the "
        "shared slot-0x68 falls back here when the input name does "
        "not start with the delegate's Name() + '.'.",
}

# find_entry (0x609e510) delegate dispatch sites, from
# RE-001-registry-find-115 (#3485) and re-verified here against the
# binary. The delegate is the Customizable at the matcher node's
# +0x28 object pointer (rdi's 4th argument chain in create host
# 0x6077820, consistent with a shared_ptr<Statistics> holder).
FIND_ENTRY_DISPATCH = {
    "find_entry": "0x609e510",
    "delegate_impl": "0x6097110",
    "sites": [
        {"addr": "0x609e5a1", "insn": "call *0x78(%rax)",
         "meaning": "delegate Name() as std::string (sret)"},
        {"addr": "0x609e644", "insn": "mov 0x80(%rax),%rdx; cmp GOT 0x64eceb8",
         "meaning": "delegate IsInstanceOf must be the canonical 0x5d2e770"},
        {"addr": "0x609e666", "insn": "call *0x70(%rax)",
         "meaning": "delegate Name()"},
        {"addr": "0x609e68a", "insn": "call *0x90(%rax)",
         "meaning": "delegate NickName()"},
        {"addr": "0x609712d", "insn": "call *0x48(%rax)",
         "meaning": "delegate_impl calls the delegate's slot 0x48 (merge host)"},
    ],
    "create_host": "0x6077820",
    "note": "The create host passes *(rbp) as find_entry's delegate, "
            "where rbp is its 4th argument (rcx): a shared_ptr<Statistics> "
            "holder whose +0x00 is the Statistics*. StatisticsImpl is the "
            "only delegate class whose slot-0x88 reads +0x28, matching the "
            "matcher node's +0x28 delegate pointer.",
}

# GOT landmarks: GOT slot -> the function the relocation binds.
GOT_LANDMARKS = [
    {"got": "0x64eceb8", "target": "0x5d2e770",
     "meaning": "canonical IsInstanceOf (slot 0x80)"},
    {"got": "0x64eceb0", "target": "0x5d2ca10",
     "meaning": "canonical NickName (slot 0x90, Env \"\")"},
    {"got": "0x64ecf50", "target": "0x5d48960",
     "meaning": "forwarder (StatisticsImpl slot 0x98 comparison)"},
    {"got": "0x64ecf80", "target": "0x5d4d490",
     "meaning": "unwrap (slot 0x98, SystemClockWrapper)"},
    {"got": "0x64ed8b0", "target": "0x5fcc240",
     "meaning": "terminal slot-0x98 stub (zeroed Status)"},
]

# Pinned literals, read back from the binary by verify.py.
LITERALS = {
    "0x4376fd": "",
    "0x441b15": "id",
    "0x445245": "=",
    "0x4341c2": "Option not changeable: ",
    "0x4496d1": "target=",
    "0x431007": "DefaultClock",
    "0x431014": "DefaultEnv",
    "0x432248": "BasicStatistics",
    "0x43e762": "CompositeEnv",
    "0x438375": "PosixEnv",
    "0x44768e": "PosixClock",
    "0x447686": "MockEnv",
    "0x4372ae": "TimeEmulatedSystemClock",
}

# The 80-byte option value struct, from RE-001-registry-find-115.
VALUE_STRUCT = {
    "size": 80,
    "fields": [
        {"offset": 0, "size": 4, "type": "u32", "note": "code"},
        {"offset": 4, "size": 1, "type": "u8", "note": "kind byte (slot 0x50 dispatch)"},
        {"offset": 8, "size": 32, "type": "std::string", "note": "name"},
        {"offset": 40, "size": 4, "type": "u32", "note": "kind (slot 0x28/0x30/0x60 gate)"},
        {"offset": 44, "size": 1, "type": "u8", "note": "flags (slot 0x18 gate: > 2 forwards)"},
        {"offset": 48, "size": 8, "type": "u64", "note": ""},
        {"offset": 56, "size": 16, "type": "bytes", "note": ""},
        {"offset": 72, "size": 8, "type": "shared_ptr control", "note": ""},
    ],
    "note": "The matcher node's +0x28 object pointer (the delegate) "
            "is a different +0x28 from this value struct's +0x28 kind "
            "field; keep the two apart.",
}


def load_sections():
    sections = {}
    out = subprocess.run(["readelf", "-S", "-W", str(BINARY)],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+"
                     r"([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            sections[m.group(1)] = (int(m.group(2), 16),
                                    int(m.group(3), 16),
                                    int(m.group(4), 16))
    return sections


def main():
    sections = load_sections()
    data = BINARY.read_bytes()
    rela_off, rela_size = sections[".rela.dyn"][1], sections[".rela.dyn"][2]
    text_lo = sections[".text"][0]
    text_hi = text_lo + sections[".text"][2]
    data_rel_ro = sections[".data.rel.ro"]

    def read_vaddr(addr, n):
        for _name, (v, o, s) in sections.items():
            if v <= addr < v + s:
                return data[o + (addr - v): o + (addr - v) + n]
        raise ValueError("address %#x not in any section" % addr)

    def read_cstr(addr):
        out = bytearray()
        cur = addr
        while True:
            b = read_vaddr(cur, 1)[0]
            if b == 0:
                return bytes(out).decode("latin1")
            out.append(b)
            cur += 1

    relocs = {}
    for i in range(rela_size // 24):
        off, info, add = struct.unpack_from(
            "<QQq", data, rela_off + i * 24)
        relocs[off] = (info & 0xFFFFFFFF, info >> 32, add & (2**64 - 1))

    # --- typeinfo objects -------------------------------------------
    typeinfos = {}
    for off, (typ, sym, _add) in relocs.items():
        if typ == 1 and sym in (260, 261):
            name = read_cstr(relocs[off + 8][2])
            base = None
            r10 = relocs.get(off + 0x10)
            if r10 and r10[0] == 8:
                base = "0x%x" % r10[2]
            typeinfos[off] = {"name": name, "base": base, "sym": sym}

    # --- strict vtables ----------------------------------------------
    strict = {}
    for off, (typ, _sym, add) in relocs.items():
        if typ == 8 and add in typeinfos:
            base = off + 8
            if (base - 0x10) not in relocs:
                strict[base] = typeinfos[add]["name"]

    bases = sorted(strict)

    def is_slot(addr):
        r = relocs.get(addr)
        if r and r[0] == 8 and text_lo <= r[2] < text_hi:
            return True
        if r and r[0] == 1 and r[1] == 263 and r[2] == 0:
            return True  # __cxa_pure_virtual
        if r is None and struct.unpack(
                "<Q", read_vaddr(addr, 8))[0] == 0:
            return True  # NULL slot
        return False

    def slot_kind(addr):
        r = relocs.get(addr)
        if r and r[0] == 8:
            return {"target": "0x%x" % r[2], "kind": "function"}
        if r and r[0] == 1 and r[1] == 263:
            return {"target": None, "kind": "pure-virtual"}
        return {"target": None, "kind": "null"}

    # --- census counts (census.py must have run first) ---------------
    counts = {}
    callers_path = PACKET / "callers.tsv"
    rows = callers_path.read_text().splitlines()[1:]
    for line in rows:
        if not line.strip():
            continue
        _site, target, _caller, kind = line.split("\t")
        key = "%s:%s" % (target, kind.strip())
        counts[key] = counts.get(key, 0) + 1

    # --- the delegate family ------------------------------------------
    vtables = []
    for base in FAMILY_BASES:
        idx = bases.index(base)
        if idx + 1 < len(bases):
            cap = (bases[idx + 1] - 0x10 - base) // 8
        else:
            cap = (data_rel_ro[0] + data_rel_ro[2] - base) // 8
        n = 0
        while n < cap and is_slot(base + n * 8):
            n += 1
        slots = {}
        for o in range(0, n * 8, 8):
            slots["0x%x" % o] = slot_kind(base + o)
        lea_key = "0x%x:lea" % base
        vtables.append({
            "vtable": "0x%x" % base,
            "class": strict[base],
            "base_typeinfo": typeinfos[
                relocs[base - 8][2]]["base"],
            "nslots": n,
            "slots": slots,
            "install_sites_lea": counts.get(lea_key, 0),
        })

    # --- interface slots ------------------------------------------------
    interface = []
    for off in sorted(SLOT_CONTRACTS):
        c = SLOT_CONTRACTS[off]
        # Which family tables use the shared implementation at this slot.
        users = []
        for v in vtables:
            s = v["slots"].get("0x%x" % off)
            if s and s["target"] == "0x%x" % c["shared"]:
                users.append(v["class"])
        interface.append({
            "offset": "0x%x" % off,
            "role": c["role"],
            "shared": "0x%x" % c["shared"],
            "shared_users": users,
            "contract": c["contract"],
            "callees": c["callees"],
            "overrides": {"0x%x" % v: k for k, v in c["overrides"].items()},
        })

    records = {
        "task": "RE-001",
        "slug": "delegate-vtable-115",
        "question": "What is node #115's Find delegate vtable family: "
                    "which vtable does each delegate class use, what "
                    "does each delegate-interface slot (0x10..0x98) "
                    "do, and how does find_entry dispatch through "
                    "the delegate?",
        "artifact": {
            "path": "artifacts/node/115/hl-node",
            "sha256": DIGEST,
        },
        "value_struct": VALUE_STRUCT,
        "census": {
            "typeinfo_objects": len(typeinfos),
            "strict_vtables": len(strict),
            "caller_rows": len(rows),
            "counts": counts,
        },
        "vtables": vtables,
        "interface_slots": interface,
        "override_notes": OVERRIDE_NOTES,
        "find_entry_dispatch": FIND_ENTRY_DISPATCH,
        "got_landmarks": GOT_LANDMARKS,
        "literals": LITERALS,
        "install_sites_note": "Only 6 of the 19 family classes have "
            "lea install sites anywhere in this binary (PosixEnv 3, "
            "PosixClock 1, PosixFileSystem 5, TestMemLogger 4, "
            "MockEnvDirectory 1, MockEnvFileLock 3; the FileSystem "
            "trio is counted in the census but is not part of the "
            "19-table delegate family). The other family vtable "
            "bases never appear as an instruction operand and no "
            "relocation holds them as a value: their objects are not "
            "constructed by any code in this binary, so the delegate "
            "objects find_entry dispatches on arrive through "
            "construction paths outside this binary's .text. See "
            "README.md open unknowns.",
        "open_unknowns": [
            "Which construction paths install a non-null +0x28 "
            "delegate on the matcher node: MockEnv's slot 0x28 "
            "lazily creates +0x28 via 0x5fcf390 and +0x38 via "
            "0x5fcf430, and SCW's slot 0x28 lazily creates its "
            "wrapped PosixClock via 0x5fe2680, but the creators' "
            "bodies (0x5fcf390, 0x5fcf430, 0x5fe2680, 0x5fe2860) are "
            "not in this packet.",
            "SystemClockWrapper's slot 0x70 (Name) is NULL: calling "
            "Name() on a SystemClockWrapper would crash; the binary "
            "never does (find_entry calls slot 0x78 on the delegate, "
            "which calls slot 0x70 only on the wrapped object).",
            "The Configurable configure worker's callee 0x6099100 "
            "(tail-jumped to by conf_slot18) is not in this packet.",
            "The slot-0x58 kind validators 0x60bf980 and 0x60bf7c0 "
            "are not in this packet.",
            "The slot-0x28/0x30 workers 0x60b9e00 and 0x60b9f50, the "
            "slot-0x50 worker 0x60bedc0 and reporter 0x61cf670, the "
            "slot-0x60 worker 0x6097630, the Configurable slot-0x10 "
            "worker 0x6098ad0, and the slot-0x60 append helpers "
            "0x5fcd890/0x5fcd6f0/0x61d13e0/0x61d1390/0x60971c0/0x5fd5cc0 "
            "are not in this packet.",
            "StatisticsImpl's +0x28 field (read by its slot 0x88) "
            "and the .bss string at 0x6506ac0 (compared by "
            "ConfigurableCFOptions' slot 0x38) are runtime-built; "
            "their values are not recoverable from the static binary.",
            "The Logger-family method bodies (EnvLogger/AutoRollLogger "
            "slots 0x18..0x50, TestMemLogger slots 0x18/0x20/0x38, "
            "MockEnvDirectory slots 0x10/0x18/0x28) belong to the "
            "Logger/Directory interfaces, not the Customizable "
            "delegate interface, and are not excerpted here.",
            "The 85-slot Env-family tables have Env-specific slots "
            "at 0xa0..0x2a0 (file IO and friends) outside the "
            "delegate interface; they are listed in vtables.tsv "
            "but not given contracts here.",
        ],
        "cross_references": {
            "3378": "DB-family vtables (0x64c9368, 0x64cb0e0, "
                    "0x64cb5c0, 0x64cbbc0) and the StatisticsImpl "
                    "table (0x64d2d88, 32 slots) were pinned there; "
                    "this packet re-ships only the StatisticsImpl "
                    "delegate-interface comparison rows and credits #3378.",
            "3362": "StatisticsImpl vtable (0x64d2d88) pinned there; "
                    "credited here for the table base.",
            "3485": "Registry Find: find_entry (0x609e510), "
                    "find_norm, the matcher, delegate_impl "
                    "(0x6097110, re-shipped here), and the value "
                    "struct layout.",
            "3488": "Sibling entry point and the '=' helper "
                    "(slot-0x40 zero-status stub).",
            "3560": "Find-family merge: host A (0x609d0e0, "
                    "re-shipped here).",
            "3563": "Default name: the twin slot-0x58 entries "
                    "(0x6086b70/0x60a7420, re-shipped here) and the "
                    "StatisticsImpl Name() literal \"BasicStatistics\".",
        },
    }

    (PACKET / "records.json").write_text(
        json.dumps(records, indent=2) + "\n")

    # --- vtables.tsv ----------------------------------------------------
    lines = ["vtable\tclass\tbase_typeinfo\tnslots\toffset\ttarget\tkind"]
    for v in vtables:
        for off, s in v["slots"].items():
            lines.append("%s\t%s\t%s\t%d\t%s\t%s\t%s" % (
                v["vtable"], v["class"],
                v["base_typeinfo"] if v["base_typeinfo"] else "-",
                v["nslots"],
                off, s["target"] if s["target"] else "-", s["kind"]))
    (PACKET / "vtables.tsv").write_text("\n".join(lines) + "\n")
    print("wrote records.json (%d vtables, %d typeinfos, %d strict)"
          % (len(vtables), len(typeinfos), len(strict)))
    print("wrote vtables.tsv (%d rows)" % (len(lines) - 1))


if __name__ == "__main__":
    sys.exit(main())
