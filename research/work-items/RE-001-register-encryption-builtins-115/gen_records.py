"""Generate records.json for the RE-001-register-encryption-builtins-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-register-encryption-builtins-115/gen_records.py

Writes records.json next to this script.  The JSON holds semantic
records only -- no per-instruction mnemonic lists; instruction-level
detail lives in the verbatim objdump excerpts.
"""

import json
from pathlib import Path

PACKET = Path(__file__).resolve().parent

RECORDS = {
    "target": {
        "artifact": "work/hl-node-115.bin",
        "sha256": "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
        "node": 115,
    },
    "work_item": "RE-001-register-encryption-builtins-115",
    "task": "RE-001",
    "question": (
        "Pin node #115's RegisterEncryptionBuiltins registrar end-to-end: "
        "the host lambda 0x5ff88c0 that creates the 'encryption' "
        "ObjectLibrary and registers three FactoryEntry records "
        "(two EncryptionProvider creators, one BlockCipher creator) "
        "through the helper 0x5ff8260, the PatternEntry records each "
        "carries (patterns CTR / 1://test / ROT13 with element modes "
        "2 / none / 3), the creator lambdas' _M_invoke bodies "
        "(CTR provider construction, the EndsWith ://test branch, "
        "and the BlockCipher ':' parse), the FactoryEntry vtables "
        "and their D2/D0/Matches/accessor slots, the std::function "
        "manager protocol, and the pthread_once call sites that run "
        "the host exactly once."
    ),
    "identity": {
        "catalogue_row": (
            "_ZZN7rocksdb12_GLOBAL__N_1L26RegisterEncryptionBuiltinsEvENKUlvE_clEv.isra.0"
        ),
        "catalogue_source": "docs/PROGRESS.md RE-002 vendor census row",
        "catalogue_match": "4550/5008 (90.85%) published-crate rebuild",
        "fde": "0x5ff88c0..0x5ff9c50",
        "cold_fde": "0x5ff844a..0x5ff88b7",
        "thunk_fde": "0x5ff9c50..0x5ff9c59",
    },
    "host": {
        "addr": 100632768,
        "fde": "0x5ff88c0..0x5ff9c50",
        "cold_fde": "0x5ff844a..0x5ff88b7",
        "size": 5008,
        "role": (
            "The lambda inside RegisterEncryptionBuiltins.  Block 1 "
            "calls the registry getter 0x61f92b0 (pinned by PR #4015), "
            "builds a 0x90-byte make_shared ObjectLibrary block named "
            "'encryption' (control-block vtable 0x64d00f0, counts "
            "0x100000001 from the global at 0x459b20, version float "
            "1.0, SSO name string), and appends it to the registry "
            "libraries vector under the registry mutex (registry+0x98) "
            "via pthread_mutex_lock/unlock; the use-count bump is a "
            "lock addl gated on the byte at GOT 0x64ed290.  Blocks 2-4 "
            "each build one FactoryEntry record (operator new 0x30) "
            "with its PatternEntry (operator new 0x70) and register it "
            "through the helper 0x5ff8260.  The host's only direct "
            "referrer is the 9-byte tail-call thunk 0x5ff9c50."
        ),
        "excerpt": "host-5ff88c0.objdump.txt",
        "cold_excerpt": "host-cold-5ff844a.objdump.txt",
        "thunk_excerpt": "thunk-5ff9c50.objdump.txt",
    },
    "once_callers": {
        "role": (
            "The thunk 0x5ff9c50 (endbr64; jmp host) is taken as the "
            "pthread_once callable at two lea sites: 0x5ffa77f inside "
            "FDE 0x5ffa710..0x5ffaad9 and 0x5ffba7f inside FDE "
            "0x5ffba10..0x5ffbdd9.  Each stores the thunk address into "
            "the TLS once slot (GOT 0x64ed820) and calls pthread_once "
            "on the once control at 0x6505278.  The host therefore "
            "runs once, on first use, as a function-local-static "
            "initializer.  The two once-host FDEs are unnamed in the "
            "catalogue; they are recorded here by FDE range only."
        ),
        "lea_sites": ["0x5ffa77f", "0x5ffba7f"],
        "once_a_fde": "0x5ffa710..0x5ffaad9",
        "once_b_fde": "0x5ffba10..0x5ffbdd9",
        "once_a_callers": ["0x5ffad95", "0x5ffae40"],
        "once_b_callers": ["0x5ffbe10"],
        "init_array_entry": "0x5ffbe80 (tiny thunk: endbr64; jmp 0x5ff7c90)",
        "excerpts": ["once-a-5ffa710.objdump.txt", "once-b-5ffba10.objdump.txt"],
    },
    "library": {
        "name": "encryption",
        "name_literal": "0x431037",
        "block_size": 144,
        "control_block_vtable": "0x64d00f0",
        "control_block_typeinfo": (
            "St23_Sp_counted_ptr_inplaceIN7rocksdb13ObjectLibraryESaIvE"
            "LN9__gnu_cxx12_Lock_policyE2EE"
        ),
        "counts": 4294967297,
        "counts_global": "0x459b20",
        "version_float": 1.0,
        "version_bits": "0x3f800000",
        "vector_growth": (
            "Full libraries vector goes through vec-insert 0x5ff7960 "
            "(pinned by PR #4015) at call site 0x5ff99c8."
        ),
    },
    "register_helper": {
        "addr": 100631136,
        "fde": "0x5ff8260..0x5ff8449",
        "signature": "(registry, name_cstring)",
        "role": (
            "Locks the mutex at rdi, builds the name string from a "
            "C-string literal, calls find-or-insert 0x5fd1da0 "
            "(rdi=arg+0x28, rsi=name string; pinned by PR #3983), "
            "appends ONE qword (the record pointer, moved then "
            "zeroed) to that name's vector (end==capacity goes "
            "through vec-insert 0x5fd17c0, pinned by PR #3983), "
            "unlocks.  Its landing pad calls 0x5fefd5e."
        ),
        "call_sites": ["0x5ff8fc4", "0x5ff9266", "0x5ff9791"],
        "other_caller": "0x620868a (FDE 0x6208290..0x6208afa, TTL creator)",
        "excerpt": "register-5ff8260.objdump.txt",
    },
    "entries": [
        {
            "index": 1,
            "name": "EncryptionProvider",
            "name_literal": "0x43e76f",
            "creator": "E_",
            "invoke": "0x5ff6d60",
            "manager": "0x5fefa50",
            "manager_typeinfo": (
                "*ZZN7rocksdb12_GLOBAL__N_1L26RegisterEncryptionBuiltinsEv"
                "ENKUlvE_clEvEUlRKNSt7__cxx1112basic_stringIcSt11char_traits"
                "IcESaIcEEEPSt10unique_ptrINS_18EncryptionProviderE"
                "St14default_deleteISB_EEPS7_E_"
            ),
            "factory_vtable": "0x64d0090",
            "pattern": "CTR",
            "pattern_literal": "0x447699",
            "elements": [{"string": "://test", "mode": 2}],
            "element_literal": "0x435247",
            "element_mode_site": "movl $0x2,0xa0(%rsp) at 0x5ff8b89",
            "flag": 1,
            "register_call": "0x5ff8fc4",
        },
        {
            "index": 2,
            "name": "EncryptionProvider",
            "name_literal": "0x43e76f (carried in r12 from block 2)",
            "creator": "E0",
            "invoke": "0x5ff6a00",
            "manager": "0x5fefa80",
            "manager_typeinfo": (
                "*ZZN7rocksdb12_GLOBAL__N_1L26RegisterEncryptionBuiltinsEv"
                "ENKUlvE_clEvEUlRKNSt7__cxx1112basic_stringIcSt11char_traits"
                "IcESaIcEEEPSt10unique_ptrINS_18EncryptionProviderE"
                "St14default_deleteISB_EEPS7_E0_"
            ),
            "factory_vtable": "0x64d0090",
            "pattern": "1://test",
            "pattern_literal": "0x4429ae",
            "elements": [],
            "flag": 1,
            "register_call": "0x5ff9266",
            "note": (
                "Built in place (operator new 0x70, pattern string "
                "range-copied from the stack string at rsp+0xf0); "
                "both sub-pattern vectors are empty, so matching is "
                "exact-match only."
            ),
        },
        {
            "index": 3,
            "name": "BlockCipher",
            "name_literal": "0x43fa43",
            "creator": "Cipher",
            "invoke": "0x5ff7120",
            "manager": "0x5fefab0",
            "manager_typeinfo": (
                "*ZZN7rocksdb12_GLOBAL__N_1L26RegisterEncryptionBuiltinsEv"
                "ENKUlvE_clEvEUlRKNSt7__cxx1112basic_stringIcSt11char_traits"
                "IcESaIcEEEPSt10unique_ptrINS_11BlockCipherE"
                "St14default_deleteISB_EEPS7_E_"
            ),
            "factory_vtable": "0x64d00c0",
            "pattern": "ROT13",
            "pattern_literal": "0x4487d6",
            "elements": [{"string": ":", "mode": 3}],
            "element_literal": "0x441b18",
            "element_mode_site": "movl $0x3,0x90(%rsp) at 0x5ff9381",
            "flag": 1,
            "register_call": "0x5ff9791",
        },
    ],
    "pattern_entry": {
        "size": 112,
        "vtable": "0x64d8ed0",
        "typeinfo": "N7rocksdb13ObjectLibrary12PatternEntryE",
        "fields": [
            {"offset": 0, "what": "vtable pointer"},
            {"offset": 8, "what": "std::string pattern (0x20)"},
            {"offset": 40, "what": "size_t pattern-length copy"},
            {"offset": 48, "what": "std::vector<std::string> sub-patterns (0x20-byte elements)"},
            {"offset": 72, "what": "bool byte (1)"},
            {"offset": 80, "what": "pointer (0)"},
            {"offset": 88, "what": "std::vector<0x28-byte> sub-pattern elements: string at +0x00, mode at +0x20"},
        ],
        "note": (
            "Layout pinned by PR #3983; the host's scratch struct at "
            "rsp+0x130 confirms it field for field (pattern string "
            "at +0x08, length copy at +0x28, string vector at +0x30, "
            "flag byte at +0x48, pointer at +0x50, element vector at "
            "+0x58).  D2/D0/Matches/accessor are pinned by PR #3983 "
            "and cited here, not re-derived."
        ),
        "matcher": (
            "str-match 0x61f8430 + elem-match 0x61f8280 (PR #3983): "
            "empty +0x58 vector means exact match only (flag not "
            "checked); equal lengths with a non-empty vector means "
            "exact match with the flag set; otherwise the query must "
            "start with the pattern, every +0x58 element must match "
            "in sequence (element 0 governed by the initial mode 2; "
            "element i+1 governed by element i's mode), and the tail "
            "is decided by the last element's mode (2: reach the end; "
            "3/4: remainder after an optional '-' is digits / dotted "
            "digits with at least one digit; other modes accept)."
        ),
    },
    "factory_entry": {
        "size": 48,
        "fields": [
            {"offset": 0, "what": "vtable pointer"},
            {"offset": 8, "what": "PatternEntry*"},
            {"offset": 16, "what": "std::function functor storage (16 bytes, zeros for these stateless lambdas)"},
            {"offset": 32, "what": "std::function manager"},
            {"offset": 40, "what": "std::function invoker (_M_invoke)"},
        ],
        "vtables": [
            {
                "kind": "EncryptionProvider",
                "header": "0x64d0080",
                "vtable": "0x64d0090",
                "typeinfo": "N7rocksdb13ObjectLibrary12FactoryEntryINS_18EncryptionProviderEEE",
                "slots": [
                    {"slot": 0, "addr": "0x5fefbc0", "name": "D2", "fde": "0x5fefbc0..0x5fefc02"},
                    {"slot": 1, "addr": "0x5ff0060", "name": "D0", "fde": "0x5ff0060..0x5ff00aa"},
                    {"slot": 2, "addr": "0x5fefca0", "name": "forward Matches", "fde": "0x5fefca0..0x5fefcae"},
                    {"slot": 3, "addr": "0x5fefcb0", "name": "forward accessor", "fde": "0x5fefcb0..0x5fefcbe"},
                ],
            },
            {
                "kind": "BlockCipher",
                "header": "0x64d00b0",
                "vtable": "0x64d00c0",
                "typeinfo": "N7rocksdb13ObjectLibrary12FactoryEntryINS_11BlockCipherEEE",
                "slots": [
                    {"slot": 0, "addr": "0x5fefb70", "name": "D2", "fde": "0x5fefb70..0x5fefbb2"},
                    {"slot": 1, "addr": "0x5ff0010", "name": "D0", "fde": "0x5ff0010..0x5ff005a"},
                    {"slot": 2, "addr": "0x5fefc80", "name": "forward Matches", "fde": "0x5fefc80..0x5fefc8e"},
                    {"slot": 3, "addr": "0x5fefc90", "name": "forward accessor", "fde": "0x5fefc90..0x5fefc9e"},
                ],
            },
        ],
        "d2_role": (
            "Installs the base vtable; if the manager is non-null "
            "calls manager(this+0x10, this+0x10, op 3) -- a no-op for "
            "these managers -- then deletes the PatternEntry via its "
            "D0 (vtable slot 1).  The std::function member starts at "
            "+0x10, which is why D2 passes this+0x10."
        ),
        "d0_role": "Same as D2, plus operator delete(node, 0x30).",
        "forward_role": (
            "Slot 2 forwards to the PatternEntry vtable slot 2 "
            "(Matches 0x61f8670); slot 3 forwards to the PatternEntry "
            "vtable slot 3 (accessor 0x61f8120).  Both pinned by PR #3983."
        ),
    },
    "managers": {
        "addrs": ["0x5fefa50", "0x5fefa80", "0x5fefab0"],
        "signature": "(to=rdi, from=rsi, op=rdx)",
        "ops": {
            "0": "store the typeinfo object address at *rdi",
            "1": "store rsi at *rdi (functor clone)",
            "2": "return false, no memory effect (the effective clone is the bitwise movdqa copy of the {manager, functor} pair)",
            "3": "return false, no memory effect (destroy is a no-op for these stateless lambdas)",
        },
        "unused_typeinfo": (
            "0x64cf7e8 is an OptionTypeInfo::AsCustomSharedPtr<"
            "EncryptionProvider> lambda -- NOT used by the host; "
            "recorded only so it is not mistaken for a fourth creator."
        ),
    },
    "creators": [
        {
            "id": "E0",
            "invoke": "0x5ff6a00",
            "fde": "0x5ff6a00..0x5ff6c70",
            "role": (
                "Builds a CTREncryptionProvider via C1 0x5ff6880 "
                "(catalogue: rocksdb::CTREncryptionProvider::C1, "
                "225/248 published-crate rebuild) from a BlockCipher "
                "looked up in the registry (virtual call at "
                "0x5ff6c33), then registers options via "
                "Configurable::RegisterOptions 0x6099ce0 (catalogue: "
                "317/340).  Uses vtables 0x64d0160/0x64cfea0/0x64cffa0/"
                "0x64d3420 and the global at 0x65052c0."
            ),
            "excerpt": "invoke-e0-5ff6a00.objdump.txt",
        },
        {
            "id": "E_",
            "invoke": "0x5ff6d60",
            "fde": "0x5ff6d60..0x5ff70a7",
            "role": (
                "Checks EndsWith(name, \"://test\") via 0x61d1390 "
                "(catalogue: rocksdb::EndsWith, 72/75) with the "
                "literal \"://test\" built inline on the stack.  On "
                "the true branch it builds the string "
                "\"ROT13BlockCipherOptions\" (literal 0x443890) via "
                "the string ctor and then builds the provider via C1 "
                "0x5ff6880; on the false branch (0x5ff6f70) it builds "
                "the provider directly.  Calls 0x61d1390 first to "
                "resolve the options name."
            ),
            "excerpt": "invoke-e_-5ff6d60.objdump.txt",
        },
        {
            "id": "Cipher",
            "invoke": "0x5ff7120",
            "fde": "0x5ff7120..0x5ff7419",
            "role": (
                "Finds ':' in the name with string::find, calls the "
                "9-byte jump thunk 0x61d1ef0 (jmp 0x61d1540), builds "
                "\"ROT13BlockCipherOptions\" (literal 0x443890), and "
                "creates the ROT13 cipher.  A bad substring throws "
                "out_of_range via __throw_out_of_range_fmt with the "
                "format string at 0x958cf8 ('%s: __pos (which is %zu) "
                "> this->size() (which is %zu)') and 'basic_string::"
                "substr' at 0x43e542."
            ),
            "excerpt": "invoke-cipher-5ff7120.objdump.txt",
        },
    ],
    "helpers": [
        {
            "addr": "0x5ff0300",
            "fde": "0x5ff0300..0x5ff03e3",
            "role": "std::string ctor from const char* (strlen, SSO <=15 else _M_create+memcpy; null throws logic_error via 0x963298).",
            "excerpt": "string-ctor-5ff0300.objdump.txt",
        },
        {
            "addr": "0x5fefd80",
            "fde": "0x5fefd80..0x5fefe23",
            "role": "std::string assign from a [begin, end) range; used for the pattern-string copies and the element inserts.",
            "excerpt": "string-range-5fefd80.objdump.txt",
        },
        {
            "addr": "0x5ff7420",
            "fde": "0x5ff7420..0x5ff7811",
            "role": (
                "Vector growth/reallocation helper for the PatternEntry "
                "0x28-byte element vector: (vec, pos=end, elem-string, "
                "mode-ptr).  Grows by doubling with overflow checks "
                "(0xcccccccccccccccd / 0x3333333333333333 division "
                "constants), deep-copies 0x28-byte {string, mode} "
                "elements (SSO fast path, _M_create for long strings, "
                "memcpy, mode u32 at +0x20).  Called from the host's "
                "cold blocks 0x5ff99bb and 0x5ff9a05."
            ),
            "excerpt": "vec-grow-5ff7420.objdump.txt",
        },
        {
            "addr": "0x5ff7900",
            "fde": "0x5ff7900..0x5ff7952",
            "role": (
                "_Sp_counted_ptr_inplace<ObjectLibrary>::_M_dispose "
                "(catalogue: 72/82 published-crate rebuild) -- the "
                "library control-block dispose (vtable slot 2).  The "
                "other LibCB slots (0x5fefc70, 0x5fefd00, 0x5fefd50, "
                "0x5feff70) are cited from the RELATIVE records, not "
                "individually disassembled."
            ),
            "excerpt": "libcb-dispose-5ff7900.objdump.txt",
        },
        {
            "addr": "0x61d1390",
            "fde": "0x61d1390..0x61d13db",
            "role": "rocksdb::EndsWith (catalogue: 72/75 published-crate rebuild); called by the E_ creator at 0x5ff6db6.",
            "excerpt": "endswith-61d1390.objdump.txt",
        },
        {
            "addr": "0x61d1ef0",
            "fde": "0x61d1ef0..0x61d1ef9",
            "role": "9-byte jump thunk (endbr64; jmp 0x61d1540); called by the BlockCipher creator at 0x5ff71ba.  The target 0x61d1540 is not pinned in this packet.",
            "excerpt": "cipher-jmp-61d1ef0.objdump.txt",
        },
    ],
    "literals": [
        {"addr": "0x431037", "value": "encryption"},
        {"addr": "0x435247", "value": "://test"},
        {"addr": "0x43e76f", "value": "EncryptionProvider"},
        {"addr": "0x43fa43", "value": "BlockCipher"},
        {"addr": "0x441b18", "value": ":"},
        {"addr": "0x4429ae", "value": "1://test"},
        {"addr": "0x443890", "value": "ROT13BlockCipherOptions"},
        {"addr": "0x447699", "value": "CTR"},
        {"addr": "0x4487d6", "value": "ROT13"},
        {"addr": "0x43e542", "value": "basic_string::substr"},
        {"addr": "0x958cf8", "value": "%s: __pos (which is %zu) > this->size() (which is %zu)"},
    ],
    "cited_not_rederived": {
        "reg_getter_0x61f92b0": "PR #4015 (ObjectRegistry lifecycle).",
        "find_or_insert_0x5fd1da0": "PR #3983 (ObjectLibrary registry).",
        "vec_insert_0x5fd17c0": "PR #3983.",
        "vec_insert_0x5ff7960": "PR #4015 (libraries-vector growth).",
        "pattern_d2_0x5ff2030": "PR #3983.",
        "pattern_d0_0x5ff2150": "PR #3983.",
        "pattern_matches_0x61f8670": "PR #3983.",
        "pattern_accessor_0x61f8120": "PR #3983.",
        "str_match_0x61f8430": "PR #3983.",
        "elem_match_0x61f8280": "PR #3983.",
        "map_destroy_0x5ff7820": "PR #3983 (registry teardown).",
        "register_options_0x6099ce0": "catalogue: Configurable::RegisterOptions, 317/340.",
        "ctr_ctor_0x5ff6880": "catalogue: CTREncryptionProvider::C1, 225/248.",
        "endswith_0x61d1390": "catalogue: rocksdb::EndsWith, 72/75; excerpted here because the E_ creator calls it.",
        "libcb_dispose_0x5ff7900": "catalogue: _Sp_counted_ptr_inplace<ObjectLibrary>::_M_dispose, 72/82; excerpted here because the host creates the library.",
    },
    "open_unknowns": [
        "The exact std::function member layout question is answered in this packet: the function object starts at FactoryEntry+0x10 (functor 16B, manager +0x20, invoker +0x28); D2 passes this+0x10 because that IS the std::function.",
        "ObjectRegistry +0x70..0x98 region (from PR #4015, still open): the host touches the registry mutex at +0x98 but the +0x70..0x98 fields are not pinned here.",
        "The two pthread_once host FDEs (0x5ffa710..0x5ffaad9, 0x5ffba10..0x5ffbdd9) are unnamed in the catalogue; only their once-callable role is pinned.",
        "The E0 creator's cipher-lookup name (the virtual call at 0x5ff6c33) is not pinned; the model resolves it through the registered BlockCipher entries.",
        "The E_ creator's fallback path (0x5ff6f70) builds the provider directly; which cipher it uses by default is not pinned.",
        "The BlockCipher creator's jump target 0x61d1540 is not pinned.",
        "The LibCB slots 0x5fefc70 / 0x5fefd00 / 0x5fefd50 / 0x5feff70 are cited from RELATIVE records, not individually disassembled.",
        "The .init_array entry 0x5ffbe80 (endbr64; jmp 0x5ff7c90) is the static-initialization chain entry in the encryption area; the full chain from 0x5ff7c90 to the once hosts is not traced.",
    ],
    "model": {
        "tool": "tools/register_encryption_builtins_115.py",
        "tests": "tests/test_register_encryption_builtins_115.py",
        "checks": 143,
    },
}


def main():
    (PACKET / "records.json").write_text(
        json.dumps(RECORDS, indent=1) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
