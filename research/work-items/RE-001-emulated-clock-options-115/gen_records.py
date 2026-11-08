#!/usr/bin/env python3
"""Generate records.json (semantic records only) for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-emulated-clock-options-115/gen_records.py

The JSON holds semantic records only: map entries, accessor roles,
method contracts, censuses. It never contains a per-instruction
mnemonic list; instruction-level detail lives only in the verbatim
excerpt text files.
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

RECORDS = {
    "target": {
        "artifact": "work/hl-node-115.bin",
        "sha256": DIGEST,
        "node": 115,
    },
    "work_item": "RE-001-emulated-clock-options-115",
    "task": "RE-001",
    "question": (
        "What do the two option maps the EmulatedSystemClock ctor "
        "registers (0x6505960, 0x6505920) hold, which accessors do "
        "their records bind, and what do the two flags at +0x48/+0x49 "
        "do to SleepForMicroseconds and GetCurrentTime?"
    ),
    "correction_to_prior": (
        "RE-001-systemclock-installers-115 (merged PR #3948) records "
        "that the third fields of the ctor's two RegisterOptions "
        "records (0x6505960/0x6505920) are '.bss (runtime-initialized); "
        "their contents are not recoverable statically'. That is "
        "superseded here: the static initializer 0x6029d10 populates "
        "both maps at load time (via the .init_array jump stub "
        "0x602e4c0), and its inserts are pinned below. Nothing else "
        "in #3948 is re-pinned: the ctor, its callers, the factory, "
        "the dtors and the wrapper ctor are cited, not repeated."
    ),
    "initializer": {
        "addr": "0x6029d10",
        "fde": "0x6029d10..0x602a25d",
        "invocation": (
            "installed in .init_array via a RELATIVE reloc addend "
            "0x602e4c0; the 9-byte stub 0x602e4c0 (endbr64; jmp "
            "0x6029d10) tail-jumps into the initializer, so it runs at "
            "load time. No direct E8 caller exists anywhere."
        ),
        "helpers": {
            "key_builder": "0x60261f0 (builds the key string)",
            "record_init": "0x5e32920 (builds the OptionTypeInfo record)",
            "record_op": "0x5d400f0 (record transform before insert)",
            "insert": "0x5d405b0 (map insert helper)",
        },
    },
    "maps": [
        {
            "map": "0x6505960",
            "group": "first RegisterOptions record of the "
                     "EmulatedSystemClock ctor 0x6029390 (call 0x6029454; "
                     "name \"\", base this; pinned by merged #3948)",
            "key": "time_elapse_only_sleep",
            "key_literal": "0x4476c8",
            "key_lea_sites": ["0x6029d11"],
            "insert_site": "0x6029e6b",
            "lea_sites": ["0x602942b", "0x6029e50"],
            "getter": "0x6025e50",
            "setter": "0x6026ba0",
            "getter_manager": "0x6025850",
            "setter_manager": "0x6025820",
            "record_table": {
                "base": "-0x230(%rbp)",
                "slots": [
                    {"offset": "+0x00", "value": "0 (null function object)"},
                    {"offset": "+0x10",
                     "value": "(manager 0x6025820, fn 0x6026ba0) setter pair"},
                    {"offset": "+0x20", "value": "0 (null function object)"},
                    {"offset": "+0x30",
                     "value": "(manager 0x6025850, fn 0x6025e50) getter pair"},
                    {"offset": "+0x40", "value": "0 (null function object)"},
                ],
            },
        },
        {
            "map": "0x6505920",
            "group": "second RegisterOptions record of the "
                     "EmulatedSystemClock ctor 0x6029390 (call 0x6029494; "
                     "name \"\", base this; pinned by merged #3948)",
            "key": "mock_sleep",
            "key_literal": "0x4331d7",
            "key_lea_sites": ["0x6029f0b"],
            "insert_site": "0x6029fff",
            "lea_sites": ["0x6029471", "0x6029fe0"],
            "getter": "0x6026100",
            "setter": "0x6026ad0",
            "getter_manager": "0x60258b0",
            "setter_manager": "0x6025880",
            "record_table": {
                "base": "-0x230(%rbp)",
                "slots": [
                    {"offset": "+0x00", "value": "0 (null function object)"},
                    {"offset": "+0x10",
                     "value": "(manager 0x6025880, fn 0x6026ad0) setter pair"},
                    {"offset": "+0x20", "value": "0 (null function object)"},
                    {"offset": "+0x30",
                     "value": "(manager 0x60258b0, fn 0x6026100) getter pair"},
                    {"offset": "+0x40", "value": "0 (null function object)"},
                ],
            },
        },
    ],
    "third_insert_lead": {
        "map": "0x65058e0",
        "key": "supports_direct_io",
        "key_literal": "0x44657e",
        "key_lea_sites": ["0x602a093"],
        "insert_site": "0x602a19a",
        "lea_sites": ["0x6028b16", "0x602a17b"],
        "note": (
            "Same initializer, third insert; its record is built "
            "zeroed (no 0x5e32920 call in that block) and its group "
            "belongs to another host (0x6028a60, RegisterOptions site "
            "0x6028b3a, still unanalysed). Recorded as a lead only."
        ),
    },
    "accessors": [
        {
            "option": "time_elapse_only_sleep",
            "getter": "0x6025e50",
            "getter_fde": "0x6025e50..0x6025ea5",
            "getter_role": (
                "reads the flag byte at object+0x48 and writes "
                "\"true\" (literal 0x43f883) or \"false\" (literal "
                "0x430e89) into the out string; returns kOk Status"
            ),
            "setter": "0x6026ba0",
            "setter_fde": "0x6026ba0..0x6026c4b",
            "setter_role": (
                "parses the input with the bool parser 0x61d1480, then "
                "writes the parsed value into BOTH object+0x48 and "
                "object+0x49 (xchg into +0x48, mov into +0x49); "
                "returns kOk Status"
            ),
        },
        {
            "option": "mock_sleep",
            "getter": "0x6026100",
            "getter_fde": "0x6026100..0x6026155",
            "getter_role": (
                "reads the flag byte at object+0x49 and writes "
                "\"true\" or \"false\" into the out string; returns "
                "kOk Status"
            ),
            "setter": "0x6026ad0",
            "setter_fde": "0x6026ad0..0x6026b77",
            "setter_role": (
                "parses the input with the bool parser 0x61d1480, then "
                "writes the parsed value into object+0x49 only; "
                "returns kOk Status"
            ),
        },
    ],
    "managers": {
        "shape": (
            "one 0x2d-byte template: op 0 stores the lambda typeinfo "
            "into *rdi, op 1 stores rsi into *rdi, any other op "
            "returns 0"
        ),
        "instances": [
            {"addr": "0x6025820", "role": "time_elapse setter manager",
             "typeinfo": "0x64d1300",
             "typeinfo_name": "*N7rocksdb12_GLOBAL__N_1L21time_elapse_type_infoMUlRKNS_13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESC_PvE_E"},
            {"addr": "0x6025850", "role": "time_elapse getter manager",
             "typeinfo": "0x64d1310",
             "typeinfo_name": "*N7rocksdb12_GLOBAL__N_1L21time_elapse_type_infoMUlRKNS_13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPKvPSA_E_E"},
            {"addr": "0x6025880", "role": "mock_sleep setter manager",
             "typeinfo": "0x64d1320",
             "typeinfo_name": "*N7rocksdb12_GLOBAL__N_1L20mock_sleep_type_infoMUlRKNS_13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESC_PvE_E"},
            {"addr": "0x60258b0", "role": "mock_sleep getter manager",
             "typeinfo": "0x64d1330",
             "typeinfo_name": "*N7rocksdb12_GLOBAL__N_1L20mock_sleep_type_infoMUlRKNS_13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPKvPSA_E_E"},
        ],
    },
    "bool_parser": {
        "addr": "0x61d1480",
        "fde": "0x61d1480..0x61d1504",
        "accepted": {
            "true": ["\"true\" (len 4)", "\"1\" (len 1)"],
            "false": ["\"false\" (len 5)", "\"0\" (len 1)"],
        },
        "rejected": (
            "any other spelling jumps to the shared throw block at "
            "0x61d1437 (allocates 0x10 bytes, throws via 0x63f1960 / "
            "0x63f1200)"
        ),
        "callers": ["0x6026b14", "0x6026be4", "0x6082f3f", "0x60830bb",
                    "0x608315a", "0x60bf3bd"],
    },
    "methods": [
        {
            "name": "SleepForMicroseconds",
            "vtable_slot": 23,
            "addr": "0x6025b40",
            "fde": "0x6025b40..0x6025b7f",
            "contract": (
                "atomically increments the sleep-call counter at "
                "object+0x38; if mock_sleep (+0x49) or "
                "time_elapse_only_sleep (+0x48) is set, advances the "
                "emulated-time offset at object+0x40 (microseconds) "
                "by the requested duration; if mock_sleep is clear, "
                "also performs the real sleep by delegating to the "
                "wrapped clock's slot 23; if neither flag is set, "
                "delegates to the wrapped clock's slot 23 with no "
                "offset advance"
            ),
        },
        {
            "name": "GetCurrentTime",
            "vtable_slot": 24,
            "addr": "0x6025eb0",
            "fde": "0x6025eb0..0x6025feb",
            "contract": (
                "if time_elapse_only_sleep (+0x48) is set, writes the "
                "stored emulated time at object+0x30 into the out "
                "slot and returns kOk; otherwise delegates to the "
                "wrapped clock's slot 24 with the same out slots. "
                "Then, when the Status is kOk, BOTH paths add the "
                "+0x40 offset converted from microseconds to whole "
                "seconds (signed division by 1,000,000 via the "
                "magic-multiply idiom at 0x6025f92..0x6025fae, magic "
                "0x431bde82d7b634db); the add is skipped on an error "
                "Status (jne 0x6025f03). The ctor seeds +0x30 from "
                "the wrapped clock's slot 24 (pinned by merged #3948)"
            ),
        },
    ],
    "object_layout": {
        "0x20": "shared_ptr<SystemClock> wrapped clock object pointer",
        "0x28": "shared_ptr<SystemClock> control block pointer",
        "0x30": "stored emulated time (GetCurrentTime value, seeded by the ctor)",
        "0x38": "sleep-call counter (u32, atomically incremented by SleepForMicroseconds)",
        "0x40": "emulated-time offset in microseconds (added by NowMicros/NowNanos; advanced by SleepForMicroseconds)",
        "0x48": "time_elapse_only_sleep flag byte (bool)",
        "0x49": "mock_sleep flag byte (bool)",
    },
    "cited_not_pinned": {
        "ctor_0x6029390": "EmulatedSystemClock ctor (merged #3948)",
        "dtors_0x6029110_0x6029620": "EmulatedSystemClock D2/D0 (merged #3948)",
        "now_micros_0x60259e0": (
            "NowMicros contract (RE-001-delegate-vtable-115): wrapped "
            "slot 0x98 plus the +0x40 offset when +0x48 is clear"
        ),
        "now_nanos_0x60259a0": (
            "NowNanos (vendor census RE-002): wrapped slot 0xa0 plus "
            "+0x40 * 1000"
        ),
        "wrapper_vtable_slots": (
            "SystemClockWrapper 26 slots (merged #3902); the shared "
            "Configurable slots 2..18 are the same methods"
        ),
        "slot_names": (
            "slot 19 NowMicros, slot 20 NowNanos, slot 23 "
            "SleepForMicroseconds, slot 24 GetCurrentTime "
            "(vendor census RE-002-node115-rocksdb-clock-emulated-vtable)"
        ),
    },
    "open_unknowns": [
        "Final OptionTypeInfo record offsets: the record-init helper "
        "0x5e32920 and transform 0x5d400f0 place the getter/setter "
        "pairs into the record; the table slots are pinned, the final "
        "record offsets are not.",
        "Why the time_elapse_only_sleep setter writes mock_sleep too: "
        "recorded as observed behavior; the upstream intent (whether "
        "time-elapse mode implies mocked sleep) is not pinned.",
        "The third insert's zeroed record: what 0x5d400f0 fills into "
        "the 'supports_direct_io' record, and which host registers "
        "the 0x65058e0 group (host 0x6028a60, site 0x6028b3a).",
        "The 0x4fb647d0 fallback constant's unit (seconds since epoch "
        "would read 2012-05-14; the value is recorded verbatim).",
        "Slots 21/22 (0x6025a30/0x6025a10) and slot 25 (0x5fcc3a0) "
        "bodies: cited by address only.",
    ],
}


def main() -> None:
    (HERE / "records.json").write_text(
        json.dumps(RECORDS, indent=2) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
