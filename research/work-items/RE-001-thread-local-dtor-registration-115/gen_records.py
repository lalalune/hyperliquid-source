#!/usr/bin/env python3
"""Generate records.json for RE-001-thread-local-dtor-registration-115.

Semantic records only: no per-instruction mnemonic list anywhere in this
packet (instruction-level detail lives verbatim in excerpts/*.txt). The
per-dtor shape table below was read by hand from the whole-function
excerpts; site counts and TLS offsets are computed from callers.tsv, which
census.py regenerates from the binary.

Usage: python3 gen_records.py
"""
import collections
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BIN = HERE.parents[2] / "work" / "hl-node-115.bin"
PROV = HERE.parents[2] / "provenance" / "artifacts.json"

# address -> (state_byte_offset, shape, drop_targets)
# shape names are descriptive labels for the observed body, not Rust types:
# no symbol names survive for these destructors, so no source type is claimed.
DTORS = {
    0x15B6CA0: (0x20, "slice-drop", {"drop": "0x64df4a0 -> 0x635de30"}),
    0x15B6CC0: (0x48, "arc-dec", {"state-0": "0x64dfdb8 -> 0x5ce86d0",
                                  "state-1": "0x64dfdc8 -> 0x5ce8da0"}),
    0x1619FE0: (0x08, "arc-dec-call", {"drop": "0x64e19c0 -> 0x5cd8910"}),
    0x16293A0: (0xA0, "multi-slice-drop", {"drop": "0x64df4a0 -> 0x635de30 (x3)"}),
    0x16F0F10: (0x48, "arc-dec", {"state-0": "0x64dfdb8 -> 0x5ce86d0",
                                  "state-1": "0x64dfdc8 -> 0x5ce8da0"}),
    0x26A0570: (0x08, "inner-counter-callback", {"callback": "0x64e1fb8 -> 0x168abe0",
                                                 "panic": "0x64df848 -> 0x1681e40"}),
    0x26A05D0: (0x20, "slice-drop", {"drop": "0x64df4a0 -> 0x635de30"}),
    0x26A05F0: (0x48, "arc-dec", {"state-0": "0x64dfdb8 -> 0x5ce86d0",
                                  "state-1": "0x64dfdc8 -> 0x5ce8da0"}),
    0x2E941A0: (0x48, "arc-dec", {"state-0": "0x64dfdb8 -> 0x5ce86d0",
                                  "state-1": "0x64dfdc8 -> 0x5ce8da0"}),
    0x3F11060: (0x08, "inner-counter-callback", {"callback": "0x64e1fb8 -> 0x168abe0",
                                                 "panic": "0x64df848 -> 0x1681e40"}),
    0x3F110C0: (0x48, "arc-dec", {"state-0": "0x64dfdb8 -> 0x5ce86d0",
                                  "state-1": "0x64dfdc8 -> 0x5ce8da0"}),
    0x4752F70: (0x18, "oncecell-state", {"log": "0x64dfa18 -> 0x167bbb6"}),
    0x4752FE0: (0x38, "delegate-call", {"drop": "direct call 0x47426e0 on t+0x08"}),
    0x4780330: (0x20, "slice-drop", {"drop": "0x64df4a0 -> 0x635de30"}),
    0x4E390E0: (0x08, "inner-counter-callback", {"callback": "0x64e1fb8 -> 0x168abe0",
                                                 "panic": "0x64df848 -> 0x1681e40"}),
    0x4E39140: (0x48, "arc-dec", {"state-0": "0x64dfdb8 -> 0x5ce86d0",
                                  "state-1": "0x64dfdc8 -> 0x5ce8da0"}),
    0x4E39190: (0x20, "slice-drop", {"drop": "0x64df4a0 -> 0x635de30"}),
    0x5BB5200: (0x28, "global-refcount-dec", {"counter": "qword at 0x64fff20 via *0x64ec168"}),
    0x5BB9630: (0x08, "non-atomic-dec-tail", {"drop": "0x64e09a0 -> 0x5bb99c0"}),
    0x5BC1830: (0x08, "inner-counter-callback", {"callback": "0x64e1fb8 -> 0x168abe0",
                                                 "panic": "0x64df848 -> 0x1681e40"}),
    0x5C7F7D0: (0x08, "arc-dec-tail", {"drop": "0x64ec630 -> 0x5c98a80"}),
    0x5C7F7F0: (0x08, "call-then-arc-dec", {"first": "0x64e15a8 -> 0x5ca5650",
                                            "drop": "0x64e15b0 -> 0x5c98b90"}),
    0x5CCC7E0: (0x08, "inner-counter-callback", {"callback": "0x64e1fb8 -> 0x168abe0",
                                                 "panic": "0x64df848 -> 0x1681e40"}),
    0x5CD8510: (0x08, "arc-dec-tail", {"drop": "0x64e19c0 -> 0x5cd8910"}),
    0x5CDF3E0: (0x08, "arc-dec-call", {"drop": "0x64e17f8 -> 0x5ce9190"}),
    0x5CDF410: (0x48, "arc-dec", {"state-0": "0x64dfdb8 -> 0x5ce86d0",
                                  "state-1": "0x64dfdc8 -> 0x5ce8da0"}),
    0x5CFFCA0: (0x28, "arc-dec-at-0x10", {"drop": "0x64df850 -> 0x5cffff0"}),
    0x5D00840: (0x28, "arc-dec-at-0x10", {"drop": "0x64df850 -> 0x5cffff0"}),
}


def main():
    prov = json.loads(PROV.read_text())
    entry = next(e for e in prov["files"] if e["path"] == "artifacts/node/115/hl-node")
    digest = entry["sha256"]
    actual = hashlib.sha256(BIN.read_bytes()).hexdigest()
    assert actual == digest, f"binary digest mismatch: {actual} != {digest}"

    rows = [l.rstrip("\n").split("\t") for l in (HERE / "callers.tsv").read_text().splitlines()[1:]]
    assert len(rows) == 1153, f"expected 1153 census rows, got {len(rows)}"
    by_dtor = collections.Counter(r[3] for r in rows)
    by_tls = collections.Counter(r[4] for r in rows)
    assert set(by_dtor) == {f"0x{a:x}" for a in DTORS}, "dtor set drifted from the shape table"

    dtors = []
    for addr, (state_off, shape, targets) in sorted(DTORS.items()):
        key = f"0x{addr:x}"
        tls = sorted({r[4] for r in rows if r[3] == key})
        dtors.append({
            "address": key,
            "state_byte_offset": f"0x{state_off:x}",
            "shape": shape,
            "sites": by_dtor[key],
            "tls_offsets": tls,
            "drop_targets": targets,
        })

    records = {
        "task": "RE-001",
        "node": 115,
        "artifact": "work/hl-node-115.bin",
        "artifact_sha256": digest,
        "question": ("How does node #115 register thread-local destructors: "
                     "which routine, which dispatch (libc fast path vs "
                     "pthread-key fallback), what the fallback registry "
                     "holds, and how many registration sites exist?"),
        "tls_slots_relative_to_fs_0x0": {
            "guard": "-0x1150",
            "capacity": "-0x1148",
            "vec_ptr": "-0x1140",
            "count": "-0x1138",
            "guard_struct_ptr": "-0x428",
            "guard_epoch": "-0x420",
        },
        "register_dtor": {
            "address": "0x5ca0d20",
            "fde": ["0x5ca0d20", "0x5ca0e1f"],
            "signature": "(t, dtor) in (rdi, rsi); dso_handle passed as 0x64fe448",
            "fast_path": {
                "condition": "GOT 0x64ec9b0 (__cxa_thread_atexit_impl, dynsym 198) != 0",
                "action": "tail-jump *0x64ec9b0 with (dtor, t, 0x64fe448)",
            },
            "slow_path": {
                "guard_states": {"0": "active", "-1": "registration in progress",
                                 "1": "dtors drained; further registration panics"},
                "key_enable": "0x5ca0e20",
                "vec_entry_bytes": 16,
                "vec_entry": ["t", "dtor"],
                "grow": "call *0x64ec878 -> 0x5c8b620 when count == capacity; "
                         "helper 0x5c8b980 sets new capacity = max(4, 2 * old capacity) "
                         "(rsi = old+1, rcx = 2*old, r14 = rsi >= 5 ? rsi : 4), so the "
                         "first grow from capacity 0 yields 4",
                "append": "vec[count] = (t, dtor); count += 1; guard 0 -> -1 -> 0",
            },
            "dso_handle_slot": {"got": "0x64fe448", "relocation": "RELATIVE -> 0x64efa20 (__dso_handle)"},
        },
        "key_enable": {
            "address": "0x5ca0e20",
            "fde": ["0x5ca0e20", "0x5ca0eea"],
            "key_var": "0x64feda8 (BSS, initial 0; no relocation)",
            "key_dtor_fn_got": "0x64fedb0 RELATIVE -> 0x5ca53f0 (dtor runner)",
            "pthread_calls": {
                "pthread_key_create": "GOT 0x64ec9b8 (dynsym 199)",
                "pthread_key_delete": "GOT 0x64ec9c0 (dynsym 200)",
                "pthread_setspecific": "GOT 0x64ec9c8 (dynsym 201)",
            },
            "race": "CAS-installs the key; the loser deletes its spare key",
            "callers": ["0x5ca0d80 (register_dtor slow path)",
                        "0x5c9d286 (guard_alloc)",
                        "0x5ca4521 (guard_use)"],
        },
        "dtor_runner": {
            "address": "0x5ca53f0",
            "fde": ["0x5ca53f0", "0x5ca5510"],
            "entry_guard": "panics via *0x64e12e0 -> 0x1680b70 when guard != 0 at entry",
            "drain": "LIFO: count -= 1; entry = vec[count]; call entry.dtor(entry.t)",
            "teardown": {"free": "*0x64e20d8 (free) when the allocated flag is set",
                         "capacity": 0, "vec_ptr": "8 (Vec::new() dangling pointer for 8-aligned entries)",
                         "count": 0, "guard": "old guard + 1"},
            "guard_tail": "guard object at %fs:-0x428; if its refcount at guard+0x00 hits 0, "
                          "calls the guard dtor via GOT 0x64dfe58 -> 0x5c98b40",
        },
        "guard_alloc": {
            "address": "0x5c9d1f0",
            "fde": ["0x5c9d1f0", "0x5c9d323"],
            "size": "0x30 bytes via malloc (GOT 0x64e1570)",
            "fields": {"+0x00": "refcount = 1", "+0x08": 1,
                       "+0x10": "epoch from global counter at 0x6500050 (lock cmpxchg)",
                       "+0x18": 0, "+0x28": 0},
            "tls": "guard+0x10 stored at %fs:-0x428",
        },
        "guard_use": {
            "address": "0x5ca44a0",
            "fde": ["0x5ca44a0", "0x5ca469d"],
            "action": "lock incq (*guard); check %fs:-0x428 / epoch at %fs:-0x420; "
                      "key_enable; store guard+0x10 at %fs:-0x428",
        },
        "guard_free": {
            "address": "0x5c98b40",
            "fde": ["0x5c98b40", "0x5c98b89"],
            "action": "clear first byte of the string at guard+0x18; invoke callback at "
                      "guard+0x20 if non-null via *0x64df4a0; lock decq guard+0x08",
        },
        "grow_one": {
            "address": "0x5c8b620",
            "fde": ["0x5c8b620", "0x5c8b649"],
            "note": "catalogued as node115-std-5c8b620 (RE-002-node115-std-census); "
                    "called with rdi = &capacity slot (TLS -0x1148)",
        },
        "destructors": dtors,
        "census": {
            "sites": 1153,
            "distinct_caller_fdes": 604,
            "distinct_dtors": 28,
            "tls_offset_distribution": dict(sorted(by_tls.items(), key=lambda kv: -kv[1])),
            "dtor_site_counts": dict(sorted(by_dtor.items(), key=lambda kv: -kv[1])),
            "tls_objects": {
                "-0x1130": "845 sites, arc-dec dtors only (state byte +0x48)",
                "-0x1180": "287 sites, slice-drop dtors only (state byte +0x20)",
                "-0x10e0": "4 sites, 0x5cffca0 / 0x5d00840",
                "-0x470": "2 sites, 0x5c7f7f0",
                "-0x480": "2 sites, 0x5c7f7d0",
                "caller-passed": "13 sites, one per remaining dtor",
            },
            "unresolved": {"tls": 0, "dtor": 0},
            "guard_corrected": 13,
            "method_note": ("Sites found by byte-scan for `FF 15 <disp32>` targeting GOT "
                            "0x64e0510 and cross-checked against a full-.text objdump grep "
                            "(1153 both ways). A naive byte-level disp32 scan MISSES the "
                            "`cmpq $0, GOT 0x64ec9b0` at 0x5ca0d35 (its imm8 follows the "
                            "disp32); objdump is authoritative there. 13 sites needed a "
                            "guard-check cross-check because the linear data-flow walk "
                            "crossed a branch boundary (e.g. site 0x5a60547, walk -0x1131 "
                            "vs guard -0x1130). Offsets are canonical signed values: the "
                            "immediate 0xffffffffffffeed0 denotes -0x1130, "
                            "0xffffffffffffee80 denotes -0x1180."),
        },
        "relocations": {
            "0x64e0510": "RELATIVE -> 0x5ca0d20 (__cxa_thread_atexit)",
            "0x64fe448": "RELATIVE -> 0x64efa20 (__dso_handle)",
            "0x64ec9b0": "GLOB_DAT dynsym 198 __cxa_thread_atexit_impl@GLIBC_2.18",
            "0x64feda8": "none (BSS key var)",
            "0x64fedb0": "RELATIVE -> 0x5ca53f0",
            "0x64ec878": "RELATIVE -> 0x5c8b620",
            "0x64ec9b8": "GLOB_DAT dynsym 199 pthread_key_create@GLIBC_2.34",
            "0x64ec9c0": "GLOB_DAT dynsym 200 pthread_key_delete@GLIBC_2.34",
            "0x64ec9c8": "GLOB_DAT dynsym 201 pthread_setspecific@GLIBC_2.34",
            "0x64ec978": "GLOB_DAT dynsym 191 stat64@GLIBC_2.33",
            "0x64dfdc8": "RELATIVE -> 0x5ce8da0",
            "0x64dfdb8": "RELATIVE -> 0x5ce86d0",
            "0x64ec630": "RELATIVE -> 0x5c98a80",
            "0x64e15a8": "RELATIVE -> 0x5ca5650",
            "0x64e15b0": "RELATIVE -> 0x5c98b90",
            "0x64e19c0": "RELATIVE -> 0x5cd8910",
            "0x64e17f8": "RELATIVE -> 0x5ce9190",
            "0x64df850": "RELATIVE -> 0x5cffff0",
            "0x64dfe58": "RELATIVE -> 0x5c98b40",
            "0x64e12e0": "RELATIVE -> 0x1680b70",
            "0x64e02e8": "RELATIVE -> 0x5c9b050",
            "0x64e09a8": "RELATIVE -> 0x5c9d1c0",
            "0x64e1570": "GLOB_DAT malloc@GLIBC_2.2.5",
            "0x64e20d8": "GLOB_DAT free@GLIBC_2.2.5",
            "0x64df508": "GLOB_DAT memcpy@GLIBC_2.14",
            "0x64dffc8": "GLOB_DAT __errno_location@GLIBC_2.2.5",
            "0x64eaf20": "GLOB_DAT pthread_self@GLIBC_2.2.5",
            "0x64eca30": "GLOB_DAT pthread_setname_np@GLIBC_2.34",
            "0x64df4a0": "RELATIVE -> 0x635de30",
            "0x64df848": "RELATIVE -> 0x1681e40",
            "0x64e1fb8": "RELATIVE -> 0x168abe0",
            "0x64df4c0": "RELATIVE -> 0x1680cab",
            "0x64ec168": "RELATIVE -> 0x64fff20",
            "0x64e09a0": "RELATIVE -> 0x5bb99c0",
            "0x64dfa18": "RELATIVE -> 0x167bbb6",
        },
    }
    (HERE / "records.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"wrote records.json ({len(dtors)} destructors, 1153 census sites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
