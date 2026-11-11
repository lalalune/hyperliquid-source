"""Generate records.json for RE-001-zstd-compress-cache-115.

Run from the repository root:
    python3 research/work-items/RE-001-zstd-compress-cache-115/gen_records.py

Derives the windows (FDE ranges from objdump --dwarf=frames), the
caller census (from census.py's binary scan) and the per-window sample
bytes (from the raw binary) directly from the digest-verified binary.
The semantic constants (layout, rules, roles, the decoded jump-table
arm maps) are the packet author's readings of the verbatim excerpts,
recorded here so the checker can re-derive them; the model in tools/
implements the same rules and its tests exercise them end to end.
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
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = {
    "factory": ("0x61c1c10", "0x61c1cc8"),
    "factory_landing": ("0x61c1bee", "0x61c1c03"),
    "create_cctx": ("0x6218920", "0x6218996"),
    "reset": ("0x62188a0", "0x621891a"),
    "free_cdict": ("0x62187a0", "0x621889b"),
    "setparam": ("0x6212010", "0x6212101"),
    "apply": ("0x6211a10", "0x621200c"),
    "range_check": ("0x62119e0", "0x6211a08"),
    "bounds": ("0x62117e0", "0x62119d9"),
    "refresh": ("0x5f041d0", "0x5f0441c"),
}

# Caller roles, read from objdump around each census site. The FDE is
# the containing function; no symbol names exist in the stripped binary
# except where the vendor census names the function (noted as such).
CALLER_ROLES = {
    0x5F0430B: "refresh routine AddCompressionTypeRecord: installs the "
               "factory product at owner+0x48 beside a fresh array at +0x50",
    0x5E21E10: "CCtx-create consumer in FDE 0x5e21b00 (exact use open)",
    0x60E582A: "CCtx-create consumer in FDE 0x60e5610 (exact use open)",
    0x60EA2ED: "CCtx-create consumer in FDE 0x60e8ab0, which also frees "
               "a CDict at 0x60eb639 (exact use open)",
    0x61C1C83: "factory: the CCtx for the new 0x70-byte holder",
    0x62AAA4F: "CCtx-create consumer in FDE 0x62aa6f0, which also frees "
               "a CDict at 0x62ab308 (exact use open)",
    0x62AD810: "CCtx-create consumer in FDE 0x62ad760, which frees four "
               "CDicts (exact use open)",
    0x6218952: "create: resets the fresh calloc'd context",
    0x5D41FC0: "CDict-free consumer in FDE 0x5d41fb0 (exact use open)",
    0x60E8480: "CDict-free consumer in FDE 0x60e8220 (exact use open)",
    0x60EB639: "CDict-free consumer in FDE 0x60e8ab0, which also creates "
               "a CCtx at 0x60ea2ed (exact use open)",
    0x60EF940: "CDict-free consumer in FDE 0x60ef340 (exact use open)",
    0x62188CC: "reset: frees the CCtx's +0xe68 CDict",
    0x62190D3: "CDict-free consumer in FDE 0x62189a0, the large function "
               "right after the create (exact use open)",
    0x6219B2F: "CDict-free consumer in FDE 0x6219ac0 (exact use open)",
    0x6219C9C: "CDict-free consumer in FDE 0x6219c20 (exact use open)",
    0x62AB308: "CDict-free consumer in FDE 0x62aa6f0, which also creates "
               "a CCtx at 0x62aaa4f (exact use open)",
    0x62AD8CE: "CDict-free consumer in FDE 0x62ad760 (four sites in one "
               "function; exact use open)",
    0x62AD91D: "CDict-free consumer in FDE 0x62ad760 (four sites in one "
               "function; exact use open)",
    0x62AD941: "CDict-free consumer in FDE 0x62ad760 (four sites in one "
               "function; exact use open)",
    0x62AD955: "CDict-free consumer in FDE 0x62ad760 (four sites in one "
               "function; exact use open)",
    0x61C1C99: "factory: sets parameter 201 to 1 on the fresh CCtx",
    0x6212036: "setter: tail-jumps into the apply worker with "
               "params = ctx+0x10",
    0x62119E4: "range-check helper: bounds lookup for its caller",
    0x6211B5D: "apply arm for param 1011: bounds lookup, inlined check",
    0x6211BD5: "apply arm for param 1013: bounds lookup, inlined check",
    0x6211D64: "apply arm for param 100: bounds lookup, clamp",
    0x5E5C5A3: "the refresh routine's one caller, FDE 0x5e5c270 "
               "(exact use open)",
    0x5F03EE3: "AddRecord (census): emits a physical record via 0x5f03b80",
    0x5F04294: "refresh routine: emits the 4-byte kind record (type 9)",
    0x5E2641B: "shared 4-byte copy helper consumer in FDE 0x5e26300",
    0x5E26987: "shared 4-byte copy helper consumer in FDE 0x5e265c0",
    0x5F03B25: "shared 4-byte copy helper consumer in FDE 0x5f03a90",
    0x5F04105: "shared 4-byte copy helper consumer in FDE 0x5f03d60 "
               "(AddRecord, census)",
    0x5F04394: "refresh routine: 4-byte copy of owner+0x00 into the "
               "template slot (overwritten by the global-qword fill)",
    0x5FCE232: "shared 4-byte copy helper consumer in FDE 0x5fce130",
    0x5FCE6B8: "shared 4-byte copy helper consumer in FDE 0x5fce280",
    0x605269A: "shared 4-byte copy helper consumer in FDE 0x60525b0",
    0x60528A6: "shared 4-byte copy helper consumer in FDE 0x6052800",
    0x6052E6C: "shared 4-byte copy helper consumer in FDE 0x6052b80",
    0x6054B5D: "shared 4-byte copy helper consumer in FDE 0x6054680",
    0x6054EF4: "shared 4-byte copy helper consumer in FDE 0x6054680",
    0x6054FA1: "shared 4-byte copy helper consumer in FDE 0x6054680",
}

# Range-check call site -> the parameter id in %edi at the call,
# read from the apply excerpt (see the arm map in records.json).
RANGE_CHECK_PARAM = {
    0x6211AA8: 1016, 0x6211AE8: 1008, 0x6211B10: 1009, 0x6211B38: 1010,
    0x6211BA0: 1012, 0x6211C18: 1014, 0x6211C45: 1015, 0x6211C75: 1004,
    0x6211CB8: 1006, 0x6211CE0: 1007, 0x6211D08: 1001, 0x6211D30: 1002,
    0x6211DAC: 101, 0x6211DD2: 102, 0x6211DF8: 103, 0x6211E1E: 104,
    0x6211E44: 105, 0x6211E65: 106, 0x6211E8B: 107, 0x6211EC1: 130,
    0x6211EE2: 160, 0x6211F08: 163, 0x6211F2E: 164, 0x6211F80: 161,
    0x6211FA2: 162, 0x6211FC7: 10,
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


def main():
    data = open(BIN, "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        print("binary digest mismatch")
        return 1
    sys.path.insert(0, HERE)
    import census as census_mod
    calls, tails, hits, slots = census_mod.scan(BIN)
    fdes = fde_table()

    windows = {}
    for name, (start, end) in WINDOWS.items():
        s, e = int(start, 16), int(end, 16)
        match = [f for f in fdes if f[0] == s and f[1] == e]
        if not match:
            print("no FDE for", name)
            return 1
        off, cie = match[0][2], match[0][3]
        first_bytes = data[s - 0x1000: s - 0x1000 + 4].hex()
        windows[name] = {
            "start": start, "end": end, "size_bytes": e - s,
            "fde_offset": "0x" + off, "cie_offset": "0x" + cie,
            "first_instruction_bytes": first_bytes,
        }

    census = {}
    for t in census_mod.TARGETS:
        census[hex(t)] = {
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
            role = CALLER_ROLES.get(site, "")
            if t == 0x62119E0 and site in RANGE_CHECK_PARAM:
                role = ("apply arm for param %d: range-checks the value"
                        % RANGE_CHECK_PARAM[site])
            rows.append({
                "site": hex(site), "kind": "direct_call",
                "containing_fde": [fs, fe],
                "role": role,
            })
        for site in tails[t]:
            fs, fe = containing(fdes, site)
            rows.append({
                "site": hex(site), "kind": "tail_jump",
                "containing_fde": [fs, fe],
                "role": CALLER_ROLES.get(site, ""),
            })
        callers[hex(t)] = rows

    bounds = {
        "10": [0, 1], "100": [-131072, 22], "101": [10, 31],
        "102": [6, 30], "103": [6, 30], "104": [1, 30],
        "105": [3, 7], "106": [0, 131072], "107": [1, 9],
        "130": [1340, 131072], "160": [0, 2], "161": [6, 30],
        "162": [4, 4096], "163": [1, 8], "164": [0, 25],
        "200": [0, 1], "201": [0, 1], "202": [0, 1],
        "400": [0, 0], "401": [0, 0], "402": [0, 0],
        "500": [0, 1], "1000": [0, 1], "1001": [0, 3],
        "1002": [0, 2], "1004": [0, 2147483647],
        "1005": [0, 1], "1006": [0, 1], "1007": [0, 1],
        "1008": [0, 1], "1009": [0, 1], "1010": [0, 1],
        "1011": [0, 2], "1012": [0, 1], "1013": [1024, 131072],
        "1014": [0, 1], "1015": [0, 2], "1016": [1024, 131072],
    }
    apply_arms = {
        "10": {"field": "+0x00", "kind": "range-checked dword store"},
        "100": {"field": "+0x2c",
                "kind": "clamp to bounds; 0 means default level 3; "
                        "returns the clamped value, 0 when negative"},
        "101": {"field": "+0x04", "kind": "range-checked dword store"},
        "102": {"field": "+0x0c", "kind": "range-checked dword store"},
        "103": {"field": "+0x08", "kind": "range-checked dword store"},
        "104": {"field": "+0x10", "kind": "range-checked dword store"},
        "105": {"field": "+0x14", "kind": "range-checked dword store"},
        "106": {"field": "+0x18", "kind": "range-checked dword store"},
        "107": {"field": "+0x1c", "kind": "range-checked dword store"},
        "130": {"field": "+0x38",
                "kind": "0 stores 0; else max(value, 1340), "
                        "range-checked, 64-bit store"},
        "160": {"field": "+0x60", "kind": "range-checked dword store"},
        "161": {"field": "+0x64", "kind": "range-checked dword store"},
        "162": {"field": "+0x6c", "kind": "range-checked dword store"},
        "163": {"field": "+0x68", "kind": "range-checked dword store"},
        "164": {"field": "+0x70", "kind": "range-checked dword store"},
        "200": {"field": "+0x20", "kind": "boolean (value != 0) store"},
        "201": {"field": "+0x24", "kind": "boolean (value != 0) store"},
        "202": {"field": "+0x28", "kind": "boolean (value == 0) store"},
        "400": {"field": "none",
                "kind": "returns 0 iff value == 0, else -40"},
        "401": {"field": "none",
                "kind": "returns 0 iff value == 0, else -40"},
        "402": {"field": "none",
                "kind": "returns 0 iff value == 0, else -40"},
        "500": {"field": "none",
                "kind": "returns 0 iff value == 0, else -40"},
        "1000": {"field": "+0x30", "kind": "boolean (value != 0) store"},
        "1001": {"field": "+0x44", "kind": "range-checked dword store"},
        "1002": {"field": "+0x48", "kind": "range-checked dword store"},
        "1004": {"field": "+0x40", "kind": "range-checked dword store"},
        "1005": {"field": "+0x78", "kind": "boolean (value != 0) store"},
        "1006": {"field": "+0x7c", "kind": "range-checked dword store"},
        "1007": {"field": "+0x80", "kind": "range-checked dword store"},
        "1008": {"field": "+0x84", "kind": "range-checked dword store"},
        "1009": {"field": "+0x88", "kind": "range-checked dword store"},
        "1010": {"field": "+0x8c", "kind": "range-checked dword store"},
        "1011": {"field": "+0x90",
                 "kind": "bounds lookup inlined; range-checked dword store"},
        "1012": {"field": "+0x94",
                 "kind": "range-checked, then boolean (value != 0) store"},
        "1013": {"field": "+0xb0",
                 "kind": "bounds lookup inlined; range-checked dword store"},
        "1014": {"field": "+0xb4", "kind": "range-checked dword store"},
        "1015": {"field": "+0xc8",
                 "kind": "0 stores 0; else range-checked, 64-bit store"},
        "1016": {"field": "+0xd0", "kind": "range-checked dword store"},
    }

    records = {
        "artifact": "work/hl-node-115.bin",
        "artifact_sha256": DIGEST,
        "provenance_path": "artifacts/node/115/hl-node",
        "task": "RE-001",
        "vendor_attribution": {
            "factory": {
                "catalogue_id": "node115-vendor-61c1c10",
                "label": "librocksdb-sys 0.11.0+8.1.1: "
                         "_ZN7rocksdb17StreamingCompress6CreateENS_15"
                         "CompressionTypeERKNS_18CompressionOptionsEjm",
                "non_relocation_bytes_equal": "167/184",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "refresh": {
                "catalogue_id": "node115-vendor-5f041d0",
                "label": "librocksdb-sys 0.11.0+8.1.1: "
                         "_ZN7rocksdb3log6Writer24AddCompressionTypeRecordEv",
                "non_relocation_bytes_equal": "547/588",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "free_cdict": {
                "catalogue_id": "node115-vendor-62187a0",
                "label": "zstd-sys 2.0.15+zstd.1.5.7/2.1.2+zstd.1.5.7: "
                         "ZSTD_freeCDict",
                "non_relocation_bytes_equal": "242/251",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "emit": {
                "catalogue_id": "node115-vendor-5f03b80",
                "label": "librocksdb-sys 0.11.0+8.1.1: "
                         "_ZN7rocksdb3log6Writer18EmitPhysicalRecordENS0_10"
                         "RecordTypeEPKcmNS_3Env10IOPriorityE",
                "non_relocation_bytes_equal": "394/422",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "create_cctx": {
                "catalogue_id": None,
                "label": "zstd ZSTD_createCCtx (identified by shape: "
                         "calloc(1, 0x1480), CPUID BMI1+BMI2 probe, reset "
                         "helper, +0x30=1/+0x3c=3; no catalogue row pins "
                         "this address)",
                "non_relocation_bytes_equal": None,
                "evidence": "this packet's excerpts",
            },
        },
        "factory": {
            "name": "rocksdb::StreamingCompress::Create",
            "arguments": ["dil = kind byte",
                          "rsi = CompressionOptions template (0x30 bytes)",
                          "edx = arg3 (2 in the one caller)",
                          "rcx = arg4 (0x7ff5 / 0x7ff9 in the one caller)"],
            "gate": "kind != 7 returns null",
            "product": {"size": "0x70", "table": "0x64d7408 + 0x10 at +0x0",
                        "kind_byte": "7 at +0x8",
                        "template": "0x30 bytes copied to +0x10..+0x40",
                        "field_40": "arg3", "field_48": "arg4",
                        "cctx": "+0x50, fresh create 0x6218920",
                        "field_58": "0", "field_60": "0 (16 bytes)"},
            "set_parameter": "setParameter(cctx, 201, 1) after the create",
            "landing_pad": "0x61c1bee (its own FDE): on unwind, "
                           "delete(0x70) and resume",
            "caller": "0x5f041d0 installs the product at owner+0x48 "
                      "beside a fresh array at +0x50",
            "sibling": "0x61c1ce0 StreamingUncompress::Create (open PR "
                       "#3635) is the decompress-side twin: 0x38-byte "
                       "holder, fresh DCtx at +0x18, no setParameter call",
        },
        "create_cctx": {
            "name": "ZSTD_createCCtx (by shape; see vendor_attribution)",
            "arguments": [],
            "alloc": "calloc(1, 0x1480); null returns null",
            "init": {"0x08": "CPUID feature flag (see below)",
                     "0x10..0xe8": "zeroed by rep stos (27 qwords)",
                     "0x30": 1, "0x3c": 3},
            "feature_probe": "+0x08 = 0 when cpuid max leaf <= 6; else 1 "
                             "iff leaf-7 EBX has both bits 3 and 8 set "
                             "(BMI1 + BMI2), else 0",
            "reset_call": "reset 0x62188a0 runs on the fresh context; "
                          "its pointers are all null, so it frees nothing",
            "callers": "6 direct call sites: the factory plus five other "
                       "CCtx consumers (see callers.tsv)",
        },
        "reset": {
            "name": "CCtx workspace release",
            "arguments": ["rdi = CCtx"],
            "steps": ["if +0xe48 != 0: custom free at +0x370 (opaque "
                      "+0x378) with (opaque, +0xe48), or plain free(+0xe48) "
                      "when the custom free is null",
                      "freeCDict(+0xe68) via 0x62187a0",
                      "zero +0xe48..+0xe90"],
            "callers": "only the create (0x6218952) calls it directly; "
                       "no separate freeCCtx was found in the census",
        },
        "free_cdict": {
            "name": "ZSTD_freeCDict (catalogue)",
            "arguments": ["rdi = CDict (null returns 0 at once)"],
            "steps": ["zero +0x20..+0x60 and +0x60",
                      "release the +0x20 backing allocation and the CDict "
                      "itself through the +0x17a0 custom free (opaque "
                      "+0x17a8) when set, else plain free",
                      "return 0"],
            "branch_note": "which of the two allocations is released "
                           "depends on whether the +0x20 pointer lies "
                           "inside the CDict object itself (bounds +0x00 "
                           "and +0x28); the exact embedded-region rule "
                           "is recorded as observed structure, not a "
                           "fully decoded contract",
            "callers": "13 direct call sites, including the reset",
        },
        "setparam": {
            "name": "ZSTD_CCtx_setParameter (by shape)",
            "arguments": ["rdi = CCtx", "esi = parameter",
                          "edx = value"],
            "flagged_gate": "CCtx+0xe18 != 0: only params 100 and "
                            "102..107 are accepted (else -60); accepted "
                            "params set CCtx+0x4 = 1, then apply",
            "unflagged_gate": "CCtx+0xe18 == 0: accepted params are "
                              "10, 100..107, 130, 160..164, 200..202, "
                              "400 (value 0, or value != 0 only when "
                              "CCtx+0x388 == 0), 401, 402, 500, "
                              "999..1002, 1004..1016; else -40; no "
                              "dirty write",
            "apply_entry": "tail-jumps to 0x6211a10 with rdi = CCtx+0x10",
            "return_codes": "-40 (parameter out of bound), -60 "
                            "(parameter unsupported in the flagged gate), "
                            "or the apply result",
            "flag_meaning": "the +0xe18 flag is unpinned; it is 0 on a "
                            "fresh calloc'd context",
        },
        "apply": {
            "name": "parameter apply worker",
            "arguments": ["rdi = params struct (CCtx+0x10)",
                          "esi = parameter", "edx = value"],
            "dispatch": "jump table 0x980e20 for params 100..202, jump "
                        "table 0x980fbc for params 1000..1016; param 10 "
                        "is a special arm; params 400..402 and 500 "
                        "return 0 iff value == 0, else -40; all other "
                        "params return -40",
            "arms": apply_arms,
            "returns": "the stored value for value arms, the boolean "
                       "for bool arms, the clamped value (or 3) for "
                       "param 100, -40 for an unlisted param, -42 when "
                       "a range check fails",
        },
        "bounds": {
            "name": "parameter bounds lookup",
            "arguments": ["edi = parameter id"],
            "returns": "(status, lo, hi): status 0 with the packed "
                       "bounds, or -40 when the parameter has no bounds row",
            "table": bounds,
            "notes": ["bounds(100) = (-131072, 22): the zstd compression "
                      "level range; the param-100 arm clamps into it and "
                      "maps 0 to the default level 3",
                      "bounds(400..402) = (0, 0): only value 0 passes",
                      "bounds(1003) errors while 1001, 1002, 1004 have rows",
                      "bounds(200..202) = (0, 1): the boolean arms do not "
                      "consult the table"],
        },
        "range_check": {
            "name": "parameter range check",
            "arguments": ["edi = parameter id", "esi = value"],
            "returns": "1 iff the bounds lookup succeeds and "
                       "lo <= value <= hi (signed); 0 otherwise",
            "callers": "26 apply arms (see callers.tsv; the parameter "
                       "id is recorded per site)",
        },
        "refresh": {
            "name": "rocksdb::log::Writer::AddCompressionTypeRecord",
            "arguments": ["rdi = 16-byte out status", "rsi = owner"],
            "steps": ["kind byte owner+0x45 == 0: zero the out, return",
                      "append the kind dword to a stack string; emit it "
                      "as a type-9 physical record via 0x5f03b80",
                      "emit failure: clear owner+0x45, return the status",
                      "build the 0x30-byte template (see below) and call "
                      "the factory with (kind, template, 2, 0x7ff5/0x7ff9)",
                      "install the holder at owner+0x48; operator new[] "
                      "a fresh array of the same size at owner+0x50, "
                      "delete[]ing the old array",
                      "copy the 16-byte emit status into the out"],
            "template": {"qwords": ["0x7ffffffffff2", "0", "0x100000000",
                                    "0", "0", "1"],
                         "global": "first qword loaded from 0x459aa0; as "
                                   "int32s (-14, 2147483647): -14 matches "
                                   "RocksDB's documented default "
                                   "window_bits; the field names are "
                                   "inferred, the qwords are pinned",
                         "array_size": "0x7ff5, or 0x7ff9 when owner+0x18 "
                                       "is 0"},
            "helpers": "0x5f03b80 emits the record (catalogue "
                       "EmitPhysicalRecord); 0x6051a20 is a shared 4-byte "
                       "copy helper whose write into the template slot is "
                       "overwritten by the global-qword fill (observed; "
                       "reason open)",
            "caller": "0x5e5c5a3 in FDE 0x5e5c270 (exact use open)",
        },
        "callers": callers,
        "census": census,
        "windows": windows,
        "unknowns": [
            "the +0xe18 flag in the setter (unpinned meaning)",
            "the +0x30 = 1 and +0x3c = 3 fields of the fresh CCtx "
            "(offsets and values pinned; field names open)",
            "the exact embedded-region rule in ZSTD_freeCDict (which of "
            "the two allocations is released in each branch)",
            "no ZSTD_freeCCtx analogue was found: the reset is called "
            "only by the create, so the 0x70-byte holder's teardown is "
            "unpinned",
            "the RocksDB-level identities of the five other CCtx-create "
            "consumers and of the refresh routine's caller (FDEs only; "
            "the binary is stripped)",
            "the 0x6051a20 helper's contract (a shared 4-byte copy; "
            "its write in the refresh path is overwritten)",
            "the LSDA call-site tables for the landing pads (not decoded)",
        ],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    # callers.tsv: one row per census site.
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("target\tsite\tkind\tcontaining_fde_start\tcontaining_fde_end\trole\n")
        for t in census_mod.TARGETS:
            for row in callers[hex(t)]:
                fs, fe = row["containing_fde"]
                fh.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (
                    hex(t), row["site"], row["kind"], fs, fe, row["role"]))
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write("No R_X86_64_RELATIVE entry in .rela.dyn has an addend "
                 "equal to any packet window start.\n")
        fh.write("The factory table 0x64d7408 is referenced by a "
                 "RIP-relative lea in the factory excerpt (no relocation).\n")
        fh.write("The template global 0x459aa0 is read by a RIP-relative "
                 "mov in the refresh excerpt (no relocation).\n")
    print("wrote records.json, callers.tsv, relocations.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
