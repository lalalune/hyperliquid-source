#!/usr/bin/env python3
"""Deterministic generator for RE-004-triob-vtable-callee-resolution-94.

Resolves #169's trioB vtable header-2/3 verdicts. #169 left those
routes "callee-extent-unverified" because the .data objects'
file bytes are (0, 0, 2) and it read the callee as
"runtime-initialized". In fact no code ever stores to those
.data objects: their runtime values come entirely from
R_X86_64_RELATIVE relocations applied at load time, and the
double indirection GOT -> .data object -> table first qword
lands on two 30-byte twin constructors (0x4ea3790, 0x4ea4dc0)
that fully write the 0x20-byte out layout. Header 0 stays
unresolved: its callee is [r14+0x8] with r14 loaded from a
stack slot (0x4e8571e), not from any static chain.

Verifies node #94 digest/size first, checks every recorded
instruction byte against the binary (code address A at file
offset A - 0x1000; .rodata address A at file offset A;
.data.rel.ro/.got address A at file offset A - 0x2000;
.data address A at file offset A - 0x3000), checks the 8
RELATIVE relocations of the chain by .rela.dyn entry index,
then writes only to --out. No node execution, no evaluation,
no disassembly, no network access.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"
EXPECTED_SIZE = 91774280
EXPECTED_SHA = (
    "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
)
RELA_OFF = 0x6BC0

# seg_id, start_va, end_va, file_offset, sha256, kind
SEGMENTS = [
    ("switch-block", 0x4E857C0, 0x4E857D0, 0x4E847C0,
     "0f3c81b700e164ab0f9b57e87cae53f50020cfbc9dfa1757938f6f29c75e89c5",
     "claim"),
    ("h2-got-load", 0x4E857D0, 0x4E857D7, 0x4E847D0,
     "b1056e833a49263a943cf7cae495b957c65a94d4643076c5052f9a169ac3788d",
     "claim"),
    ("h3-got-load", 0x4E8584A, 0x4E85851, 0x4E8484A,
     "f75a2c6020896771083d02070e6fc5ad69ac39b5c9fdcaa3aff4f5adaa6ca7aa",
     "claim"),
    ("callee-h3", 0x4EA3790, 0x4EA37AE, 0x4EA2790,
     "292f756a74aebaa29b149f3b508cc2672954f08b41da195e5da61243b8777025",
     "claim"),
    ("callee-h2", 0x4EA4DC0, 0x4EA4DDE, 0x4EA3DC0,
     "82c9fa0ddc701fdd092be9641a8ced1aeae6de15decd3638c795ad12fe7e9bd9",
     "claim"),
    ("r14-reassign", 0x4E8571E, 0x4E85723, 0x4E8471E,
     "5b857c273acf472494f0d278f9a817164eb772c0d6c7f88758a22a2bdd0dfa92",
     "claim"),
    ("shared-tail", 0x4E85851, 0x4E85867, 0x4E84851,
     "b45b8ad2e049a8e696a070a1ba391be1be43dff9bd99063b81677ac1cd5e705d",
     "anchor"),
    ("vtable-copy", 0x4E85867, 0x4E858C3, 0x4E84867,
     "9668ed493bb51d8dc3ba121a190543da5a4f90dd972e39ee4b3e8492b1c10f8e",
     "anchor"),
    ("jump-table", 0x7C3B84, 0x7C3B98, 0x7C3B84,
     "7506ac7943094a1b57a3080f5b84d7f4c2e6f4d6dfbb5a590963f838c1070eda",
     "anchor"),
    ("header0-block", 0x4E8596D, 0x4E85982, 0x4E8496D,
     "010d7205c3d2d51d4c46612b51bd17282f4bd59bb7836e8d64e8886d6056243d",
     "anchor"),
]

# .rela.dyn entry index, r_offset, r_addend. All type 8 (RELATIVE).
RELOCS = [
    (75461, 0x57732A8, 0x5786858),   # H2 GOT slot -> H2 .data object
    (75462, 0x57732B0, 0x5786838),   # H3 GOT slot -> H3 .data object
    (78766, 0x5786838, 0x574F9E0),   # H3 .data q0 -> H3 table
    (78767, 0x5786840, 0x7C5417),    # H3 .data q1 -> .rodata pointer
    (78768, 0x5786858, 0x574FB08),   # H2 .data q0 -> H2 table
    (78769, 0x5786860, 0x202802),    # H2 .data q1 -> .rodata pointer
    (62708, 0x574F9E0, 0x4EA3790),   # H3 table q0 -> H3 callee
    (62728, 0x574FB08, 0x4EA4DC0),   # H2 table q0 -> H2 callee
]

# route, step, site, value, note
CHAIN = [
    ("H2", "got-slot", "0x57732a8",
     "reloc-entry-75461-RELATIVE-addend-0x5786858",
     "runtime GOT value is the H2 .data object address"),
    ("H2", "data-q0", "0x5786858",
     "reloc-entry-78768-addend-0x574fb08",
     "first qword of the H2 .data object is the H2 table address"),
    ("H2", "data-q1", "0x5786860",
     "reloc-entry-78769-addend-0x202802",
     ".rodata pointer, passed as rdx to the callee"),
    ("H2", "data-q2", "0x5786868",
     "file-value-2",
     "passed as rcx to the callee"),
    ("H2", "table-q0", "0x574fb08",
     "reloc-entry-62728-addend-0x4ea4dc0",
     "first qword of the H2 table is the H2 callee address"),
    ("H2", "callee", "0x4ea4dc0",
     "FDE-30B-writes-out-0x00-0x08-0x10-0x18",
     "twin of the H3 callee; installs table 0x574fb08 at [out+0x0]"),
    ("H3", "got-slot", "0x57732b0",
     "reloc-entry-75462-RELATIVE-addend-0x5786838",
     "runtime GOT value is the H3 .data object address"),
    ("H3", "data-q0", "0x5786838",
     "reloc-entry-78766-addend-0x574f9e0",
     "first qword of the H3 .data object is the H3 table address"),
    ("H3", "data-q1", "0x5786840",
     "reloc-entry-78767-addend-0x7c5417",
     ".rodata pointer, passed as rdx to the callee"),
    ("H3", "data-q2", "0x5786848",
     "file-value-2",
     "passed as rcx to the callee"),
    ("H3", "table-q0", "0x574f9e0",
     "reloc-entry-62708-addend-0x4ea3790",
     "first qword of the H3 table is the H3 callee address"),
    ("H3", "callee", "0x4ea3790",
     "FDE-30B-writes-out-0x00-0x08-0x10-0x18",
     "twin of the H2 callee; installs table 0x574f9e0 at [out+0x0]"),
    ("H0", "r14-source", "0x4e8571e",
     "mov-r14-QWORD-PTR-[rsp+0x28]",
     "overwrites the entry mov r14,rsi (0x4e856ff) before the "
     "switch; r14 is a stack argument, not a static chain"),
    ("H0", "callee-source", "0x4e85971",
     "mov-rax-QWORD-PTR-[r14+0x8]",
     "callee is [r14+0x8]; r14 is runtime data, so this stays "
     "unresolved-indirect"),
]

# callee, store_site, out_offset, stored_value
CALLEES = [
    ("H3-0x4ea3790", "0x4ea37aa", "+0x00", "0x574f9e0 (lea 0x4ea37a3)"),
    ("H3-0x4ea3790", "0x4ea3793", "+0x08", "rdx (0x7c5417 via H3 data-q1)"),
    ("H3-0x4ea3790", "0x4ea3797", "+0x10", "rcx (2 via H3 data-q2)"),
    ("H3-0x4ea3790", "0x4ea379b", "+0x18", "0"),
    ("H2-0x4ea4dc0", "0x4ea4dda", "+0x00", "0x574fb08 (lea 0x4ea4dd3)"),
    ("H2-0x4ea4dc0", "0x4ea4dc3", "+0x08", "rdx (0x202802 via H2 data-q1)"),
    ("H2-0x4ea4dc0", "0x4ea4dc7", "+0x10", "rcx (2 via H2 data-q2)"),
    ("H2-0x4ea4dc0", "0x4ea4dcb", "+0x18", "0"),
]

EVIDENCE = {
    "node": {"id": 94, "size": EXPECTED_SIZE, "sha256": EXPECTED_SHA},
    "fdes": {
        "triob_vtable_func": {"start": "0x4e856f0", "end": "0x4e85b12",
                               "size": 1058},
        "callee_h3": {"start": "0x4ea3790", "end": "0x4ea37ae",
                      "size": 30},
        "callee_h2": {"start": "0x4ea4dc0", "end": "0x4ea4dde",
                      "size": 30},
    },
    "switch": {
        "table": "0x7c3b84",
        "entries": ["0x046c1de9", "0x046c1d7f", "0x046c1c4c",
                    "0x046c1cc6", "0x046c1ed2"],
        "targets": {"0": "0x4e8596d", "1": "0x4e85903",
                    "2": "0x4e857d0", "3": "0x4e8584a",
                    "4": "0x4e85a56"},
        "block": "0x4e857c0..0x4e857d0",
    },
    "chain": {
        "got_slots": {"H2": "0x57732a8", "H3": "0x57732b0"},
        "got_code_refs": {"0x57732a8": 26, "0x57732b0": 9},
        "data_objects": {
            "H3": {"addr": "0x5786838",
                   "runtime": ["0x574f9e0", "0x7c5417", 2]},
            "H2": {"addr": "0x5786858",
                   "runtime": ["0x574fb08", "0x202802", 2]},
        },
        "tables": {"H3": "0x574f9e0", "H2": "0x574fb08"},
        "callees": {"H3": "0x4ea3790", "H2": "0x4ea4dc0"},
        "data_code_refs": "none (zero RIP-relative references and zero "
                          "absolute 8-byte patterns for 0x5786838 / "
                          "0x5786858 / 0x5786840 / 0x5786860 in .text)",
    },
    "twin": {"identical_bytes": 28, "total_bytes": 30,
             "differing_offsets": [22, 23],
             "differing_field": "lea disp32 (table address)"},
    "header0": {"callee": "[r14+0x8] at 0x4e85971",
                "r14_source": "[rsp+0x28] at 0x4e8571e",
                "verdict": "unresolved-indirect (unchanged from #169)"},
    "verdict": {
        "header2": "fully-produced (callee writes all 0x20 out bytes; "
                   "copy at 0x4e85867 reads exactly [rsp+0x50..0x70])",
        "header3": "fully-produced (same, via the H3 twin)",
        "header0": "unresolved-indirect",
        "correction": "#169's callee-extent-unverified for headers 2 "
                      "and 3 is superseded; no runtime initializer "
                      "fills the .data objects — RELATIVE relocations "
                      "fix every value at load time",
    },
    "counts": {"chain_rows": len(CHAIN),
               "callee_rows": len(CALLEES),
               "reloc_rows": len(RELOCS),
               "segments": len(SEGMENTS),
               "claim_bytes": sum(e - s for _, s, e, _, _, k in SEGMENTS
                                  if k == "claim"),
               "anchor_bytes": sum(e - s for _, s, e, _, _, k in SEGMENTS
                                   if k == "anchor")},
}


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--node", default=str(NODE))
    args = ap.parse_args()
    data = Path(args.node).read_bytes()
    if len(data) != EXPECTED_SIZE:
        fail(f"node size {len(data)} != {EXPECTED_SIZE}")
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        fail("node digest mismatch")
    # Relocation chain: entry index, offset, type, addend.
    for idx, off, addend in RELOCS:
        o, info, ad = struct.unpack_from("<QQq", data, RELA_OFF + idx * 24)
        if o != off or (info & 0xFFFFFFFF) != 8 or ad != addend:
            fail(f"rela entry {idx}: offset {o:#x} type "
                 f"{info & 0xFFFFFFFF} addend {ad:#x}, want offset "
                 f"{off:#x} type 8 addend {addend:#x}")
    # GOT slot file bytes are zero (.got: VA - 0x2000).
    for slot in (0x57732A8, 0x57732B0):
        if data[slot - 0x2000:slot - 0x2000 + 8] != b"\x00" * 8:
            fail(f"GOT slot {slot:#x} file bytes are not zero")
    # .data q2 file values are 2 (.data: VA - 0x3000); table q0
    # file bytes are zero (.data.rel.ro: VA - 0x2000).
    for va, want in ((0x5786848, 2), (0x5786868, 2)):
        got = struct.unpack_from("<Q", data, va - 0x3000)[0]
        if got != want:
            fail(f".data {va:#x} = {got}, want {want}")
    for va in (0x574F9E0, 0x574FB08):
        if data[va - 0x2000:va - 0x2000 + 8] != b"\x00" * 8:
            fail(f"table {va:#x} file bytes are not zero")
    # Jump-table int32s.
    want_jt = [0x046C1DE9, 0x046C1D7F, 0x046C1C4C, 0x046C1CC6,
               0x046C1ED2]
    got_jt = list(struct.unpack_from("<5i", data, 0x7C3B84))
    if got_jt != want_jt:
        fail(f"jump table {got_jt} != {want_jt}")
    # Segment bytes.
    seg_lines = ["seg_id start_va end_va length file_offset sha256 kind"]
    for seg_id, s, e, fo, sha, kind in SEGMENTS:
        chunk = data[fo:fo + (e - s)]
        if len(chunk) != e - s:
            fail(f"{seg_id}: short read")
        if hashlib.sha256(chunk).hexdigest() != sha:
            fail(f"{seg_id}: digest mismatch")
        seg_lines.append(
            f"{seg_id} 0x{s:x} 0x{e:x} {e - s} 0x{fo:x} {sha} {kind}")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(
        json.dumps(EVIDENCE, indent=2, sort_keys=True) + "\n")
    (out / "chain.tsv").write_text(
        "route step site value note\n" + "\n".join(
            " ".join(row) for row in CHAIN) + "\n")
    (out / "callees.tsv").write_text(
        "callee store_site out_offset stored_value\n" + "\n".join(
            " ".join(row) for row in CALLEES) + "\n")
    (out / "segments.txt").write_text("\n".join(seg_lines) + "\n")
    print(f"wrote {len(SEGMENTS)} segments to {out}")


if __name__ == "__main__":
    main()
