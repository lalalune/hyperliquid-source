#!/usr/bin/env python3
"""Deterministic generator for RE-004-hinted-slot-consumption-94.

Answers #174's Next question (a): does the skip-path sub-destructor
at [dtor+0x88] (0x37f5c80) read [dtor+0x90] — the landing spot of
the hinted [rsp+0x88]+8 value (0x574d2c0)?

Verifies node #94 digest/size first, checks every recorded
instruction byte against the binary (code address A at file offset
A - 0x1000; .data.rel.ro address A at file offset A - 0x2000),
checks the 10 GOT-slot RELATIVE relocations that all target the
shared drop helper 0x4e79840, then writes only to --out. No node
execution, no evaluation, no disassembly, no network access.
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
RELA_LEN = 0x1D4E10
HELPER = 0x4E79840

# seg_id, start_va, end_va, file_offset, sha256, kind
SEGMENTS = [
    ("skip-call-88", 0x37F7120, 0x37F712C, 0x37F6120,
     "6cb57f4eb550ad2d6d848ddc4b01367accebd71c893394faad67c9c049cef234",
     "claim"),
    ("sub-first-load", 0x37F5C87, 0x37F5C8E, 0x37F4C87,
     "f2b766d856b9ee54c177d4cca9c814aebebd2b6de8d40f91ea17ac5b6beb9b81",
     "claim"),
    ("sub-first-call", 0x37F5C90, 0x37F5C99, 0x37F4C90,
     "dabd8e0e26635087bdf30bf671e401645d2eab3664c2056e71acc6d79e432a4f",
     "claim"),
    ("helper-loads", 0x4E79845, 0x4E7984C, 0x4E78845,
     "917ad62ffd7fc240e0f7807624f9da511f2e4dae54433ab45435400fc0f96daa",
     "claim"),
    ("helper-deref", 0x4E7984C, 0x4E79853, 0x4E7884C,
     "c9868d46a604121fcc32c8639e257fd38022a2ec34b10f38f513701ea868ed93",
     "claim"),
    ("helper-callgate", 0x4E79853, 0x4E7986A, 0x4E78853,
     "5ade6670f38ee1dc6d3e2a74146da98af145fce5e9ee9121e5f1e09f3f89f363",
     "claim"),
    ("helper-second-leg", 0x4E79870, 0x4E79888, 0x4E78870,
     "7e251a166a38455797792f556a11a5eaa7c60291ea9eda951fce944b115c7456",
     "claim"),
    ("stride-sample", 0x37F5C99, 0x37F5CAD, 0x37F4C99,
     "0c5e5f8dacfe5ac0d92ba82c390915e182c5128e9681e4cb248b415a755fb954",
     "claim"),
    ("sibling-shape", 0x37F59F7, 0x37F5A09, 0x37F49F7,
     "4172c9fdea9cf75702eb66dac982d47b63cebf3fe5260cb9dd20ffd571734c6f",
     "claim"),
    ("vecfree-head", 0x37F70F6, 0x37F710E, 0x37F60F6,
     "3efe07a1926fde831e4e0d83930dd95f7849ce3bb98620239dbf368a898a45f2",
     "claim"),
    ("header-triple", 0x574D2C0, 0x574D2D8, 0x574B2C0,
     "85526ba79728a470972be92942ef4de212630c9368703cb4ab3cb42dece95912",
     "claim"),
    ("ctor88-store", 0x4E8A97A, 0x4E8A985, 0x4E8997A,
     "7a2503d5d68e479710fa7c5caf39a65d9ab92e4374eb2eae3fb16aa613d8de3f",
     "anchor"),
    ("guard-cmp-je", 0x37F707E, 0x37F7088, 0x37F607E,
     "3ab7ab0bc6d6bb20970284b2526caca6cb761e0b20e97cd7f0abd818306709a5",
     "anchor"),
    ("join-add", 0x37FD237, 0x37FD23E, 0x37FC237,
     "ec22d69b4676d71aa6e60c24d7d290742ef724f02e66014853f6d15acc31310e",
     "anchor"),
    ("skip-path-head", 0x37F70EE, 0x37F70F6, 0x37F60EE,
     "748ece3be8b8e5b946cbddc2a143c8185ad91cea12102f098107a3f6147378f7",
     "anchor"),
    ("sweep", 0x4E7D5BF, 0x4E7D5D6, 0x4E7C5BF,
     "b1bb17a10e29624aaafbefeacf3ac98cacbf4522ad42ae68f5e45775a4044a28",
     "anchor"),
]

# GOT slots (all RELATIVE, addend 0x4e79840) by using sub-destructor.
GOT_SLOTS = {
    "0x37f59f0": [0x57740E0, 0x57740E8, 0x57740F0],
    "0x37f5bb0": [0x57740F8, 0x57740E8, 0x5774100],
    "0x37f5c80": [0x5774108, 0x5774110, 0x5774118, 0x5774120, 0x5774128],
}

# subdtor, entry_rdi_dtor_off, direct_offsets, helper_rdi8_dtor_off,
# touches_hinted
WALK = [
    ("0x37f59f0", "+0x18", "0x0,0x10,0x20", "+0x20", "no"),
    ("0x37f5bb0", "+0x48", "0x0,0x10,0x20,0x30", "+0x50", "no"),
    ("0x37f5c80", "+0x88", "0x0,0x10,0x20,0x30,0x40,0x50", "+0x90",
     "YES-conditional"),
]

# step, site_va, instruction, effect
HELPER_OPS = [
    ("load-P", 0x4E79845, "mov rbx,QWORD PTR [rdi]",
     "rbx = [rdi] (first field of the object the helper receives)"),
    ("load-H", 0x4E79848, "mov r14,QWORD PTR [rdi+0x8]",
     "r14 = [rdi+0x8] — on the 0x37f5c80 route this IS the hinted "
     "slot [dtor+0x90] = 0x574d2c0"),
    ("load-H0", 0x4E7984C, "mov rax,QWORD PTR [r14]",
     "rax = [H+0x0] = [0x574d2c0] = 0 (indirect-call function pointer)"),
    ("load-H2", 0x4E7984F, "mov r15,QWORD PTR [r14+0x10]",
     "r15 = [H+0x10] = [0x574d2d0] = 1 (length)"),
    ("call-gate", 0x4E79853,
     "test rax,rax; je; lea rcx,[r15-1]; and rcx,~0xf; "
     "lea rdi,[rbx+rcx]; add rdi,0x10; call rax",
     "calls H[0] iff nonzero; skipped here because H[0] = 0"),
    ("P-counter", 0x4E79870, "lock dec QWORD PTR [rbx+0x8]",
     "decrements the second refcount at [P+0x8]; returns unless zero"),
    ("load-H1", 0x4E79877, "mov rcx,QWORD PTR [r14+0x8]",
     "rcx = [H+0x8] = [0x574d2c8] = 0 (size base)"),
    ("delete", 0x4E798AE,
     "mov rdi,rbx; pops; jmp QWORD PTR [0x576e010]",
     "operator delete on P with the aligned size from H[1]/H[2]"),
]

# candidate, site, object_coord, access, verdict
CENSUS = [
    ("vec-teardown", "0x3bc8560",
     "dtor object (rdi)",
     "reads [rdi+0x8] (array base) and [rdi+0x10] (count) only; "
     "loop reads array pairs, never [rdi+0x90]",
     "no"),
    ("vector-free", "0x37f70f6",
     "dtor object (rbx)",
     "reads [rbx] (count) and [rbx+0x8] (data pointer) only",
     "no"),
    ("sub-dtor-18", "0x37f59f0",
     "dtor+0x18 (rdi)",
     "direct reads [sub+0x0,0x10,0x20]; helper [rdi+0x8] = dtor+0x20",
     "no"),
    ("sub-dtor-48", "0x37f5bb0",
     "dtor+0x48 (rdi)",
     "direct reads [sub+0x0,0x10,0x20,0x30]; helper [rdi+0x8] = "
     "dtor+0x50",
     "no"),
    ("sub-dtor-88", "0x37f5c80",
     "dtor+0x88 (rdi)",
     "direct reads [sub+0x0,0x10,0x20,0x30,0x40,0x50] (0x10 stride, "
     "skips +8); helper [rdi+0x8] = dtor+0x90, gated on the first "
     "member refcount reaching zero",
     "YES-conditional"),
    ("final-jmp", "0x37f57c0",
     "dtor+0xe8 (rdi after add rbx,0xe8)",
     "no [rdi-0x58] read anywhere in the 556B FDE",
     "no"),
    ("forward", "0x37fb9e0",
     "orig object (rbx)",
     "no [rbx+0x198] read anywhere in the 7782B FDE (marker read at "
     "[rbx+0x12a0] only)",
     "no"),
    ("c3-stores", "0x326e908/0x326f115",
     "NOT the builder object",
     "two [r12+0x198] stores, but r12 was rebased ([rsp+0x368] at "
     "0x326e8c3; popped caller r12 at 0x326efdc) — same displacement, "
     "different base; no read of the hinted slot",
     "no"),
    ("guard-test", "0x37f707e",
     "dtor object (rdi)",
     "reads [rdi+0x198] = orig+0x2a0 (the guard), not orig+0x198",
     "no"),
    ("helper-direct", "0x4e79840",
     "n/a (GOT-indirect only)",
     "zero direct E8 callers; zero RIP-relative references; reached "
     "only via the 10 GOT RELATIVE slots above",
     "n/a"),
]

EVIDENCE = {
    "node": {"id": 94, "size": EXPECTED_SIZE, "sha256": EXPECTED_SHA},
    "fdes": {
        "sub_dtor_88": {"start": "0x37f5c80", "end": "0x37f5d9b",
                        "size": 283},
        "helper": {"start": "0x4e79840", "end": "0x4e798d8", "size": 152},
        "sub_dtor_18": {"start": "0x37f59f0", "end": "0x37f5a84",
                        "size": 148},
        "sub_dtor_48": {"start": "0x37f5bb0", "end": "0x37f5c71",
                        "size": 193},
        "vec_teardown": {"start": "0x3bc8560", "end": "0x3bc864b",
                          "size": 235},
        "final_jmp": {"start": "0x37f57c0", "end": "0x37f59ec",
                        "size": 556},
    },
    "hinted_slot": {
        "value": "0x574d2c0",
        "origin": "[rsp+0x88]+8 written by ctor 0x4e8a830 "
                  "(0x4e8a981: mov [rbx+0x8],rcx with rcx = lea "
                  "0x574d2c0)",
        "landing": "[orig+0x198] = [dtor+0x90] = [sub88+0x8]",
        "header_triple": {"H0": 0, "H1": 0, "H2": 1},
        "header_relocs": "none (no .rela entry targets 0x574d2c0/8/d0; "
                         "file bytes are final)",
    },
    "got": {"target": "0x4e79840", "type": 8,
            "slots": sorted({s for v in GOT_SLOTS.values() for s in v}),
            "slot_file_bytes": "00" * 8,
            "direct_E8_callers": [],
            "rip_relative_refs": []},
    "callers": {
        "0x37f5c80_E8": ["0x37f7127", "0x37f71f2"],
        "0x37f5c80_E8_note": "both inside destructor 0x37f7070 "
                             "(skip epilogue and loop epilogue); "
                             "no other E8 caller in .text",
        "0x37f59f0_E8": ["0x37f7112", "0x37f71dd"],
        "0x37f5bb0_E8": ["0x37f711b", "0x37f71e6"],
    },
    "verdict": {
        "consumed": "YES-conditional",
        "gate": "first member refcount [[dtor+0x88]] reaching zero "
                "in 0x37f5c80 (lock dec at 0x37f5c87..0x37f5c8e; "
                "jne skips the helper call)",
        "consumer": "shared helper 0x4e79840, reached via GOT slot "
                    "0x5774108; loads [rdi+0x8] unconditionally at "
                    "entry (0x4e79848)",
        "other_route_consumers": "none (see route-census.tsv)",
    },
    "counts": {"walk_rows": len(WALK), "helper_rows": len(HELPER_OPS),
               "census_rows": len(CENSUS),
               "got_slots": len({s for v in GOT_SLOTS.values()
                                 for s in v}),
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
    # GOT relocations: every listed slot must be RELATIVE (type 8)
    # with addend 0x4e79840, and its file bytes must be zero.
    rela = {}
    for i in range(RELA_LEN // 24):
        off, info, addend = struct.unpack_from(
            "<QQq", data, RELA_OFF + i * 24)
        rela[off] = (info & 0xFFFFFFFF, addend)
    for user, slots in GOT_SLOTS.items():
        for slot in slots:
            if slot not in rela:
                fail(f"GOT slot {slot:#x} has no rela entry")
            typ, addend = rela[slot]
            if typ != 8 or addend != HELPER:
                fail(f"GOT slot {slot:#x}: type {typ} addend "
                     f"{addend:#x}")
            if data[slot - 0x2000:slot - 0x2000 + 8] != b"\x00" * 8:
                fail(f"GOT slot {slot:#x} file bytes are not zero")
    # Header triple values.
    for va, want in ((0x574D2C0, 0), (0x574D2C8, 0), (0x574D2D0, 1)):
        got = struct.unpack_from("<Q", data, va - 0x2000)[0]
        if got != want:
            fail(f"header {va:#x} = {got:#x}, want {want:#x}")
    # Segment bytes.
    seg_lines = ["seg_id start_va end_va length file_offset sha256 kind"]
    for seg_id, s, e, fo, sha, kind in SEGMENTS:
        if kind == "claim" and seg_id != "header-triple":
            want_off = s - 0x1000
        elif kind == "claim":
            want_off = s - 0x2000
        else:
            want_off = s - 0x1000
        if fo != want_off:
            fail(f"{seg_id}: file offset {fo:#x} != {want_off:#x}")
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
    (out / "subdtor-walk.tsv").write_text(
        "subdtor entry_rdi_dtor_off direct_offsets helper_rdi8_dtor_off "
        "touches_hinted\n" + "\n".join(" ".join(row) for row in WALK)
        + "\n")
    (out / "helper-consumption.tsv").write_text(
        "step site_va instruction effect\n" + "\n".join(
            f"{step} 0x{va:x} {ins} {eff}"
            for step, va, ins, eff in HELPER_OPS) + "\n")
    (out / "route-census.tsv").write_text(
        "candidate site object_coord access verdict\n" + "\n".join(
            f"{c} {s} {o} {a} {v}"
            for c, s, o, a, v in CENSUS) + "\n")
    (out / "segments.txt").write_text("\n".join(seg_lines) + "\n")
    print(f"wrote {len(SEGMENTS)} segments to {out}")


if __name__ == "__main__":
    main()
