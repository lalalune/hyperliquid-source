#!/usr/bin/env python3
"""Deterministic generator for RE-004-destructor-guard-zero-94.

Verifies node #94 digest/size first, checks every recorded instruction
byte against the binary (code address A at file offset A - 0x1000),
checks the GOT-slot relocation for the builder's caller, then writes
only to --out. No node execution, no evaluation, no disassembly,
no network access.
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
GOT_SLOT = 0x5773FF8
BUILDER_CALLER = 0x4E7D360

# seg_id, start_va, end_va, file_offset, sha256, kind
SEGMENTS = [
    ("hash-store-1440", 0x4E7D3DD, 0x4E7D3E5, 0x4E7C3DD,
     "70ea794ed55d40c5ba40188f2e1a0451d8db3b77044fef56539caa7b9d32d053",
     "claim"),
    ("zero-store-1440", 0x4E7D454, 0x4E7D460, 0x4E7C454,
     "5ada25d7d5626c14f8ebb5fae681a70ebd95cdbcca89e334a29c03f2362bfecf",
     "claim"),
    ("buf-memcpy", 0x4E7D4A8, 0x4E7D4C0, 0x4E7C4A8,
     "f0b97d9105bc0529d86d52b57f094416bda6bcd30312c9a02d57d90f2b150520",
     "claim"),
    ("movups-load-88", 0x4E7D554, 0x4E7D55C, 0x4E7C554,
     "402c867f842d70edf5add6c9ca783f088232d9a20869cb75ce38bd1abf9f53be",
     "claim"),
    ("movups-store-328", 0x4E7D58C, 0x4E7D594, 0x4E7C58C,
     "b550e6c680f9b2696e3af80d10369166f758412dd9b41a087518a6411bcd6935",
     "claim"),
    ("ctor88-lea-tag", 0x4E8A97A, 0x4E8A981, 0x4E8997A,
     "56ab58481449930cbc9d577705c78ab60ac8296c2f5a9a37defc8fcf73aca666",
     "claim"),
    ("ctor88-slot8", 0x4E8A981, 0x4E8A985, 0x4E89981,
     "79342acfd68a656ac780ebba4649e49ec8f3e133512a464fef4d14a36e2b802e",
     "claim"),
    ("fwd-rbx-rsi", 0x37FBA12, 0x37FBA15, 0x37FAA12,
     "dfc71f429438bd461c6755593b7156153caa69906c3361187d2d4c8194482827",
     "claim"),
    ("unwind-add", 0x37FD829, 0x37FD830, 0x37FC829,
     "ec22d69b4676d71aa6e60c24d7d290742ef724f02e66014853f6d15acc31310e",
     "claim"),
    ("unwind-dtor-call", 0x37FD830, 0x37FD838, 0x37FC830,
     "067361ac3682ad9c6f327d102f89a28a6daf7bcf6874a5b2d356989853a925be",
     "claim"),
    ("skip-path-head", 0x37F70EE, 0x37F70F6, 0x37F60EE,
     "748ece3be8b8e5b946cbddc2a143c8185ad91cea12102f098107a3f6147378f7",
     "claim"),
    ("sweep", 0x4E7D5BF, 0x4E7D5D6, 0x4E7C5BF,
     "b1bb17a10e29624aaafbefeacf3ac98cacbf4522ad42ae68f5e45775a4044a28",
     "anchor"),
    ("c3-got-call", 0x326E592, 0x326E598, 0x326D592,
     "4d91192e60d864f5f159fa07a7f79588121fcebb11df155bd4857e3a6d97d884",
     "anchor"),
    ("c3-fwd-setup-call", 0x326E5A0, 0x326E5AB, 0x326D5A0,
     "3f5ad8df9f44214c7a649debcfe92fe98dc023476f171ba160f5169f7dd19ed1",
     "anchor"),
    ("join-add", 0x37FD237, 0x37FD23E, 0x37FC237,
     "ec22d69b4676d71aa6e60c24d7d290742ef724f02e66014853f6d15acc31310e",
     "anchor"),
    ("fwd-dtor-call", 0x37FD26F, 0x37FD277, 0x37FC26F,
     "d499c995b580643a433e2f72bdb378ff852aa41c0ef1125d937f5856e7311d76",
     "anchor"),
    ("guard-cmp-je", 0x37F707E, 0x37F7088, 0x37F607E,
     "3ab7ab0bc6d6bb20970284b2526caca6cb761e0b20e97cd7f0abd818306709a5",
     "anchor"),
    ("loop-head-loads", 0x37F70AD, 0x37F70B7, 0x37F60AD,
     "b4f065252831f4727ce1ee637c944cdd44a39c382ff2c47801cec474f411a9fd",
     "anchor"),
]

# link, site_va, instruction, effect
CHAIN = [
    ("prologue-zero", 0x4E7D36C, "mov QWORD PTR [rsp],0x0",
     "[final rsp+0x1440] = 0 (first prologue store; final rsp sits "
     "0x1440 below this store)"),
    ("hash-store-1440", 0x4E7D3DD, "mov QWORD PTR [rsp+0x1440],r14",
     "[rsp+0x1440] = hash (transient)"),
    ("zero-store-1440", 0x4E7D454, "mov QWORD PTR [rsp+0x1440],0x0",
     "[rsp+0x1440] = 0 (final normal-path value; no later store to "
     "this slot in the builder-caller FDE)"),
    ("buf-memcpy", 0x4E7D4A8,
     "memcpy([rsp+0x438],[rsp+0x1440],0x1000)",
     "[rsp+0x438] = [rsp+0x1440] = 0"),
    ("movups-load-88", 0x4E7D554, "movups xmm0,[rsp+0x88]",
     "load [rsp+0x88] sub-object head"),
    ("movups-store-328", 0x4E7D58C, "movups [rsp+0x328],xmm0",
     "[rsp+0x330] = [rsp+0x88]+8 (the hinted slot; maps to orig+0x198)"),
    ("ctor88-lea-tag", 0x4E8A97A, "lea rcx,[0x574d2c0]",
     "rcx = tag pointer 0x574d2c0"),
    ("ctor88-slot8", 0x4E8A981, "mov QWORD PTR [rbx+0x8],rcx",
     "[rsp+0x88]+8 = 0x574d2c0 (nonzero, but not the guard)"),
    ("sweep", 0x4E7D5BF,
     "memcpy([rbx+0x108],[rsp+0x2a0],0x1198)",
     "[rbx+0x2a0] = [rsp+0x438] = 0"),
    ("c3-got-call", 0x326E592, "call QWORD PTR [rip+...] # 5773ff8",
     "c3 calls builder-caller via GOT slot 0x5773ff8 "
     "(RELATIVE addend 0x4e7d360); rdi = [rsp+0x1540] output buffer"),
    ("c3-fwd-setup-call", 0x326E5A0,
     "mov rsi,r12; mov rdx,r15; call 0x37fb9e0",
     "c3 forwards the builder-caller output object (rsi) to forward"),
    ("fwd-rbx-rsi", 0x37FBA12, "mov rbx,rsi",
     "forward rbx = builder-caller output object"),
    ("join-add", 0x37FD237, "add rbx,0x108",
     "forward join shifts to the +0x108 sub-object"),
    ("fwd-dtor-call", 0x37FD26F, "mov rdi,rbx; call 0x37f7070",
     "normal path passes (orig+0x108) to the destructor"),
    ("unwind-add", 0x37FD829, "add rbx,0x108",
     "unwind path shifts to the same +0x108 sub-object"),
    ("unwind-dtor-call", 0x37FD830, "mov rdi,rbx; call 0x37f7070",
     "unwind path passes (orig+0x108) to the destructor"),
    ("guard-cmp-je", 0x37F707E, "cmp QWORD PTR [rdi+0x198],0x0; je 0x37f70ee",
     "guard = [dtor+0x198] = [orig+0x2a0] = 0, so je skips the loop"),
    ("loop-head-loads", 0x37F70AD,
     "mov r15,[rbx+r12-0x18]; mov r13,[rbx+r12-0x10]",
     "loop head (skipped): first loads would be [dtor+0x198]/[dtor+0x1a0] "
     "= [orig+0x2a0]/[orig+0x2a8], past the pair array"),
    ("skip-path-head", 0x37F70EE, "mov rdi,rbx; call 0x3bc8560",
     "skip path: vector teardown head, then sub-destructors at "
     "[rbx+0x18]/[rbx+0x48]/[rbx+0x88] (dtor coords)"),
]

# dtor_offset, orig_offset, builder_caller_slot, buf_slot, value, verdict
COORD = [
    ("dtor+0x198 (guard)", "orig+0x2a0", "[rsp+0x438]", "[rsp+0x1440]",
     "0", "LOOP SKIPPED"),
    ("dtor+0x198 (walk start, hypothetical)", "orig+0x2a0", "[rsp+0x438]",
     "[rsp+0x1440]", "0", "first walked cell is past the pair array end"),
    ("dtor+0x1a0 (walk first element, hypothetical)", "orig+0x2a8",
     "[rsp+0x440]", "[rsp+0x1448]", ".rodata head (0x574c318 copy)",
     "not a table element"),
    ("dtor+0x210 (#173 alleged oc cell)", "orig+0x318", "[rsp+0x4b0]",
     "[rsp+0x14b8]", ".rodata-derived qword", "NOT C3 (correction)"),
    ("dtor+0x218 (#173 alleged oc element)", "orig+0x320", "[rsp+0x4b8]",
     "[rsp+0x14c0]", ".rodata-derived qword", "NOT 0x574bd30 (correction)"),
    ("orig+0x198 (hinted slot)", "[rsp+0x330]", "[rsp+0x88]+8",
     "0x574d2c0 (ctor88)", "nonzero pointer",
     "maps to dtor+0x90: below walk start, NOT the guard"),
    ("orig pair array [0x1f0..0x2a0]", "dtor [0xE8..0x198)",
     "builder output [rsp+0x1f0..0x2a0]", "n/a",
     "11 pairs incl. oc pair", "entirely below loop start: NEVER WALKED"),
]

EVIDENCE = {
    "node": {"id": 94, "size": EXPECTED_SIZE, "sha256": EXPECTED_SHA},
    "fdes": {
        "builder_caller": {"start": "0x4e7d360", "end": "0x4e7d678",
                          "size": 792},
        "c3": {"start": "0x326e540", "end": "0x326f350", "size": 3600},
        "forward": {"start": "0x37fb9e0", "end": "0x37fd846",
                    "size": 7782},
        "destructor": {"start": "0x37f7070", "end": "0x37f721a",
                       "size": 426},
        "ctor88": {"start": "0x4e8a830", "end": "0x4e8a9e2", "size": 434},
    },
    "got": {"slot": "0x5773ff8", "rela_dyn_entry": 75886, "type": 8,
            "addend": "0x4e7d360", "slot_file_bytes": "00" * 8},
    "guard": {"dtor_offset": "0x198", "orig_offset": "0x2a0",
              "value": 0, "loop_runs": False},
    "correction_to_173": {
        "destructor_object": "orig+0x108 (not orig)",
        "walk_range_dtor_coords": "[0x198..0x11a8]",
        "walk_range_orig_coords": "[0x2a0..0x12b0]",
        "pair_array_orig_coords": "[0x1f0..0x2a0]",
        "pair_array_dtor_coords": "[0xE8..0x198)",
        "oc_pair_loaded": False,
    },
    "counts": {"chain_rows": len(CHAIN), "coord_rows": len(COORD),
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
    # GOT relocation: entry 75886 must be slot 0x5773ff8, RELATIVE,
    # addend 0x4e7d360.
    off, info, addend = struct.unpack_from(
        "<QQq", data, RELA_OFF + 75886 * 24)
    if off != GOT_SLOT or (info & 0xFFFFFFFF) != 8 or addend != BUILDER_CALLER:
        fail(f"GOT reloc mismatch: {off:#x} type {info & 0xffffffff} "
             f"addend {addend:#x}")
    if data[GOT_SLOT - 0x2000:GOT_SLOT - 0x2000 + 8] != b"\x00" * 8:
        fail("GOT slot file bytes are not zero")
    # Segment bytes.
    seg_lines = ["seg_id start_va end_va length file_offset sha256 kind"]
    for seg_id, s, e, fo, sha, kind in SEGMENTS:
        if fo != s - 0x1000:
            fail(f"{seg_id}: file offset {fo:#x} != VA-0x1000")
        chunk = data[fo:fo + (e - s)]
        if len(chunk) != e - s:
            fail(f"{seg_id}: short read")
        if hashlib.sha256(chunk).hexdigest() != sha:
            fail(f"{seg_id}: digest mismatch")
        seg_lines.append(
            f"{seg_id} 0x{s:x} 0x{e:x} {e - s} 0x{fo:x} {sha} {kind}")
    # Chain instruction bytes that are not segments (prologue zero).
    if data[0x4E7D36C - 0x1000:0x4E7D36C - 0x1000 + 8] != bytes.fromhex(
            "48c7042400000000"):
        fail("prologue-zero bytes mismatch")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(
        json.dumps(EVIDENCE, indent=2, sort_keys=True) + "\n")
    (out / "guard-chain.tsv").write_text(
        "link site_va instruction effect\n" + "\n".join(
            f"{link} 0x{va:x} {ins} {eff}"
            for link, va, ins, eff in CHAIN) + "\n")
    (out / "coord-map.tsv").write_text(
        "dtor_offset orig_offset builder_caller_slot buf_slot value verdict\n"
        + "\n".join(" ".join(row) for row in COORD) + "\n")
    (out / "segments.txt").write_text("\n".join(seg_lines) + "\n")
    print(f"wrote {len(SEGMENTS)} segments to {out}")


if __name__ == "__main__":
    main()
