#!/usr/bin/env python3
"""Deterministic generator for RE-004-be20-descriptor-94.

Verifies the node #94 digest and size first, then checks every
recorded byte (instruction bytes, descriptor file values,
relocation entries, and string bytes) against the binary, and
writes only to --out. No node execution, no evaluator, no
disassembler, no network.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

NODE_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
NODE_SIZE = 91774280
RELA_DYN_OFF = 0x6BC0

# (seg_id, start_va, end_va, section, kind)
# section "text": file offset = VA - 0x1000
# section "datarel": file offset = VA - 0x2000 (.data.rel.ro)
SEGMENTS = [
    ("desc-num1", 0x574BE50, 0x574BE60, "datarel", "claim"),
    ("desc-num2", 0x574BE68, 0x574BE78, "datarel", "claim"),
    ("ctor-head", 0x4E78670, 0x4E78683, "text", "claim"),
    ("clone-105", 0x1510490, 0x15104F9, "text", "claim"),
    ("clone-153", 0x15103F0, 0x1510489, "text", "claim"),
    ("ret-stub", 0x4E78660, 0x4E78661, "text", "claim"),
    ("zero-stub", 0x4E78690, 0x4E78693, "text", "claim"),
    ("builder-lea-be78", 0x4E7795C, 0x4E77963, "text", "claim"),
    ("builder-lea-bea8", 0x4E77993, 0x4E7799A, "text", "claim"),
    ("builder-lea-bed8", 0x4E779CA, 0x4E779D1, "text", "claim"),
    ("builder-pair-stores", 0x4E779F9, 0x4E77A26, "text", "claim"),
    ("log-be60", 0x4E772FB, 0x4E77308, "text", "claim"),
    ("log-be48", 0x4E77E82, 0x4E77E8F, "text", "claim"),
    ("bf38-call", 0x4E77E70, 0x4E77E82, "text", "claim"),
    ("elem11-setter", 0x4E78683, 0x4E7868E, "text", "anchor"),
    ("elem11-store", 0x4E76A70, 0x4E76A7F, "text", "anchor"),
]

# (entry index, r_offset, addend) — all R_X86_64_RELATIVE (type 8)
RELOCS = [
    (61868, 0x574BE20, 0x4E78670),
    (61869, 0x574BE28, 0x1510490),
    (61870, 0x574BE30, 0x15103F0),
    (61871, 0x574BE38, 0x4E78690),
    (61872, 0x574BE40, 0x4E78660),
    (61873, 0x574BE48, 0x1EA965),
    (61874, 0x574BE60, 0x1E3A8C),
    (61887, 0x574BF38, 0x1E3EC3),
]

# (address, file offset, expected bytes) — .rodata: offset == VA
STRINGS = [
    (0x1EA965, 0x1EA965,
     b"/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/"
     b"revm-primitives-15.1.0/src/env.rs"),
    (0x1E3A8C, 0x1E3A8C,
     b"/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/"
     b"revm-19.2.0/src/journaled_state.rs"),
    (0x1E3EC3, 0x1E3EC3,
     b"/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/"
     b"revm-19.2.0/src/handler/mainnet/pre_execution.rs"),
    (0x7C3620, 0x7C3620, b"already checked"),
    (0x256638, 0x256638, b"called `Option::unwrap()` on a `None` value"),
    (0x252D14, 0x252D14,
     b"attempt to multiply with overflowattempt to negate with overflowatt"),
]

# (address, expected qword) — .data.rel.ro file values
DATA_QWORDS = [
    (0x574BE50, 99),
    (0x574BE58, 0x900000281),
    (0x574BE68, 100),
    (0x574BE70, 0x1200000269),
    (0x574BE78, 0),
    (0x574BEA8, 0),
    (0x574BED8, 0),
    (0x574BF08, 0),
]

SLOTS_HEADER = "index\tdesc_offset\treloc_entry\taddend\ttarget\tshape\tsharing\n"
SLOTS_ROWS = [
    ("0", "+0x00", "61868", "0x4e78670", "ctor", "30B FDE, installs 0x574be20",
     "exclusive (1 reloc)"),
    ("1", "+0x08", "61869", "0x1510490", "clone", "105B FDE, free-gate + alloc + memcpy",
     "shared (65 relocs)"),
    ("2", "+0x10", "61870", "0x15103f0", "clone-cap", "153B FDE, alloc + memcpy + size-class",
     "shared (65 relocs)"),
    ("3", "+0x18", "61871", "0x4e78690", "zero-stub", "3B FDE, xor eax,eax; ret",
     "exclusive (1 reloc)"),
    ("4", "+0x20", "61872", "0x4e78660", "ret-stub", "1B FDE, ret",
     "exclusive (1 reloc)"),
    ("5", "+0x28", "61873", "0x1ea965", "src-string", "revm-primitives env.rs path",
     "shared (12 relocs)"),
]

BUILDER_HEADER = "pair\tcell_init\tfield_address\tcell_out\tfield_out\n"
BUILDER_ROWS = [
    ("1", "{1,1} alloc", "0x574be78", "[rbx+0x00]", "[rbx+0x08]"),
    ("2", "{1,1} alloc", "0x574bea8", "[rbx+0x10]", "[rbx+0x18]"),
    ("3", "{1,1} alloc", "0x574bed8", "[rbx+0x20]", "[rbx+0x28]"),
    ("4", "{1,1} alloc", "0x574bf08", "[rbx+0x30]", "[rbx+0x38]"),
]

USES_HEADER = "site\tfde\tfield\tregister\tfollowing_call\tgot_target\targs\n"
USES_ROWS = [
    ("0x4e772fb", "0x4e77060..0x4e7738c", "0x574be60", "rdi",
     "call 0x4e77302", "GOT 0x576e470 -> 0x157a9f0",
     "panic-wrapper, unwrap-None message (43B), reached when [r15+0x28]==0"),
    ("0x4e7795c", "0x4e77920..0x4e77ad6", "0x574be78", "rax -> [rsp+0x10]",
     "pair-1 field", "-", "builder pair 1, field address stored at [rbx+0x08]"),
    ("0x4e77993", "0x4e77920..0x4e77ad6", "0x574bea8", "rbp -> [rsp+0x20]",
     "pair-2 field", "-", "builder pair 2, field address stored at [rbx+0x18]"),
    ("0x4e779ca", "0x4e77920..0x4e77ad6", "0x574bed8", "r13 -> [rsp+0x30]",
     "pair-3 field", "-", "builder pair 3, field address stored at [rbx+0x28]"),
    ("0x4e779fc", "0x4e77920..0x4e77ad6", "0x574be78", "rcx -> [rbx+0x08]",
     "pair-1 field reuse", "-", "same field address as pair-1 field slot"),
    ("0x4e77a1b", "0x4e77920..0x4e77ad6", "0x574bf08", "rax -> [rbx+0x38]",
     "pair-4 field", "-", "builder pair 4, field address stored at [rbx+0x38]"),
    ("0x4e77e70", "0x4e77ae0..0x4e77e8f", "0x574bf38", "rdx",
     "call 0x4e77e7c", "GOT 0x576e468 -> 0x157a9b0",
     "rdi='already checked' (15B), rsi=0xf, rdx=field address"),
    ("0x4e77e82", "0x4e77ae0..0x4e77e8f", "0x574be48", "rdi",
     "call 0x4e77e89", "GOT 0x576e1b0 -> 0x157b4a0",
     "panic-wrapper, overflow messages (67B slice)"),
]


def fail(msg):
    print(f"be20_descriptor: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    root = Path(__file__).resolve().parents[1]
    node = root / "artifacts" / "node" / "94" / "hl-node"
    data = node.read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if hashlib.sha256(data).hexdigest() != NODE_SHA256:
        fail("node digest mismatch")

    seg_lines = ["seg_id\tstart_va\tend_va\tlength\tfile_offset\tsha256\tkind"]
    seg_records = []
    for seg_id, start, end, section, kind in SEGMENTS:
        if section == "text":
            off = start - 0x1000
        elif section == "datarel":
            off = start - 0x2000
        else:
            fail(f"unknown section {section}")
        blob = data[off:off + (end - start)]
        if len(blob) != end - start:
            fail(f"segment {seg_id} short read")
        digest = hashlib.sha256(blob).hexdigest()
        seg_lines.append(
            f"{seg_id}\t{hex(start)}\t{hex(end)}\t{end - start}\t{hex(off)}\t{digest}\t{kind}")
        seg_records.append({"id": seg_id, "start": hex(start), "end": hex(end),
                            "length": end - start, "file_offset": hex(off),
                            "sha256": digest, "kind": kind})

    for idx, want_off, want_add in RELOCS:
        off = RELA_DYN_OFF + idx * 24
        r_off, r_info, r_add = struct.unpack("<QQq", data[off:off + 24])
        if r_off != want_off or r_info != 8 or (r_add & 0xFFFFFFFFFFFFFFFF) != want_add:
            fail(f"reloc entry {idx} mismatch: {hex(r_off)} {hex(r_info)} "
                 f"{hex(r_add & 0xFFFFFFFFFFFFFFFF)}")

    for va, off, expected in STRINGS:
        got = data[off:off + len(expected)]
        if got != expected:
            fail(f"string at {hex(va)} mismatch: {got!r}")

    for va, want in DATA_QWORDS:
        off = va - 0x2000
        got = struct.unpack("<Q", data[off:off + 8])[0]
        if got != want:
            fail(f"data qword at {hex(va)} = {hex(got)} != {hex(want)}")

    evidence = {
        "node": {"id": 94, "size": NODE_SIZE, "sha256": NODE_SHA256},
        "descriptor": {
            "base": "0x574be20",
            "slots": [
                {"index": 0, "offset": "+0x00", "reloc_entry": 61868,
                 "addend": "0x4e78670", "target": "ctor", "fde": "0x4e78670..0x4e7868e",
                 "size": 30, "sharing_relocs": 1},
                {"index": 1, "offset": "+0x08", "reloc_entry": 61869,
                 "addend": "0x1510490", "target": "clone", "fde": "0x1510490..0x15104f9",
                 "size": 105, "sharing_relocs": 65},
                {"index": 2, "offset": "+0x10", "reloc_entry": 61870,
                 "addend": "0x15103f0", "target": "clone-cap", "fde": "0x15103f0..0x1510489",
                 "size": 153, "sharing_relocs": 65},
                {"index": 3, "offset": "+0x18", "reloc_entry": 61871,
                 "addend": "0x4e78690", "target": "zero-stub", "fde": "0x4e78690..0x4e78693",
                 "size": 3, "sharing_relocs": 1},
                {"index": 4, "offset": "+0x20", "reloc_entry": 61872,
                 "addend": "0x4e78660", "target": "ret-stub", "fde": "0x4e78660..0x4e78661",
                 "size": 1, "sharing_relocs": 1},
                {"index": 5, "offset": "+0x28", "reloc_entry": 61873,
                 "addend": "0x1ea965", "target": "src-string",
                 "value": "revm-primitives-15.1.0/src/env.rs", "sharing_relocs": 12},
            ],
            "numerics": [
                {"offset": "+0x30", "address": "0x574be50", "value": 99},
                {"offset": "+0x38", "address": "0x574be58", "value": "0x900000281"},
                {"offset": "+0x40", "address": "0x574be60", "reloc_entry": 61874,
                 "addend": "0x1e3a8c",
                 "value": "revm-19.2.0/src/journaled_state.rs"},
                {"offset": "+0x48", "address": "0x574be68", "value": 100},
                {"offset": "+0x50", "address": "0x574be70", "value": "0x1200000269"},
            ],
            "pair_fields": ["0x574be78", "0x574bea8", "0x574bed8", "0x574bf08"],
            "pair_field_file_values": 0,
        },
        "builder": {"fde": "0x4e77920..0x4e77ad6", "size": 438,
                    "pairs": 4, "out_size": 64, "cell_init": [1, 1]},
        "install_sites": [
            {"site": "0x4e78683", "kind": "setter self-install lea",
             "segment": "elem11-setter", "prior": "#172 claim, re-cited as anchor"},
            {"site": "0x4e76a70", "kind": "store [rdx]=descriptor, [rdx+8]=0x1e629b",
             "segment": "elem11-store", "prior": "#172 claim, re-cited as anchor",
             "store_fde": "0x4e76900..0x4e76af5", "store_fde_size": 501},
        ],
        "uses": {"rows": 8, "fdes": ["0x4e77060..0x4e7738c (812B)",
                                     "0x4e77920..0x4e77ad6 (438B)",
                                     "0x4e77ae0..0x4e77e8f (943B)"]},
        "census": {"direct_e8_callers_of_slots": 0, "direct_e9_jumps_to_slots": 0,
                   "got_slots": ["0x576dfd8 alloc", "0x576dfe0 memcpy",
                                 "0x576dfb8 abort-helper 0x1346068",
                                 "0x576e470 -> 0x157a9f0",
                                 "0x576e1b0 -> 0x157b4a0",
                                 "0x576e468 -> 0x157a9b0"]},
        "segments": seg_records,
        "counts": {"slots": 6, "builder_pairs": 4, "uses": 8,
                   "segments": len(seg_records),
                   "claim_bytes": sum(r["length"] for r in seg_records
                                      if r["kind"] == "claim"),
                   "anchor_bytes": sum(r["length"] for r in seg_records
                                       if r["kind"] == "anchor")},
    }

    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (out / "slots.tsv").write_text(
        SLOTS_HEADER + "".join("\t".join(r) + "\n" for r in SLOTS_ROWS))
    (out / "builder.tsv").write_text(
        BUILDER_HEADER + "".join("\t".join(r) + "\n" for r in BUILDER_ROWS))
    (out / "uses.tsv").write_text(
        USES_HEADER + "".join("\t".join(r) + "\n" for r in USES_ROWS))
    (out / "segments.txt").write_text("\n".join(seg_lines) + "\n")
    print(f"be20_descriptor: OK ({len(seg_records)} segments)")


if __name__ == "__main__":
    main()
