#!/usr/bin/env python3
"""Deterministic generator for RE-004 pair-array escape (node #94).

Reads only artifacts/node/94/hl-node, checks its SHA-256 and size first,
verifies every recorded instruction byte against the binary (code address A
at file offset A - 0x1000), checks the GOT relocation, the init/fini arrays,
and the direct-call census, then writes only to --out. No execution,
evaluation, disassembly or network access.
"""
import argparse
import hashlib
import json
import os
import struct
import sys

NODE_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
NODE_SIZE = 91774280
TARGET = 0x4E7D360
GOT_SLOT = 0x5773FF8
RELOC_INDEX = 75886

# name -> (start_va, end_va_or_None, hex_bytes)
SPANS = {
    'anchor_memcpy_site': (82302356, 82302380, '488dbc2488030000488db424f0010000bab000000041ffd7'),
    'anchor_oc_pair': (82259443, 82259463, '488b4c241048894b20488d0d2d8f8d0048894b28'),
    'c1_got': (38038291, 38038297, 'ff15dfd43203'),
    'c1_rep': (38038852, 38038855, '4d89e5'),
    'c1_t1': (38038297, 38038322, '488dbc2490020000488b2db8743203ba080100004c89eeffd5'),
    'c1_t2': (38038322, 38038343, '4c8dbc2440150000bae00000004c89ff4c89eeffd5'),
    'c1_t3': (38038351, 38038369, '488dbc24a8000000bab80000004c89eeffd5'),
    'c2_got': (38272379, 38272385, 'ff1577422f03'),
    'c2_rep': (38272638, 38272641, '4989d6'),
    'c2_t1': (38272385, 38272418, '488dbc24d00200004c8db42480150000488b2d48e22e03ba080100004c89f6ffd5'),
    'c2_t2': (38272418, 38272439, '4c8da42438280000bae00000004c89e74c89f6ffd5'),
    'c2_t3': (38272447, 38272465, '488dbc24c0010000bab80000004c89f6ffd5'),
    'c3_fwd': (52880792, 52880811, '488dbc24900200004c89e64c89fae835d45800'),
    'c3_got': (52880786, 52880792, 'ff15605a5002'),
    'c3_rep': (52880995, 52880998, '4989c4'),
    'c4_got': (58574184, 58574190, 'ff158a7af901'),
    'c4_o8': (58583720, 58583750, '4c8dbc24a82a0000488db42440060000ba900000004c89ffff151af5f801'),
    'c4_rd': (58581916, 58581934, '488dbc24603d0000bab00000004c89feffd5'),
    'c4_small_0x37df2e9': (58585833, None, '498b57f7'),
    'c4_small_0x37df2f9': (58585849, None, '410f1047e7'),
    'c4_small_0x37df302': (58585858, None, '418b17'),
    'c4_small_0x37df305': (58585861, None, '418b7703'),
    'c4_small_0x37df3c6': (58586054, None, '410f1047df'),
    'c4_small_0x37df3dd': (58586077, None, '410f1047ef'),
    'c4_small_0x37df3e2': (58586082, None, '410f104fff'),
    'c4_small_0x37df406': (58586118, None, '418b4710'),
    'c4_small_0x37df40a': (58586122, None, '418b4f13'),
    'c4_small_0x37df416': (58586134, None, '418b4718'),
    'c4_small_0x37df41a': (58586138, None, '418b4f1b'),
    'c4_t1': (58574195, 58574228, '488dbc24e01700004c8dbc24a02a0000488b2d561af901ba080100004c89feffd5'),
    'c4_t2': (58574228, 58574249, '488d9c2440060000bae00000004889df4c89feffd5'),
    'c4_t3': (58574257, 58574275, '488dbc2460030000bab80000004c89feffd5'),
    'c4_vt': (58583764, 58583771, '4c89f941ff5628'),
    'c4_wb': (58581833, 58581859, '4c8dbc24a02a0000488db424e0170000ba180100004c89ffffd5'),
    'c5_got': (71709923, 71709929, 'ff150f0b3101'),
    'c5_rep': (71710484, 71710487, '4d89e5'),
    'c5_t1': (71709929, 71709954, '488dbc2490020000488b2de8aa3001ba080100004c89eeffd5'),
    'c5_t2': (71709954, 71709975, '4c8dbc2440150000bae00000004c89ff4c89eeffd5'),
    'c5_t3': (71709983, 71710001, '488dbc24a8000000bab80000004c89eeffd5'),
    'dtor_e0': (58683575, 58683579, '498b4500'),
    'dtor_e10': (58683598, 58683602, '498b4510'),
    'dtor_e8': (58683589, 58683593, '498b7508'),
    'dtor_guard': (58683518, 58683528, '4883bf98010000007466'),
    'dtor_loads': (58683565, 58683575, '4e8b7c23e84e8b6c23f0'),
    'esc_m2': (82302380, 82302399, '488db424e8000000ba080100004889df41ffd7'),
    'esc_m3': (82302399, 82302422, '488dbb08010000488db424a0020000ba9811000041ffd7'),
    'fwd_dtor_lp': (0x37fd830, 0x37fd838, '4889dfe83898ffff'),
    'fwd_dtor': (58708591, 58708599, '4889dfe8f99dffff'),
    'fwd_join': (58708535, 58708561, '4881c308010000488db42438130000ba100100004c89f741ffd5'),
    'fwd_m1': (58702360, 58702383, '488dbc24a00100004c8b2db925f701ba0801000041ffd5'),
    'fwd_m2': (58702383, 58702405, '4c8dbc2448140000bae00000004c89ff4889de41ffd5'),
    'fwd_m3': (58702413, 58702432, '488dbc2438130000bab80000004889de41ffd5'),
    'fwd_marker': (58702763, 58702770, '0fb683a0120000'),
    'fwd_tail': (58708561, 58708584, '498dbe10010000488db424a0010000ba9811000041ffd5'),
    'marker_store': (82302422, 82302429, 'c683a0120000ff'),
    'rbx_rdi': (82301834, 82301837, '4889fb'),
}

SEGMENTS = [
    ("rbx-rdi", 0x4E7D38A, 0x4E7D38D, "claim"),
    ("esc-memcpy2", 0x4E7D5AC, 0x4E7D5BF, "claim"),
    ("esc-memcpy3", 0x4E7D5BF, 0x4E7D5D6, "claim"),
    ("marker-store", 0x4E7D5D6, 0x4E7D5DD, "claim"),
    ("got-c1", 0x2446B13, 0x2446B19, "claim"),
    ("got-c2", 0x247FD7B, 0x247FD81, "claim"),
    ("got-c3", 0x326E592, 0x326E598, "claim"),
    ("got-c4", 0x37DC568, 0x37DC56E, "claim"),
    ("got-c5", 0x44634E3, 0x44634E9, "claim"),
    ("c1-t1", 0x2446B19, 0x2446B32, "claim"),
    ("c2-t1", 0x247FD81, 0x247FDA2, "claim"),
    ("c3-fwd", 0x326E598, 0x326E5AB, "claim"),
    ("c4-t1", 0x37DC573, 0x37DC594, "claim"),
    ("c5-t1", 0x44634E9, 0x4463502, "claim"),
    ("fwd-m1", 0x37FBA18, 0x37FBA2F, "claim"),
    ("fwd-m2", 0x37FBA2F, 0x37FBA45, "claim"),
    ("fwd-m3", 0x37FBA4D, 0x37FBA60, "claim"),
    ("fwd-marker", 0x37FBBAB, 0x37FBBB2, "claim"),
    ("fwd-join", 0x37FD237, 0x37FD251, "claim"),
    ("fwd-tail", 0x37FD251, 0x37FD268, "claim"),
    ("fwd-dtor", 0x37FD26F, 0x37FD277, "claim"),
    ("dtor-guard", 0x37F707E, 0x37F7088, "claim"),
    ("dtor-loads", 0x37F70AD, 0x37F70B7, "claim"),
    ("dtor-e0", 0x37F70B7, 0x37F70BB, "claim"),
    ("dtor-e8", 0x37F70C5, 0x37F70C9, "claim"),
    ("dtor-e10", 0x37F70CE, 0x37F70D2, "claim"),
    ("anchor-memcpy-site", 0x4E7D594, 0x4E7D5AC, "anchor"),
    ("anchor-oc-pair", 0x4E72DF3, 0x4E72E07, "anchor"),
]


def fail(msg):
    raise SystemExit("pair_array_escape: FAIL: " + msg)


def parse_sections(data):
    if data[:4] != b"\x7fELF":
        fail("not an ELF file")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, o)
        secs.append({"name_off": name, "type": typ, "addr": addr,
                     "off": off, "size": size})
    shstr = secs[e_shstrndx]
    base = shstr["off"]
    for s in secs:
        end = data.index(b"\x00", base + s["name_off"])
        s["name"] = data[base + s["name_off"]:end].decode()
    return {s["name"]: s for s in secs}


def code_bytes(data, va, length):
    # .text VA -> file offset VA - 0x1000 (verified section layout)
    off = va - 0x1000
    return data[off:off + length]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--node", default="artifacts/node/94/hl-node")
    args = ap.parse_args()
    with open(args.node, "rb") as fh:
        data = fh.read()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if hashlib.sha256(data).hexdigest() != NODE_SHA:
        fail("node SHA-256 mismatch")
    secs = parse_sections(data)
    text = secs[".text"]
    if text["addr"] != 0x1343C80 or text["off"] != 0x1342C80:
        fail(".text layout unexpected")
    # Relocation census: every SHT_RELA section, entries referencing TARGET.
    rel_hits = []
    for name, s in secs.items():
        if s["type"] != 4:  # SHT_RELA
            continue
        ent = 24
        for i in range(s["size"] // ent):
            o = s["off"] + i * ent
            off, info, add = struct.unpack("<QQq", data[o:o + 24])
            if off == TARGET or add == TARGET:
                rel_hits.append({"section": name, "index": i, "slot": hex(off),
                                 "type": info & 0xFFFFFFFF, "addend": hex(add)})
    if len(rel_hits) != 1:
        fail(f"relocation hits for target: {len(rel_hits)} (expected 1)")
    hit = rel_hits[0]
    if hit["section"] != ".rela.dyn" or hit["index"] != RELOC_INDEX \
            or hit["slot"] != hex(GOT_SLOT) or hit["type"] != 8 \
            or hit["addend"] != hex(TARGET):
        fail(f"unexpected relocation hit: {hit}")
    # init/fini arrays must not contain the target.
    for arr in (".init_array", ".fini_array"):
        s = secs[arr]
        for i in range(s["size"] // 8):
            val = struct.unpack_from("<Q", data, s["off"] + i * 8)[0]
            if val == TARGET:
                fail(f"{arr} entry {i} references target")
    # Direct-call census: E8/E9 + rel32 over .text resolving to TARGET.
    e8e9 = []
    start, size = text["off"], text["size"]
    va0 = text["addr"]
    for o in range(start, start + size - 5):
        op = data[o]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", data, o + 1)[0]
            va = va0 + (o - start)
            if va + 5 + rel == TARGET:
                e8e9.append(hex(va))
    if e8e9:
        fail(f"direct E8/E9 references to target: {e8e9}")
    # Verify every recorded span byte.
    for name, (sva, eva, hx) in sorted(SPANS.items()):
        raw = bytes.fromhex(hx)
        if eva is not None and len(raw) != eva - sva:
            fail(f"span {name} length mismatch")
        if code_bytes(data, sva, len(raw)) != raw:
            fail(f"span {name} bytes mismatch at {hex(sva)}")
    # Escape arithmetic (checked, not assumed).
    if not (0x108 + (0x388 - 0x2A0) == 0x1F0):
        fail("escape offset arithmetic")
    if not (0x1F0 + 0x20 == 0x210 and 0x1F0 + 0x28 == 0x218):
        fail("oc-pair offset arithmetic")
    # Destructor loop coverage: iterations r12 in [0x1b0, 0x11b0) step 0x10
    # read [base+r12-0x18] and [base+r12-0x10]; pair array [0x1f0, 0x2a0)
    # must be fully covered.
    covered = set()
    r12 = 0x1B0
    while r12 < 0x11B0:
        covered.add(r12 - 0x18)
        covered.add(r12 - 0x10)
        r12 += 0x10
    # coverage is in 8-byte slots; pair array slots are 8-byte aligned
    for slot in range(0x1F0, 0x2A0, 8):
        if slot not in covered:
            fail(f"destructor loop does not cover pair slot {hex(slot)}")
    # oc-pair iteration: r12 == 0x228 reads [0x210] and [0x218].
    if not (0x228 - 0x18 == 0x210 and 0x228 - 0x10 == 0x218):
        fail("oc-pair iteration arithmetic")
    os.makedirs(args.out, exist_ok=True)
    seg_lines = ["seg_id start_va end_va length file_offset sha256 kind"]
    seg_inv = []
    for name, sva, eva, kind in SEGMENTS:
        raw = code_bytes(data, sva, eva - sva)
        seg_lines.append(
            f"{name} {hex(sva)} {hex(eva)} {eva - sva} {hex(sva - 0x1000)} "
            f"{hashlib.sha256(raw).hexdigest()} {kind}")
        seg_inv.append({"seg_id": name, "start_va": hex(sva),
                        "end_va": hex(eva), "length": eva - sva, "kind": kind})
    with open(os.path.join(args.out, "segments.txt"), "w") as fh:
        fh.write("\n".join(seg_lines) + "\n")
    evidence = {
        "node": {"sha256": NODE_SHA, "size": NODE_SIZE},
        "target_caller": {"fde": ["0x4e7d360", "0x4e7d678"],
                          "builder_call": "0x4e7d4a3",
                          "rbx_is_rdi": "0x4e7d38a"},
        "escape": {
            "pair_copy": {"dst": "0x388", "src": "0x1f0", "len": "0xb0"},
            "sweep": {"dst": "rbx+0x108", "src": "0x2a0", "len": "0x1198"},
            "pair_array_in_object": ["0x1f0", "0x2a0"],
            "oc_pair_in_object": {"cell": "0x210", "element": "0x218"},
            "marker": "rbx+0x12a0 = 0xff",
        },
        "reachability": {
            "direct_e8_e9_hits": 0,
            "relocation_hits": rel_hits,
            "got_slot": hex(GOT_SLOT),
            "got_call_sites": ["0x2446b13", "0x247fd7b", "0x326e592",
                               "0x37dc568", "0x44634e3"],
            "init_array_hit": False,
            "fini_array_hit": False,
        },
        "segments": seg_inv,
        "counts": {
            "segments_total": len(SEGMENTS),
            "segments_claim": sum(1 for s in SEGMENTS if s[3] == "claim"),
            "segments_anchor": sum(1 for s in SEGMENTS if s[3] == "anchor"),
            "claim_bytes": sum(s[2] - s[1] for s in SEGMENTS if s[3] == "claim"),
            "anchor_bytes": sum(s[2] - s[1] for s in SEGMENTS if s[3] == "anchor"),
            "indirect_callers": 5,
            "spans_verified": len(SPANS),
        },
    }
    with open(os.path.join(args.out, "evidence.json"), "w") as fh:
        json.dump(evidence, fh, indent=1, sort_keys=True)
        fh.write("\n")
    escape_tsv = [
        "step	va_start	va_end	desc",
        "rbx_is_rdi	0x4e7d38a	0x4e7d38d	builder caller saves rdi into rbx; rbx is the returned object",
        "pair_copy_anchor	0x4e7d594	0x4e7d5ac	#172 claim: builder output [rsp+0x1f0] (0xb0) copied to [rsp+0x388]",
        "head_copy	0x4e7d5ac	0x4e7d5bf	[rbx+0x0..0x108] = [rsp+0xe8..0x1f0]",
        "sweep_copy	0x4e7d5bf	0x4e7d5d6	[rbx+0x108..0x12a0] = [rsp+0x2a0..0x1438]; pair array [rsp+0x388..0x438] lies inside this span",
        "marker_store	0x4e7d5d6	0x4e7d5dd	[rbx+0x12a0] = 0xff end marker; function returns rbx",
        "pair_in_object	0x1f0	0x2a0	pair array lands at [rbx+0x1f0..0x2a0] (0x108 + (0x388 - 0x2a0) = 0x1f0)",
        "oc_pair_in_object	0x210	0x220	oc pair (pair 3, array offset 0x20): [rbx+0x210] = cell C3, [rbx+0x218] = element 0x574bd30",
    ]
    with open(os.path.join(args.out, "escape.tsv"), "w") as fh:
        fh.write("\n".join(escape_tsv) + "\n")
    callers_tsv = [
        "caller	fde_start	fde_end	got_site	obj_base	t1_dst	t1_len	t2_dst	t2_len	t3_dst	t3_len	repurpose_va	verdict	later_uses",
        "c1	0x2446ac0	0x2447970	0x2446b13	r13=[rsp+0x27e8]	[rsp+0x290]	0x108	[rsp+0x1540]	0xe0	[rsp+0xa8]	0xb8	0x2446d44	NO-READ	none; object pointer never forwarded",
        "c2	0x247fd20	0x2480ef4	0x247fd7b	r14=[rsp+0x1580]	[rsp+0x2d0]	0x108	[rsp+0x2838]	0xe0	[rsp+0x1c0]	0xb8	0x247fe7e	NO-READ	none; object pointer never forwarded",
        "c3	0x326e540	0x326f350	0x326e592	r12=[rsp+0x1540]	-	-	-	-	-	-	0x326e663	FORWARDED	object passed as rsi to 0x37fb9e0 at 0x326e5a6 (rdi=[rsp+0x290], rdx=r15); no direct read of [obj+0x1f0..0x2a0] in c3",
        "c4	0x37dc350	0x37e1581	0x37dc568	r15=[rsp+0x2aa0]	[rsp+0x17e0]	0x108	[rsp+0x640]	0xe0	[rsp+0x360]	0xb8	0x37dde5f	NO-READ	write-back [obj+0x0..0x118] from [rsp+0x17e0] at 0x37de35e; read [obj+0x0..0xb0] to [rsp+0x3d60] at 0x37de3a4; obj+8 copied (0x90) and passed as rcx to vtable call [r14+0x28] at 0x37dead7; small reads via obj+0x39 base cover obj offsets 0x18..0x54 only; max pair-region read: none",
        "c5	0x4463490	0x4464340	0x44634e3	r13=[rsp+0x27e8]	[rsp+0x290]	0x108	[rsp+0x1540]	0xe0	[rsp+0xa8]	0xb8	0x4463714	NO-READ	none; object pointer never forwarded; same instruction skeleton as c1 modulo RIP-relative displacements and two .rodata constants",
    ]
    with open(os.path.join(args.out, "callers.tsv"), "w") as fh:
        fh.write("\n".join(callers_tsv) + "\n")
    forward_tsv = [
        "step	va_start	va_end	desc",
        "fwd_m1	0x37fba18	0x37fba2f	[obj+0x0..0x108] copied to [rsp+0x1a0]",
        "fwd_m2	0x37fba2f	0x37fba45	[obj+0x0..0xe0] copied to [rsp+0x1448]",
        "fwd_m3	0x37fba4d	0x37fba60	[obj+0x0..0xb8] copied to [rsp+0x1338]",
        "fwd_marker	0x37fbbab	0x37fbbb2	reads [rbx+0x12a0] (the builder-caller end marker, 0xff); cmp 0x13, ja to 0x37fc644 block family",
        "fwd_join	0x37fd237	0x37fd251	join block: rbx += 0x108, then [r14] gets [rsp+0x1338] (0x110); falls through to tail",
        "fwd_tail	0x37fd251	0x37fd268	[r14+0x110..0x12a8] = [rsp+0x1a0..0x1338] (0x1198)",
        "fwd_dtor_normal	0x37fd26f	0x37fd277	rdi=rbx (the input object) passed to destructor 0x37f7070; function returns r14",
        "fwd_dtor_landingpad	0x37fd830	0x37fd833	rdi=rbx+0x108 (the +0x108 sub-object) passed to destructor 0x37f7070 on the unwind path",
    ]
    with open(os.path.join(args.out, "forward.tsv"), "w") as fh:
        fh.write("\n".join(forward_tsv) + "\n")
    dtor_tsv = [
        "item	va_start	va_end	desc",
        "guard	0x37f707e	0x37f7088	if [rdi+0x198] == 0 skip the loop (value not statically determined for this object; see Limitations)",
        "loop_bounds	0x37f70a0	0x37f70ab	r12 starts 0x1b0, steps 0x10, exits at 0x11b0",
        "pair_load_cell	0x37f70ad	0x37f70b2	r15 = [rbx+r12-0x18] (pair first qword: cell)",
        "pair_load_elem	0x37f70b2	0x37f70b7	r13 = [rbx+r12-0x10] (pair second qword: element)",
        "elem_slot0	0x37f70b7	0x37f70bb	rax = [r13+0x0]; if nonzero, call rax with rdi=cell",
        "elem_slot8	0x37f70c5	0x37f70c9	rsi = [r13+0x8]; if nonzero, call free (GOT 0x576e010) with rdi=cell",
        "elem_slot10	0x37f70ce	0x37f70d2	rax = [r13+0x10]; read only when [r13+0x8] != 0",
        "oc_pair_iteration	r12=0x228	-	reads [rbx+0x210] (cell C3) and [rbx+0x218] (element 0x574bd30)",
        "table_element_verdict	-	-	for table elements [element+0x0]=0 and [element+0x8]=0, so both guarded actions are skipped; slots [element+0x18/0x20/0x28] (oc3/oc2/oc1) are never loaded by this loop (full-FDE operand census; see Limitations)",
        "pair_coverage	0x198	0x11a8	loop reads [rbx+0x198..0x11a8], which fully contains the pair array [rbx+0x1f0..0x2a0]",
    ]
    with open(os.path.join(args.out, "dtor.tsv"), "w") as fh:
        fh.write("\n".join(dtor_tsv) + "\n")
    print("pair_array_escape: OK")


if __name__ == "__main__":
    main()
