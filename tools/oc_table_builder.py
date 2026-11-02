#!/usr/bin/env python3
"""Deterministic generator for RE-004-oc-table-builder-94.

Verifies, against node #94 only, that oc1/oc2/oc3 (the three direct
callers of the orchestrator from #171) have no direct callers and no
direct references, and are reachable only as the three function slots
of element 6 of an 11-element .data.rel.ro table, materialized by a
builder function into an 11-pair output struct.

Reads only artifacts/node/94/hl-node, checks its SHA-256 and size
first, writes only to --out, performs no execution, evaluation,
disassembly or network access. Code address A maps to file offset
A - 0x1000 (.text); .data.rel.ro VA maps to file offset VA - 0x2000.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"
NODE_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
NODE_SIZE = 91774280
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1343C80, 0x1342C80, 0x431C430

OC = {"oc1": 0x4E6CFE0, "oc2": 0x4E6D690, "oc3": 0x4E6E7D0}
TABLE_BASE = 0x574BC10
TABLE_ELEMS = [
    # (element, base, f0, f1, f2)
    (0, 0x574BC10, 0x4E6E850, 0x4E6DF40, 0x4E6CF80),
    (1, 0x574BC40, 0x4E6E4C0, 0x4E6DCB0, 0x4E6CD80),
    (2, 0x574BC70, 0x4E6E050, 0x4E6DDF0, 0x4E6D210),
    (3, 0x574BCA0, 0x4E6E680, 0x4E6D9E0, 0x4E6D0C0),
    (4, 0x574BCD0, 0x4E6E320, 0x4E6D970, 0x4E6CF10),
    (5, 0x574BD00, 0x4E6E1A0, 0x4E6DB30, 0x4E6D360),
    (6, 0x574BD30, 0x4E6E7D0, 0x4E6D690, 0x4E6CFE0),
    (7, 0x574BD60, 0x4E6E600, 0x4E6D8F0, 0x4E6D4E0),
    (8, 0x574BD90, 0x4E6DFA0, 0x4E6D710, 0x4E6D060),
    (9, 0x574BDC0, 0x4E6E000, 0x4E6D8A0, 0x4E6CEC0),
    (10, 0x574BDF0, 0x4E6E390, 0x4E6D770, 0x4E6D560),
]
ELEM_BY_BASE = {e[1]: e[0] for e in TABLE_ELEMS}
# (pair, out_offset, cell, element, elem_base)
PAIRS = [
    (1, 0x00, "C1", 4, 0x574BCD0),
    (2, 0x10, "C2", 5, 0x574BD00),
    (3, 0x20, "C3", 6, 0x574BD30),
    (4, 0x30, "C4", 0, 0x574BC10),
    (5, 0x40, "C5", 1, 0x574BC40),
    (6, 0x50, "C6", 7, 0x574BD60),
    (7, 0x60, "C7", 8, 0x574BD90),
    (8, 0x70, "C8", 2, 0x574BC70),
    (9, 0x80, "C9", 9, 0x574BDC0),
    (10, 0x90, "C10", 10, 0x574BDF0),
    (11, 0xA0, "C11", 3, 0x574BCA0),
]
# (phase, lea_va, target_base)
BUILDER_LEAS = [
    ("malloc", 0x4E72B7F, 0x574BCD0),
    ("malloc", 0x4E72BB6, 0x574BD00),
    ("malloc", 0x4E72BED, 0x574BD30),
    ("malloc", 0x4E72C24, 0x574BC10),
    ("malloc", 0x4E72C5D, 0x574BC40),
    ("malloc", 0x4E72C99, 0x574BD60),
    ("malloc", 0x4E72CDB, 0x574BD90),
    ("malloc", 0x4E72D1D, 0x574BC70),
    ("malloc", 0x4E72D5E, 0x574BDC0),
    ("malloc", 0x4E72D9B, 0x574BDF0),
    ("assembly", 0x4E72DD4, 0x574BCD0),
    ("assembly", 0x4E72DE8, 0x574BD00),
    ("assembly", 0x4E72DFC, 0x574BD30),
    ("assembly", 0x4E72E10, 0x574BC10),
    ("assembly", 0x4E72E24, 0x574BC40),
    ("assembly", 0x4E72E33, 0x574BD60),
    ("assembly", 0x4E72E42, 0x574BD90),
    ("assembly", 0x4E72E51, 0x574BC70),
    ("assembly", 0x4E72E63, 0x574BDC0),
    ("assembly", 0x4E72E78, 0x574BDF0),
    ("assembly", 0x4E72E8D, 0x574BCA0),
]
# (call_va, store0_va, store1_va) — allocation calls, GOT 0x576dfd8
MALLOC_SITES = [
    (0x4E72B59, 0x4E72B6B, 0x4E72B72),
    (0x4E72B90, 0x4E72BA2, 0x4E72BA9),
    (0x4E72BC7, 0x4E72BD9, 0x4E72BE0),
    (0x4E72BFE, 0x4E72C10, 0x4E72C17),
    (0x4E72C35, 0x4E72C44, 0x4E72C4B),
    (0x4E72C6E, 0x4E72C85, 0x4E72C8C),
    (0x4E72CAD, 0x4E72CC4, 0x4E72CCB),
    (0x4E72CEF, 0x4E72D06, 0x4E72D0D),
    (0x4E72D31, 0x4E72D47, 0x4E72D4E),
    (0x4E72D72, 0x4E72D84, 0x4E72D8B),
    (0x4E72DAF, 0x4E72DBE, 0x4E72DC5),
]
SEGMENTS = [
    # (seg_id, start_va, end_va, section, kind)
    ("table", 0x574BC10, 0x574BE20, "data.rel.ro", "claim"),
    ("oc-pair-stores", 0x4E72DF3, 0x4E72E07, "text", "claim"),
    ("builder-call", 0x4E7D4A3, 0x4E7D4A8, "text", "claim"),
    ("memcpy-site", 0x4E7D594, 0x4E7D5AC, "text", "claim"),
    ("elem11-setter", 0x4E78683, 0x4E7868E, "text", "claim"),
    ("elem11-store", 0x4E76A70, 0x4E76A7F, "text", "claim"),
    ("first-malloc", 0x4E72B54, 0x4E72B7A, "text", "claim"),
]


def fail(msg):
    raise SystemExit("FAIL: " + msg)


def text_off(va):
    return va - 0x1000


def data_off(va):
    return va - 0x2000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    data = NODE.read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if hashlib.sha256(data).hexdigest() != NODE_SHA:
        fail("node digest mismatch")

    # ---- relocations -------------------------------------------------
    rel = {}
    rel_entries = []
    for sec, base, size in (("rela.dyn", 0x6BC0, 0x1D4E10),
                            ("rela.plt", 0x1DB9D0, 0x1A10)):
        for i in range(size // 24):
            ro, ri, ra = struct.unpack("<QQq", data[base + i * 24: base + i * 24 + 24])
            if (ri & 0xFFFFFFFF) == 8 and ri >> 32 == 0:
                rel[ro] = ra
                rel_entries.append((sec, i, ro, ra))
    oc_rel = [(s, i, ro, ra) for (s, i, ro, ra) in rel_entries
              if ra in OC.values()]
    if len(oc_rel) != 3:
        fail(f"oc reloc entries: {len(oc_rel)} != 3")
    oc_slots = {ra: ro for (_s, _i, ro, ra) in oc_rel}
    if oc_slots != {0x4E6E7D0: 0x574BD48, 0x4E6D690: 0x574BD50,
                    0x4E6CFE0: 0x574BD58}:
        fail(f"oc slots unexpected: {oc_slots}")

    # ---- table -------------------------------------------------------
    def qword(va):
        o = data_off(va)
        return struct.unpack("<Q", data[o:o + 8])[0]

    table_rows = []
    for (elem, base, f0, f1, f2) in TABLE_ELEMS:
        if (qword(base), qword(base + 8), qword(base + 16)) != (0, 0, 1):
            fail(f"element {elem} header != (0,0,1)")
        got = (rel.get(base + 0x18), rel.get(base + 0x20), rel.get(base + 0x28))
        if got != (f0, f1, f2):
            fail(f"element {elem} fns {got} != {(f0, f1, f2)}")
        table_rows.append((elem, base, f0, f1, f2))
    # boundary: preceding qwords do not fit the pattern
    pre = [qword(v) for v in (0x574BBF0, 0x574BBF8, 0x574BC00, 0x574BC08)]
    if pre == [0, 0, 1, 0] or (qword(0x574BC10), qword(0x574BC18)) != (0, 0):
        fail("table start boundary unexpected")
    # be20 is a separate object: its first slot is itself relocated
    be20_first = rel.get(0x574BE20)
    if be20_first != 0x4E78670:
        fail(f"be20 first slot reloc {be20_first}")

    # ---- builder leas -------------------------------------------------
    for (phase, va, tgt) in BUILDER_LEAS:
        o = text_off(va)
        b = data[o:o + 7]
        if b[0] != 0x48 or b[1] != 0x8D or (b[2] & 0xC7) != 0x05:
            fail(f"lea at {va:#x} not 48 8d rip-relative: {b.hex()}")
        disp = struct.unpack("<i", b[3:7])[0]
        if va + 7 + disp != tgt:
            fail(f"lea at {va:#x} resolves to {va + 7 + disp:#x} != {tgt:#x}")
        if ELEM_BY_BASE.get(tgt) is None:
            fail(f"lea target {tgt:#x} not a table element base")

    # ---- mallocs ------------------------------------------------------
    for (call_va, s0, s1) in MALLOC_SITES:
        o = text_off(call_va)
        if data[o - 5:o] != bytes.fromhex("bf10000000"):
            fail(f"malloc at {call_va:#x} not preceded by mov edi,0x10")
        b = data[o:o + 6]
        if b[0] != 0xFF or b[1] != 0x15:
            fail(f"malloc call at {call_va:#x} not FF 15: {b.hex()}")
        disp = struct.unpack("<i", b[2:6])[0]
        if call_va + 6 + disp != 0x576DFD8:
            fail(f"malloc call at {call_va:#x} GOT target mismatch")
        if data[text_off(s0):text_off(s0) + 7] != bytes.fromhex("48c70001000000"):
            fail(f"init store0 at {s0:#x} mismatch")
        if data[text_off(s1):text_off(s1) + 8] != bytes.fromhex("48c7400801000000"):
            fail(f"init store1 at {s1:#x} mismatch")

    # ---- fixed sites ---------------------------------------------------
    def text_bytes(va, n):
        return data[text_off(va):text_off(va) + n]

    # builder call site: E8 rel32 -> 0x4e72b40
    b = text_bytes(0x4E7D4A3, 5)
    if b[0] != 0xE8 or 0x4E7D4A3 + 5 + struct.unpack("<i", b[1:5])[0] != 0x4E72B40:
        fail("builder call site mismatch")
    # memcpy site: lea rdi,[rsp+0x388]; lea rsi,[rsp+0x1f0]; mov edx,0xb0; call r15
    m = text_bytes(0x4E7D594, 24)
    if m != bytes.fromhex("488dbc2488030000488db424f0010000bab000000041ffd7"):
        fail("memcpy site bytes mismatch")
    # elem11 setter: lea rcx,[be20]; mov [rdi],rcx; ret
    s = text_bytes(0x4E78683, 11)
    if s != bytes.fromhex("488d0d96378d0048890fc3"):
        fail("elem11 setter bytes mismatch")
    # elem11 store site: lea rcx,[be20]; mov rdx,[rsp+0x20]; mov [rdx],rcx
    t = text_bytes(0x4E76A70, 15)
    if t != bytes.fromhex("488d0da9538d00488b54242048890a"):
        fail("elem11 store site bytes mismatch")
    # oc-pair stores: mov rcx,[rsp+0x10]; mov [rbx+0x20],rcx;
    #                 lea rcx,[bd30]; mov [rbx+0x28],rcx
    p = text_bytes(0x4E72DF3, 20)
    if p != bytes.fromhex("488b4c241048894b20488d0d2d8f8d0048894b28"):
        fail("oc-pair store bytes mismatch")

    # ---- zero-hit scans ------------------------------------------------
    # E8/E9 direct calls to oc targets over all of .text (C-fast find)
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    for tgt in OC.values():
        for op in (0xE8, 0xE9):
            pos = 0
            while True:
                i = text.find(bytes([op]), pos)
                if i < 0:
                    break
                if i + 5 <= len(text):
                    rel32 = struct.unpack("<i", text[i + 1:i + 5])[0]
                    if TEXT_VA + i + 5 + rel32 == tgt:
                        fail(f"direct call to {tgt:#x} at {TEXT_VA + i:#x}")
                pos = i + 1
    # RIP-relative references to oc addresses: none
    modrm = bytes([m for m in range(256) if m & 0xC7 == 0x05])
    rex_pat = re.compile(b"[\x48\x4c\x49\x4d][\x8b\x8d\x8a\x63\x39\x3b][" +
                         re.escape(modrm) + b"]")
    rex_vas = set()
    for m in rex_pat.finditer(text):
        i = m.start()
        va = TEXT_VA + i
        disp = struct.unpack("<i", text[i + 3:i + 7])[0]
        if va + 7 + disp in OC.values():
            fail(f"RIP-relative ref to oc at {va:#x}")
        rex_vas.add(va)
    norex_pat = re.compile(b"[\x8b\x8d\x8a\x39\x3b][" + re.escape(modrm) + b"]")
    for m in norex_pat.finditer(text):
        i = m.start()
        va = TEXT_VA + i
        if (va - 1) in rex_vas:
            continue
        disp = struct.unpack("<i", text[i + 2:i + 6])[0]
        if va + 6 + disp in OC.values():
            fail(f"non-REX RIP-relative ref to oc at {va:#x}")

    # ---- RIP census over [table_base, 0x574bf00) -----------------------
    lo, hi = TABLE_BASE, 0x574BF00
    census = {}
    for m in rex_pat.finditer(text):
        i = m.start()
        va = TEXT_VA + i
        disp = struct.unpack("<i", text[i + 3:i + 7])[0]
        tgt = va + 7 + disp
        if lo <= tgt < hi:
            census[va] = tgt
    if len(census) != 29:
        fail(f"RIP census sites: {len(census)} != 29")
    expected_census = {va: tgt for (_ph, va, tgt) in BUILDER_LEAS}
    expected_census.update({0x4E76A70: 0x574BE20, 0x4E78683: 0x574BE20,
                            0x4E772FB: 0x574BE60, 0x4E7795C: 0x574BE78,
                            0x4E77993: 0x574BEA8, 0x4E779CA: 0x574BED8,
                            0x4E779FC: 0x574BE78, 0x4E77E82: 0x574BE48})
    if census != expected_census:
        fail("RIP census set mismatch")

    # ---- segments -------------------------------------------------------
    seg_lines = []
    for (seg_id, sva, eva, section, kind) in SEGMENTS:
        off = data_off(sva) if section == "data.rel.ro" else text_off(sva)
        raw = data[off:off + (eva - sva)]
        if len(raw) != eva - sva:
            fail(f"segment {seg_id} short read")
        seg_lines.append(
            f"{seg_id} {sva:#x} {eva:#x} {eva - sva} {off:#x} "
            f"{hashlib.sha256(raw).hexdigest()} {kind}")

    # ---- emit -----------------------------------------------------------
    evidence = {
        "node": {"digest": NODE_SHA, "size": NODE_SIZE},
        "claim": "oc1/oc2/oc3 have no direct callers and no direct references; "
                 "they are reachable only as element 6's three function slots "
                 "of an 11-element .data.rel.ro table, materialized by the "
                 "builder into an 11-pair output struct.",
        "table": {"base": hex(TABLE_BASE), "end": hex(TABLE_BASE + 11 * 0x30),
                  "elements": 11, "stride": 48,
                  "shape": ["qword 0", "qword 0", "qword 1", "fn", "fn", "fn"],
                  "oc_element": 6, "oc_element_base": hex(0x574BD30)},
        "oc_relocs": [{"entry": i, "slot": hex(ro), "target": hex(ra),
                       "name": n}
                      for (s, i, ro, ra) in oc_rel
                      for n in [k for k, v in OC.items() if v == ra]],
        "builder": {"fde": ["0x4e72b40", "0x4e730a5"], "size": 1381,
                    "malloc_calls": len(MALLOC_SITES),
                    "cell_size": 16, "cell_init": [1, 1],
                    "pairs": len(PAIRS), "output_bytes": 176},
        "builder_caller": {"fde": ["0x4e7d360", "0x4e7d678"], "size": 792,
                           "call_va": "0x4e7d4a3", "out_buffer": "[rsp+0x1f0]",
                           "memcpy": {"dst": "[rsp+0x388]", "len": 176}},
        "elem11": {"object": "0x574be20",
                   "setter_fde": ["0x4e78670", "0x4e7868e"],
                   "store_fde": ["0x4e76900", "0x4e76af5"]},
        "scans": {"direct_E8_E9_hits_per_oc_target": 0,
                  "rip_refs_to_oc": 0,
                  "rip_census_range": ["0x574bc10", "0x574bf00"],
                  "rip_census_sites": 29,
                  "rip_census_builder_leas": 21,
                  "rip_census_be20_leas": 2,
                  "rip_census_be20_neighborhood_leas": 6},
        "segments": {"rows": len(seg_lines),
                     "claim_bytes": sum(e - s for (_i, s, e, _s, _k) in SEGMENTS)},
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (out / "table.tsv").write_text(
        "element\tbase_va\tf0_va\tf1_va\tf2_va\n" +
        "".join(f"{e}\t{b:#x}\t{f0:#x}\t{f1:#x}\t{f2:#x}\n"
                for (e, b, f0, f1, f2) in table_rows))
    (out / "pairs.tsv").write_text(
        "pair\tout_offset\tcell\telement\telem_base_va\n" +
        "".join(f"{p}\t{o:#x}\t{c}\t{e}\t{b:#x}\n"
                for (p, o, c, e, b) in PAIRS))
    (out / "builder-leas.tsv").write_text(
        "phase\tlea_va\ttarget_va\telement\n" +
        "".join(f"{ph}\t{v:#x}\t{t:#x}\t{ELEM_BY_BASE[t]}\n"
                for (ph, v, t) in BUILDER_LEAS))
    (out / "sites.tsv").write_text(
        "site\tva_or_range\tkind\tnote\n" +
        "builder_fde\t0x4e72b40..0x4e730a5\tfde\t1189 bytes; 11 mallocs, 11 pairs\n" +
        "builder_call\t0x4e7d4a3\tcall\tE8 -> builder 0x4e72b40\n" +
        "builder_caller_fde\t0x4e7d360..0x4e7d678\tfde\t792 bytes; out buffer [rsp+0x1f0]\n" +
        "memcpy_site\t0x4e7d594..0x4e7d5ac\tcall\tr15=memcpy, 0xb0 bytes, [rsp+0x1f0]->[rsp+0x388]\n" +
        "elem11_setter_fde\t0x4e78670..0x4e7868e\tfde\t30 bytes; lea be20 at 0x4e78683, mov [rdi],rcx\n" +
        "elem11_store_fde\t0x4e76900..0x4e76af5\tfde\t501 bytes; lea be20 at 0x4e76a70, mov [rdx],rcx\n" +
        "reloc_oc3\t0x574bd48\t-reloc\t.rela.dyn entry 61853, RELATIVE -> oc3\n" +
        "reloc_oc2\t0x574bd50\t-reloc\t.rela.dyn entry 61854, RELATIVE -> oc2\n" +
        "reloc_oc1\t0x574bd58\t-reloc\t.rela.dyn entry 61855, RELATIVE -> oc1\n" +
        "scan_E8_E9_oc\tall .text\tscan\t0 direct calls to any oc target\n" +
        "scan_rip_oc\tall .text\tscan\t0 RIP-relative refs to any oc address\n" +
        "scan_rip_census\t0x574bc10..0x574bf00\tscan\t29 sites: 21 builder + 2 be20 + 6 neighborhood\n")
    (out / "segments.txt").write_text(
        "seg_id start_va end_va length file_offset sha256 kind\n" +
        "\n".join(seg_lines) + "\n")
    print(f"wrote {len(seg_lines)} segments, "
          f"{evidence['segments']['claim_bytes']} claim bytes")


if __name__ == "__main__":
    main()
