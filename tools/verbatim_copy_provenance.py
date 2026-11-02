#!/usr/bin/env python3
"""Deterministic generator for RE-004-verbatim-copy-provenance-94.

Reads artifacts/node/94/hl-node, verifies its SHA-256 and size first,
then extracts the verbatim-copy provenance evidence (segments, path
tables, slot verdicts) and writes evidence.json, verbatim-paths.tsv,
vtable-routes.tsv, slot-verdicts.tsv and segments.txt into --out.

Writes ONLY to --out. No node execution, no evaluator, no disassembler,
no network.

Address convention (empirically verified for this artifact):
  - Code addresses are the addresses objdump prints for this binary.
    File bytes for a code address A live at file offset A - 0x1000
    (verified: offset 0x4e6ed50 holds trioA's prologue 55 41 56 53,
    matching objdump at 0x4e6fd50; jump-table entries read from .rodata
    resolve exactly to the analyzed blocks).
  - .rodata: file offset == VA (jump table 0x7c3b84).
  - .got: file offset == VA - 0x2000 (slots 0x57732a8/0x57732b0).
  - .data: file offset == VA - 0x3000 (objects 0x5786838/0x5786858).
Relocation addends are read from .rela.dyn itself (offset 0x6bc0,
entry size 24), not assumed.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

NODE_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
NODE_SIZE = 91774280
NODE_REL = Path("artifacts/node/94/hl-node")

# region -> file-offset delta
REGION_DELTA = {"code": -0x1000, "rodata": 0, "got": -0x2000, "data": -0x3000}

# (name, start_va, end_va, region, kind)
SEGMENTS = [
    ("trioA-verbatim-read", 0x4E6FE04, 0x4E6FE39, "code", "claim"),
    ("doublegate-path1-read", 0x4E853E0, 0x4E8540E, "code", "claim"),
    ("doublegate-path1-store", 0x4E85588, 0x4E855CA, "code", "claim"),
    ("doublegate-path2-read", 0x4E854FF, 0x4E8552D, "code", "claim"),
    ("triob-direct-read", 0x4E857D9, 0x4E85808, "code", "claim"),
    ("triob-direct-store", 0x4E859BA, 0x4E859FD, "code", "claim"),
    ("triob-vtable-call", 0x4E85851, 0x4E85867, "code", "claim"),
    ("triob-vtable-copy", 0x4E85867, 0x4E858C3, "code", "claim"),
    ("triob-jump-table", 0x7C3B84, 0x7C3B98, "rodata", "claim"),
    ("triob-vtable-header0", 0x4E8596D, 0x4E85982, "code", "claim"),
    ("triob-vtable-header1-nonzero", 0x4E8592D, 0x4E8596D, "code", "claim"),
    ("triob-vtable-header1-zero", 0x4E85A17, 0x4E85A37, "code", "claim"),
    ("triob-vtable-assembly", 0x4E85A37, 0x4E85A56, "code", "claim"),
    ("gatelike-verbatim-read", 0x4E863D7, 0x4E86405, "code", "claim"),
    ("gatelike-verbatim-store", 0x4E86636, 0x4E86678, "code", "claim"),
    ("decoder-A-writes", 0x4E6F5CC, 0x4E6F5D6, "code", "anchor"),
    ("decoder-B-writes", 0x4E8476C, 0x4E84776, "code", "anchor"),
]

FUNCTIONS = [
    # (id, start, end) -- FDE extents, verified against disassembly
    ("trioA", 0x4E6FD50, 0x4E6FEE2),
    ("double-gate", 0x4E852A0, 0x4E85663),
    ("trioB", 0x4E856F0, 0x4E85B12),
    ("gate-like", 0x4E862B0, 0x4E8673A),
    ("decoder-A", 0x4E6F360, 0x4E6F68C),
    ("decoder-B", 0x4E84500, 0x4E8482C),
]

DECODERS = [
    # (id, start, end, write_sites)
    ("A", 0x4E6F360, 0x4E6F68C, ["0x4e6f5cc", "0x4e6f5d0", "0x4e6f5d3"]),
    ("B", 0x4E84500, 0x4E8482C, ["0x4e8476c", "0x4e84770", "0x4e84773"]),
]

# Jump-table entries: header value -> target (base-relative, add rax,rcx
# at 0x4e857cb). Entry 4 is unreachable from this switch (header == 4
# takes the sentinel-compare route); it is recorded, not a verbatim route.
JUMP_TABLE_BASE = 0x7C3B84
JUMP_TARGETS = {0: 0x4E8596D, 1: 0x4E85903, 2: 0x4E857D0, 3: 0x4E8584A, 4: 0x4E85A56}

PATH_HEADER = (
    "caller\tpath\tdecoder_buffer_rsp\tdecoder_or_callee\tdecoder_call_va\t"
    "tag_branch_va\tcopy_read_start\tcopy_read_end\tfinal_store_start\t"
    "final_store_end\tdestination\tverdict\tstale_bytes\n"
)
PATH_ROWS = [
    # caller, path, buf_rsp, callee, call_va, branch_va, read_start,
    # read_end, store_start, store_end, destination, verdict, stale_bytes
    ("trioA", "direct", "0x0", "decoder-A 0x4e6f360", "0x4e6fd5e", "0x4e6fd69",
     "0x4e6fe04", "0x4e6fe39", "0x4e6fe04", "0x4e6fe39", "[rbx+0x0..0x20]",
     "unwritten", "22"),
    ("double-gate", "first-decode", "0x20", "decoder-B 0x4e84500", "0x4e852c7",
     "0x4e852d6", "0x4e853e0", "0x4e8540e", "0x4e85588", "0x4e855ca",
     "[rbx+0xb8..0xd8]", "unwritten", "22"),
    ("double-gate", "second-decode", "0x50", "decoder-B 0x4e84500", "0x4e854d8",
     "0x4e854e7", "0x4e854ff", "0x4e8552d", "0x4e85588", "0x4e855ca",
     "[rbx+0xb8..0xd8]", "path-dependent", "22-or-0"),
    ("trioB", "direct", "0x20", "decoder-B 0x4e84500", "0x4e8570a", "0x4e85718",
     "0x4e857d9", "0x4e85808", "0x4e859ba", "0x4e859fd", "[r14+0xb8..0xd0]",
     "unwritten", "22"),
    ("trioB", "vtable", "0x50", "vtable-callee (see vtable-routes.tsv)",
     "switch 0x4e857c0", "jump-table 0x7c3b84", "0x4e85867", "0x4e858c3",
     "0x4e85867", "0x4e858c3", "[rbx+0x0..0x20]", "mixed (see vtable-routes.tsv)",
     "mixed"),
    ("gate-like", "direct", "0x20", "decoder-B 0x4e84500", "0x4e862ca",
     "0x4e862d8", "0x4e863d7", "0x4e86405", "0x4e86636", "0x4e86678",
     "[r14+0xb8..0xd0]", "unwritten", "22"),
]

ROUTE_HEADER = (
    "header_value\tswitch_entry_va\tentry_target_va\tcallee_source\t"
    "callee_out_rsp\tassembly\tverdict\n"
)
ROUTE_ROWS = [
    ("0", "0x7c3b84", "0x4e8596d", "[r14+0x8] (indirect)", "0x50", "none",
     "callee-extent-unverified"),
    ("1-zero", "0x7c3b88", "0x4e85903->0x4e85a17",
     "none (caller-constructed)", "0x50", "0x4e85a37", "fully-produced"),
    ("1-nonzero", "0x7c3b88", "0x4e85903->0x4e8592d",
     "[r14+0x8] (indirect)", "0x70", "0x4e85a37",
     "0x68-from-0x88-unresolved (rest produced)"),
    ("2", "0x7c3b8c", "0x4e857d0",
     ".got slot 0x57732a8 -> .data object 0x5786858 (runtime-initialized)",
     "0x50", "none", "callee-extent-unverified"),
    ("3", "0x7c3b90", "0x4e8584a",
     ".got slot 0x57732b0 -> .data object 0x5786838 (runtime-initialized)",
     "0x50", "none", "callee-extent-unverified"),
]

SLOT_HEADER = "path\tslot_buf_rel\tslot_abs_rsp\twriter\tverdict\n"


def slot_rows():
    rows = []
    # Direct paths: identical relative shape, different absolute buffers.
    for path, buf, dec in [
        ("trioA-direct", "0x0", "decoder-A"),
        ("doublegate-path1", "0x20", "decoder-B"),
        ("triob-direct", "0x20", "decoder-B"),
        ("gatelike-direct", "0x20", "decoder-B"),
    ]:
        base = int(buf, 16)

        def absr(lo, hi):
            if lo == hi:
                return "0x%x" % (base + lo)
            return "0x%x..0x%x" % (base + lo, base + hi)

        rows += [
            (path, "0x0", absr(0, 0), dec, "decoder-written"),
            (path, "0x1..0x8", absr(1, 8), "none", "stale"),
            (path, "0x8", absr(8, 8), dec, "decoder-written"),
            (path, "0x10", absr(0x10, 0x10), dec, "decoder-written"),
            (path, "0x11..0x20", absr(0x11, 0x20), "none", "stale"),
        ]
    # Double-gate second decode: path-dependent low/high slots.
    rows += [
        ("doublegate-path2", "0x0", "0x50", "decoder-B", "decoder-written"),
        ("doublegate-path2", "0x1..0x8", "0x51..0x58",
         "header-store 0x4e85325 on non-match route, none otherwise",
         "path-dependent"),
        ("doublegate-path2", "0x8", "0x58", "decoder-B", "decoder-written"),
        ("doublegate-path2", "0x10", "0x60", "decoder-B", "decoder-written"),
        ("doublegate-path2", "0x11..0x20", "0x61..0x70",
         "constructor-B 0x4e81dc0 on non-match route, none otherwise",
         "path-dependent"),
    ]
    # TrioB vtable routes (buffer [rsp+0x50..]).
    for route, callee in [
        ("triob-vtable-h0", "[r14+0x8] (indirect)"),
        ("triob-vtable-h2", ".got slot 0x57732a8 -> object 0x5786858"),
        ("triob-vtable-h3", ".got slot 0x57732b0 -> object 0x5786838"),
    ]:
        rows += [
            (route, "0x0", "0x50", callee, "callee-extent-unverified"),
            (route, "0x1..0x8", "0x51..0x58", callee, "callee-extent-unverified"),
            (route, "0x8", "0x58", callee, "callee-extent-unverified"),
            (route, "0x10", "0x60", callee, "callee-extent-unverified"),
            (route, "0x11..0x20", "0x61..0x70", callee, "callee-extent-unverified"),
        ]
    rows += [
        ("triob-vtable-h1zero", "0x0", "0x50",
         "caller: low byte of 0x574f910 pointer", "produced"),
        ("triob-vtable-h1zero", "0x1..0x8", "0x51..0x58",
         "caller: remaining pointer bytes", "produced"),
        ("triob-vtable-h1zero", "0x8", "0x58", "caller: [r14+0x10]", "produced"),
        ("triob-vtable-h1zero", "0x10", "0x60", "caller: zeroed [rsp+0x20]",
         "produced"),
        ("triob-vtable-h1zero", "0x11..0x18", "0x61..0x68",
         "caller: zeroed", "produced"),
        ("triob-vtable-h1zero", "0x18..0x20", "0x68..0x70",
         "caller: zeroed [rsp+0x20..0x30] (movdqa 0x4e85a21)", "produced"),
    ]
    rows += [
        ("triob-vtable-h1nonzero", "0x0", "0x50",
         "vtable-callee [r14+0x8] via [0x70..0x80] copy",
         "callee-extent-unverified"),
        ("triob-vtable-h1nonzero", "0x1..0x8", "0x51..0x58",
         "vtable-callee [r14+0x8] via [0x70..0x80] copy",
         "callee-extent-unverified"),
        ("triob-vtable-h1nonzero", "0x8", "0x58",
         "vtable-callee [r14+0x8] via [0x70..0x80] copy",
         "callee-extent-unverified"),
        ("triob-vtable-h1nonzero", "0x10..0x18", "0x60..0x68",
         "caller: r15=[r14+0x30]", "produced"),
        ("triob-vtable-h1nonzero", "0x18..0x20", "0x68..0x70",
         "vtable-callee [r14+0x8] via [0x88]; extent >=0x18 required",
         "unresolved-indirect"),
    ]
    return rows


def read_at(data, va, length, region):
    off = va + REGION_DELTA[region]
    if off < 0 or off + length > len(data):
        raise ValueError("read out of bounds: va %#x region %s" % (va, region))
    return data[off:off + length]


def read_qword(data, va, region):
    return struct.unpack("<Q", read_at(data, va, 8, region))[0]


def rela_addends(data):
    """Scan .rela.dyn (file offset 0x6bc0, size 0x1d4e10, entsize 24)
    for R_X86_64_RELATIVE entries at the two .got slots."""
    out = {}
    off, size = 0x6BC0, 0x1D4E10
    for i in range(size // 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", data, off + i * 24)
        if r_off in (0x57732A8, 0x57732B0):
            r_type = r_info & 0xFFFFFFFF
            if r_type != 8:
                raise ValueError("slot %#x has non-RELATIVE type %d" % (r_off, r_type))
            out[r_off] = r_add
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", default=str(NODE_REL))
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    node_path = Path(args.node)
    data = node_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != NODE_SHA256:
        sys.exit("node digest mismatch: %s" % digest)
    if len(data) != NODE_SIZE:
        sys.exit("node size mismatch: %d" % len(data))

    segments = []
    for name, s, e, region, kind in SEGMENTS:
        raw = read_at(data, s, e - s, region)
        segments.append({
            "name": name, "start": "0x%x" % s, "end": "0x%x" % e,
            "length": e - s, "sha256": hashlib.sha256(raw).hexdigest(),
            "kind": kind, "region": region,
        })

    # Jump-table self-check: entries must decode to the expected targets.
    jt = []
    for header in range(5):
        entry = struct.unpack(
            "<i", read_at(data, JUMP_TABLE_BASE + 4 * header, 4, "rodata"))[0]
        target = JUMP_TABLE_BASE + entry
        if target != JUMP_TARGETS[header]:
            sys.exit("jump-table entry %d decodes to %#x, expected %#x"
                     % (header, target, JUMP_TARGETS[header]))
        jt.append({"header": header,
                   "entry_va": "0x%x" % (JUMP_TABLE_BASE + 4 * header),
                   "target": "0x%x" % target})

    relocs = rela_addends(data)
    if set(relocs) != {0x57732A8, 0x57732B0}:
        sys.exit("relocation scan missed a .got slot: %s"
                 % sorted(hex(k) for k in relocs))
    vtable_objects = []
    for slot, obj in [(0x57732A8, relocs[0x57732A8]),
                      (0x57732B0, relocs[0x57732B0])]:
        first = read_qword(data, obj, "data")
        second = read_qword(data, obj + 8, "data")
        third = read_qword(data, obj + 16, "data")
        if (first, second, third) != (0, 0, 2):
            sys.exit("vtable object %#x file bytes unexpected: %#x %#x %#x"
                     % (obj, first, second, third))
        vtable_objects.append({
            "got_slot": "0x%x" % slot, "object": "0x%x" % obj,
            "file_qwords": ["0x%x" % first, "0x%x" % second, "0x%x" % third],
            "note": "first qword is 0 in file: callee resolved at runtime only",
        })

    slots = slot_rows()
    evidence = {
        "node": 94,
        "node_sha256": NODE_SHA256,
        "node_size": NODE_SIZE,
        "functions": [{"id": fid, "start": "0x%x" % s, "end": "0x%x" % e,
                       "len": e - s} for fid, s, e in FUNCTIONS],
        "decoders": [{"id": did, "start": "0x%x" % s, "end": "0x%x" % e,
                      "len": e - s, "output_stores": 3,
                      "write_sites": sites,
                      "fields": ["[out+0x0] tag byte 0x5",
                                 "[out+0x8] object-pointer qword",
                                 "[out+0x10] flag byte"]}
                     for did, s, e, sites in DECODERS],
        "segments": segments,
        "jump_table": {"base": "0x%x" % JUMP_TABLE_BASE, "entries": jt,
                       "note": "header 4 entry is unreachable from this switch "
                               "(header == 4 takes the sentinel-compare route)"},
        "relocations": [{"got_slot": "0x%x" % slot,
                         "type": "R_X86_64_RELATIVE",
                         "addend": "0x%x" % add}
                        for slot, add in sorted(relocs.items())],
        "vtable_objects": vtable_objects,
        "counts": {
            "paths": len(PATH_ROWS),
            "vtable_routes": len(ROUTE_ROWS),
            "slot_rows": len(slots),
            "segment_rows": len(segments),
            "claim_segments": sum(1 for s in segments if s["kind"] == "claim"),
            "anchor_segments": sum(1 for s in segments if s["kind"] == "anchor"),
            "claim_bytes": sum(s["length"] for s in segments
                               if s["kind"] == "claim"),
            "anchor_bytes": sum(s["length"] for s in segments
                                if s["kind"] == "anchor"),
            "direct_unwritten_paths": 4,
            "stale_bytes_per_direct_path": 22,
        },
    }

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (out / "verbatim-paths.tsv").write_text(
        PATH_HEADER + "".join("\t".join(r) + "\n" for r in PATH_ROWS))
    (out / "vtable-routes.tsv").write_text(
        ROUTE_HEADER + "".join("\t".join(r) + "\n" for r in ROUTE_ROWS))
    (out / "slot-verdicts.tsv").write_text(
        SLOT_HEADER + "".join("\t".join(r) + "\n" for r in slots))
    seg_lines = ["# name start..end length sha256 kind region"]
    for s in segments:
        seg_lines.append("%s %s..%s length=%d sha256=%s kind=%s region=%s"
                         % (s["name"], s["start"], s["end"], s["length"],
                            s["sha256"], s["kind"], s["region"]))
    (out / "segments.txt").write_text("\n".join(seg_lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
