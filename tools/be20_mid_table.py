#!/usr/bin/env python3
"""Deterministic generator for RE-004-be20-mid-table-94.

Verifies the node #94 digest and size first, then checks every recorded
byte against the binary (code address A at file offset A - 0x1000 for
.text; .data.rel.ro address A at file offset A - 0x2000), checks the
12 RELATIVE relocations by .rela.dyn entry index (entries are 24 bytes
at file offset 0x6bc0), checks the four record prefixes, and checks the
pairwise body differences inside each fn triple. Writes only to --out.
No node execution, no evaluator, no disassembler, no network.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

NODE_SIZE = 91774280
NODE_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
RELA_DYN_FILE_OFF = 0x6BC0
RELA_ENTRY_SIZE = 24
RELATIVE_TYPE = 8

# name, start, end, kind, sha256
SEGMENTS = [
    ("rec0-prefix", 0x574BE78, 0x574BE90, "datarelro",
     "85526ba79728a470972be92942ef4de212630c9368703cb4ab3cb42dece95912"),
    ("rec1-prefix", 0x574BEA8, 0x574BEC0, "datarelro",
     "85526ba79728a470972be92942ef4de212630c9368703cb4ab3cb42dece95912"),
    ("rec2-prefix", 0x574BED8, 0x574BEF0, "datarelro",
     "85526ba79728a470972be92942ef4de212630c9368703cb4ab3cb42dece95912"),
    ("rec3-prefix", 0x574BF08, 0x574BF20, "datarelro",
     "85526ba79728a470972be92942ef4de212630c9368703cb4ab3cb42dece95912"),
    ("rec0-fn1", 0x4E76DE0, 0x4E76E00, "text",
     "c46f029f3b11d3b5c685c182379123b488a66738d20a835ba407a6b1adca3c1d"),
    ("rec0-fn2", 0x4E76CC0, 0x4E76CE0, "text",
     "c9b8c13ab6d82edcbbea8fad368264e8c13352ede6ef6655c7f68f783581763d"),
    ("rec0-fn3", 0x4E76BC0, 0x4E76BE0, "text",
     "cc7875076c8dae45375c1bdffe2f71c80c5f7722f3582207fd7c6230d19ada17"),
    ("rec1-fn1", 0x4E76D40, 0x4E76DD8, "text",
     "ac05befd7457cdd49cf0ad2c74dc8a1f663536982254bb58bdefbcea62a2c490"),
    ("rec1-fn2", 0x4E76C20, 0x4E76CB8, "text",
     "8e0ac6ac599fb75d07b1db9f1e6f7c4395eed92401db967bd918bb18519570f1"),
    ("rec1-fn3", 0x4E76B20, 0x4E76BB8, "text",
     "8a9e3caa7492b8920713ab77a2dbeafb10a55fb57b5aaf089defa53b297d458c"),
    ("rec2-fn1", 0x4E76D20, 0x4E76D31, "text",
     "4d2dc38a462c4c8c99c9b77800763415835aecdfc62b1b7d845157526265487c"),
    ("rec2-fn2", 0x4E76CE0, 0x4E76CF1, "text",
     "3bf1da2d766d70ba666ded7971260f7f7fe5dddc5cda48788d4ac428628d09a2"),
    ("rec2-fn3", 0x4E76B00, 0x4E76B11, "text",
     "c93ca5a518e7831cf39a1ccc58449be44c6df9886fad8a963113d21f3f1d41fc"),
    ("rec3-fn1", 0x4E76D00, 0x4E76D11, "text",
     "aa7843ca63e4cd0cf49e12794bec0985757f52d657479323afdcf2b5b81ef490"),
    ("rec3-fn2", 0x4E76C00, 0x4E76C11, "text",
     "863cd11a875b7fc0bb689a4b0fb3d5b64f44910a91fc54121a63d7757aa96d53"),
    ("rec3-fn3", 0x4E76BE0, 0x4E76BF1, "text",
     "1ff8ebb0291fd4828f2348d9a3192e88de26a8dabc6833b4c060e69998108b87"),
]

# record, base, fn1, fn2, fn3, triple_size, shape, shared_callee
RECORDS = [
    ("rec0", 0x574BE78, 0x4E76DE0, 0x4E76CC0, 0x4E76BC0, 32,
     "allocator-out", "0x4e9a310"),
    ("rec1", 0x574BEA8, 0x4E76D40, 0x4E76C20, 0x4E76B20, 152,
     "copy-with-tag5-branch", "0x4e8c640+0x4e77390"),
    ("rec2", 0x574BED8, 0x4E76D20, 0x4E76CE0, 0x4E76B00, 17,
     "wrapper-to-forward", "0x4e77ae0"),
    ("rec3", 0x574BF08, 0x4E76D00, 0x4E76C00, 0x4E76BE0, 17,
     "wrapper-to-next-fde", "0x4e77e90"),
]

# .rela.dyn entry, slot offset, addend (fn address)
RELOCS = [
    (61875, 0x574BE90, 0x4E76DE0),
    (61876, 0x574BE98, 0x4E76CC0),
    (61877, 0x574BEA0, 0x4E76BC0),
    (61878, 0x574BEC0, 0x4E76D40),
    (61879, 0x574BEC8, 0x4E76C20),
    (61880, 0x574BED0, 0x4E76B20),
    (61881, 0x574BEF0, 0x4E76D20),
    (61882, 0x574BEF8, 0x4E76CE0),
    (61883, 0x574BF00, 0x4E76B00),
    (61884, 0x574BF20, 0x4E76D00),
    (61885, 0x574BF28, 0x4E76C00),
    (61886, 0x574BF30, 0x4E76BE0),
]

# Pairwise body-difference offsets inside each triple, relative to FDE start.
# All differences are displacement low bytes of calls / rip-relative loads.
TRIPLE_DIFFS = {
    "rec0": {"fn1-fn2": [7, 8, 12, 13], "fn1-fn3": [7, 8, 12, 13],
             "fn2-fn3": [8, 13]},
    "rec1": {"fn1-fn2": [67, 68, 74, 75, 97, 98, 108, 109],
             "fn1-fn3": [67, 68, 74, 75, 97, 98, 108, 109],
             "fn2-fn3": [68, 75, 98, 109]},
    "rec2": {"fn1-fn2": [8], "fn1-fn3": [8, 9], "fn2-fn3": [8, 9]},
    "rec3": {"fn1-fn2": [9], "fn1-fn3": [8, 9], "fn2-fn3": [8]},
}


def fail(msg):
    print(f"be20_mid_table: FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def file_offset(addr, kind):
    if kind == "text":
        return addr - 0x1000
    if kind == "datarelro":
        return addr - 0x2000
    fail(f"unknown segment kind {kind!r}")


def verify(node_path):
    data = Path(node_path).read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if hashlib.sha256(data).hexdigest() != NODE_SHA256:
        fail("node sha256 mismatch")
    seg_bytes = {}
    for name, start, end, kind, digest in SEGMENTS:
        off = file_offset(start, kind)
        chunk = data[off:off + (end - start)]
        if len(chunk) != end - start:
            fail(f"segment {name} truncated")
        if hashlib.sha256(chunk).hexdigest() != digest:
            fail(f"segment {name} digest mismatch")
        seg_bytes[name] = chunk
    for entry, slot, addend in RELOCS:
        off = RELA_DYN_FILE_OFF + entry * RELA_ENTRY_SIZE
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        r_type = r_info & 0xFFFFFFFF
        if r_type != RELATIVE_TYPE or r_offset != slot or r_addend != addend:
            fail(f"reloc entry {entry} mismatch: type={r_type} "
                 f"offset={r_offset:#x} addend={r_addend:#x}")
    for rec, base, _fn1, _fn2, _fn3, _size, _shape, _callee in RECORDS:
        vals = struct.unpack_from("<QQQ", data, base - 0x2000)
        if vals != (0, 0, 1):
            fail(f"record {rec} prefix {vals} != (0, 0, 1)")
    for rec, _base, fn1, fn2, fn3, size, _shape, _callee in RECORDS:
        bodies = {}
        for col, fn in (("fn1", fn1), ("fn2", fn2), ("fn3", fn3)):
            bodies[col] = data[fn - 0x1000:fn - 0x1000 + size]
        for pair, want in TRIPLE_DIFFS[rec].items():
            a, b = pair.split("-")
            got = [i for i in range(size) if bodies[a][i] != bodies[b][i]]
            if got != want:
                fail(f"triple {rec} {pair} diffs {got} != {want}")
    return data


def emit(out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rec_lines = ["record\tbase\tprefix\tfn1\tfn2\tfn3\ttriple_size\tshape\tshared_callee"]
    for rec, base, fn1, fn2, fn3, size, shape, callee in RECORDS:
        rec_lines.append(
            f"{rec}\t{base:#x}\t0,0,1\t{fn1:#x}\t{fn2:#x}\t{fn3:#x}\t"
            f"{size}\t{shape}\t{callee}")
    tri_lines = ["fn\trecord\tcolumn\tfde_start\tfde_end\tsize\tdiff_vs_first\tshared_callee"]
    for rec, _base, fn1, fn2, fn3, size, _shape, callee in RECORDS:
        for col, fn in (("fn1", fn1), ("fn2", fn2), ("fn3", fn3)):
            if col == "fn1":
                diff = "-"
            else:
                diff = ",".join(str(i) for i in TRIPLE_DIFFS[rec][f"fn1-{col}"])
            tri_lines.append(
                f"{fn:#x}\t{rec}\t{col}\t{fn:#x}\t{fn + size:#x}\t{size}\t{diff}\t{callee}")
    seg_lines = []
    for name, start, end, kind, digest in SEGMENTS:
        seg_lines.append(
            f"{name}\t{start:#x}\t{end:#x}\t{end - start}\t"
            f"{file_offset(start, kind):#x}\t{digest}\tclaim")
    (out_dir / "records.tsv").write_text("\n".join(rec_lines) + "\n")
    (out_dir / "triples.tsv").write_text("\n".join(tri_lines) + "\n")
    (out_dir / "segments.txt").write_text("\n".join(seg_lines) + "\n")
    evidence = {
        "node": {"id": 94, "size": NODE_SIZE, "sha256": NODE_SHA256},
        "layout": {
            "descriptor_base": "0x574be20",
            "header_bytes": 0x58,
            "record_size": 0x30,
            "record_count": 4,
            "record_bases": ["0x574be78", "0x574bea8", "0x574bed8", "0x574bf08"],
            "region_end": "0x574bf38",
            "next_array_entry_size": 0x18,
        },
        "records": [
            {"record": rec, "base": f"{base:#x}", "prefix": [0, 0, 1],
             "fns": [f"{fn1:#x}", f"{fn2:#x}", f"{fn3:#x}"],
             "triple_size": size, "shape": shape, "shared_callee": callee}
            for rec, base, fn1, fn2, fn3, size, shape, callee in RECORDS
        ],
        "relocations": [
            {"entry": e, "slot": f"{s:#x}", "addend": f"{a:#x}", "type": "RELATIVE"}
            for e, s, a in RELOCS
        ],
        "triple_diffs": TRIPLE_DIFFS,
        "census": {
            "direct_e8_callers_of_12_fns": 0,
            "direct_e9_jumps_to_12_fns": 0,
            "relocations_per_fn_target": 1,
        },
        "shared_callees": {
            "0x4e9a310": {"fde": "0x4e9a310..0x4e9a897", "size": 1421},
            "0x4e8c640": {"fde": "0x4e8c640..0x4e8c827", "size": 487},
            "0x4e77390": {"fde": "0x4e77390..0x4e77914", "size": 1324},
            "0x4e77ae0": {"fde": "0x4e77ae0..0x4e77e8f", "size": 943},
            "0x4e77e90": {"fde": "0x4e77e90..0x4e78653", "size": 2147},
        },
        "counts": {
            "records": 4, "fns": 12, "segments": 16, "claim_bytes": 750,
            "relocations": 12, "anchors": 0,
        },
    }
    (out_dir / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"be20_mid_table: OK ({len(SEGMENTS)} segments)")


def main(argv):
    if len(argv) != 3 or argv[1] != "--out":
        print("usage: be20_mid_table.py --out <dir>", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    node = root / "artifacts" / "node" / "94" / "hl-node"
    verify(node)
    emit(argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
