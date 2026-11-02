#!/usr/bin/env python3
"""Deterministic generator for RE-004-downstream-stale-readers-94.

Verifies node #94 digest/size, checks every recorded instruction byte
against the binary (code address A lives at file offset A - 0x1000),
then writes evidence.json, reader-sites.tsv, propagation.tsv and
segments.txt to --out only. No node execution, no disassembly, no network.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

NODE = "artifacts/node/94/hl-node"
NODE_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
NODE_SIZE = 91774280

# (name, kind, start_va, instruction_hex) -- kind: call | read | store | anchor
SEGMENTS = [
    # 11 direct call sites (claim)
    ("orch-call1", "call", 0x4E6FF83, "e8c8fdffff"),
    ("orch-call2", "call", 0x4E707B9, "e892f5ffff"),
    ("orch-call3", "call", 0x4E70E2A, "e821efffff"),
    ("dg1-call", "call", 0x4E64A0B, "e890080200"),
    ("dg2-call", "call", 0x4E653E8, "e8b3fe0100"),
    ("dg3-call", "call", 0x4E66671, "e82aec0100"),
    ("dg4-call", "call", 0x4E66BAA, "e8f1e60100"),
    ("dg5-call", "call", 0x4E68040, "e85bd20100"),
    ("tb1-call", "call", 0x4E6927C, "e86fc40100"),
    ("tb2-call", "call", 0x4E6961B, "e8d0c00100"),
    ("gl1-call", "call", 0x4E694CB, "e8e0cd0100"),
    # orchestrator read block 1 (0x4e700fc): stale-span loads (claim)
    ("b1-load-e1", "read", 0x4E700FC, "0fb68c24e1000000"),
    ("b1-load-e2", "read", 0x4E70104, "0fb69424e2000000"),
    ("b1-load-e3", "read", 0x4E7010C, "0fb6b424e3000000"),
    ("b1-load-e4", "read", 0x4E70114, "8bbc24e4000000"),
    ("b1-load-f1", "read", 0x4E7012C, "4c8b9424f1000000"),
    ("b1-load-f8", "read", 0x4E7013C, "4c8b9424f8000000"),
    # orchestrator read block 1: propagation stores (claim)
    ("b1-store-9", "store", 0x4E7014F, "884b09"),
    ("b1-store-a", "store", 0x4E70152, "88530a"),
    ("b1-store-b", "store", 0x4E70155, "4088730b"),
    ("b1-store-c", "store", 0x4E70159, "897b0c"),
    ("b1-store-19", "store", 0x4E70174, "48894319"),
    ("b1-store-20", "store", 0x4E70178, "48894b20"),
    # orchestrator read block 2 (0x4e70827)
    ("b2-load-e1", "read", 0x4E70827, "8b8c24e1000000"),
    ("b2-load-e4", "read", 0x4E7082E, "8b9424e4000000"),
    ("b2-load-f8", "read", 0x4E7084B, "488bb424f8000000"),
    ("b2-load-f1", "read", 0x4E70857, "488bb424f1000000"),
    ("b2-store-c", "store", 0x4E70835, "89530c"),
    ("b2-store-9", "store", 0x4E70838, "894b09"),
    ("b2-store-20", "store", 0x4E70853, "48897320"),
    ("b2-store-19", "store", 0x4E7085F, "48897319"),
    # orchestrator read block 3 (0x4e70f21)
    ("b3-load-e1", "read", 0x4E70F21, "8b8c24e1000000"),
    ("b3-load-e4", "read", 0x4E70F28, "8b9424e4000000"),
    ("b3-load-f8", "read", 0x4E70F45, "488bb424f8000000"),
    ("b3-load-f1", "read", 0x4E70F51, "488bb424f1000000"),
    ("b3-store-c", "store", 0x4E70F2F, "89530c"),
    ("b3-store-9", "store", 0x4E70F32, "894b09"),
    ("b3-store-20", "store", 0x4E70F4D, "48897320"),
    ("b3-store-19", "store", 0x4E70F59, "48897319"),
    # trioA verbatim stores, #169's claim re-cited as anchors (not re-claimed)
    ("trioA-vs-4", "anchor", 0x4E6FE0C, "895304"),
    ("trioA-vs-1", "anchor", 0x4E6FE0F, "894b01"),
    ("trioA-vs-18", "anchor", 0x4E6FE21, "48897318"),
    ("trioA-vs-11", "anchor", 0x4E6FE2A, "48897311"),
    ("trioA-vs-0", "anchor", 0x4E6FE2E, "8803"),
    ("trioA-vs-8", "anchor", 0x4E6FE30, "48894b08"),
    ("trioA-vs-10", "anchor", 0x4E6FE34, "885310"),
]

READER_SITES_HEADER = [
    "caller", "caller_fde_start", "caller_fde_end", "callee", "call_va",
    "dest_object", "stale_span_1", "stale_span_2", "verdict",
    "read_block_va", "propagation_target", "basis",
]
READER_SITES = [
    ["orchestrator", "0x4e6fef0", "0x4e713bd", "trioA", "0x4e6ff83",
     "rdi=[rsp+0xe0] local buffer", "[obj+0x1..0x8]", "[obj+0x11..0x20]",
     "READ", "0x4e700fc", "[rbx+0x9..0x10]+[rbx+0x19..0x28]",
     "tag-check jne directly to read block; no writes to buffer between call and reads"],
    ["orchestrator", "0x4e6fef0", "0x4e713bd", "trioA", "0x4e707b9",
     "rdi=[rsp+0xe0] local buffer", "[obj+0x1..0x8]", "[obj+0x11..0x20]",
     "READ", "0x4e70827", "[rbx+0x9..0x10]+[rbx+0x19..0x28]",
     "tag-check jne directly to read block; no writes to buffer between call and reads"],
    ["orchestrator", "0x4e6fef0", "0x4e713bd", "trioA", "0x4e70e2a",
     "rdi=[rsp+0xe0] local buffer", "[obj+0x1..0x8]", "[obj+0x11..0x20]",
     "READ", "0x4e70f21", "[rbx+0x9..0x10]+[rbx+0x19..0x28]",
     "tag-check jne directly to read block; no writes to buffer between call and reads"],
    ["dg1", "0x4e64730", "0x4e64d9e", "double-gate", "0x4e64a0b",
     "rdi=r14=entry rsi", "[obj+0xb9..0xc0]", "[obj+0xc9..0xd8]",
     "NO-READ", "-", "-",
     "dest register r14 never dereferenced anywhere in the caller FDE"],
    ["dg2", "0x4e65140", "0x4e656e4", "double-gate", "0x4e653e8",
     "rdi=r14=entry rsi", "[obj+0xb9..0xc0]", "[obj+0xc9..0xd8]",
     "NO-READ", "-", "-",
     "dest register r14 never dereferenced anywhere in the caller FDE"],
    ["dg3", "0x4e66660", "0x4e6680c", "double-gate", "0x4e66671",
     "rdi=entry rsi (arg-shifted wrapper)", "[obj+0xb9..0xc0]", "[obj+0xc9..0xd8]",
     "NO-READ", "-", "-",
     "dest pointer not retained after the call; rsi reused for size math and later calls"],
    ["dg4", "0x4e66810", "0x4e66f9b", "double-gate", "0x4e66baa",
     "rdi=rbx=entry rsi", "[obj+0xb9..0xc0]", "[obj+0xc9..0xd8]",
     "NO-READ", "-", "-",
     "dest read post-call via saved-rsi alias rcx only at 0x80/0x90/0x1e0/0x1f3, never at stale offsets"],
    ["dg5", "0x4e67d30", "0x4e6839f", "double-gate", "0x4e68040",
     "rdi=rbx=entry rsi", "[obj+0xb9..0xc0]", "[obj+0xc9..0xd8]",
     "NO-READ", "-", "-",
     "dest read post-call via saved-rsi alias rcx only at 0x80/0x90/0x1e0/0x1f3, never at stale offsets"],
    ["tb1", "0x4e69150", "0x4e69425", "trioB", "0x4e6927c",
     "D=decoder-derived (trioB r14)", "[D+0xb9..0xc0]", "[D+0xc9..0xd8]",
     "NO-READ", "-", "-",
     "caller holds only rdi=[rsp+0x80]; all post-call reads target the rdi object, never D"],
    ["tb2", "0x4e69580", "0x4e696ff", "trioB", "0x4e6961b",
     "D=decoder-derived (trioB r14)", "[D+0xb9..0xc0]", "[D+0xc9..0xd8]",
     "NO-READ", "-", "-",
     "caller holds only rdi=[rsp+0x48]; all post-call reads target the rdi object, never D"],
    ["gl1", "0x4e69430", "0x4e69573", "gate-like", "0x4e694cb",
     "D=decoder-derived (gate-like r14)", "[D+0xb9..0xc0]", "[D+0xc9..0xd8]",
     "NO-READ", "-", "-",
     "caller holds only rdi=[rsp+0xf]; all post-call reads target the rdi object, never D"],
]

PROPAGATION_HEADER = [
    "orch_call_va", "read_block_va", "stale_span", "stale_len",
    "output_span", "read_instr_vas", "store_instr_vas",
]
PROPAGATION = [
    ["0x4e6ff83", "0x4e700fc", "[obj+0x1..0x8]", "7", "[rbx+0x9..0x10]",
     "0x4e700fc,0x4e70104,0x4e7010c,0x4e70114", "0x4e7014f,0x4e70152,0x4e70155,0x4e70159"],
    ["0x4e6ff83", "0x4e700fc", "[obj+0x11..0x20]", "15", "[rbx+0x19..0x28]",
     "0x4e7012c,0x4e7013c", "0x4e70174,0x4e70178"],
    ["0x4e707b9", "0x4e70827", "[obj+0x1..0x8]", "7", "[rbx+0x9..0x10]",
     "0x4e70827,0x4e7082e", "0x4e70838,0x4e70835"],
    ["0x4e707b9", "0x4e70827", "[obj+0x11..0x20]", "15", "[rbx+0x19..0x28]",
     "0x4e70857,0x4e7084b", "0x4e7085f,0x4e70853"],
    ["0x4e70e2a", "0x4e70f21", "[obj+0x1..0x8]", "7", "[rbx+0x9..0x10]",
     "0x4e70f21,0x4e70f28", "0x4e70f32,0x4e70f2f"],
    ["0x4e70e2a", "0x4e70f21", "[obj+0x11..0x20]", "15", "[rbx+0x19..0x28]",
     "0x4e70f51,0x4e70f45", "0x4e70f59,0x4e70f4d"],
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    blob = (root / NODE).read_bytes()
    if len(blob) != NODE_SIZE:
        print(f"node size mismatch: {len(blob)} != {NODE_SIZE}", file=sys.stderr)
        return 1
    if hashlib.sha256(blob).hexdigest() != NODE_SHA:
        print("node digest mismatch", file=sys.stderr)
        return 1

    seg_rows = []
    for name, kind, va, hexs in SEGMENTS:
        raw = blob[va - 0x1000:va - 0x1000 + len(hexs) // 2]
        if raw.hex() != hexs:
            print(f"byte mismatch at {name} {hex(va)}: {raw.hex()} != {hexs}",
                  file=sys.stderr)
            return 1
        seg_rows.append({
            "name": name, "kind": kind,
            "start_va": hex(va), "end_va": hex(va + len(raw)),
            "len": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "instruction_hex": hexs,
        })

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    evidence = {
        "node": {"artifact": NODE, "size": NODE_SIZE, "sha256": NODE_SHA},
        "call_sites": 11,
        "caller_fdes": 9,
        "read_sites": 3,
        "no_read_sites": 8,
        "propagated_stale_bytes_per_read_site": 22,
        "segments": {"claim": 39, "anchor": 7, "total": 46,
                     "claim_bytes": 211, "anchor_bytes": 23},
        "read_blocks": ["0x4e700fc", "0x4e70827", "0x4e70f21"],
        "shared_block_edges_excluded": [
            "0x4e700fc also reachable via decoder-A re-decode edge 0x4e6ffdf",
            "0x4e70827 also reachable via decoder-A edge 0x4e705f2",
        ],
        "segments_detail": seg_rows,
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (out / "reader-sites.tsv").write_text(
        "\t".join(READER_SITES_HEADER) + "\n"
        + "".join("\t".join(r) + "\n" for r in READER_SITES))
    (out / "propagation.tsv").write_text(
        "\t".join(PROPAGATION_HEADER) + "\n"
        + "".join("\t".join(r) + "\n" for r in PROPAGATION))
    (out / "segments.txt").write_text(
        "name\tkind\tstart_va\tend_va\tlen\tsha256\tinstruction_hex\n"
        + "".join(
            f"{s['name']}\t{s['kind']}\t{s['start_va']}\t{s['end_va']}\t"
            f"{s['len']}\t{s['sha256']}\t{s['instruction_hex']}\n"
            for s in seg_rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
