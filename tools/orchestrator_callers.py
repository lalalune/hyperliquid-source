#!/usr/bin/env python3
"""Deterministic generator for RE-004-orchestrator-callers-94.

Verifies node #94 digest/size, scans .text for direct E8 calls (and E9
tail jumps) to the orchestrator 0x4e6fef0, reads the three enclosing
caller FDEs, checks that the three FDEs differ only inside seven
address-displacement fields, checks the orchestrator prologue
(mov rbx,rdi at 0x4e6ff04), and writes only to --out.

No node execution, no disassembly, no evaluation, no network.
Code address A maps to file offset A - 0x1000 for .text.
"""

import argparse
import hashlib
import itertools
import json
import struct
import sys
from pathlib import Path

NODE_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
NODE_SIZE = 91774280
ORCH = 0x4E6FEF0
# .text section of node #94: VA 0x1343c80, file offset 0x1342c80.
TEXT_VA = 0x1343C80
TEXT_OFF = 0x1342C80
TEXT_SIZE = 0x431C430
# Caller FDEs (from .eh_frame), each 119 bytes.
CALLERS = [
    {"site": "oc1", "fde_start": 0x4E6CFE0, "fde_end": 0x4E6D057, "call_va": 0x4E6CFF0},
    {"site": "oc2", "fde_start": 0x4E6D690, "fde_end": 0x4E6D707, "call_va": 0x4E6D6A0},
    {"site": "oc3", "fde_start": 0x4E6E7D0, "fde_end": 0x4E6E847, "call_va": 0x4E6E7E0},
]
# Displacement fields inside a caller FDE (half-open FDE offsets).
# Each entry: (field name, field range, expected target kind).
DISP_FIELDS = [
    ("orchestrator_call_rel32", (0x11, 0x15), "rel32"),
    ("plt_call_disp32_normal", (0x34, 0x38), "disp32"),
    ("plt_call_disp32_pad1", (0x52, 0x56), "disp32"),
    ("unwind_resume_call_rel32_pad1", (0x5A, 0x5E), "rel32"),
    ("destructor_call_rel32_pad2", (0x65, 0x69), "rel32"),
    ("unwind_resume_call_rel32_pad2", (0x6D, 0x71), "rel32"),
    ("plt_call_disp32_pad3", (0x73, 0x77), "disp32"),
]
PROLOGUE_VA = 0x4E6FF04
PROLOGUE_HEX = "4889fb"  # mov rbx,rdi


def fail(msg):
    raise SystemExit(f"orchestrator_callers: FAIL: {msg}")


def va_to_off(va):
    if not (TEXT_VA <= va < TEXT_VA + TEXT_SIZE):
        fail(f"address {va:#x} outside .text")
    return TEXT_OFF + (va - TEXT_VA)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--node", default="artifacts/node/94/hl-node")
    args = ap.parse_args()
    node = Path(args.node)
    data = node.read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    digest = hashlib.sha256(data).hexdigest()
    if digest != NODE_SHA:
        fail("node SHA-256 mismatch")

    def text_bytes(va, n):
        off = va_to_off(va)
        return data[off:off + n]

    # Census: direct E8 calls and E9 tail jumps to the orchestrator.
    e8_hits = []
    e9_hits = []
    for i in range(TEXT_SIZE - 5):
        op = data[TEXT_OFF + i]
        if op not in (0xE8, 0xE9):
            continue
        rel = struct.unpack("<i", data[TEXT_OFF + i + 1:TEXT_OFF + i + 5])[0]
        va = TEXT_VA + i
        if va + 5 + rel == ORCH:
            (e8_hits if op == 0xE8 else e9_hits).append(va)
    expected_calls = [c["call_va"] for c in CALLERS]
    if e8_hits != expected_calls:
        fail(f"E8 census {e8_hits} != expected {expected_calls}")
    if e9_hits:
        fail(f"unexpected E9 tail jumps to orchestrator: {e9_hits}")

    # FDE bytes and template-diff check.
    fde_bytes = {}
    for c in CALLERS:
        n = c["fde_end"] - c["fde_start"]
        if n != 119:
            fail(f"{c['site']} FDE length {n} != 119")
        fde_bytes[c["site"]] = text_bytes(c["fde_start"], n)
        call_off = c["call_va"] - c["fde_start"]
        if fde_bytes[c["site"]][call_off] != 0xE8:
            fail(f"{c['site']} call site is not E8")
        rel = struct.unpack(
            "<i", fde_bytes[c["site"]][call_off + 1:call_off + 5])[0]
        if c["call_va"] + 5 + rel != ORCH:
            fail(f"{c['site']} call target mismatch")
    allowed = set()
    for _, (lo, hi), _ in DISP_FIELDS:
        allowed.update(range(lo, hi))
    diff_rows = []
    for (a, b) in itertools.combinations([c["site"] for c in CALLERS], 2):
        ba, bb = fde_bytes[a], fde_bytes[b]
        diffs = [i for i in range(119) if ba[i] != bb[i]]
        for i in diffs:
            if i not in allowed:
                fail(f"{a}/{b} differ at FDE offset {i:#x}, outside displacement fields")
        for name, (lo, hi), kind in DISP_FIELDS:
            ndiff = sum(1 for i in range(lo, hi) if ba[i] != bb[i])
            diff_rows.append({
                "pair": f"{a}-{b}", "field": name,
                "fde_offset_start": lo, "fde_offset_end": hi,
                "differing_bytes": ndiff, "kind": kind,
            })

    # Orchestrator prologue anchor: mov rbx,rdi at 0x4e6ff04.
    pro = text_bytes(PROLOGUE_VA, 3)
    if pro.hex() != PROLOGUE_HEX:
        fail(f"prologue bytes {pro.hex()} != {PROLOGUE_HEX}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    def seg(kind, start, end, note):
        b = text_bytes(start, end - start)
        return {
            "kind": kind, "start": hex(start), "end": hex(end),
            "length": end - start, "sha256": hashlib.sha256(b).hexdigest(),
            "note": note,
        }

    segments = []
    for c in CALLERS:
        segments.append(seg("claim", c["fde_start"], c["fde_end"],
                            f"{c['site']} caller FDE, full census scope"))
    segments.append(seg("anchor", PROLOGUE_VA, PROLOGUE_VA + 3,
                        "orchestrator prologue mov rbx,rdi (#170 claim, re-cited)"))

    evidence = {
        "node": {"sha256": NODE_SHA, "size": NODE_SIZE, "artifact": "node #94"},
        "orchestrator": {"va": hex(ORCH), "fde": "0x4e6fef0..0x4e713bd",
                         "output_object": "rdi (rbx after prologue mov rbx,rdi)"},
        "census": {"direct_e8_call_sites": [hex(v) for v in e8_hits],
                   "e9_tail_jumps": [],
                   "caller_fdes": len(CALLERS), "fde_size": 119},
        "template": {"instances": 3, "displacement_fields": len(DISP_FIELDS),
                     "differing_bytes_outside_fields": 0},
        "verdict": {"sites": 3, "read": 0, "no_read": 3,
                    "output_object_reads": 0, "output_object_overwrites": 0,
                    "returned_untouched": 3},
        "segments": segments,
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")

    with open(out / "caller-sites.tsv", "w") as f:
        f.write("site\tcaller_fde_start\tcaller_fde_end\tcall_va\trdi_routing\t"
                "postcall_reads\toutput_object_reads\tverdict\n")
        for c in CALLERS:
            f.write(f"{c['site']}\t{hex(c['fde_start'])}\t{hex(c['fde_end'])}\t"
                    f"{hex(c['call_va'])}\t"
                    "rdi passed through unchanged (saved to r14, returned)\t"
                    "[rbx+0x28],[rbx+0x30],[rbx+0x38] loads; [rbx+0x40] lea for "
                    "vtable call; PLT calls with rdi=rbx\t0\tNO-READ\n")
    with open(out / "template-diff.tsv", "w") as f:
        f.write("pair\tfield\tfde_offset_start\tfde_offset_end\tdiffering_bytes\tkind\n")
        for r in diff_rows:
            f.write(f"{r['pair']}\t{r['field']}\t{r['fde_offset_start']}\t"
                    f"{r['fde_offset_end']}\t{r['differing_bytes']}\t{r['kind']}\n")
    with open(out / "segments.txt", "w") as f:
        f.write("kind\tstart\tend\tlength\tsha256\tnote\n")
        for s in segments:
            f.write(f"{s['kind']}\t{s['start']}\t{s['end']}\t{s['length']}\t"
                    f"{s['sha256']}\t{s['note']}\n")
    print(f"wrote {len(segments)} segments, {len(diff_rows)} template-diff rows")


if __name__ == "__main__":
    main()
