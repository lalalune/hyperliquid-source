#!/usr/bin/env python3
"""RE-006 table-context producers: who makes the ctx objects behind the
six context-embedded gate-family sites (PR #2652 edge 1, first leg).

The family-callers packet pinned six call sites whose table argument is
`lea [ctx+0x90]` (an embedded table inside a context object).  This tool
traces ctx backwards from those six callers: level 0 (how each of the six
caller bodies obtains ctx), level 1 (a validated direct-call census of
the six caller bodies, giving nine frontier bodies and the exact
argument slot ctx arrives in), level 2 (a validated census of the nine
frontier bodies' callers), the P/Q funnel three of the level-2 paths
converge on (ctx = [P+0x450], P = [Q+0x20]), and a validated census of
every non-frame store to a +0x450 field in the binary.  It also pins the
negative: none of the traced bodies stores to the table header fields
[ctx+0xB0] (record base) or [ctx+0xB8] (record count).

Everything is re-derived from the pinned node #115 binary; body digests
are computed over the same normalized disassembly the exports carry.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from artifacts import ROOT as ARTIFACT_ROOT  # noqa: E402
from elf_index import sections  # noqa: E402
from gate_callee_static import (  # noqa: E402
    _bindings,
    _body_export,
    _decode,
    _digest,
    _fde_index,
    _rela_entries,
)

PACKET = ROOT / "research" / "work-items" / "RE-006-node115-table-context-producers"
BINARY = ARTIFACT_ROOT / "artifacts" / "node" / "115" / "hl-node"
EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# Level 0: the six context-embedded sites from RE-006-node115-family-callers
# (records.json there): (call va, caller body, lea va, inner target).
LEVEL0 = [
    (0x2A8A054, 0x2A8A000, 0x2A8A044, 0x2BBC750),
    (0x2BE7E17, 0x2BDF8F0, 0x2BE7DE9, 0x2BBC750),
    (0x54B3288, 0x54A9C70, 0x54B325A, 0x5494720),
    (0x54BF8A9, 0x54B66B0, 0x54BF87B, 0x5494720),
    (0x55A1E32, 0x55A1DE0, 0x55A1E22, 0x5494720),
    (0x55A20A2, 0x55A2050, 0x55A2092, 0x5494720),
]
SMALL_CALLERS = {0x2A8A000, 0x55A1DE0, 0x55A2050}
# Frame slot where the large callers keep [arg0] (the ctx pointer).
LARGE_FRAME_SLOT = "0x18(%rsp)"

# Level 1 frontier bodies and the argument slot ctx arrives in, with the
# entry rows that prove the form (address -> substring of the AT&T text).
# ctx form -> a fragment of the entry row that proves it (AT&T text).
FRONTIER = {
    0x2BDF270: ("rdi", "%rdi,%rbx"),
    0x2A892F0: ("rdi", "%rdi,%r14"),
    0x2C31C70: ("rsi", "%rsi,%rbp"),
    0x5483F50: ("mem_rsi", "(%rsi),%r13"),
    0x55A05D0: ("rdi", "%rdi,%r14"),
    0x55746E0: ("rsi", "%rsi,%rbp"),
    0x5483850: ("mem_rsi", "(%rsi),%r13"),
    0x55A03C0: ("rdi", "%rdi,%r14"),
    0x5573D40: ("rsi", "%rsi,%rbp"),
}
# Bodies whose callers are censused at level 2 as well: the P-bodies and
# their single callers (the 224-byte once-getters).
P_BODIES = {0x2D23610, 0x5A06600, 0x5A04E40}
ONCE_GETTERS = {0x2774590, 0x56186C0, 0x56185E0}
# P install rows inside the once-getters' callers: the frame store that
# places P into the Q descriptor's +0x20 slot.
P_INSTALLS = [
    (0x59EC200, 0x59EC283, "mov    %r13,0x60(%rsp)", "P = [rcx+0x50] loaded at 0x59ec27f"),
    (0x4FCB590, 0x4FCB783, "mov    %rax,0x70(%rsp)", "P = r14+0x6b0 formed at 0x4fcb77e"),
    (0x5443930, 0x544398B, "mov    %rbp,0x20(%rsp)", "P = [rsi+0x50] loaded at 0x544397e"),
    (0x2B1DF60, 0x2B1E3D0, "mov    %rax,0xa0(%rsp)",
     "P = frame-embedded sub-object lea [rsp+0xd18] at 0x2b1e3c8; Q assembled at [rsp+0x80]"),
]
TRACED_BODIES = (
    set(FRONTIER) | P_BODIES | ONCE_GETTERS
    | {caller for _c, caller, _l, _t in LEVEL0}
    | {0x59EC200, 0x4FCB590, 0x5443930, 0x2B1DF60}
)
DUMP_LIMIT = 2000  # bodies at most this many bytes are exported in full


def _owner(starts, fdes, va):
    i = bisect.bisect_right(starts, va) - 1
    if i < 0:
        return None
    start = starts[i]
    return start if start <= va < fdes[start][0] else None


def _census(data, secs, fdes, starts, targets, rows_of):
    """Validated direct-E8 census: {target: [(site, caller_start)]}."""
    text = next(s for s in secs if s["name"] == ".text")
    va0, fo0, size = text["address"], text["offset"], text["size"]
    blob = data[fo0:fo0 + size]
    raw = {t: [] for t in targets}
    for m in re.finditer(rb"\xe8", blob):
        i = m.start()
        va = va0 + i
        tgt = va + 5 + struct.unpack_from("<i", blob, i + 1)[0]
        if tgt in raw:
            raw[tgt].append(va)
    slot_of = {}
    result = {}
    for tgt, sites in raw.items():
        good = []
        for va in sites:
            caller = _owner(starts, fdes, va)
            if caller is None:
                continue
            rows = rows_of(caller)
            row = rows.get(va)
            if row is None or not row[0].startswith("e8"):
                continue
            disp = struct.unpack("<i", bytes.fromhex(row[0][2:10]))[0]
            if va + 5 + disp != tgt:
                continue
            good.append((va, caller))
        result[tgt] = sorted(good)
    return result, slot_of


def _last_writes(rows, reg, before):
    hits = []
    for a in sorted(rows):
        if a >= before:
            break
        text = rows[a][1]
        m = re.match(r"(\S+)\s+(.*)", text)
        if not m:
            continue
        mnem, ops = m.groups()
        parts = [p.strip() for p in ops.split(",")]
        if mnem in ("mov", "lea", "pop", "xor") and parts[-1] in (f"%{reg}", reg):
            hits.append((a, text))
        elif mnem.startswith("call") and reg == "rax":
            hits.append((a, text + " [rax is the return value]"))
    return hits


def _store450_census(data, secs, fdes, starts, rows_of):
    """Every validated store `mov [reg+0x450], src` whose base is not rsp.

    Raw byte candidates (REX.W 89 /r or C7 /0 with a disp32 of 0x450) are
    validated against the decoded rows of their containing FDE, so byte
    patterns inside other instructions never count.
    """
    text = next(s for s in secs if s["name"] == ".text")
    va0, fo0, size = text["address"], text["offset"], text["size"]
    blob = data[fo0:fo0 + size]
    disp = struct.pack("<i", 0x450)
    candidates = set()
    for m in re.finditer(re.escape(disp), blob):
        i = m.start()
        for modrm_off, op_off in ((i - 1, i - 2), (i - 2, i - 3)):
            if op_off < 1:
                continue
            modrm = blob[modrm_off]
            if not 0x80 <= modrm <= 0xBF:
                continue
            if (modrm_off == i - 1) != ((modrm & 7) != 4):
                continue
            op = blob[op_off]
            rex = blob[op_off - 1]
            if not 0x48 <= rex <= 0x4F:
                continue
            if op == 0x89 or (op == 0xC7 and (modrm >> 3) & 7 == 0):
                candidates.add(va0 + op_off - 1)
                break
    stores = []
    for va in sorted(candidates):
        fde = _owner(starts, fdes, va)
        if fde is None:
            continue
        row = rows_of(fde).get(va)
        if row is None:
            continue
        m = re.match(r"mov\w*\s+%?(\w+),0x450\(%(\w+)\)$", row[1].strip())
        if not m:
            # AT&T store form: mov <src>,0x450(%base)
            m2 = re.match(r"mov\w*\s+(.+),0x450\(%(\w+)\)$", row[1].strip())
            if not m2:
                continue
            src, base = m2.group(1), m2.group(2)
        else:
            src, base = m.group(1), m.group(2)
        if base == "rsp":
            continue
        stores.append({"site": va, "fde": fde, "base": base, "src": src,
                       "text": row[1]})
    return stores


def analyze(data=None):
    if data is None:
        data = BINARY.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"binary sha256 {digest} != pinned {EXPECTED_SHA256}")
    secs = sections(data)
    fdes = _fde_index(data)
    starts = sorted(fdes)
    cache = {}

    def rows_of(start):
        if start not in cache:
            cache[start] = _decode(data, secs, start, fdes[start][0])
        return cache[start]

    frames = []
    exports = {}

    def note_body(start):
        end = fdes[start][0]
        dg = _digest(data, secs, start, end)
        frames.append(f"{start:#x}..{end:#x} ({end - start} bytes) sha256 {dg}")
        if end - start <= DUMP_LIMIT:
            exports[start] = _body_export(data, start, end)
        return dg

    # --- level 0 -------------------------------------------------------
    level0 = []
    for call, caller, lea, target in LEVEL0:
        rows = rows_of(caller)
        lea_row = rows[lea][1]
        assert "lea" in lea_row and "0x90(" in lea_row and ",%rcx" in lea_row, lea_row
        if caller in SMALL_CALLERS:
            form = "ctx is the caller body's own rdi (arg0)"
        else:
            reload_re = re.compile(r"mov\s+0x18\(%rsp\),%rbx")
            reloads = [(a, t) for a, (_r, t) in rows.items() if reload_re.search(t)]
            assert reloads, caller
            form = ("ctx is [arg0], saved to the frame slot " + LARGE_FRAME_SLOT
                    + " at entry and reloaded into rbx before the lea")
        level0.append({
            "call": call, "caller": caller, "lea": lea, "inner_target": target,
            "lea_text": lea_row, "ctx_form": form,
        })
        note_body(caller)

    # --- level 1 -------------------------------------------------------
    targets1 = sorted({caller for _c, caller, _l, _t in LEVEL0})
    census1, _ = _census(data, secs, fdes, starts, set(targets1), rows_of)
    level1 = []
    intra = []
    frontier_seen = set()
    for tgt in targets1:
        for site, caller in census1[tgt]:
            rows = rows_of(caller)
            rec = {
                "target": tgt, "site": site, "caller": caller,
                "caller_end": fdes[caller][0],
                "bindings": _bindings(rows, site),
            }
            if caller in {c for _x, c, _l, _t in LEVEL0}:
                intra.append(rec)  # a large caller body calling a small one
            else:
                level1.append(rec)
                frontier_seen.add(caller)
    assert frontier_seen == set(FRONTIER), (
        f"frontier mismatch: {sorted(frontier_seen ^ set(FRONTIER))}")
    assert len(intra) == 3, intra
    for body, (form, frag) in FRONTIER.items():
        rows = rows_of(body)
        hits = [a for a in sorted(rows) if a < body + 0x40 and frag in rows[a][1]]
        assert hits, (body, frag)
        note_body(body)

    # --- level 2 -------------------------------------------------------
    census2, _ = _census(data, secs, fdes, starts, set(FRONTIER), rows_of)
    level2 = []
    for tgt in sorted(FRONTIER):
        for site, caller in census2[tgt]:
            rows = rows_of(caller)
            level2.append({
                "target": tgt, "site": site, "caller": caller,
                "caller_end": fdes[caller][0],
                "bindings": _bindings(rows, site),
            })

    # --- P/Q funnel ----------------------------------------------------
    census_p, _ = _census(data, secs, fdes, starts, P_BODIES, rows_of)
    census_o, _ = _census(data, secs, fdes, starts, ONCE_GETTERS, rows_of)
    pq = {"p_body_callers": {}, "once_callers": {}, "p_installs": []}
    for body in sorted(P_BODIES):
        sites = census_p[body]
        assert len(sites) == 1, (body, sites)
        site, caller = sites[0]
        assert caller in ONCE_GETTERS, (body, caller)
        rows = rows_of(caller)
        assert any("0x20(%rsi),%rsi" in t and a < site
                   for a, (_r, t) in rows.items()), caller
        pq["p_body_callers"][f"{body:#x}"] = {
            "site": site, "caller": caller,
            "bindings": _bindings(rows, site),
            "p_form": "P is [the once-getter's rsi + 0x20]",
        }
        note_body(body)
        note_body(caller)
    for body in sorted(ONCE_GETTERS):
        lst = []
        for site, caller in census_o[body]:
            rows = rows_of(caller)
            lst.append({"site": site, "caller": caller,
                        "caller_end": fdes[caller][0],
                        "bindings": _bindings(rows, site)})
            note_body(caller)
        pq["once_callers"][f"{body:#x}"] = lst
    for fde, addr, frag, note in P_INSTALLS:
        rows = rows_of(fde)
        assert frag in rows[addr][1], (fde, addr, rows[addr][1])
        pq["p_installs"].append({"fde": fde, "store": addr,
                                 "text": rows[addr][1], "note": note})

    # --- ctx pointer store census (+0x450) ------------------------------
    stores = _store450_census(data, secs, fdes, starts, rows_of)
    store_records = []
    for st in stores:
        rows = rows_of(st["fde"])
        src = st["src"].strip().lstrip("%")
        writers = _last_writes(rows, src, st["site"]) if src in {
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        } else []
        last = writers[-1][1] if writers else None
        if last and "call" in last:
            kind = "call-return"
        elif last and ("(%r" in last or "(%rsp" in last):
            kind = "field-load"
        elif last and last.startswith("lea"):
            kind = "address-of"
        elif src.startswith("$"):
            kind = "immediate"
        else:
            kind = "register-forward"
        store_records.append({**st, "src_last_writer": last, "kind": kind})

    # --- negative: no traced body writes the table header scalars -------
    # Scalar stores to [reg+0xB0] / [reg+0xB8] (the gate header's base and
    # count slots, at ctx+0xB0 / ctx+0xB8) must not occur in any traced
    # body.  Vector stores are recorded separately: the three hits are
    # one clone-shaped bulk copy per P-body (a contiguous frame-to-heap
    # copy spanning +0x30..+0xF8 of a small record), not header writes.
    header_re = re.compile(r",0xb[08]\(%(?!rsp)")
    offenders = []
    bulk_touches = []
    for body in sorted(TRACED_BODIES):
        rows = rows_of(body)
        for a, (_raw, text) in rows.items():
            if not header_re.search(text):
                continue
            mnem = text.split(None, 1)[0]
            rec = {"body": body, "addr": a, "text": text}
            if mnem in ("mov", "movq", "movl"):
                offenders.append(rec)
            elif mnem in ("movups", "movaps", "movdqu", "movdqa"):
                bulk_touches.append(rec)
    assert not offenders, offenders

    payload = {
        "question": (
            "RE-006 gate family, edge 1 first leg: the six context-embedded "
            "sites bind the gate table argument as lea [ctx+0x90]. Who makes "
            "the ctx objects, and what fills the embedded table header at "
            "ctx+0x90 (+0x20 record base, +0x28 record count)?"
        ),
        "binary_sha256": digest,
        "level0_sites": level0,
        "level1_census": level1,
        "intra_family_edges": intra,
        "frontier_forms": {f"{b:#x}": f for b, (f, _e) in FRONTIER.items()},
        "level2_census": level2,
        "pq_funnel": pq,
        "ctx_pointer_stores_0x450": store_records,
        "table_header_store_offenders": offenders,
        "table_header_bulk_copy_touches": bulk_touches,
        "counts": {
            "level0": len(level0),
            "level1_sites": len(level1),
            "intra_family_edges": len(intra),
            "frontier_bodies": len(FRONTIER),
            "level2_sites": len(level2),
            "ctx_pointer_stores_0x450": len(store_records),
            "table_header_bulk_copy_touches": len(bulk_touches),
        },
    }
    return payload, sorted(set(frames)), exports


def generate(data, out_dir):
    """Write records.json, frames.txt and the body exports into out_dir."""
    payload, frames, exports = analyze(data)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "records.json").write_text(
        json.dumps(payload, indent=1, sort_keys=True) + "\n")
    (out / "frames.txt").write_text("\n".join(frames) + "\n")
    for start, text in exports.items():
        (out / f"body_{start:x}.txt").write_text(text)
    return payload


def main():
    payload = generate(BINARY.read_bytes(), PACKET)
    print(json.dumps(payload["counts"], indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
