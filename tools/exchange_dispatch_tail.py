#!/usr/bin/env python3
"""RE-010 follow-up: name dispatcher cases 76..87 and map the shared tail (node #94).

Stdlib only. Additive to tools/exchange_dispatch.py: it reuses that tool's ELF,
FDE and arm-walk code, checks that its output is unchanged, and adds:

* the serde variant-name tables (RELATIVE (ptr, len) arrays ending in the serde
  "variant index 0 <= i < N" message) and their agreement with the 76
  reconstruction wire types for cases 0..75;
* for cases 76..87: entry gate, first call, post-call continuation idiom and
  join point, serde variant name at the same index, and RIP-lea anchors inside
  the first-call FDE;
* the shared tail 0x275a136 / 0x275a180 / 0x275a182 / 0x275a186: pinned bytes,
  branch sources inside the dispatcher, and the calls made there.

Addresses are virtual addresses of instruction starts.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exchange_dispatch as ed  # noqa: E402

EvidenceError = ed.EvidenceError
BASE_JSON_SHA256 = "bf82df7744abc508bd73bc8337d5b21af0a17eab9c64b6849137a4f58dfa5cb1"
FIRST_UNCLAIMED = 76
TAIL_COPY = 0x275A136   # copy callee result [rsp,+0x60) -> [rsp+0x70,+0x60), fall into 0x275a180
TAIL_ERR = 0x275A180    # mov al,0xe
TAIL_STORE = 0x275A182  # mov [rsp+0x68],al
TAIL_JOIN = 0x275A186   # cmp ebp,1e9 ; elapsed-time block ; copy 0x68 bytes to *rbx ; ret
TAIL_END = 0x275A230    # first byte after the ret at 0x275a22f
TAIL_ENTRIES = (TAIL_COPY, TAIL_ERR, TAIL_STORE, TAIL_JOIN)
CLOCK_FN = 0x4EE3800
SUB_FN = 0x4EE3730
NANOS_NONE = 0x3B9ACA00
VARIANT_MSG = re.compile(rb"variant index 0 <= i < (\d+)")
LEA_RIP = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")


def rel32(b, i):
    return struct.unpack_from("<i", b, i)[0]


def branch_sources(elf, lo, hi, targets):
    """Byte-pattern scan of [lo,hi) for rel8/rel32 jmp/jcc whose target is in `targets`.

    Pattern-based (not a full decoder); the GNU cross-check test compares the
    resulting site lists with objdump instruction starts.
    """
    code = elf.read(lo, hi - lo)
    out = {t: [] for t in targets}
    for i in range(len(code)):
        b = code[i]
        hits = []
        if b == 0xE9 and i + 5 <= len(code):
            hits.append(("jmp", lo + i + 5 + rel32(code, i + 1)))
        elif b == 0xEB and i + 2 <= len(code):
            hits.append(("jmp", lo + i + 2 + struct.unpack_from("<b", code, i + 1)[0]))
        elif 0x70 <= b <= 0x7F and i + 2 <= len(code):
            hits.append(("jcc", lo + i + 2 + struct.unpack_from("<b", code, i + 1)[0]))
        elif b == 0x0F and i + 6 <= len(code) and 0x80 <= code[i + 1] <= 0x8F:
            hits.append(("jcc", lo + i + 6 + rel32(code, i + 2)))
        for kind, t in hits:
            if t in out:
                out[t].append({"site": lo + i, "kind": kind})
    return out


def variant_tables(elf, relocs):
    """Find (ptr,len) RELATIVE arrays whose entry N is the serde 'variant index' message."""
    ro_va, ro_off, ro_size = elf.sections[".rodata"]
    data = elf.data
    by_addend = {}
    for slot, add in relocs.items():
        by_addend.setdefault(add, []).append(slot)
    tables = []
    for m in VARIANT_MSG.finditer(data, ro_off, ro_off + ro_size):
        n = int(m.group(1))
        msg_va = ro_va + m.start() - ro_off
        for slot in sorted(by_addend.get(msg_va, [])):
            ln = struct.unpack_from("<Q", elf.read(slot + 8, 8))[0]
            if ln != m.end() - m.start():
                continue
            base = slot - 16 * n
            names = []
            for k in range(n):
                s = base + 16 * k
                if s not in relocs:
                    break
                sl = struct.unpack_from("<Q", elf.read(s + 8, 8))[0]
                names.append(elf.read(relocs[s], sl).decode("utf-8"))
            if len(names) == n:
                tables.append({"va": base, "entries": n, "names": names,
                               "message": m.group(0).decode()})
    tables.sort(key=lambda t: t["va"])
    return tables


def name_class(recon, binary):
    if recon == binary:
        return "exact"
    if recon + "Action" == binary:
        return "action_suffix"
    if recon[:1].lower() + recon[1:] == binary[:1].lower() + binary[1:]:
        return "first_letter_case"
    r2 = recon + "Action"
    if r2[:1].lower() + r2[1:] == binary[:1].lower() + binary[1:]:
        return "first_letter_case_and_action_suffix"
    return "different"


def match_gate(elf, arm):
    """`cmp byte [r15+disp32],imm8 ; je rel32` at the arm, target `mov word [rsp+0x70],imm16 ; jmp rel32`."""
    b = elf.read(arm, 13)
    if b[:3] != b"\x41\x80\xbf" or b[8:10] != b"\x0f\x84":
        return None
    disp, imm = struct.unpack_from("<i", b, 3)[0], b[7]
    tgt = arm + 14 + rel32(elf.read(arm, 14), 10)
    t = elf.read(tgt, 14)
    if t[:5] != b"\x66\xc7\x44\x24\x70" or t[7] != 0xE9:
        raise EvidenceError(f"gate target {tgt:#x} is not the pinned error-code idiom")
    return {"site": arm, "field_offset": disp, "compare_imm": imm, "taken_when": "byte == imm",
            "taken_to": tgt, "error_code_word": struct.unpack_from("<H", t, 5)[0],
            "error_code_slot": "[rsp+0x70]", "then_jmp": tgt + 12 + rel32(t, 8)}


def continuation(elf, after):
    """Classify the bytes after an arm's first call (pinned idioms only)."""
    b = elf.read(after, 24)
    if b[0] == 0xE9:
        return {"idiom": "join", "at": after, "jmp_site": after, "to": after + 5 + rel32(b, 1)}
    i, al = 0, None
    if b[0] == 0xB0:
        al, i = b[1], 2
    if b[i:i + 4] == b"\x66\x81\x3c\x24" and b[i + 6:i + 8] == b"\x0f\x85" and b[i + 12] == 0xE9:
        word = struct.unpack_from("<H", b, i + 4)[0]
        ne_to = after + i + 12 + rel32(b, i + 8)
        jmp_to = after + i + 17 + rel32(b, i + 13)
        row = {"idiom": "result_word_check", "at": after, "cmp_word_at_rsp": word,
               "al_before": al, "ne_to": ne_to, "jmp_site": after + i + 12, "to": jmp_to}
        j = elf.read(jmp_to, 7)
        if j[0] == 0xB0 and j[2] == 0xE9:  # mov al,imm8 ; jmp rel32  (shared trampoline)
            row["trampoline"] = {"at": jmp_to, "al": j[1], "to": jmp_to + 7 + rel32(j, 3)}
        return row
    raise EvidenceError(f"unrecognised continuation at {after:#x}: {b[:12].hex()}")


def lea_anchors(elf, relocs, lo, hi):
    """RIP-lea targets in [lo,hi): Location records (RELATIVE ptr to a rodata path) and literals."""
    ro_va, _o, ro_size = elf.sections[".rodata"]
    code = elf.read(lo, hi - lo)
    rows = []
    for m in LEA_RIP.finditer(code):
        k = m.start()
        if k + 7 > len(code):
            continue
        tgt = lo + k + 7 + rel32(code, k + 3)
        if tgt in relocs and ro_va <= relocs[tgt] < ro_va + ro_size:
            ln = struct.unpack_from("<Q", elf.read(tgt + 8, 8))[0]
            line, col = struct.unpack_from("<II", elf.read(tgt + 16, 8))
            path = elf.read(relocs[tgt], ln)
            rows.append({"site": lo + k, "kind": "location", "target": tgt,
                         "file": path.decode("utf-8", "replace"), "line": line, "col": col})
        elif ro_va <= tgt < ro_va + ro_size:
            raw = elf.read(tgt, 64)
            text = raw.split(b"\0")[0]
            printable = text[:48] if all(32 <= c < 127 for c in text[:48]) else b""
            rows.append({"site": lo + k, "kind": "rodata", "target": tgt,
                         "prefix_hex": raw[:16].hex(), "ascii_prefix": printable.decode()})
    return rows


def tail_facts(elf, starts):
    b = elf.read(TAIL_ERR, TAIL_END - TAIL_ERR)
    want = {0: b"\xb0\x0e", 2: b"\x88\x44\x24\x68", 6: b"\x81\xfd" + struct.pack("<I", NANOS_NONE),
            0x0E: b"\xbf\x01\x00\x00\x00\xe8", 0x49: b"\xe8", 0x9B: b"\x48\x89\xd8", 0xAF: b"\xc3"}
    for off, pat in want.items():
        if b[off:off + len(pat)] != pat:
            raise EvidenceError(f"tail byte idiom mismatch at {TAIL_ERR + off:#x}")
    clock = TAIL_ERR + 0x18 + rel32(b, 0x14)
    sub = TAIL_ERR + 0x4E + rel32(b, 0x4A)
    if (clock, sub) != (CLOCK_FN, SUB_FN) or not ed.is_fde_start(starts, clock) or not ed.is_fde_start(starts, sub):
        raise EvidenceError("tail calls moved")
    copy = elf.read(TAIL_COPY, TAIL_ERR - TAIL_COPY)
    return {
        "bytes_sha256": hashlib.sha256(elf.read(TAIL_COPY, TAIL_END - TAIL_COPY)).hexdigest(),
        "range": [TAIL_COPY, TAIL_END],
        "copy_block": {"start": TAIL_COPY, "end": TAIL_ERR, "movups": copy.count(b"\x0f\x10"),
                       "falls_into": TAIL_ERR},
        "err_entry": {"va": TAIL_ERR, "sets_al": 0x0E},
        "store_entry": {"va": TAIL_STORE, "stores_al_to": "[rsp+0x68]"},
        "join_entry": {"va": TAIL_JOIN, "skip_if_ebp_eq": NANOS_NONE,
                       "calls": [{"site": TAIL_ERR + 0x13, "target": clock, "edi": 1},
                                 {"site": TAIL_ERR + 0x49, "target": sub}],
                       "result_copy_bytes": 0x68, "ret_site": TAIL_ERR + 0xAF},
    }


def build(data: bytes, rs: Path = ed.SOURCE, expected_sha256: str = ed.EXPECTED_SHA256,
          check_base: bool = True) -> dict:
    """check_base=False is only for tamper tests on a mutated copy of the binary."""
    base = ed.build(data, rs, expected_sha256=expected_sha256)
    base_text = ed.render(base)
    base_sha = hashlib.sha256(base_text).hexdigest()
    if check_base and base_sha != BASE_JSON_SHA256:
        raise EvidenceError(f"base exchange_dispatch output changed: {base_sha}")
    elf = ed.Elf(data)
    starts, ends = ed.fde_index(elf)
    relocs = ed.relative_relocs(elf)
    lo, hi = base["dispatcher"]["start"], base["dispatcher"]["end"]
    n = base["table_entries"]
    tables = [t for t in variant_tables(elf, relocs) if t["entries"] == n]
    if not tables:
        raise EvidenceError(f"no serde variant table with {n} entries")
    names = tables[0]["names"]
    if any(t["names"] != names for t in tables):
        raise EvidenceError("variant tables disagree")
    agreement, agree_counts = [], {}
    for c in base["cases"]:
        r = c.get("reconstruction")
        if not r:
            continue
        cls = name_class(r["wire_type"], names[c["index"]])
        agree_counts[cls] = agree_counts.get(cls, 0) + 1
        if cls != "exact":
            agreement.append({"index": c["index"], "reconstruction_wire_type": r["wire_type"],
                              "serde_name": names[c["index"]], "class": cls})
    cases = []
    for c in base["cases"][FIRST_UNCLAIMED:]:
        if "reconstruction" in c:
            raise EvidenceError(f"case {c['index']} is claimed")
        fc = c["first_call"]
        if fc is None or fc["kind"] != "rel32":
            raise EvidenceError(f"case {c['index']} has no rel32 first call")
        tgt = fc["target"]
        fend = ends[bisect.bisect_left(starts, tgt)]
        cases.append({
            "index": c["index"], "discriminant": c["discriminant"], "arm": c["arm"],
            "serde_name": names[c["index"]],
            "entry_gate": match_gate(elf, c["arm"]),
            "first_call": {"site": fc["site"], "target": tgt, "target_fde_end": fend},
            "continuation": continuation(elf, fc["site"] + 5),
            "callee_lea_anchors": lea_anchors(elf, relocs, tgt, fend),
        })
    sources = branch_sources(elf, lo, hi, TAIL_ENTRIES)
    joins = {}
    for c in cases:
        k = c["continuation"].get("trampoline", c["continuation"])["to"]
        joins[k] = joins.get(k, 0) + 1
    return {
        "binary_sha256": base["binary_sha256"],
        "base_packet": {"tool": "tools/exchange_dispatch.py", "json_sha256": base_sha,
                        "table_entries": n, "reconstruction_claims": base["reconstruction_claims"]},
        "dispatcher": base["dispatcher"],
        "variant_tables": [{"va": t["va"], "entries": t["entries"], "message": t["message"]} for t in tables],
        "variant_names": names,
        "name_agreement_counts": dict(sorted(agree_counts.items())),
        "name_agreement_non_exact": agreement,
        "unclaimed_cases": cases,
        "unclaimed_join_counts": dict(sorted(joins.items())),
        "tail": tail_facts(elf, starts),
        "tail_branch_sources": {k: sorted(v, key=lambda r: r["site"]) for k, v in sorted(sources.items())},
        "tail_branch_source_counts": {k: len(v) for k, v in sorted(sources.items())},
    }


ADDR_KEYS = ed.ADDR_KEYS | {"at", "to", "ne_to", "jmp_site", "taken_to", "then_jmp", "ret_site", "range", "falls_into", "va", "start", "end"}


def hexify(o, addr=False):
    """Addresses (values under ADDR_KEYS, and int dict keys) as hex; counts stay decimal."""
    if isinstance(o, dict):
        return {(f"{k:#x}" if isinstance(k, int) else k): hexify(v, k in ADDR_KEYS) for k, v in o.items()}
    if isinstance(o, list):
        return [hexify(v, addr) for v in o]
    if addr and isinstance(o, int) and not isinstance(o, bool):
        return f"{o:#x}"
    return o


def render(result: dict) -> bytes:
    return (json.dumps(hexify(result), sort_keys=True, indent=1) + "\n").encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", default=str(ed.TARGET))
    ap.add_argument("--source", default=str(ed.SOURCE))
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    out = render(build(Path(a.binary).read_bytes(), Path(a.source)))
    if a.out:
        Path(a.out).write_bytes(out)
    else:
        sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
