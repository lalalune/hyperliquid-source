#!/usr/bin/env python3
"""RE-012: InfoRequest API path evidence for node #94.

Stdlib only. From the pinned ELF this derives:

* FDE bounds (``.eh_frame_hdr``);
* first-party panic ``Location`` records under ``info_server/src/**``
  (and the ``node/src/hl_node.rs`` Locations that share an FDE with them);
* RIP ``lea`` attribution of those Locations;
* the hub FDE that owns ``handle_request`` / ``router`` / ``handler`` /
  ``user_ip`` Locations, and its FDE-start-landing rel32 edge into the
  main InfoRequest-tag deserializer;
* every ``#[serde(rename = ...)]`` tag from the can1357
  ``info_server/request.rs`` reconstruction, anchored by exact or
  length-prefixed ``lea`` and attributed to owning FDEs;
* write / external side-effect markers: ``outPath`` / ``fileSnapshot``
  tags and the ``not writing snapshot ... localhost`` diagnostic
  template.

Addresses are virtual addresses of instruction starts (REX prefix
included when present). Claims are limited to what these scans pin.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

EXPECTED_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
FIRST_PARTY = b"/home/ubuntu/hl/code_Mainnet/"
SCOPE_PREFIX = "info_server/"
HL_NODE = "node/src/hl_node.rs"
REF_REQUEST = "references/can1357-hl/info_server/request.rs"
HUB = 0x24AF210
DESER = 0x28C7C80
SNAPSHOT_GATE = 0x27E91D0
HUB_TO_DESER_SITE = 0x24AFF82
SNAPSHOT_TEMPLATE = "not writing snapshot to file because request was not from localhost"
SIDE_EFFECT_TAGS = ("fileSnapshot", "outPath", "l4Snapshots", "referrerStates")

LEA_RE = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
RENAME_RE = re.compile(r'#\[serde\(rename = "([^"]+)"\)\]')
TEMPLATE_WINDOW = 80

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/94/hl-node"


class EvidenceError(ValueError):
    pass


class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise EvidenceError("not an ELF64 little-endian file")
        self.data = data
        phoff, = struct.unpack_from("<Q", data, 0x20)
        shoff, = struct.unpack_from("<Q", data, 0x28)
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
        self.loads = []
        for i in range(phnum):
            p_type, _f, p_off, p_va, _pa, p_filesz, _m, _a = struct.unpack_from(
                "<IIQQQQQQ", data, phoff + i * phentsize)
            if p_type == 1:
                self.loads.append((p_va, p_off, p_filesz))
        secs = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
        stro = secs[shstrndx][4]
        self.sections = {}
        for s in secs:
            name = data[stro + s[0]:data.index(b"\0", stro + s[0])].decode()
            self.sections[name] = (s[3], s[4], s[5])

    def off(self, va):
        for v, o, s in self.loads:
            if v <= va < v + s:
                return o + va - v
        return None

    def read(self, va, n):
        o = self.off(va)
        if o is None:
            raise EvidenceError(f"{va:#x} not file-backed")
        return self.data[o:o + n]


def fde_index(elf: Elf):
    addr, off, size = elf.sections[".eh_frame_hdr"]
    d = elf.data
    ver, ep_enc, cnt_enc, tab_enc = d[off:off + 4]
    if (ver, ep_enc, cnt_enc, tab_enc) != (1, 0x1B, 0x03, 0x3B):
        raise EvidenceError("unexpected .eh_frame_hdr encodings")
    count = struct.unpack_from("<I", d, off + 8)[0]
    starts, ends = [], []
    for i in range(count):
        pos = off + 12 + 8 * i
        pc = addr + struct.unpack_from("<i", d, pos)[0]
        fde_va = addr + struct.unpack_from("<i", d, pos + 4)[0]
        fo = elf.off(fde_va)
        pc_begin = fde_va + 8 + struct.unpack_from("<i", d, fo + 8)[0]
        if pc_begin != pc:
            raise EvidenceError(f"FDE pc_begin mismatch at {fde_va:#x}")
        starts.append(pc)
        ends.append(pc + struct.unpack_from("<I", d, fo + 12)[0])
    if any(b <= a for a, b in zip(starts, starts[1:])):
        raise EvidenceError(".eh_frame_hdr table not strictly sorted")
    return starts, ends


def containing(starts, ends, va):
    j = bisect.bisect_right(starts, va) - 1
    if j >= 0 and va < ends[j]:
        return starts[j], ends[j]
    return None


def is_fde_start(starts, va):
    j = bisect.bisect_left(starts, va)
    return j < len(starts) and starts[j] == va


def relative_relocs(elf: Elf) -> dict:
    _a, off, size = elf.sections[".rela.dyn"]
    out = {}
    for o in range(off, off + size, 24):
        r_off, info, add = struct.unpack_from("<QQq", elf.data, o)
        if info & 0xFFFFFFFF == 8:
            out[r_off] = add
    return out


def first_party_locations(elf, relocs):
    ro_va, _o, ro_size = elf.sections[".rodata"]
    drr_va, _o2, drr_size = elf.sections[".data.rel.ro"]
    out = {}
    for slot, a in relocs.items():
        if not (drr_va <= slot < drr_va + drr_size and ro_va <= a < ro_va + ro_size):
            continue
        ln, line, col = struct.unpack_from("<QII", elf.read(slot + 8, 16))
        if not 0 < ln < 256 or line == 0 or col == 0:
            continue
        s = elf.read(a, ln)
        if s.startswith(FIRST_PARTY) and s.endswith(b".rs") and b"\0" not in s:
            out[slot] = (s[len(FIRST_PARTY):].decode(), line, col)
    return out


def lea_targets(elf):
    t_va, t_off, t_size = elf.sections[".text"]
    text = elf.data[t_off:t_off + t_size]
    out = {}
    for m in LEA_RE.finditer(text):
        i = m.start()
        if i + 7 > len(text):
            continue
        tgt = t_va + i + 7 + struct.unpack_from("<i", text, i + 3)[0]
        out.setdefault(tgt, []).append(t_va + i)
    return out


def literal_anchors(elf, kind, lit, leas, relocs):
    ro_va, ro_off, ro_size = elf.sections[".rodata"]
    ro = elf.data[ro_off:ro_off + ro_size]
    rel_targets = set(relocs.values())
    out = []
    for m in re.finditer(re.escape(lit.encode()), ro):
        s = ro_va + m.start()
        if kind == "exact":
            cands = [s]
        else:
            z = ro.rfind(b"\0", max(0, m.start() - TEMPLATE_WINDOW), m.start())
            if z < 0:
                continue
            cands = list(range(ro_va + z + 1, s + 1))
        for t in cands:
            if t in leas or t in rel_targets:
                out.append({
                    "occurrence": s, "anchor": t,
                    "lea_sites": sorted(leas.get(t, ())),
                    "reloc_slots": sorted(k for k, v in relocs.items() if v == t),
                })
                break
    return out


def serde_rename_tags(ref_text: str):
    seen = set()
    out = []
    for t in RENAME_RE.findall(ref_text):
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def tag_anchor(elf, tag, leas, relocs):
    """Prefer exact lea at occurrence; else length-prefixed (NUL..len byte)."""
    ro_va, ro_off, ro_size = elf.sections[".rodata"]
    ro = elf.data[ro_off:ro_off + ro_size]
    b = tag.encode()
    rel_targets = set(relocs.values())
    hits = []
    for m in re.finditer(re.escape(b), ro):
        s = ro_va + m.start()
        # exact
        if s in leas or s in rel_targets:
            hits.append({"kind": "exact", "occurrence": s, "anchor": s,
                         "lea_sites": sorted(leas.get(s, ())),
                         "reloc_slots": sorted(k for k, v in relocs.items() if v == s)})
            continue
        # length-prefixed: byte immediately before equals len(tag) and is lea target
        if m.start() > 0 and ro[m.start() - 1] == len(b):
            t = s - 1
            if t in leas or t in rel_targets:
                hits.append({"kind": "len_prefix", "occurrence": s, "anchor": t,
                             "lea_sites": sorted(leas.get(t, ())),
                             "reloc_slots": sorted(k for k, v in relocs.items() if v == t)})
    return hits


def fde_edges(elf, starts, ends, relocs, fde_start):
    start_set = set(starts)
    t_va, t_off, t_size = elf.sections[".text"]
    text = elf.data[t_off:t_off + t_size]
    c = containing(starts, ends, fde_start)
    if c is None or c[0] != fde_start:
        raise EvidenceError(f"{fde_start:#x} is not an FDE start")
    body = text[fde_start - t_va:c[1] - t_va]
    edges = []
    for m in re.finditer(rb"\xe8", body):
        i = m.start()
        site = fde_start + i
        dst = site + 5 + struct.unpack_from("<i", body, i + 1)[0]
        if dst in start_set and dst != fde_start:
            edges.append({"kind": "rel32", "site": site, "to": dst, "slot": None})
    for m in re.finditer(rb"\xff[\x15\x25]", body):
        i = m.start()
        site = fde_start + i
        slot = site + 6 + struct.unpack_from("<i", body, i + 2)[0]
        dst = relocs.get(slot)
        if dst in start_set:
            edges.append({"kind": "slot", "site": site, "to": dst, "slot": slot})
    edges.sort(key=lambda e: (e["site"], e["kind"], e["to"]))
    return {"start": fde_start, "end": c[1], "edges": edges}


def build(data: bytes, ref_request: Path = ROOT / REF_REQUEST,
          expected_sha256: str = EXPECTED_SHA256) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    if sha != expected_sha256:
        raise EvidenceError(f"binary sha256 {sha} != {expected_sha256}")
    elf = Elf(data)
    starts, ends = fde_index(elf)
    relocs = relative_relocs(elf)
    locs = first_party_locations(elf, relocs)
    leas = lea_targets(elf)

    def owner(site):
        c = containing(starts, ends, site)
        if c is None:
            raise EvidenceError(f"reference site {site:#x} outside every FDE")
        return c

    fn_files = {}
    fn_end = {}
    for slot, (f, line, _col) in locs.items():
        for site in leas.get(slot, ()):
            s, e = owner(site)
            fn_end[s] = e
            fn_files.setdefault(s, {}).setdefault(f, set()).add(line)

    scoped_locs = []
    for slot in sorted(locs):
        f, line, col = locs[slot]
        if f.startswith(SCOPE_PREFIX):
            sites = sorted(leas.get(slot, ()))
            scoped_locs.append({
                "slot": slot, "file": f, "line": line, "col": col,
                "lea_sites": sites,
                "functions": sorted({owner(x)[0] for x in sites}),
            })
    per_file = {}
    for l in scoped_locs:
        per_file[l["file"]] = per_file.get(l["file"], 0) + 1

    info_fns = {s for s, files in fn_files.items()
                if any(f.startswith(SCOPE_PREFIX) for f in files)}
    # hl_node Locations that share an FDE with info_server
    linked_hl = []
    for slot, (f, line, col) in locs.items():
        if f != HL_NODE:
            continue
        sites = sorted(leas.get(slot, ()))
        fns = sorted({owner(x)[0] for x in sites})
        if any(fn in info_fns for fn in fns):
            linked_hl.append({
                "slot": slot, "file": f, "line": line, "col": col,
                "lea_sites": sites, "functions": fns,
                "shared_info_functions": sorted(fn for fn in fns if fn in info_fns),
            })

    functions = []
    for s in sorted(info_fns):
        files = fn_files.get(s, {})
        functions.append({
            "start": s, "end": fn_end[s],
            "first_party_locations": {
                f: sorted(v) for f, v in sorted(files.items())
                if f.startswith(SCOPE_PREFIX) or f == HL_NODE
            },
        })

    # Hub + deserializer + snapshot gate
    for pinned in (HUB, DESER, SNAPSHOT_GATE):
        if not is_fde_start(starts, pinned):
            raise EvidenceError(f"pinned {pinned:#x} is not an FDE start")
    hub = fde_edges(elf, starts, ends, relocs, HUB)
    deser_edge = next((e for e in hub["edges"] if e["to"] == DESER and e["kind"] == "rel32"), None)
    if deser_edge is None or deser_edge["site"] != HUB_TO_DESER_SITE:
        raise EvidenceError(
            f"hub→deser edge missing or site drift: got {deser_edge!r}, "
            f"want site {HUB_TO_DESER_SITE:#x}")
    hub_locs = {
        f: sorted(v) for f, v in sorted(fn_files.get(HUB, {}).items())
        if f.startswith(SCOPE_PREFIX)
    }
    if set(hub_locs) < {"info_server/src/handle_request.rs",
                        "info_server/src/router.rs",
                        "info_server/src/handler.rs",
                        "info_server/src/user_ip.rs"}:
        raise EvidenceError(f"hub Location set incomplete: {hub_locs}")

    # Tags
    tags_list = serde_rename_tags(ref_request.read_text(encoding="utf-8"))
    if len(tags_list) < 40:
        raise EvidenceError(f"too few serde rename tags: {len(tags_list)}")
    tags = []
    owner_hist = {}
    for tag in tags_list:
        anchors = tag_anchor(elf, tag, leas, relocs)
        if not anchors:
            raise EvidenceError(f"unanchored InfoRequest tag {tag!r}")
        # Prefer an anchor whose lea sites land in known info-related FDEs when possible
        def score(a):
            fns = {owner(x)[0] for x in a["lea_sites"]}
            return (len(fns & info_fns) + len(fns & {DESER, 0x28CEE90, 0x28CB0C0, HUB}),
                    -len(a["lea_sites"]))
        anchors.sort(key=score, reverse=True)
        chosen = anchors[0]
        fns = sorted({owner(x)[0] for x in chosen["lea_sites"]})
        for f in fns:
            owner_hist[f] = owner_hist.get(f, 0) + 1
        tags.append({
            "text": tag,
            "kind": chosen["kind"],
            "occurrence": chosen["occurrence"],
            "anchor": chosen["anchor"],
            "lea_sites": chosen["lea_sites"],
            "reloc_slots": chosen["reloc_slots"],
            "functions": fns,
            "alternate_anchor_count": len(anchors) - 1,
        })

    # Side-effect markers
    side = []
    for tag in SIDE_EFFECT_TAGS:
        t = next(x for x in tags if x["text"] == tag)
        side.append({"marker": tag, "kind": "tag", **{k: t[k] for k in
                    ("occurrence", "anchor", "functions", "lea_sites")}})
    tpl_anchors = literal_anchors(elf, "template", SNAPSHOT_TEMPLATE, leas, relocs)
    if not tpl_anchors:
        raise EvidenceError("snapshot localhost template not anchored")
    tpl_fns = sorted({owner(x)[0] for a in tpl_anchors for x in a["lea_sites"]})
    if SNAPSHOT_GATE not in tpl_fns:
        raise EvidenceError(f"snapshot template owners {tpl_fns} miss gate {SNAPSHOT_GATE:#x}")
    side.append({
        "marker": SNAPSHOT_TEMPLATE,
        "kind": "template",
        "anchors": tpl_anchors,
        "functions": tpl_fns,
        "gate_function": SNAPSHOT_GATE,
        "gate_locations": {
            f: sorted(v) for f, v in sorted(fn_files.get(SNAPSHOT_GATE, {}).items())
            if f.startswith(SCOPE_PREFIX)
        },
    })

    return {
        "binary_sha256": sha,
        "fde_count": len(starts),
        "first_party_location_count": len(locs),
        "scoped_location_counts": dict(sorted(per_file.items())),
        "scoped_locations": scoped_locs,
        "functions": functions,
        "linked_hl_node_locations": linked_hl,
        "hub": {
            "start": hub["start"], "end": hub["end"],
            "edge_count": len(hub["edges"]),
            "locations": hub_locs,
            "to_deserializer": deser_edge,
        },
        "deserializer": {
            "start": DESER,
            "end": ends[bisect.bisect_left(starts, DESER)],
            "tag_owner_count": owner_hist.get(DESER, 0),
        },
        "tags": tags,
        "tag_count": len(tags),
        "tag_owner_histogram": {f"{k:#x}": v for k, v in sorted(owner_hist.items(), key=lambda x: -x[1])},
        "side_effects": side,
    }


ADDR_KEYS = {
    "slot", "lea_sites", "functions", "start", "end", "occurrence", "anchor",
    "reloc_slots", "site", "to", "shared_info_functions", "gate_function",
}


def hexify(o, addr=False):
    if isinstance(o, dict):
        return {k: hexify(v, k in ADDR_KEYS or (addr and k not in
                ("tag_owner_histogram", "scoped_location_counts", "locations",
                 "gate_locations", "first_party_locations")))
                for k, v in o.items()}
    if isinstance(o, list):
        return [hexify(v, addr) for v in o]
    if addr and isinstance(o, int) and not isinstance(o, bool):
        return f"{o:#x}"
    return o


def render(result: dict) -> bytes:
    return (json.dumps(hexify(result), indent=1, sort_keys=True) + "\n").encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", type=Path, default=TARGET)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    try:
        r = build(a.binary.read_bytes())
    except EvidenceError as e:
        print(f"info_request_path: {e}", file=sys.stderr)
        return 2
    text = render(r)
    if a.out:
        a.out.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
