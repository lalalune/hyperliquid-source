#!/usr/bin/env python3
"""RE-009 hashing ownership for node #94: hasher functions, constants, call paths.

Stdlib only; reuses the ELF/FDE/relocation readers in ``tools/state_roots.py``.

* Hasher functions are FDEs that satisfy at least one rule:
  - ``crate_location``: a RIP ``lea`` in the function points at a panic Location
    whose path lies in a ``blake3-*``, ``tiny-keccak-*``, ``sha2-*`` or
    ``ripemd-*`` crate directory;
  - ``const:<name>``: the function's bytes contain a pinned hash constant as a
    little-endian immediate;
  - ``keccak_rc_table``: the function ``lea``s the 24-qword Keccak-f round
    constant table in ``.rodata``.
* Call edges come from byte-scanned ``e8``/``e9`` rel32 calls/jumps that land
  on an FDE start (``rel32``), ``ff 15``/``ff 25`` RIP-slot calls whose slot is
  an ``R_X86_64_RELATIVE`` relocation targeting an FDE start (``slot``), and,
  as an explicit over-approximation, every FDE-start pointer in a run of
  RELATIVE slots that a function ``lea``s in ``.data.rel.ro`` (``vtable``).
* For each source function, a breadth-first search to the first hasher.
* For the RE-005 (PR #10) integer encoders, reachability to hashers and
  co-calling.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import hashlib
import importlib.util
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("state_roots", ROOT / "tools/state_roots.py")
sr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sr)
EvidenceError = sr.EvidenceError

HASH_CRATE_RE = re.compile(r"/((?:blake3|tiny-keccak|sha2|ripemd)-[0-9][^/]*)/")
CONSTANTS = (  # name, little-endian bytes
    ("u32_0x6a09e667_blake3_iv0_sha256_h0", struct.pack("<I", 0x6A09E667)),
    ("u32_0xbb67ae85_blake3_iv1_sha256_h1", struct.pack("<I", 0xBB67AE85)),
    ("u32_0x3c6ef372_blake3_iv2_sha256_h2", struct.pack("<I", 0x3C6EF372)),
    ("u32_0xa54ff53a_blake3_iv3_sha256_h3", struct.pack("<I", 0xA54FF53A)),
    ("u32_0x510e527f_blake3_iv4_sha256_h4", struct.pack("<I", 0x510E527F)),
    ("u32_0x9b05688c_blake3_iv5_sha256_h5", struct.pack("<I", 0x9B05688C)),
    ("u32_0x1f83d9ab_blake3_iv6_sha256_h6", struct.pack("<I", 0x1F83D9AB)),
    ("u32_0x5be0cd19_blake3_iv7_sha256_h7", struct.pack("<I", 0x5BE0CD19)),
    ("u32_0x428a2f98_sha256_k0", struct.pack("<I", 0x428A2F98)),
    ("u32_0x71374491_sha256_k1", struct.pack("<I", 0x71374491)),
    ("u64_0x428a2f98d728ae22_sha512_k0", struct.pack("<Q", 0x428A2F98D728AE22)),
    ("u64_0x0000000000008082_keccak_rc1", struct.pack("<Q", 0x8082)),
    ("u64_0x800000000000808a_keccak_rc2", struct.pack("<Q", 0x800000000000808A)),
)
KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# RE-005 (PR #10 head 5586d6253484dc686d352ac088355fbf553951d8) pinned encoders.
RE005_ENCODERS = (0x27AB0A0, 0x27AB280, 0x27AB300, 0x27AB5B0, 0x4AA9AE0, 0x4AA9F80, 0x4AAA230)
LT_HASH_SOURCES = (0x332D440, 0x32699C0, 0x3269AE0)
VTABLE_MAX_SLOTS = 64
KINDS_DIRECT = ("rel32", "slot")
KINDS_ALL = ("rel32", "slot", "vtable")


def build(data: bytes, expected_sha256: str = sr.EXPECTED_SHA256) -> dict:
    base = sr.build(data, expected_sha256=expected_sha256)
    elf = sr.Elf(data)
    starts, ends = sr.fde_index(elf)
    start_set = set(starts)
    relocs = sr.relative_relocs(elf)
    leas = sr.lea_targets(elf)
    t_va, t_off, t_size = elf.sections[".text"]
    text = data[t_off:t_off + t_size]
    ro_va, ro_off, ro_size = elf.sections[".rodata"]
    dr_va, _o, dr_size = elf.sections[".data.rel.ro"]

    def own(v):
        c = sr.containing(starts, ends, v)
        return c[0] if c else None

    # every Location (any path) -> owning functions
    fn_paths = collections.defaultdict(set)
    for slot, a in relocs.items():
        if not (dr_va <= slot < dr_va + dr_size and ro_va <= a < ro_va + ro_size):
            continue
        ln, line, col = struct.unpack_from("<QII", elf.read(slot + 8, 16))
        if not 0 < ln < 256 or line == 0 or col == 0:
            continue
        p = elf.read(a, ln)
        if not p.endswith(b".rs") or b"\0" in p:
            continue
        for site in leas.get(slot, ()):
            f = own(site)
            if f is not None:
                fn_paths[f].add(p.decode())
    fp_prefix = sr.FIRST_PARTY.decode()

    def first_party_files(f):
        return sorted(p[len(fp_prefix):] for p in fn_paths.get(f, ()) if p.startswith(fp_prefix))

    def location_files(f):
        out = set()
        for p in fn_paths.get(f, ()):
            if p.startswith(fp_prefix):
                out.add(p[len(fp_prefix):])
            else:
                m = re.search(r"/registry/src/[^/]+/(.+)$", p)
                out.add(m.group(1) if m else p)
        return sorted(out)

    reasons = collections.defaultdict(set)
    for f, ps in fn_paths.items():
        for p in ps:
            m = HASH_CRATE_RE.search(p)
            if m:
                reasons[f].add("crate_location:" + m.group(1))
    const_sites = []
    for name, pat in CONSTANTS:
        sites = [t_va + m.start() for m in re.finditer(re.escape(pat), text)]
        fns = sorted({own(s) for s in sites if own(s) is not None})
        for f in fns:
            reasons[f].add("const:" + name)
        const_sites.append({"constant": name, "text_hits": len(sites), "sites": sites,
                            "functions": fns,
                            "first_party_functions": [f for f in fns if first_party_files(f)]})
    table = b"".join(struct.pack("<Q", v) for v in KECCAK_RC)
    ro = data[ro_off:ro_off + ro_size]
    tables = [ro_va + m.start() for m in re.finditer(re.escape(table), ro)]
    table_refs = []
    for t in tables:
        sites = sorted(leas.get(t, ()))
        fns = sorted({own(s) for s in sites if own(s) is not None})
        for f in fns:
            reasons[f].add("keccak_rc_table")
        table_refs.append({"table": t, "lea_sites": sites, "functions": fns})
    hashers = sorted(reasons)
    hset = set(hashers)

    # call graph
    edges = collections.defaultdict(list)  # src -> [(dst, kind, site, slot)]
    for m in re.finditer(rb"[\xe8\xe9]", text):
        i = m.start()
        if i + 5 > len(text):
            continue
        site = t_va + i
        dst = site + 5 + struct.unpack_from("<i", text, i + 1)[0]
        if dst in start_set:
            f = own(site)
            if f is not None and f != dst:
                edges[f].append((dst, "rel32", site, 0))
    for m in re.finditer(rb"\xff[\x15\x25]", text):
        i = m.start()
        if i + 6 > len(text):
            continue
        site = t_va + i
        slot = site + 6 + struct.unpack_from("<i", text, i + 2)[0]
        dst = relocs.get(slot)
        if dst in start_set:
            f = own(site)
            if f is not None:
                edges[f].append((dst, "slot", site, slot))
    for tgt in sorted(leas):
        if not (dr_va <= tgt < dr_va + dr_size and tgt in relocs):
            continue
        run, s = [], tgt
        while s in relocs and len(run) < VTABLE_MAX_SLOTS:
            if relocs[s] in start_set:
                run.append((relocs[s], s))
            s += 8
        for site in leas[tgt]:
            f = own(site)
            if f is not None:
                for dst, sl in run:
                    edges[f].append((dst, "vtable", site, sl))
    for f in edges:
        edges[f].sort()
    kind_counts = collections.Counter(k for es in edges.values() for _d, k, _s, _l in es)

    def bfs(srcs, kinds):
        prev = {s: None for s in srcs}
        depth = {s: 0 for s in srcs}
        q = collections.deque(sorted(srcs))
        hit = None
        while q:
            f = q.popleft()
            if f in hset and f not in srcs:
                hit = f
                break
            for dst, k, site, slot in edges.get(f, ()):
                if k in kinds and dst not in prev:
                    prev[dst] = (f, k, site, slot)
                    depth[dst] = depth[f] + 1
                    q.append(dst)
        chain = []
        x = hit
        while x is not None and prev[x] is not None:
            f, k, site, slot = prev[x]
            chain.append({"from": f, "kind": k, "site": site, "slot": slot or None, "to": x,
                          "to_location_files": location_files(x)})
            x = f
        return {"reached": len(prev), "max_depth": max(depth.values()), "exhausted": hit is None,
                "hit": hit, "chain": chain[::-1]}

    scoped = [f["start"] for f in base["functions"] if f["scoped"]]
    paths = []
    for label, srcs in ([(f"{s:#x}", (s,)) for s in LT_HASH_SOURCES] +
                        [("all_scoped_db_state_functions", tuple(scoped))]):
        for kinds in (KINDS_DIRECT, KINDS_ALL):
            r = bfs(set(srcs), kinds)
            r.update({"source": label, "edge_kinds": list(kinds)})
            paths.append(r)

    direct_callers = []
    for f in sorted(edges):
        hits = [(d, k, s, l) for d, k, s, l in edges[f] if k in KINDS_DIRECT and d in hset]
        if hits and first_party_files(f):
            direct_callers.append({
                "function": f, "first_party_files": first_party_files(f),
                "calls": [{"to": d, "kind": k, "site": s, "slot": l or None} for d, k, s, l in hits]})

    def reach(src):
        seen, q = {src}, [src]
        while q:
            f = q.pop()
            for d, k, _s, _l in edges.get(f, ()):
                if k in KINDS_DIRECT and d not in seen:
                    seen.add(d)
                    q.append(d)
        return seen

    callers = collections.defaultdict(set)
    for f, es in edges.items():
        for d, k, _s, _l in es:
            if k in KINDS_DIRECT:
                callers[d].add(f)
    for e in RE005_ENCODERS:
        if e not in start_set:
            raise EvidenceError(f"RE-005 encoder {e:#x} is not an FDE start")
    hasher_callers = set().union(*(callers[h] for h in hashers))
    enc_callers = set().union(*(callers[e] for e in RE005_ENCODERS))
    re005 = {
        "encoders": [{"function": e, "reachable": len(reach(e)),
                      "reachable_hashers": sorted(reach(e) & hset)} for e in RE005_ENCODERS],
        "hasher_direct_caller_count": len(hasher_callers),
        "encoder_direct_caller_count": len(enc_callers),
        "functions_calling_both": sorted(hasher_callers & enc_callers),
        "lt_hash_sources_reaching_encoders": {f"{s:#x}": sorted(reach(s) & set(RE005_ENCODERS))
                                             for s in LT_HASH_SOURCES},
    }
    hasher_rows = [{"function": f, "end": ends[bisect.bisect_left(starts, f)],
                    "reasons": sorted(reasons[f]), "first_party_files": first_party_files(f)}
                   for f in hashers]
    return {
        "binary_sha256": base["binary_sha256"],
        "hasher_count": len(hashers),
        "hasher_with_first_party_location_count": sum(1 for r in hasher_rows if r["first_party_files"]),
        "hashers": hasher_rows,
        "constants": const_sites,
        "keccak_rc_tables": table_refs,
        "edge_counts": {f"{k}_edges": v for k, v in sorted(kind_counts.items())},
        "paths": paths,
        "first_party_direct_hasher_callers": direct_callers,
        "first_party_direct_hasher_caller_count": len(direct_callers),
        "re005_encoders": re005,
    }


ADDR_KEYS = sr.ADDR_KEYS | {"from", "to", "hit", "table", "sites", "first_party_functions",
                            "reachable_hashers", "functions_calling_both"}


def render(result: dict) -> bytes:
    def hexify(o, addr=False):
        if isinstance(o, dict):
            return {k: hexify(v, k in ADDR_KEYS or k.startswith("0x")) for k, v in o.items()}
        if isinstance(o, list):
            return [hexify(v, addr) for v in o]
        if addr and isinstance(o, int) and not isinstance(o, bool):
            return f"{o:#x}"
        return o
    import json
    return (json.dumps(hexify(result), indent=1, sort_keys=True) + "\n").encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", type=Path, default=sr.TARGET)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    try:
        text = render(build(a.binary.read_bytes()))
    except (EvidenceError, OSError) as e:
        print(f"state_hashers: {e}", file=sys.stderr)
        return 2
    if a.out:
        a.out.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
