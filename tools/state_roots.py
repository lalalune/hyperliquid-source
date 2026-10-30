#!/usr/bin/env python3
"""RE-009: storage / ABCI-state ownership evidence for node #94.

Stdlib only. From the pinned ELF this derives:

* FDE bounds (``.eh_frame_hdr`` binary-search table);
* first-party panic ``Location`` records (``R_X86_64_RELATIVE`` slots whose
  addend is a ``/home/ubuntu/hl/code_Mainnet/...rs`` path, followed by the
  ``len``/``line``/``col`` words);
* RIP-relative ``lea`` references to those records and to a fixed list of
  storage/snapshot literals, attributed to the FDE that contains each site;
* inline ``"/dev/null"`` comparisons (``movabs rax, imm64``) in the scoped functions;
* the status of every ``.text`` address the reconstruction writes in
  ``db/*.rs`` and ``l1/abci/state.rs``.

It then emits a small snapshot fixture schema whose every entry cites the
functions above. Addresses are virtual addresses of instruction starts.
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
SCOPE_FILES = ("db/src/", "l1/src/abci/state.rs")
REF_DIR = "references/can1357-hl"
REF_FILES = ("db/block_reader.rs", "db/db_home.rs", "db/db_hub.rs", "db/dh.rs",
             "db/owned_db_home.rs", "db/rocks_db.rs", "l1/abci/state.rs")
# Literal texts. "template" literals sit inside Rust format templates, which
# are referenced at the byte after the preceding NUL; "exact" literals are
# referenced at their first byte.
LITERALS = (
    ("template", "/CHECKPOINT_COMPLETE"),
    ("template", "/lt_hashes.json"),
    ("template", "@@ linked abci state @@"),
    ("exact", "/tmp/abci_checkpoint.rmp"),
    ("exact", "/tmp/abci_checkpoint_evm_db"),
    ("exact", "/tmp/abci_state_bad_app_hash.rmp"),
    ("exact", "/tmp/abci_state_with_l1_hash_mismatch.rmp"),
    ("exact", "periodic_abci_states"),
)
TEMPLATE_WINDOW = 64
DEV_NULL_IMM = b"\x48\xb8" + b"/dev/nul"   # movabs rax, "/dev/nul"
LEA_RE = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
HEX_RE = re.compile(r"\b0x([0-9A-Fa-f_]{6,11})\b")


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
            self.sections[name] = (s[3], s[4], s[5])  # addr, offset, size

    def off(self, va):
        for v, o, s in self.loads:
            if v <= va < v + s:
                return o + va - v
        return None

    def va(self, off):
        for v, o, s in self.loads:
            if o <= off < o + s:
                return v + off - o
        return None

    def read(self, va, n):
        o = self.off(va)
        if o is None:
            raise EvidenceError(f"{va:#x} not file-backed")
        return self.data[o:o + n]


def _pe(data, pos, enc, base):
    if enc == 0x03:
        return struct.unpack_from("<I", data, pos)[0], 4
    if enc == 0x1B:
        return base + pos + struct.unpack_from("<i", data, pos)[0], 4
    if enc == 0x3B:
        return base + struct.unpack_from("<i", data, pos)[0], 4
    raise EvidenceError(f"unsupported pointer encoding {enc:#x}")


def fde_index(elf: Elf):
    """Return (sorted starts, ends) from the .eh_frame_hdr table and each FDE's pc_range."""
    addr, off, size = elf.sections[".eh_frame_hdr"]
    d = elf.data
    ver, ep_enc, cnt_enc, tab_enc = d[off:off + 4]
    if (ver, ep_enc, cnt_enc, tab_enc) != (1, 0x1B, 0x03, 0x3B):
        raise EvidenceError("unexpected .eh_frame_hdr encodings")
    count = struct.unpack_from("<I", d, off + 8)[0]
    if off + 12 + 8 * count > off + size or off + 12 + 8 * count > len(d):
        raise EvidenceError(".eh_frame_hdr table truncated")
    starts, ends = [], []
    for i in range(count):
        pos = off + 12 + 8 * i
        pc = addr + struct.unpack_from("<i", d, pos)[0]
        fde_va = addr + struct.unpack_from("<i", d, pos + 4)[0]
        fo = elf.off(fde_va)
        # length(4) CIE_pointer(4) pc_begin(4, pcrel sdata4) pc_range(4, udata4)
        pc_begin = fde_va + 8 + struct.unpack_from("<i", d, fo + 8)[0]
        if pc_begin != pc:
            raise EvidenceError(f"FDE pc_begin mismatch at {fde_va:#x}")
        starts.append(pc)
        ends.append(pc + struct.unpack_from("<I", d, fo + 12)[0])
    if starts != sorted(starts):
        raise EvidenceError(".eh_frame_hdr table not sorted")
    return starts, ends


def containing(starts, ends, va):
    j = bisect.bisect_right(starts, va) - 1
    if j >= 0 and va < ends[j]:
        return starts[j], ends[j]
    return None


def relative_relocs(elf: Elf) -> dict:
    _a, off, size = elf.sections[".rela.dyn"]
    out = {}
    for o in range(off, off + size, 24):
        r_off, info, add = struct.unpack_from("<QQq", elf.data, o)
        if info & 0xFFFFFFFF == 8:
            out[r_off] = add
    return out


def first_party_locations(elf, relocs):
    """Panic Location {&str file, u32 line, u32 col} records for first-party files."""
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
                raise EvidenceError(f"no template start before {lit!r} at {s:#x}")
            cands = list(range(ro_va + z + 1, s + 1))
        for t in cands:
            if t in leas or t in rel_targets:
                out.append({"occurrence": s, "anchor": t, "lea_sites": sorted(leas.get(t, ())),
                            "reloc_slots": sorted(k for k, v in relocs.items() if v == t)})
    return out


def is_fde_start(starts, va):
    j = bisect.bisect_left(starts, va)
    return j < len(starts) and starts[j] == va


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/94/hl-node"


def build(data: bytes, ref_root: Path = ROOT / REF_DIR, expected_sha256: str = EXPECTED_SHA256) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    if sha != expected_sha256:
        raise EvidenceError(f"binary sha256 {sha} != {expected_sha256}")
    elf = Elf(data)
    starts, ends = fde_index(elf)
    relocs = relative_relocs(elf)
    locs = first_party_locations(elf, relocs)
    leas = lea_targets(elf)
    t_va, _o, t_size = elf.sections[".text"]

    def owner(site):
        c = containing(starts, ends, site)
        if c is None:
            raise EvidenceError(f"reference site {site:#x} outside every FDE")
        return c

    fn_files = {}      # fde start -> {file: set(lines)}
    fn_end = {}
    for slot, (f, line, _col) in locs.items():
        for site in leas.get(slot, ()):
            s, e = owner(site)
            fn_end[s] = e
            fn_files.setdefault(s, {}).setdefault(f, set()).add(line)
    scoped = sorted(s for s, files in fn_files.items() if any(f.startswith(SCOPE_FILES) for f in files))

    scoped_locs = []
    for slot in sorted(locs):
        f, line, col = locs[slot]
        if f.startswith(SCOPE_FILES):
            sites = sorted(leas.get(slot, ()))
            scoped_locs.append({"slot": slot, "file": f, "line": line, "col": col,
                                "lea_sites": sites,
                                "functions": sorted({owner(x)[0] for x in sites})})

    literals = []
    lit_fns = {}
    for kind, lit in LITERALS:
        anchors = literal_anchors(elf, kind, lit, leas, relocs)
        fns = sorted({owner(x)[0] for a in anchors for x in a["lea_sites"]})
        for s in fns:
            fn_end[s] = ends[bisect.bisect_left(starts, s)]
            lit_fns.setdefault(s, []).append(lit)
        literals.append({"kind": kind, "text": lit, "anchors": anchors, "functions": fns})

    dev_null = []
    for s in scoped:
        code = elf.read(s, fn_end[s] - s)
        for m in re.finditer(re.escape(DEV_NULL_IMM), code):
            site = s + m.start()
            tail = code[m.start() + 10:m.start() + 30]
            # xor rax,[reg]; movzx ecx,byte [reg+8]; xor rcx,0x6c  -> 9th byte 'l'
            if b"\x48\x83\xf1\x6c" not in tail:
                raise EvidenceError(f"/dev/null compare at {site:#x} lacks the 9th-byte check")
            dev_null.append({"function": s, "site": site})

    functions = []
    for s in sorted(set(scoped) | set(lit_fns)):
        files = fn_files.get(s, {})
        functions.append({
            "start": s, "end": fn_end[s],
            "first_party_locations": {f: sorted(v) for f, v in sorted(files.items())},
            "literals": sorted(lit_fns.get(s, [])),
            "scoped": s in scoped,
        })

    claims = []
    for rel in REF_FILES:
        text = (ref_root / rel).read_text(encoding="utf-8")
        for m in HEX_RE.finditer(text):
            v = int(m.group(1).replace("_", ""), 16)
            if not t_va <= v < t_va + t_size:
                continue
            want = "l1/src/abci/state.rs" if rel.endswith("state.rs") else "db/src/" + rel.split("/", 1)[1]
            c = containing(starts, ends, v)
            files = fn_files.get(v, {})
            status = ("fde_start_with_own_location" if is_fde_start(starts, v) and want in files else
                      "fde_start_no_own_location" if is_fde_start(starts, v) else
                      "inside_fde" if c else "no_fde")
            claims.append({"file": rel, "va": v, "status": status,
                           "containing_fde": list(c) if c else None})
    claims = sorted({(c["file"], c["va"]): c for c in claims}.values(), key=lambda c: (c["file"], c["va"]))

    def fns_for(lit):
        return next(x["functions"] for x in literals if x["text"] == lit)

    def owners(fns):
        out = set()
        for s in fns:
            out.update(fn_files.get(s, {}))
        return sorted(out)

    schema = {
        "schema": "re009-snapshot-fixture/v1",
        "binary_sha256": sha,
        "entries": [
            {"name": lit, "role": role, "referenced_by": fns_for(lit),
             "first_party_owner_files": owners(fns_for(lit))}
            for lit, role in (
                ("/CHECKPOINT_COMPLETE", "checkpoint completion marker path suffix"),
                ("/lt_hashes.json", "checkpoint lt-hash file path suffix"),
                ("@@ linked abci state @@", "linked ABCI state log template"),
                ("/tmp/abci_checkpoint.rmp", "debug dump path (.rmp suffix)"),
                ("/tmp/abci_checkpoint_evm_db", "debug dump path (name says EVM db checkpoint)"),
                ("/tmp/abci_state_bad_app_hash.rmp", "debug dump path (.rmp suffix, name says bad app hash)"),
                ("/tmp/abci_state_with_l1_hash_mismatch.rmp", "debug dump path (.rmp suffix, name says L1 hash mismatch)"),
                ("periodic_abci_states", "relocated &str name (static table)"),
            )
        ],
        "dump_path_dev_null_guard": sorted({x["function"] for x in dev_null}),
    }

    status_counts = {}
    for c in claims:
        status_counts[c["status"]] = status_counts.get(c["status"], 0) + 1
    per_file = {}
    for l in scoped_locs:
        per_file[l["file"]] = per_file.get(l["file"], 0) + 1
    return {
        "binary_sha256": sha,
        "fde_count": len(starts),
        "first_party_location_count": len(locs),
        "scoped_location_counts": dict(sorted(per_file.items())),
        "scoped_locations": scoped_locs,
        "functions": functions,
        "literals": literals,
        "dev_null_compares": dev_null,
        "reconstruction_addresses": claims,
        "reconstruction_status_counts": dict(sorted(status_counts.items())),
        "fixture_schema": schema,
    }


ADDR_KEYS = {"slot", "lea_sites", "functions", "start", "end", "occurrence", "anchor",
             "reloc_slots", "function", "site", "va", "containing_fde", "referenced_by",
             "dump_path_dev_null_guard"}


def hexify(o, addr=False):
    if isinstance(o, dict):
        return {k: hexify(v, k in ADDR_KEYS) for k, v in o.items()}
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
    ap.add_argument("--schema-out", type=Path)
    a = ap.parse_args(argv)
    try:
        r = build(a.binary.read_bytes())
    except EvidenceError as e:
        print(f"state_roots: {e}", file=sys.stderr)
        return 2
    text = render(r)
    if a.schema_out:
        a.schema_out.write_bytes(render(r["fixture_schema"]))
    if a.out:
        a.out.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
