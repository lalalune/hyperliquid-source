#!/usr/bin/env python3
"""RE-008: consensus wire/state evidence for node #94.

Stdlib only. From the pinned ELF this derives:

* FDE bounds (``.eh_frame_hdr``);
* first-party panic ``Location`` records for
  ``node/src/consensus/{types,signed,state}.rs``;
* RIP ``lea`` attribution of those Locations and of a fixed message/tag
  literal inventory;
* reconstruction seed address status against FDE starts and Locations;
* the signature-verification call graph among four pinned verifier FDEs
  (rel32 and RIP-slot edges that land on FDE starts);
* the quorum-weight compare site inside the callee reached from
  ``verify_qc`` (``2 * total < 3 * signed`` → ``setb``).

Addresses are virtual addresses of instruction starts (REX prefix included
when present). Claims are limited to what these scans pin.
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
SCOPE_FILES = (
    "node/src/consensus/types.rs",
    "node/src/consensus/signed.rs",
    "node/src/consensus/state.rs",
)
REF_DIR = "references/can1357-hl"
REF_FILES = (
    "node/consensus/types.rs",
    "node/consensus/signed.rs",
    "node/consensus/state.rs",
)
# Message / diagnostic tags. "exact" = lea/reloc at the first byte of the
# literal; "template" = lea at the Rust format-template start (byte after the
# preceding NUL within TEMPLATE_WINDOW).
TAGS = (
    ("exact", "VerifyQcSignature"),
    ("exact", "SignableContentVerifySignature"),
    ("exact", "QcNoQuorum"),
    ("exact", "TcNoQuorum"),
    ("exact", "BadBlockRound"),
    ("exact", "BadBlockQcRound"),
    ("exact", "BadBlockTcRound"),
    ("exact", "BlockAlreadyRegistered"),
    ("exact", "TimeoutRoundMismatch"),
    ("exact", "EmptyValidators"),
    ("exact", "ClientBlockMissingCommitProof"),
    ("exact", "ClientBlockMissingTxCommitProof"),
    ("exact", "QcRoundBeforeHardfork"),
    ("exact", "DuplicateBlockRound"),
    ("exact", "AlreadyHaveTimeoutFromNode"),
    ("exact", "ValidatorSetSnapshot"),
    ("exact", "signed_timeouts"),
    ("exact", "commit_proof"),
    ("template", "Unexpected proposer for block"),
    ("exact", "Qc does not have quorum"),
    ("exact", "Tc does not have quorum"),
    ("exact", "Failed to verify qc signature"),
    ("exact", "Bad block QC round"),
    ("exact", "Bad block TC round"),
)
TEMPLATE_WINDOW = 80
# Reconstruction seeds cited in can1357 consensus notes (TASKS RE-008 paths).
SEEDS = (
    ("types_Timeout_ser_a", 0x3969010),
    ("types_Timeout_ser_b", 0x39697A0),
    ("types_Tc", 0x396AB40),
    ("types_Block_a", 0x3969FB0),
    ("types_Block_b", 0x396A960),
    ("types_Signed", 0x396BC00),
    ("types_ValidatorSetSnapshot", 0x39F39F0),
    ("signed_verify_signed_block", 0x47B01B0),
    ("signed_verify_signed_timeout", 0x454AA10),
    ("signed_verify_qc", 0x4758D70),
    ("signed_verify_tc", 0x47594F0),
    ("state_new", 0x44A8420),
    ("state_register_client_block", 0x44AB560),
)
# Verifiers whose outgoing FDE-start edges form the signature map.
VERIFIERS = {
    "verify_signed_block": 0x47B01B0,
    "verify_signed_timeout": 0x454AA10,
    "verify_qc": 0x4758D70,
    "verify_tc": 0x47594F0,
}
# Quorum-weight compare pinned inside the slot-callee of verify_qc.
QUORUM_FN = 0x4AD90D0
QUORUM_MOV_IMM3 = 0x4AD9612  # mov edx, 3
QUORUM_MOV_R10 = 0x4AD9617   # rex.W mov rax, r10
QUORUM_MUL = 0x4AD961A       # rex.W mul rdx
QUORUM_ADD_RCX = 0x4AD961D   # rex.W add rcx, rcx  (*2)
QUORUM_CMP = 0x4AD9620       # rex.W cmp rax, rcx
QUORUM_SBB = 0x4AD9623       # rex.W sbb rsi, rdx
QUORUM_SETB = 0x4AD9626      # setb al
# verify_qc site that loads the quorum callee through a RELATIVE slot.
VERIFY_QC_QUORUM_CALL = 0x47590CA  # ff 15 ...
VERIFY_QC_QUORUM_SLOT = 0x5776AE8

LEA_RE = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
HEX_RE = re.compile(r"\b0x([0-9A-Fa-f_]{6,11})\b")

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
            try:
                name = s[len(FIRST_PARTY):].decode()
            except UnicodeDecodeError:
                raise EvidenceError("first-party location name not UTF-8")
            out[slot] = (name, line, col)
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
                out.append({"occurrence": s, "anchor": t,
                            "lea_sites": sorted(leas.get(t, ())),
                            "reloc_slots": sorted(k for k, v in relocs.items() if v == t)})
                break
    return out


def is_fde_start(starts, va):
    j = bisect.bisect_left(starts, va)
    return j < len(starts) and starts[j] == va


def verifier_edges(elf, starts, ends, relocs, verifiers):
    start_set = set(starts)
    t_va, t_off, t_size = elf.sections[".text"]
    text = elf.data[t_off:t_off + t_size]
    out = {}
    for name, f in verifiers.items():
        c = containing(starts, ends, f)
        if c is None or c[0] != f:
            raise EvidenceError(f"verifier {name} {f:#x} is not an FDE start")
        body = text[f - t_va:c[1] - t_va]
        edges = []
        for m in re.finditer(rb"\xe8", body):
            i = m.start()
            site = f + i
            dst = site + 5 + struct.unpack_from("<i", body, i + 1)[0]
            if dst in start_set and dst != f:
                edges.append({"kind": "rel32", "site": site, "to": dst, "slot": None})
        for m in re.finditer(rb"\xff[\x15\x25]", body):
            i = m.start()
            site = f + i
            slot = site + 6 + struct.unpack_from("<i", body, i + 2)[0]
            dst = relocs.get(slot)
            if dst in start_set:
                edges.append({"kind": "slot", "site": site, "to": dst, "slot": slot})
        edges.sort(key=lambda e: (e["site"], e["kind"], e["to"]))
        out[name] = {"start": f, "end": c[1], "edges": edges}
    return out


def quorum_evidence(elf, starts, ends, relocs):
    c = containing(starts, ends, QUORUM_FN)
    if c is None or c[0] != QUORUM_FN:
        raise EvidenceError(f"quorum function {QUORUM_FN:#x} is not an FDE start")
    # Exact instruction bytes at pinned sites.
    expected = {
        QUORUM_MOV_IMM3: bytes.fromhex("ba03000000"),          # mov edx, 3
        QUORUM_MOV_R10: bytes.fromhex("4c89d0"),               # rex.WR mov rax, r10
        QUORUM_MUL: bytes.fromhex("48f7e2"),                   # rex.W mul rdx
        QUORUM_ADD_RCX: bytes.fromhex("4801c9"),               # rex.W add rcx, rcx
        QUORUM_CMP: bytes.fromhex("4839c1"),                   # rex.W cmp rcx, rax  (AT&T cmp %rax,%rcx)
        QUORUM_SBB: bytes.fromhex("4819d6"),                   # rex.W sbb rsi, rdx
        QUORUM_SETB: bytes.fromhex("0f92c0"),                  # setb al
    }
    # AT&T objdump showed: cmp %rax,%rcx → opcode 48 39 c1 (cmp r/m64, r64 with rax→rcx)
    sites = {}
    for va, want in expected.items():
        got = elf.read(va, len(want))
        if got != want:
            raise EvidenceError(f"quorum opcode mismatch at {va:#x}: {got.hex()} != {want.hex()}")
        sites[va] = got.hex()
    # verify_qc call site → slot → quorum FDE
    call = elf.read(VERIFY_QC_QUORUM_CALL, 6)
    if call[:2] != b"\xff\x15":
        raise EvidenceError(f"expected ff15 at {VERIFY_QC_QUORUM_CALL:#x}, got {call.hex()}")
    slot = VERIFY_QC_QUORUM_CALL + 6 + struct.unpack_from("<i", call, 2)[0]
    if slot != VERIFY_QC_QUORUM_SLOT:
        raise EvidenceError(f"quorum slot {slot:#x} != {VERIFY_QC_QUORUM_SLOT:#x}")
    if relocs.get(slot) != QUORUM_FN:
        raise EvidenceError(f"slot {slot:#x} relocates to {relocs.get(slot)!r}, not {QUORUM_FN:#x}")
    return {
        "function": QUORUM_FN,
        "function_end": c[1],
        "compare": "2*rcx < 3*r10 → setb al; live regs at 0x4ad960b make rcx=total and r10=signed_weight (2*total < 3*signed ≡ signed > 2/3 total)",
        "instruction_starts": {
            "mov_edx_3": QUORUM_MOV_IMM3,
            "mov_rax_r10": QUORUM_MOV_R10,
            "mul_rdx": QUORUM_MUL,
            "add_rcx_rcx": QUORUM_ADD_RCX,
            "cmp_rcx_rax": QUORUM_CMP,
            "sbb_rsi_rdx": QUORUM_SBB,
            "setb_al": QUORUM_SETB,
        },
        "instruction_bytes": {f"{k:#x}": v for k, v in sites.items()},
        "verify_qc_call": {
            "site": VERIFY_QC_QUORUM_CALL,
            "kind": "slot",
            "slot": slot,
            "to": QUORUM_FN,
        },
    }


def build(data: bytes, ref_root: Path = ROOT / REF_DIR,
          expected_sha256: str = EXPECTED_SHA256) -> dict:
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

    fn_files = {}
    fn_end = {}
    for slot, (f, line, _col) in locs.items():
        for site in leas.get(slot, ()):
            s, e = owner(site)
            fn_end[s] = e
            fn_files.setdefault(s, {}).setdefault(f, set()).add(line)
    scoped = sorted(s for s, files in fn_files.items()
                    if any(f in SCOPE_FILES for f in files))

    scoped_locs = []
    for slot in sorted(locs):
        f, line, col = locs[slot]
        if f in SCOPE_FILES:
            sites = sorted(leas.get(slot, ()))
            scoped_locs.append({
                "slot": slot, "file": f, "line": line, "col": col,
                "lea_sites": sites,
                "functions": sorted({owner(x)[0] for x in sites}),
            })

    tags = []
    tag_fns = {}
    for kind, lit in TAGS:
        anchors = literal_anchors(elf, kind, lit, leas, relocs)
        fns = sorted({owner(x)[0] for a in anchors for x in a["lea_sites"]})
        for s in fns:
            fn_end[s] = ends[bisect.bisect_left(starts, s)]
            tag_fns.setdefault(s, []).append(lit)
        tags.append({"kind": kind, "text": lit, "anchors": anchors, "functions": fns})

    functions = []
    for s in sorted(set(scoped) | set(tag_fns)):
        files = fn_files.get(s, {})
        functions.append({
            "start": s, "end": fn_end[s],
            "first_party_locations": {f: sorted(v) for f, v in sorted(files.items())},
            "tags": sorted(tag_fns.get(s, [])),
            "scoped": s in scoped,
        })

    claims = []
    for rel in REF_FILES:
        text = (ref_root / rel).read_text(encoding="utf-8")
        for m in HEX_RE.finditer(text):
            v = int(m.group(1).replace("_", ""), 16)
            if not t_va <= v < t_va + t_size:
                continue
            want = "node/src/consensus/" + Path(rel).name
            c = containing(starts, ends, v)
            files = fn_files.get(v, {})
            status = ("fde_start_with_own_location" if is_fde_start(starts, v) and want in files else
                      "fde_start_no_own_location" if is_fde_start(starts, v) else
                      "inside_fde" if c else "no_fde")
            claims.append({"file": rel, "va": v, "status": status,
                           "containing_fde": list(c) if c else None,
                           "own_scoped_files": sorted(f for f in files if f in SCOPE_FILES)})
    claims = sorted({(c["file"], c["va"]): c for c in claims}.values(),
                    key=lambda c: (c["file"], c["va"]))

    seeds = []
    for name, va in SEEDS:
        c = containing(starts, ends, va)
        files = fn_files.get(va, {}) if is_fde_start(starts, va) else {}
        # also collect Locations of containing FDE
        cont_files = fn_files.get(c[0], {}) if c else {}
        seeds.append({
            "name": name, "va": va,
            "fde_start": is_fde_start(starts, va),
            "containing_fde": list(c) if c else None,
            "own_scoped_files": {f: sorted(v) for f, v in sorted(files.items()) if f in SCOPE_FILES},
            "containing_scoped_files": {f: sorted(v) for f, v in sorted(cont_files.items())
                                       if f in SCOPE_FILES},
        })

    verifiers = verifier_edges(elf, starts, ends, relocs, VERIFIERS)
    # Cross-verifier edges only (signature map).
    vset = set(VERIFIERS.values())
    cross = []
    for name, info in sorted(verifiers.items()):
        for e in info["edges"]:
            if e["to"] in vset:
                cross.append({"from": name, "from_va": info["start"], **e})
    cross.sort(key=lambda e: (e["from_va"], e["site"], e["to"]))

    quorum = quorum_evidence(elf, starts, ends, relocs)

    status_counts = {}
    for c in claims:
        status_counts[c["status"]] = status_counts.get(c["status"], 0) + 1
    per_file = {}
    for l in scoped_locs:
        per_file[l["file"]] = per_file.get(l["file"], 0) + 1

    # Signature-map summary: which verifier owns which diagnostic templates.
    signature_map = {
        "verifiers": {k: {"start": v["start"], "end": v["end"],
                          "edge_count": len(v["edges"]),
                          "cross_verifier_callees": sorted({e["to"] for e in v["edges"] if e["to"] in vset})}
                      for k, v in sorted(verifiers.items())},
        "cross_verifier_edges": cross,
        "proposer_mismatch_template_owner": next(
            t["functions"] for t in tags if t["text"] == "Unexpected proposer for block"),
        "quorum_diagnostic_template_owners": {
            t["text"]: t["functions"] for t in tags
            if t["text"] in ("Qc does not have quorum", "Tc does not have quorum",
                             "Failed to verify qc signature")
        },
    }

    return {
        "binary_sha256": sha,
        "fde_count": len(starts),
        "first_party_location_count": len(locs),
        "scoped_location_counts": dict(sorted(per_file.items())),
        "scoped_locations": scoped_locs,
        "functions": functions,
        "tags": tags,
        "seeds": seeds,
        "reconstruction_addresses": claims,
        "reconstruction_status_counts": dict(sorted(status_counts.items())),
        "verifiers": verifiers,
        "signature_map": signature_map,
        "quorum": quorum,
    }


ADDR_KEYS = {
    "slot", "lea_sites", "functions", "start", "end", "occurrence", "anchor",
    "reloc_slots", "function", "site", "va", "containing_fde", "to", "from_va",
    "function_end", "mov_edx_3", "mov_rax_r10", "mul_rdx", "add_rcx_rcx", "cmp_rcx_rax",
    "sbb_rsi_rdx", "setb_al", "cross_verifier_callees", "proposer_mismatch_template_owner",
    "quorum_diagnostic_template_owners",
}


def hexify(o, addr=False):
    if isinstance(o, dict):
        return {k: hexify(v, k in ADDR_KEYS or (addr and k != "instruction_bytes"))
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
        print(f"consensus_wire: {e}", file=sys.stderr)
        return 2
    text = render(r)
    if a.out:
        a.out.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
