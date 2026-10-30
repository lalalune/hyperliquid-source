#!/usr/bin/env python3
"""RE-010: map the node #94 execute-action jump table to FDE-bounded callees.

Stdlib only. Reads the ELF, decodes the jump table of the dispatcher that the
can1357 reconstruction places at 0x2759240, finds the rel32 direct calls (and
RIP-relative indirect calls through RELATIVE-relocated slots) on each case
arm's straight-line path (strict subset decoder; conditional branches on that
path are followed one level), and compares them with the HandlerRef addresses written in
references/can1357-hl/l1/exchange/impl_execute_action.rs.

Addresses are virtual addresses of instruction starts (REX prefix included).
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

EXPECTED_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
DISPATCHER = 0x2759240
# mov rax,[r12]; lea rcx,[rax-0x74]; cmp rax,0x74; mov eax,0x14; cmovae rax,rcx
BIAS_BYTES = bytes.fromhex("498b0424" "488d488c" "4883f874" "b814000000" "480f43c1")
BIAS_AT = 0x2759298
# lea rcx,[rip+rel32]; movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax
LEA_AT = 0x27592AD
TAIL_BYTES = bytes.fromhex("48630481" "4801c8" "ffe0")
TAG_BASE = 0x74
DEFAULT_INDEX = 0x14
R_X86_64_RELATIVE = 8
RS_PATH = "references/can1357-hl/l1/exchange/impl_execute_action.rs"
HANDLER_RE = re.compile(
    r'HandlerRef::new\(\s*(\d+),\s*"([^"]*)",\s*"([^"]*)",\s*0x([0-9A-Fa-f_]+),\s*"([^"]*)"'
)


class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise EvidenceError("not an ELF64 little-endian file")
        self.data = data
        if len(data) < 64:
            raise EvidenceError("truncated ELF header")
        phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
        if phnum and phoff + (phnum - 1) * phentsize + 40 > len(data):
            raise EvidenceError("program header table extends past end of file")
        if shnum and shoff + (shnum - 1) * shentsize + 64 > len(data):
            raise EvidenceError("section header table extends past end of file")
        self.loads = []
        for i in range(phnum):
            p_type, _f, p_off, p_va, _pa, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
            if p_type == 1:
                self.loads.append((p_va, p_off, p_filesz))
        raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
        stro = raw[shstrndx][4]
        self.sections = {}
        for s in raw:
            end = data.index(b"\0", stro + s[0])
            self.sections[data[stro + s[0]:end].decode()] = (s[3], s[4], s[5])

    def off(self, va: int) -> int:
        for v, o, n in self.loads:
            if v <= va < v + n:
                return o + va - v
        raise EvidenceError(f"unmapped va {va:#x}")

    def read(self, va: int, n: int) -> bytes:
        o = self.off(va)
        return self.data[o:o + n]


def fde_index(elf: Elf):
    va, off, size = elf.sections[".eh_frame_hdr"]
    d = elf.data
    if d[off] != 1 or tuple(d[off + 1:off + 4]) != (0x1B, 0x03, 0x3B):
        raise EvidenceError("unexpected .eh_frame_hdr encodings")
    count = struct.unpack_from("<I", d, off + 8)[0]
    starts, ends = [], []
    prev = None
    for i in range(count):
        pc_rel, fde_rel = struct.unpack_from("<ii", d, off + 12 + 8 * i)
        start, fde_va = va + pc_rel, va + fde_rel
        fo = elf.off(fde_va)
        pc_begin = fde_va + 8 + struct.unpack_from("<i", d, fo + 8)[0]
        pc_range = struct.unpack_from("<I", d, fo + 12)[0]
        if pc_begin != start:
            raise EvidenceError(f"FDE pc_begin mismatch at {start:#x}")
        if prev is not None and start <= prev:
            raise EvidenceError(".eh_frame_hdr table not strictly sorted")
        prev = start
        starts.append(start)
        ends.append(start + pc_range)
    return starts, ends


def relative_relocs(elf: Elf) -> dict:
    _va, off, size = elf.sections[".rela.dyn"]
    out = {}
    for i in range(0, size, 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", elf.data, off + i)
        if r_info & 0xFFFFFFFF == R_X86_64_RELATIVE:
            out[r_off] = r_add
    return out


def containing(starts, ends, va):
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and va < ends[i]:
        return starts[i], ends[i]
    return None


def parse_reconstruction(text: str):
    rows = {}
    for m in HANDLER_RE.finditer(text):
        case = int(m.group(1))
        if case in rows:
            raise EvidenceError(f"duplicate HandlerRef case {case}")
        rows[case] = {
            "case": case,
            "wire_type": m.group(2),
            "rust_variant": m.group(3),
            "claimed_ea": int(m.group(4).replace("_", ""), 16),
            "claimed_symbol": m.group(5),
        }
    return rows


class Insn:
    __slots__ = ("va", "size", "kind", "target", "slot")

    def __init__(self, va, size, kind="other", target=None, slot=None):
        self.va, self.size, self.kind, self.target, self.slot = va, size, kind, target, slot


def _modrm(code, i):
    """Return (length of ModRM+SIB+displacement, RIP displacement or None, reg field)."""
    m = code[i]
    mod, reg, rm = m >> 6, (m >> 3) & 7, m & 7
    n = 1
    rip = None
    if mod != 3 and rm == 4:
        sib = code[i + 1]
        n += 1
        if mod == 0 and sib & 7 == 5:
            n += 4
    if mod == 0 and rm == 5:
        rip = struct.unpack_from("<i", code, i + 1)[0]
        n += 4
    elif mod == 1:
        n += 1
    elif mod == 2:
        n += 4
    return n, rip, reg


def decode_one(code, i, va):
    """Strict length decoder for the opcode subset used on the dispatcher arm paths.

    Anything outside the subset raises EvidenceError instead of being guessed.
    """
    start = i
    opsize16 = False
    if code[i] == 0x66:
        opsize16 = True
        i += 1
    rex_w = False
    if 0x40 <= code[i] <= 0x4F:
        rex_w = bool(code[i] & 8)
        i += 1
    op = code[i]
    i += 1
    if op == 0x0F:
        op2 = code[i]
        i += 1
        if op2 in (0x10, 0x11, 0x28, 0x29, 0xB6, 0xB7):
            i += _modrm(code, i)[0]
        elif 0x80 <= op2 <= 0x8F:
            rel = struct.unpack_from("<i", code, i)[0]
            i += 4
            return Insn(va, i - start, "jcc", va + i - start + rel)
        else:
            raise EvidenceError(f"unsupported opcode 0f {op2:02x} at {va:#x}")
    elif op in (0x39, 0x89, 0x8B, 0x8D):
        i += _modrm(code, i)[0]
    elif op in (0x80, 0x83, 0xC6):
        i += _modrm(code, i)[0] + 1
    elif op == 0x81:
        i += _modrm(code, i)[0] + 4
    elif op == 0xC7:
        i += _modrm(code, i)[0] + (2 if opsize16 else 4)
    elif op == 0x3C or 0xB0 <= op <= 0xB7:
        i += 1
    elif 0xB8 <= op <= 0xBF:
        i += 8 if rex_w else 4
    elif op in (0xE8, 0xE9):
        rel = struct.unpack_from("<i", code, i)[0]
        i += 4
        return Insn(va, i - start, "call" if op == 0xE8 else "jmp", va + i - start + rel)
    elif op == 0xEB or 0x70 <= op <= 0x7F:
        rel = struct.unpack_from("<b", code, i)[0]
        i += 1
        return Insn(va, i - start, "jmp" if op == 0xEB else "jcc", va + i - start + rel)
    elif op == 0xFF:
        n, rip, reg = _modrm(code, i)
        i += n
        if reg == 2 and rip is not None:
            return Insn(va, i - start, "call_slot", None, va + i - start + rip)
        raise EvidenceError(f"unsupported ff /{reg} at {va:#x}")
    else:
        raise EvidenceError(f"unsupported opcode {op:02x} at {va:#x}")
    return Insn(va, i - start)


MAX_PATH = 48


def walk(elf, va, relocs, starts):
    """Decode linearly from va to the first call or unconditional jmp.

    Returns (instruction addresses, conditional branches seen, terminator).
    """
    code = elf.read(va, 15 * MAX_PATH)
    i = 0
    addrs, jccs = [], []
    for _ in range(MAX_PATH):
        ins = decode_one(code, i, va + i)
        addrs.append(ins.va)
        i += ins.size
        if ins.kind == "jcc":
            jccs.append({"site": ins.va, "target": ins.target})
        elif ins.kind == "call":
            if not is_fde_start(starts, ins.target):
                raise EvidenceError(f"call at {ins.va:#x} to non-FDE-start {ins.target:#x}")
            return addrs, jccs, {"site": ins.va, "kind": "rel32", "target": ins.target}
        elif ins.kind == "call_slot":
            if ins.slot not in relocs:
                raise EvidenceError(f"call slot {ins.slot:#x} has no RELATIVE relocation")
            return addrs, jccs, {"site": ins.va, "kind": "rip_slot", "slot": ins.slot,
                                 "target": relocs[ins.slot]}
        elif ins.kind == "jmp":
            return addrs, jccs, {"site": ins.va, "kind": "jmp", "target": ins.target}
    raise EvidenceError(f"no call/jmp within {MAX_PATH} instructions of {va:#x}")


def is_fde_start(starts, va):
    j = bisect.bisect_left(starts, va)
    return j < len(starts) and starts[j] == va


def classify(claim, first_call, branch_calls, starts):
    ea = claim["claimed_ea"]
    if ea == DISPATCHER:
        return "inline_claim_no_call" if first_call is None else "inline_claim_but_arm_calls"
    if not is_fde_start(starts, ea):
        return "claimed_not_fde_start"
    if first_call is not None and first_call["target"] == ea:
        return "real_first_call"
    if first_call is None and ea in branch_calls:
        return "real_first_call_on_branch"
    return "fde_start_not_called_from_arm"


HEX_RE = re.compile(r"0x([0-9A-Fa-f_]{6,9})\b")
TEXT_LO, TEXT_HI = 0x1343C80, 0x1343C80 + 0x431C430


def survey_addresses(src_dir: Path, starts, ends):
    """Classify every .text-range hex literal in the reconstruction's exchange tree."""
    rows = []
    for path in sorted(src_dir.rglob("*.rs")):
        seen = set()
        for m in HEX_RE.finditer(path.read_text(encoding="utf-8")):
            va = int(m.group(1).replace("_", ""), 16)
            if not TEXT_LO <= va < TEXT_HI or va in seen:
                continue
            seen.add(va)
            cf = containing(starts, ends, va)
            if cf is None:
                kind = "no_fde"
            elif cf[0] == va:
                kind = "at_fde_start"
            else:
                kind = "inside_fde"
            rows.append({
                "file": path.relative_to(src_dir).as_posix(),
                "va": va,
                "kind": kind,
                "fde_start": cf[0] if cf else None,
                "fde_end": cf[1] if cf else None,
            })
    rows.sort(key=lambda r: (r["file"], r["va"]))
    return rows


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/94/hl-node"
SOURCE = ROOT / RS_PATH


class EvidenceError(ValueError):
    pass


def build(data: bytes, rs: Path = SOURCE, expected_sha256: str = EXPECTED_SHA256) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    if sha != expected_sha256:
        raise EvidenceError(f"unexpected binary sha256 {sha}")
    elf = Elf(data)
    starts, ends = fde_index(elf)
    relocs = relative_relocs(elf)
    fn = containing(starts, ends, DISPATCHER)
    if fn is None or fn[0] != DISPATCHER:
        raise EvidenceError("dispatcher is not an FDE start")
    lo, hi = fn
    if elf.read(BIAS_AT, len(BIAS_BYTES)) != BIAS_BYTES:
        raise EvidenceError("tag-bias idiom not found")
    lea = elf.read(LEA_AT, 7)
    if lea[:3] != b"\x48\x8d\x0d" or elf.read(LEA_AT + 7, len(TAIL_BYTES)) != TAIL_BYTES:
        raise EvidenceError("jump-table idiom not found")
    table = LEA_AT + 7 + struct.unpack_from("<i", lea, 3)[0]
    targets = []
    while True:
        rel = struct.unpack_from("<i", elf.read(table + 4 * len(targets), 4))[0]
        tgt = table + rel
        if not lo <= tgt < hi:
            break
        targets.append(tgt)
    if len(set(targets)) != len(targets):
        raise EvidenceError("duplicate jump-table targets")
    claims = parse_reconstruction(rs.read_text(encoding="utf-8"))
    cases = []
    for idx, tgt in enumerate(targets):
        addrs, jccs, term = walk(elf, tgt, relocs, starts)
        first_call = None
        if term["kind"] != "jmp":
            first_call = dict(term, target_fde_end=ends[bisect.bisect_left(starts, term["target"])]
                              if is_fde_start(starts, term["target"]) else None)
        branch_calls = []
        for br in jccs:
            if not lo <= br["target"] < hi:
                raise EvidenceError(f"jcc at {br['site']:#x} leaves the dispatcher")
            _a, _j, bterm = walk(elf, br["target"], relocs, starts)
            br["path_end"] = bterm
            if bterm["kind"] != "jmp":
                branch_calls.append(bterm["target"])
        row = {
            "index": idx,
            "discriminant": TAG_BASE + idx,
            "arm": tgt,
            "arm_path_insns": len(addrs),
            "arm_path_end": term,
            "first_call": first_call,
            "entry_branches": jccs,
        }
        claim = claims.get(idx)
        if claim:
            ea = claim["claimed_ea"]
            cf = containing(starts, ends, ea)
            row["reconstruction"] = dict(
                claim,
                claimed_is_fde_start=is_fde_start(starts, ea),
                claimed_containing_fde=list(cf) if cf else None,
                status=classify(claim, first_call, branch_calls, starts),
            )
        cases.append(row)
    extra = sorted(set(claims) - set(range(len(targets))))
    if extra:
        raise EvidenceError(f"claims beyond table: {extra}")
    status_counts = {}
    for row in cases:
        if "reconstruction" in row:
            s = row["reconstruction"]["status"]
            status_counts[s] = status_counts.get(s, 0) + 1
    survey = survey_addresses(rs.parent, starts, ends)
    survey_counts = {}
    for r in survey:
        survey_counts[r["kind"]] = survey_counts.get(r["kind"], 0) + 1
    return {
        "address_survey": survey,
        "address_survey_counts": dict(sorted(survey_counts.items())),
        "binary_sha256": sha,
        "dispatcher": {"start": lo, "end": hi},
        "tag_base": TAG_BASE,
        "below_base_index": DEFAULT_INDEX,
        "jump_table": table,
        "table_entries": len(targets),
        "reconstruction_claims": len(claims),
        "status_counts": dict(sorted(status_counts.items())),
        "fde_count": len(starts),
        "cases": cases,
    }


ADDR_KEYS = {"start", "end", "jump_table", "arm", "site", "slot",
             "target", "target_fde_end", "fde_start", "fde_end", "claimed_ea", "claimed_containing_fde", "va"}


def hexify(o, addr=False):
    if isinstance(o, dict):
        return {k: hexify(v, k in ADDR_KEYS) for k, v in o.items()}
    if isinstance(o, list):
        return [hexify(v, addr) for v in o]
    if addr and isinstance(o, int) and not isinstance(o, bool):
        return f"{o:#x}"
    return o


def render(result: dict) -> bytes:
    return (json.dumps(hexify(result), sort_keys=True, indent=1) + "\n").encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", default=str(TARGET))
    ap.add_argument("--source", default=str(SOURCE))
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
