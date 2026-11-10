#!/usr/bin/env python3
"""Caller census for `GetBGJobLimits` 0x5dd5f00 (node #115).

Self-contained: it re-reads the artifact, finds every direct call to the routine
in `.text`, attributes each call site to its enclosing `.eh_frame` FDE, and
classifies how the site consumes the packed `rax` return. Writes the packet's
`callers.tsv` and `caller_use.tsv` and prints the census.

The classification reads the *first* use of `rax` after the call through
Capstone's `regs_access()`, which includes the base and index registers of a
memory operand - a plain operand-type scan misses `mov (%rax),%rdx` and, in
another packet, that blind spot misclassified nine call sites.

Usage: python3 census.py [--write]
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-get-bg-job-limits-5dd5f00-115")
START = 0x5DD5F00
SYMBOL = "_ZN7rocksdb6DBImpl14GetBGJobLimitsEiiib"

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True

RAX = {capstone.x86.X86_REG_RAX, capstone.x86.X86_REG_EAX,
       capstone.x86.X86_REG_AX, capstone.x86.X86_REG_AL,
       capstone.x86.X86_REG_AH}


def readelf(*args):
    return subprocess.check_output(["readelf", *args, str(BINARY)]).decode()


def sections():
    out = {}
    for line in readelf("-SW").splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m and m.group(2) == "PROGBITS":
            out[m.group(1)] = (int(m.group(3), 16), int(m.group(4), 16), int(m.group(5), 16))
    return out


def load_segments():
    segs = []
    for line in readelf("-lW").splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            segs.append((int(p[2], 16), int(p[1], 16), int(p[4], 16)))
    return segs


def va_to_off(va, segs=None):
    for v, o, f in segs or load_segments():
        if v <= va < v + f:
            return o + (va - v)
    raise AssertionError(f"{va:#x} is not in a LOAD segment")


def fdes():
    """Every FDE pc range, verbatim from the .eh_frame dump."""
    rows = []
    for line in readelf("--debug-dump=frames").splitlines():
        m = re.search(r"FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            rows.append((int(m.group(1), 16), int(m.group(2), 16), line.strip()))
    rows.sort()
    return rows


def enclosing_fde(va, rows=None):
    for s, e, line in rows or fdes():
        if s <= va < e:
            return s, e, line
        if s > va:
            break
    raise AssertionError(f"{va:#x} is in no FDE")


def call_sites():
    """Direct `call 0x5dd5f00` sites, from a linear sweep of .text."""
    sec = sections()["text"] if "text" in sections() else sections()[".text"]
    addr, off, size = sec
    data = BINARY.read_bytes()[off:off + size]
    sites = []
    for ins in MD.disasm(data, addr):
        if ins.mnemonic == "call" and ins.operands and \
                ins.operands[0].type == capstone.x86.X86_OP_IMM and \
                ins.operands[0].imm == START:
            sites.append(ins.address)
    return sorted(sites)


def _touches_rax(ins):
    return bool(RAX & set(ins.regs_access()[0]))


def classify(site, window=10):
    o = va_to_off(site)
    code = BINARY.read_bytes()
    insns = []
    for ins in MD.disasm(code[o:o + 64], site):
        insns.append(ins)
        if len(insns) > window:
            break
    first = None
    for k, ins in enumerate(insns):
        if _touches_rax(ins):
            first = (k, ins)
            break
    if first is None:
        return {"consumer": "overwritten", "distance": None, "use": "",
                "after": "", "meaning": "the return is not read in the next "
                                        "10 instructions"}
    k, ins = first
    use = f"{ins.mnemonic} {ins.op_str}"
    after = "; ".join(f"{i.mnemonic} {i.op_str}" for i in insns[1:7]).strip("; ")
    mem_base = any(op.type == capstone.x86.X86_OP_MEM and
                   set(op.mem.base and [op.mem.base] or []) & RAX
                   for op in ins.operands)
    writes_rax = bool(RAX & set(ins.regs_access()[1]))
    if mem_base:
        consumer, meaning = "memory-base", "rax is the base of a memory operand"
    elif writes_rax:
        consumer = "arithmetic"
        meaning = "rax is read and written in place (the packed pair is split here)"
    else:
        consumer = "register-copy"
        meaning = "the packed pair is kept in another register and split later"
    return {"consumer": consumer, "distance": k, "use": use, "after": after,
            "meaning": meaning}


_32_TO_64 = {}
for _n in ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di"):
    _32_TO_64["e" + _n] = {"ax": "rax", "cx": "rcx", "dx": "rdx", "bx": "rbx",
                          "sp": "rsp", "bp": "rbp", "si": "rsi", "di": "rdi"}[_n]
for _n in range(8, 16):
    _32_TO_64[f"r{_n}d"] = f"r{_n}"


def _canon(reg):
    """Capstone register id -> the 64-bit register name."""
    name = MD.reg_name(reg)
    return _32_TO_64.get(name, name)


def split_of(site, fde_end, cap=80):
    """Where this call site splits the packed pair, or None.

    The packed value starts in `rax`; the analysis follows it through register
    copies inside the caller's FDE and reports the first `sar/shr $0x20` that
    lands on a register still holding it. A register stops holding it when it is
    written from anything that is not the tainted value.
    """
    o = va_to_off(site)
    code = BINARY.read_bytes()
    taint = {"rax"}
    steps = 0
    for ins in MD.disasm(code[o:o + (fde_end - site)], site):
        if ins.address == site:
            continue          # the call itself: rax holds the return only after it
        steps += 1
        if steps > cap or ins.address >= fde_end:
            break
        # A call clobbers the caller-saved registers: capstone reports only the
        # implicit operands of `call`, so the ABI kill has to be applied here.
        # Without it a stale rax would taint the *next* call's copy (the two
        # adjacent sites in 0x5d71fe0..0x5d72e50 exercise exactly that trap).
        if ins.mnemonic in ("call", "ret", "jmp") or ins.mnemonic.startswith("j"):
            taint -= {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
            if not taint:
                break
            continue
        reads, writes = ins.regs_access()
        if ins.mnemonic in ("sar", "shr", "shl", "sal") and ins.operands and \
                ins.operands[0].type == capstone.x86.X86_OP_REG:
            cnt = ins.operands[1].imm if len(ins.operands) > 1 else None
            if cnt == 0x20 and _canon(ins.operands[0].reg) in taint:
                return ins.mnemonic, ins.address
        gained = set()
        if ins.mnemonic in ("mov", "movabs") and len(ins.operands) == 2 and \
                ins.operands[0].type == capstone.x86.X86_OP_REG and \
                ins.operands[1].type == capstone.x86.X86_OP_REG and \
                _canon(ins.operands[1].reg) in taint:
            # intel order in capstone: operand 0 is the destination
            gained.add(_canon(ins.operands[0].reg))
        for reg in writes:
            name = _canon(reg)
            if name in taint and name not in gained:
                taint.discard(name)
        taint |= gained
        if not taint:
            break
    return None


def census():
    sites = call_sites()
    rows = fdes()
    out = []
    for s in sites:
        f0, f1, _ = enclosing_fde(s, rows)
        c = classify(s)
        split = split_of(s, f1)
        c.update(site=s, caller_fde_start=f0, caller_fde_end=f1,
                 split=split[0] if split else "none",
                 split_va=split[1] if split else None)
        out.append(c)
    fde_count = len({(r["caller_fde_start"], r["caller_fde_end"]) for r in out})
    consumers = {}
    for r in out:
        consumers[r["consumer"]] = consumers.get(r["consumer"], 0) + 1
    reading = sum(1 for r in out if r["consumer"] != "overwritten")
    splits = {}
    for r in out:
        key = r["split"]
        splits[key] = splits.get(key, 0) + 1
    return {"direct_calls": len(out), "tail_jumps": 0, "caller_fdes": fde_count,
            "consumers": consumers, "sites_reading_the_return": reading,
            "discarded_sites": len(out) - reading, "splits": splits, "rows": out}


def write(rows):
    lines = ["site\tkind\tcaller_fde_start\tcaller_fde_end"]
    for r in rows:
        lines.append(f"{r['site']:#x}\tcall\t{r['caller_fde_start']:#x}\t"
                     f"{r['caller_fde_end']:#x}")
    (PACKET / "callers.tsv").write_text("\n".join(lines) + "\n")
    cols = ("site", "consumer", "distance", "use", "after", "split", "split_va",
            "caller_fde", "meaning")
    lines = ["\t".join(cols)]
    for r in rows:
        lines.append("\t".join([
            f"{r['site']:#x}", r["consumer"], str(r["distance"]), r["use"],
            r["after"], r["split"],
            f"{r['split_va']:#x}" if r["split_va"] else "-",
            f"{r['caller_fde_start']:#x}..{r['caller_fde_end']:#x}",
            r["meaning"]]))
    (PACKET / "caller_use.tsv").write_text("\n".join(lines) + "\n")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    c = census()
    if "--write" in argv or True:
        write(c["rows"])
    print(f"{SYMBOL} 0x{START:x}: {c['direct_calls']} direct calls in "
          f"{c['caller_fdes']} caller FDEs; consumers {c['consumers']}; "
          f"reading {c['sites_reading_the_return']}, discarded "
          f"{c['discarded_sites']}; splits {c['splits']}")
    for r in c["rows"]:
        at = f" at {r['split_va']:#x}" if r["split_va"] else ""
        print(f"  {r['site']:#x} {r['caller_fde_start']:#x}..{r['caller_fde_end']:#x}"
              f"  {r['consumer']:<14} d={r['distance']}  {r['use']}"
              f"  split {r['split']}{at}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
