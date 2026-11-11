#!/usr/bin/env python3
"""Recompute, from the artifact alone, who calls `AreFilesInCompaction` and how
each caller consumes the returned byte.

The census is independent of the excerpts: it linearly sweeps `.text` with
Capstone, attributes every direct call to the owning `.eh_frame` FDE, and then
follows the returned value (`rax`/`eax`/`al`) from the call site forward inside
that FDE until it is first consumed.  The taint is dropped when the register is
overwritten and at every intervening call, which the ABI clobbers - Capstone does
not report what a `call` writes, so that kill has to be applied here.

Classification of the first use:
  arithmetic    - read by test/cmp/xor/add/sub/setcc/movzx/shift
  register-copy - copied into another register first, then consumed
  stored        - written to memory before any arithmetic use
  discarded     - overwritten without ever being read

Writes `callers.tsv` (one row per call site) and `caller_use.tsv` (the first-use
context) into the packet directory.  Reproduce with:
  python3 research/work-items/RE-002-node115-rocksdb-are-files-in-compaction-5d9a390-115/census.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = Path(__file__).resolve().parent
SYMBOL = ("_ZN7rocksdb16CompactionPicker20AreFilesInCompaction"
          "ERKSt6vectorIPNS_12FileMetaDataESaIS3_EE")
START = 0x5D9A390
END = 0x5D9A3CF
CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
ARITH = {"test", "cmp", "xor", "and", "or", "add", "sub", "sar", "shr", "shl",
         "movzx", "movzxw", "setne", "sete", "seta", "setb", "movzbl", "movzwl",
         "not", "neg"}
REG64 = {"rax", "rcx", "rdx", "rbx", "rsi", "rdi", "rsp", "rbp"} | {
    f"r{i}" for i in range(8, 16)}


def canon(reg):
    """Capstone register id -> canonical 64-bit name."""
    name = MD.reg_name(reg)
    if name.startswith("r") and name[1:].isdigit():
        return name
    m = {"eax": "rax", "ax": "rax", "al": "rax", "ebx": "rbx", "bx": "rbx", "bl": "rbx",
         "ecx": "rcx", "cx": "rcx", "cl": "rcx", "edx": "rdx", "dx": "rdx", "dl": "rdx",
         "esi": "rsi", "si": "rsi", "sil": "rsi", "edi": "rdi", "di": "rdi", "dil": "rdi",
         "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
         "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
         "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx"}
    return m.get(name, name)


MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True


def text_section():
    out = subprocess.check_output(["readelf", "-SW", str(BINARY)]).decode()
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                     line)
        if m and m.group(1) == ".text":
            addr, off, size = int(m.group(3), 16), int(m.group(4), 16), int(m.group(5), 16)
            data = BINARY.read_bytes()
            return data[off:off + size], addr
    raise AssertionError("no .text section")


def fdes():
    out = subprocess.check_output(
        ["readelf", "--debug-dump=frames", str(BINARY)]).decode()
    spans = []
    for line in out.splitlines():
        m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            spans.append((int(m.group(1), 16), int(m.group(2), 16)))
    spans.sort()
    return spans


def owner(addr, spans):
    lo, hi = 0, len(spans)
    while lo < hi:                       # last span whose start <= addr
        mid = (lo + hi) // 2
        if spans[mid][0] <= addr:
            lo = mid + 1
        else:
            hi = mid
    if lo and spans[lo - 1][0] <= addr < spans[lo - 1][1]:
        return spans[lo - 1]
    return None


def first_use(code, base, site, fde_end, cap=60):
    """Follow the returned value from `site` and classify its first consumption."""
    taint = {"rax"}
    steps = 0
    after = []
    for ins in MD.disasm(code[site - base:], site):
        if ins.address >= fde_end:
            break
        steps += 1
        if steps > cap:
            break
        after.append(f"{ins.mnemonic} {ins.op_str}")
        if ins.address == site:
            continue                     # the call itself
        if ins.mnemonic == "ret":
            if not taint:
                return "discarded", "; ".join(after[:10])
            return ("returned" if "rax" in taint else "live-at-exit"), "; ".join(after[:10])
        if ins.mnemonic == "call":
            if ins.address == site:
                continue
            taint -= CALLER_SAVED        # a call clobbers the caller-saved set
            if not taint:
                return "discarded", "; ".join(after[:10])
            continue
        # a conditional branch does NOT clobber registers; the walk follows the
        # linear fall-through path, so the first read reported is the first one
        # reachable that way (documented in the packet README).
        reads, writes = ins.regs_access()
        reads = {canon(r) for r in reads}
        writes = {canon(r) for r in writes}
        gained = set()
        if ins.mnemonic in ("mov", "movabs") and len(ins.operands) == 2 and \
                ins.operands[0].type == capstone.x86.X86_OP_REG and \
                ins.operands[1].type == capstone.x86.X86_OP_REG:
            src, dst = canon(ins.operands[1].reg), canon(ins.operands[0].reg)
            if src in taint:
                gained.add(dst)
                if dst not in taint and gained == {dst}:
                    taint.add(dst)
                    continue             # pure copy: keep following
        if reads & taint:
            # the value is consumed here
            if ins.mnemonic in ARITH or ins.mnemonic.startswith("set"):
                return "arithmetic", "; ".join(after[:10])
            if ins.mnemonic in ("mov", "movzx", "movsx", "movsxd"):
                for op in ins.operands:
                    if op.type == capstone.x86.X86_OP_MEM:
                        return "stored", "; ".join(after[:10])
                return "register-copy", "; ".join(after[:10])
            return "arithmetic", "; ".join(after[:10])
        for reg in writes:
            if reg in taint and reg not in gained:
                taint.discard(reg)
        taint |= gained
        if not taint:
            return "discarded", "; ".join(after[:10])
    if not taint:
        return "discarded", "; ".join(after[:10])
    return ("returned" if "rax" in taint else "live-at-exit"), "; ".join(after[:10])


def census():
    code, base = text_section()
    spans = fdes()
    rows = []
    for ins in MD.disasm(code, base):
        if ins.mnemonic != "call" or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type != capstone.x86.X86_OP_IMM or op.imm != START:
            continue
        span = owner(ins.address, spans)
        assert span, f"call at {ins.address:#x} is in no FDE"
        use, after = first_use(code, base, ins.address, span[1])
        rows.append({"site": ins.address, "fde": span, "use": use, "after": after})
    kinds = {}
    for r in rows:
        kinds[r["use"]] = kinds.get(r["use"], 0) + 1
    return {"symbol": SYMBOL, "start": START, "end": END, "fdes": spans and len(
        {(r["fde"][0], r["fde"][1]) for r in rows}), "call_sites": rows,
        "consumers": kinds, "discarded_sites": kinds.get("discarded", 0)}


def main():
    c = census()
    lines = ["site\tfde_start\tfde_end\tuse"]
    use_lines = ["site\tfirst_use\tafter"]
    for r in c["call_sites"]:
        lines.append(f"{r['site']:#x}\t{r['fde'][0]:#x}\t{r['fde'][1]:#x}\t{r['use']}")
        use_lines.append(f"{r['site']:#x}\t{r['use']}\t{r['after']}")
    (PACKET / "callers.tsv").write_text("\n".join(lines) + "\n")
    (PACKET / "caller_use.tsv").write_text("\n".join(use_lines) + "\n")
    print(f"{SYMBOL} {START:#x}: {len(c['call_sites'])} direct calls in "
          f"{c['fdes']} caller FDEs; consumers {c['consumers']}; reading "
          f"{len(c['call_sites']) - c['discarded_sites']}, discarded {c['discarded_sites']}")
    for r in c["call_sites"]:
        print(f"  {r['site']:#x} {r['fde'][0]:#x}..{r['fde'][1]:#x}  {r['use']:<13} "
              f"{r['after'][:96]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
