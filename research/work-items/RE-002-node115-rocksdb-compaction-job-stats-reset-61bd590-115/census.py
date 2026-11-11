#!/usr/bin/env python3
"""Recompute, from the artifact alone, who calls `CompactionJobStats::Reset` and
what each caller does around the call.

**Bounded by construction.** This never disassembles the whole `.text`: it scans
the section's raw bytes for the five-byte direct-call encoding (`e8 rel32`) whose
target is `Reset`'s entry, then hands *only small windows* around each hit to
Capstone. A full-artifact Capstone sweep in detail mode allocates millions of
instruction objects and will exhaust memory on this 105 MB binary - it is not an
option, and this census does not need it.

`Reset()` is a **void** method that works by writing memory, so the caller facts
worth recomputing are not "how is the return used" (there is none) but:

* that no caller reads `rax` afterwards - the register the body leaves behind is
  the last `std::string` data pointer it loaded, not a result;
* how each caller forms the object argument in `rdi` (a `lea` of an object, a
  register copy, or a load of a pointer field), walked backwards from the call
  site inside the owning FDE.

Writes `callers.tsv` and `caller_use.tsv`.

Reproduce with:
  python3 research/work-items/RE-002-node115-rocksdb-compaction-job-stats-reset-61bd590-115/census.py
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
SYMBOL = "_ZN7rocksdb18CompactionJobStats5ResetEv"
START = 0x61BD590
END = 0x61BD60F
CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
FORWARD_WINDOW = 0x180          # bytes decoded after a call site
BACKWARD_WINDOW = 0x180         # bytes decoded before a call site
MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True

_ALIAS = {"eax": "rax", "ax": "rax", "al": "rax", "ebx": "rbx", "bx": "rbx",
          "bl": "rbx", "ecx": "rcx", "cx": "rcx", "cl": "rcx", "edx": "rdx",
          "dx": "rdx", "dl": "rdx", "esi": "rsi", "si": "rsi", "sil": "rsi",
          "edi": "rdi", "di": "rdi", "dil": "rdi", "esp": "rsp", "sp": "rsp",
          "ebp": "rbp", "bp": "rbp"}


def canon(reg):
    name = MD.reg_name(reg)
    return _ALIAS.get(name, name)


def text_section():
    """(bytes, base address) of .text, plus its file offset."""
    out = subprocess.check_output(["readelf", "-SW", str(BINARY)]).decode()
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                     line)
        if m and m.group(1) == ".text":
            addr, off, size = int(m.group(3), 16), int(m.group(4), 16), int(m.group(5), 16)
            return BINARY.read_bytes()[off:off + size], addr
    raise AssertionError("no .text section")


def fdes():
    out = subprocess.check_output(["readelf", "--debug-dump=frames", str(BINARY)]).decode()
    spans = []
    for line in out.splitlines():
        m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            spans.append((int(m.group(1), 16), int(m.group(2), 16)))
    spans.sort()
    return spans


def owner(addr, spans):
    lo, hi = 0, len(spans)
    while lo < hi:
        mid = (lo + hi) // 2
        if spans[mid][0] <= addr:
            lo = mid + 1
        else:
            hi = mid
    if lo and spans[lo - 1][0] <= addr < spans[lo - 1][1]:
        return spans[lo - 1]
    return None


def find_calls(code, base, target):
    """Byte-scan for `e8 rel32` whose target is `target`. No disassembly."""
    sites, pos = [], code.find(b"\xe8")
    while pos != -1:
        if pos + 5 <= len(code):
            rel = int.from_bytes(code[pos + 1:pos + 5], "little", signed=True)
            if base + pos + 5 + rel == target:
                sites.append(base + pos)
        pos = code.find(b"\xe8", pos + 1)
    return sites


def window(code, base, lo, hi):
    lo = max(lo, base)
    hi = min(hi, base + len(code))
    return code[lo - base:hi - base], lo


def reads_return(code, base, site, fde_end, cap=48):
    """Does any path read rax before overwriting it? (void method: expect no.)"""
    blob, lo = window(code, base, site, min(site + FORWARD_WINDOW, fde_end))
    ins = list(MD.disasm(blob, lo))
    taint, steps, after = {"rax"}, 0, []
    for i, x in enumerate(ins):
        if i == 0:
            continue                      # the call itself
        steps += 1
        after.append(f"{x.mnemonic} {x.op_str}")
        if x.mnemonic == "call":
            taint -= CALLER_SAVED
            if not taint:
                return "discarded", "; ".join(after[:8])
            continue
        if x.mnemonic == "ret":
            return ("read" if not taint else "live-at-return"), "; ".join(after[:8])
        reads = {canon(r) for r in x.regs_access()[0]}
        writes = {canon(r) for r in x.regs_access()[1]}
        if reads & taint:
            return "read", "; ".join(after[:8])
        if writes & taint:
            taint -= writes
            if not taint:
                return "discarded", "; ".join(after[:8])
        if steps >= cap:
            break
    return ("live-at-window-end" if taint else "discarded"), "; ".join(after[:8])


def forms_argument(code, base, site, fde_start, back=24):
    """How was rdi last written before the call, inside this FDE?"""
    blob, lo = window(code, base, max(site - BACKWARD_WINDOW, fde_start), site)
    ins = list(MD.disasm(blob, lo))
    steps = 0
    for x in reversed(ins):
        steps += 1
        if steps > back:
            break
        for op in x.operands:
            if op.type == capstone.x86.X86_OP_REG and canon(op.reg) == "rdi" and \
                    (op.access & capstone.CS_AC_WRITE):
                if x.mnemonic == "lea":
                    return "lea", f"{x.mnemonic} {x.op_str}"
                if x.mnemonic.startswith("mov"):
                    mem = any(o.type == capstone.x86.X86_OP_MEM for o in x.operands)
                    return ("load" if mem else "register-copy"), f"{x.mnemonic} {x.op_str}"
                return "other", f"{x.mnemonic} {x.op_str}"
    return "not-seen", ""


def census():
    code, base = text_section()
    spans = fdes()
    sites = find_calls(code, base, START)
    rows = []
    for s in sites:
        span = owner(s, spans)
        assert span, f"call at {s:#x} is in no FDE"
        # the hit must really be a direct call to Reset, not a coincidental byte
        blob, lo = window(code, base, s, s + 5)
        ins = list(MD.disasm(blob, lo))
        assert len(ins) == 1 and ins[0].mnemonic == "call" and \
            ins[0].operands[0].type == capstone.x86.X86_OP_IMM and \
            ins[0].operands[0].imm == START, f"{s:#x} is not a direct call to Reset"
        use, after = reads_return(code, base, s, span[1])
        how, text = forms_argument(code, base, s, span[0])
        rows.append({"site": s, "fde": span, "return_use": use, "after": after,
                     "argument": how, "argument_text": text})
    consumers, args = {}, {}
    for r in rows:
        consumers[r["return_use"]] = consumers.get(r["return_use"], 0) + 1
        args[r["argument"]] = args.get(r["argument"], 0) + 1
    return {"symbol": SYMBOL, "start": START, "end": END,
            "caller_fdes": len({(r["fde"][0], r["fde"][1]) for r in rows}),
            "call_sites": rows, "consumers": consumers, "argument_forms": args,
            "read_sites": sum(1 for r in rows if r["return_use"] == "read")}


def main():
    c = census()
    lines = ["site\tfde_start\tfde_end\treturn_use\targument"]
    use_lines = ["site\treturn_use\targument\targument_text\tafter"]
    for r in c["call_sites"]:
        lines.append(f"{r['site']:#x}\t{r['fde'][0]:#x}\t{r['fde'][1]:#x}\t"
                     f"{r['return_use']}\t{r['argument']}")
        use_lines.append(f"{r['site']:#x}\t{r['return_use']}\t{r['argument']}\t"
                         f"{r['argument_text']}\t{r['after']}")
    (PACKET / "callers.tsv").write_text("\n".join(lines) + "\n")
    (PACKET / "caller_use.tsv").write_text("\n".join(use_lines) + "\n")
    print(f"{SYMBOL} {START:#x}: {len(c['call_sites'])} direct calls in "
          f"{c['caller_fdes']} caller FDEs; return use {c['consumers']}; "
          f"argument forms {c['argument_forms']}; sites reading rax {c['read_sites']}")
    for r in c["call_sites"]:
        print(f"  {r['site']:#x} {r['fde'][0]:#x}..{r['fde'][1]:#x}  "
              f"{r['return_use']:<9} rdi<- {r['argument']:<13} {r['argument_text']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
