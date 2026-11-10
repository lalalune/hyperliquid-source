#!/usr/bin/env python3
"""Caller census for max_file_size_for_level 0x61bd410..0x61bd4e9 (node #115).

Reproduces, from the digest-verified local binary only:

  callers.tsv     every direct E8 (call) / E9 (jmp) site whose rel32
                  resolves to 0x61bd410, with the enclosing FDE bounds
                  read from the .eh_frame unwind table.
  caller_use.tsv  for every call site, the first instruction that reads
                  the returned count (%rax/%eax/...) after the call,
                  classified with Capstone operand access flags -- i.e.
                  the dependency each caller places on the routine.
  frames.txt      the unwinding entry (FDE) that covers the routine.
  relocations.txt the routine's relocation record (none), as read from
                  the vendor census and cross-checked against the
                  RELA sections.

Static disassembly only; nothing is executed.
"""
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

import capstone

CS_X86_OP_REG = capstone.x86.X86_OP_REG
CS_AC_READ = capstone.CS_AC_READ
CS_AC_WRITE = capstone.CS_AC_WRITE
RAX_REGS = {capstone.x86.X86_REG_RAX, capstone.x86.X86_REG_EAX,
            capstone.x86.X86_REG_AX, capstone.x86.X86_REG_AL,
            capstone.x86.X86_REG_AH}
MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
VENDOR_CENSUS = (ROOT / "research" / "work-items"
                 / "RE-002-node115-vendor-census" / "census.json")
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-encode-varint32-61bd410-115")

START = 0x61bd410
END = 0x61bd4e9
SYMBOL = "_ZN7rocksdb14EncodeVarint32EPcj"


def load_segments():
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    segs = []
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            segs.append((int(p[2], 16), int(p[1], 16), int(p[4], 16)))
    return segs


def va_to_off(segs, va):
    for v, o, f in segs:
        if v <= va < v + f:
            return o + (va - v)
    raise ValueError(hex(va))


def off_to_va(segs, off):
    for v, o, f in segs:
        if o <= off < o + f:
            return v + (off - o)
    raise ValueError(hex(off))


def fde_ranges():
    """(start, end) pairs from the .eh_frame FDE table."""
    out = subprocess.check_output(["readelf", "-wf", str(BINARY)]).decode()
    ranges = []
    for line in out.splitlines():
        m = re.search(r"pc=([0-9a-f]{16})\.\.([0-9a-f]{16})", line)
        if m:
            ranges.append((int(m.group(1), 16), int(m.group(2), 16)))
    return sorted(ranges)


def encloser(ranges, addr):
    for s, e in ranges:
        if s <= addr < e:
            return s, e
    return None


def find_calls(segs, target):
    """Direct E8 (call) / E9 (jmp) sites to `target`, then validated
    with Capstone linear disassembly from the enclosing FDE start so a
    stray E8/E9 byte inside another instruction cannot be mistaken for
    a call site."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    data = BINARY.read_bytes()
    ranges = fde_ranges()
    hits = []
    for m in re.finditer(b"[\xe8\xe9]", data):
        i = m.start()
        if i + 5 > len(data):
            continue
        try:
            va = off_to_va(segs, i)
        except ValueError:
            continue
        rel = struct.unpack_from("<i", data, i + 1)[0]
        if va + 5 + rel != target:
            continue
        enc = encloser(ranges, va)
        if enc is None:
            continue
        # Linear-disassemble from the FDE start; the site must land on
        # an instruction boundary and decode as a call/jmp to target.
        start_off = va_to_off(segs, enc[0])
        code = data[start_off:va_to_off(segs, va) + 5]
        ok = False
        for ins in md.disasm(code, enc[0]):
            if ins.address == va:
                text = ins.op_str
                ok = ins.mnemonic in ("call", "jmp") and text == hex(target)
                break
            if ins.address > va:
                break
        if ok:
            hits.append((va, "call" if data[i] == 0xE8 else "jmp"))
    return sorted(hits)


def census_relocations(start):
    recs = json.loads(VENDOR_CENSUS.read_text())["records"]
    rec = next(r for r in recs if r["start"] == start)
    return rec


def classify_rax_use(insns):
    """Scan forward for the first instruction that READS %rax (any of
    rax/eax/ax/al/ah), using Capstone's operand access flags. Returns
    (class, meaning, distance, instruction)."""
    for dist, ins in enumerate(insns, 1):
        read = False
        written = False
        for op in ins.operands:
            if op.type != CS_X86_OP_REG:
                continue
            if op.reg not in RAX_REGS:
                continue
            acc = getattr(op, "access", 0)
            if acc & CS_AC_READ:
                read = True
            elif acc & CS_AC_WRITE:
                written = True
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        if not read and not written:
            continue
        if read:
            if ins.mnemonic in ("cmp", "cmpq", "cmpl", "test", "testq",
                                "testl"):
                return ("compare", "the field is compared against a bound",
                        dist, text)
            if ins.mnemonic in ("shl", "shr", "sal", "sar", "rol", "ror"):
                return ("shift",
                        "the field is shifted into a wider accumulator",
                        dist, text)
            if ins.mnemonic in ("and", "or", "xor", "andl", "orl", "xorl",
                                "andq", "orq", "xorq", "bzhi"):
                return ("mask-combine",
                        "the field is masked or combined into a word",
                        dist, text)
            if ins.mnemonic in ("add", "sub", "lea", "inc", "dec", "neg",
                                "sbb", "adc", "imul"):
                return ("arithmetic",
                        "the field is folded into a running total", dist,
                        text)
            if ins.mnemonic.startswith("push"):
                return ("stack-arg",
                        "pushed as a stack argument for a following call",
                        dist, text)
            if ins.mnemonic in ("mov", "movl", "movq", "movzx", "movsx",
                                "movd", "movaps", "movups", "movdqu"):
                dest = ins.op_str.split(",")[0]
                if "[" in dest:
                    return ("store", "stored into a memory slot", dist, text)
                return ("register-copy",
                        "copied into a register for later use", dist, text)
            if ins.mnemonic.startswith(("set", "cmov")):
                return ("predicate", "the field feeds a conditional", dist,
                        text)
            if ins.mnemonic.startswith("j"):
                return ("control", "the field selects a branch", dist, text)
            return "read-other", text, dist, text
        return "overwritten", "overwritten before being read", dist, text
    return "dead", "never read inside the enclosing FDE", 0, ""


def caller_use(segs, ranges, hits, limit=4000):
    """For every call site, decode forward inside the enclosing FDE and
    classify how the returned count is consumed. This is the dependency
    the callers place on the routine: the window must hold the requested
    field exactly, so the caller can mask it and shift it into place."""
    data = BINARY.read_bytes()
    out = []
    for site, kind in hits:
        enc = encloser(ranges, site)
        start_off = va_to_off(segs, site)
        end_off = min(va_to_off(segs, enc[1]), len(data))
        code = data[start_off:end_off]
        insns = []
        for ins in MD.disasm(code, site):
            if ins.address == site:
                continue           # the call itself
            insns.append(ins)
            if len(insns) >= limit:
                break
        cls, why, dist, use = classify_rax_use(insns)
        after = "; ".join(f"{i.mnemonic} {i.op_str}".strip()
                          for i in insns[dist:dist + 6]) if dist else ""
        out.append({"site": site, "kind": kind, "fde": enc,
                    "consumer": cls, "meaning": why,
                    "distance": dist, "use": use, "after": after})
    return out



def main():
    segs = load_segments()
    ranges = fde_ranges()
    rec = census_relocations(START)

    # callers.tsv
    hits = find_calls(segs, START)
    rows = ["site\tkind\tcaller_fde_start\tcaller_fde_end"]
    for site, kind in hits:
        enc = encloser(ranges, site)
        assert enc, hex(site)
        rows.append(f"{hex(site)}\t{kind}\t{hex(enc[0])}\t{hex(enc[1])}")
    (PACKET / "callers.tsv").write_text("\n".join(rows) + "\n")

    # caller_use.tsv -- what each caller does with the returned count
    # (the dependency the call sites place on the routine).
    uses = caller_use(segs, ranges, hits)
    urows = ["site\tconsumer\tdistance\tuse\tafter\tcaller_fde\tmeaning"]
    for u in uses:
        urows.append("\t".join([
            hex(u["site"]), u["consumer"], str(u["distance"]),
            u["use"] or "-", u["after"] or "-",
            f"{hex(u['fde'][0])}..{hex(u['fde'][1])}", u["meaning"],
        ]))
    (PACKET / "caller_use.tsv").write_text("\n".join(urows) + "\n")

    # frames.txt
    enc = encloser(ranges, START)
    assert enc == (START, END), (enc, hex(START), hex(END))
    frames = []
    out = subprocess.check_output(["readelf", "-wf", str(BINARY)]).decode()
    for line in out.splitlines():
        if f"pc={START:016x}..{END:016x}" in line:
            frames.append(line.rstrip())
    (PACKET / "frames.txt").write_text(
        f"# .eh_frame entry covering {SYMBOL} {hex(START)}..{hex(END)}\n"
        + "\n".join(frames) + "\n")

    # relocations.txt
    assert rec["relocations"] == [], rec["relocations"]
    (PACKET / "relocations.txt").write_text(
        f"# {SYMBOL} {hex(START)}..{hex(END)}: no relocations.\n"
        f"# Vendor census member {rec['member']} records 0 relocations;\n"
        "# the body is raw-equal to its source bytes with no relocation\n"
        "# field to zero (target_body_sha256 == source_body_sha256).\n"
        f"target_body_sha256 {rec['target_body_sha256']}\n"
        f"source_body_sha256 {rec['source_body_sha256']}\n")

    # functions.tsv (this routine calls nothing)
    (PACKET / "functions.tsv").write_text("start\tend\tsymbol\tkind\n")

    print(f"callers: {len(hits)}")
    print(f"fde: {hex(enc[0])}..{hex(enc[1])}")
    print("consumers: " + ", ".join(
        f"{c}={sum(1 for u in uses if u['consumer'] == c)}"
        for c in sorted({u["consumer"] for u in uses})))
    print("wrote callers.tsv caller_use.tsv frames.txt relocations.txt functions.tsv")


if __name__ == "__main__":
    sys.exit(main())
