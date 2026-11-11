#!/usr/bin/env python3
"""Reproduce the thread-local dtor registration census for this work item.

Usage: python3 research/work-items/RE-001-thread-local-dtor-registration-115/census.py [--out PATH]
Run from the repository root. Writes callers.tsv (default: next to this file)
with one row per `call *__cxa_thread_atexit@GOTPCREL(%rip)` site in node #115.

Method (two independent checks agree on the site list):
  1. PRIMARY, byte-level: scan .text for the 6-byte shape `FF 15 <disp32>` whose
     RIP-relative target is the __cxa_thread_atexit GOT slot 0x64e0510. For a
     `call *disp(%rip)` the disp32 sits at instruction+2 and the target is
     (disp_pos + 4 + disp32), so the equation is exact for this opcode shape --
     no trailing immediate exists after the disp32, unlike e.g. the
     `cmpq $0,mem` at 0x5ca0d35 (which the naive disp32 equation misses because
     its imm8 follows the disp32). 1153 sites.
  2. CROSS-CHECK, full disassembly: `objdump -d` over the whole .text, grepping
     lines annotated `# 64e0510` whose bytes start with `ff 15`. Run once during
     the cycle it agreed exactly (1153 sites, same set; the earlier scratch
     dump only covered 0x5c00000.. and saw 64). Re-run with --full-objdump-check.
     verify.py spot-checks a seeded sample of sites via fresh objdump instead of
     re-running the whole-text dump on every verification.

Per site, the containing FDE comes from tools/fde_extents.py (the repo's own
unwind index). The dtor and the TLS offset are extracted from one objdump run
per distinct caller FDE (604 FDEs): the dtor is the last `lea ADDR(%rip)`
feeding %rsi before the call; the TLS offset resolves %rdi at the call through
mov/lea/add chains (including one stack-slot hop), falling back to the guard
check (`movzbl %fs:0xDISP(%rNN)` with %rNN = $imm) and finally to
`caller-passed` when the FDE receives the TLS object pointer in %rdi.
"""
import argparse
import bisect
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work" / "hl-node-115.bin"
OUT = Path(__file__).resolve().parent
TEXT_ADDR, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
GOT_SLOT = 0x64E0510


def parse_imm(s):
    return int(s, 16) if not s.startswith("-") else -int(s[1:], 16)


def find_sites(data):
    """Byte-level scan for `FF 15 <disp32>` targeting GOT_SLOT. Exact for this shape."""
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    sites = []
    for j in range(2, len(text) - 4):
        if text[j - 2] != 0xFF or text[j - 1] != 0x15:
            continue
        d = struct.unpack_from("<i", text, j)[0]
        if TEXT_ADDR + j + 4 + d == GOT_SLOT:
            sites.append(TEXT_ADDR + j - 2)
    return sites


def full_objdump_check(data):
    """Slow independent check: full .text objdump, grep call lines annotated # 64e0510."""
    proc = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(TEXT_ADDR)}",
         f"--stop-address={hex(TEXT_ADDR + TEXT_SIZE)}", str(BIN)],
        capture_output=True, text=True, check=True)
    found = []
    for line in proc.stdout.splitlines():
        if "# 64e0510" not in line:
            continue
        m = re.match(r"\s*([0-9a-f]+):\tff 15 ", line)
        if m:
            found.append(int(m.group(1), 16))
    return sorted(found)


def fde_table(data):
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import fde_extents
    _, ordered, _ = fde_extents(data)
    starts = [f["start"] for f in ordered]
    ends = [f["end"] for f in ordered]
    return starts, ends


def containing_fde(starts, ends, addr):
    i = bisect.bisect_right(starts, addr) - 1
    return starts[i], ends[i]


def objdump_range(start, stop):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(stop)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    ins = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$", line)
        if m:
            ins.append((int(m.group(1), 16), m.group(3).strip()))
    return ins


def resolve_t(ins, site_idx, fstart):
    """Resolve %rdi at the call to a TLS offset (int, negative) or 'caller-passed' or None.

    Two derivations are computed over the FDE text before the call: (a) a linear
    data-flow walk of %rdi through mov/lea/add (plus one stack-slot hop), and
    (b) the guard check that gates this registration, `movzbl %fs:0xDISP(%rNN)`
    with %rNN = $imm. They must agree; when the linear walk crosses a branch
    boundary it can pick up a wrong value (seen once: site 0x5a60547, where a
    `lea -0x1(%r13),%r12` in the guard==2 path corrupts the walk to -0x1131
    while the gating guard check at 0x5a60245 pins -0x1130), so the guard
    derivation wins on disagreement and the site is counted as guard-corrected.
    """
    vals = {}
    guard_checks = []
    for k in range(site_idx):
        _, t = ins[k]
        m = re.match(r"mov\s+\$(-?0x[0-9a-f]+),%(\w+)$", t)
        if m:
            vals[m.group(2)] = ("imm", parse_imm(m.group(1)))
            continue
        m = re.match(r"mov\s+%fs:0x0,%(\w+)$", t)
        if m:
            vals[m.group(1)] = ("fs0",)
            continue
        m = re.match(r"lea\s+(-?0x[0-9a-f]+)\(%(\w+)\),%(\w+)$", t)
        if m:
            vals[m.group(3)] = ("lea", vals.get(m.group(2), ("reg", m.group(2))), parse_imm(m.group(1)))
            continue
        m = re.match(r"add\s+%(\w+),%(\w+)$", t)
        if m:
            vals[m.group(2)] = ("add", vals.get(m.group(1), ("reg", m.group(1))), vals.get(m.group(2)))
            continue
        m = re.match(r"mov\s+%(\w+),%(\w+)$", t)
        if m:
            vals[m.group(2)] = vals.get(m.group(1), ("reg", m.group(1)))
            continue
        m = re.match(r"mov\s+%(\w+),(0x[0-9a-f]+\(%rsp\))$", t)
        if m:
            vals["stack:" + m.group(2)] = vals.get(m.group(1), ("reg", m.group(1)))
            continue
        m = re.match(r"mov\s+(0x[0-9a-f]+\(%rsp\)),%(\w+)$", t)
        if m:
            vals[m.group(2)] = vals.get("stack:" + m.group(1), ("reg", "stack:" + m.group(1)))
            continue
        m = re.search(r"%fs:0x[0-9a-f]+\(%(\w+)\)", t)
        if m and ("movzbl" in t or "movb" in t):
            reg = m.group(1)
            v = vals.get(reg)
            if v is not None and v[0] == "imm":
                guard_checks.append(v[1])

    def ev(v, depth=0):
        if v is None or depth > 8:
            return None
        if v[0] == "imm":
            return v[1]
        if v[0] == "fs0":
            return 0
        if v[0] == "lea":
            b = ev(v[1], depth + 1)
            return None if b is None else b + v[2]
        if v[0] == "add":
            b = ev(v[2], depth + 1)
            o = ev(v[1], depth + 1)
            return None if b is None or o is None else b + o
        if v[0] == "reg":
            return ev(vals.get(v[1]), depth + 1)
        return None

    flow = ev(vals.get("rdi"))
    guard = guard_checks[-1] if guard_checks else None
    if flow is not None and guard is not None and flow != guard:
        return guard, True
    if flow is not None:
        return flow, False
    if guard is not None:
        return guard, False
    # Caller-passed: the guard is read through the incoming %rdi.
    for k in range(site_idx):
        _, t = ins[k]
        if re.search(r"0x[0-9a-f]+\(%rdi\)", t) and ("movzbl" in t or "movb" in t):
            return "caller-passed", False
    return None, False


def find_dtor(ins, site_idx):
    for k in range(site_idx - 1, max(site_idx - 26, 0), -1):
        _, t = ins[k]
        m = re.search(r"lea\s+(-?0x[0-9a-f]+)\(%rip\),%(\w+)\s+#\s*([0-9a-f]+)", t)
        if m:
            return int(m.group(3), 16)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--full-objdump-check", action="store_true")
    args = ap.parse_args()
    data = BIN.read_bytes()
    sites = find_sites(data)
    if args.full_objdump_check:
        checked = full_objdump_check(data)
        assert checked == sites, (
            f"objdump cross-check disagrees: byte-scan {len(sites)} vs objdump {len(checked)}")
        print(f"full-objdump cross-check agrees: {len(sites)} sites", file=sys.stderr)
    starts, ends = fde_table(data)
    by_fde = {}
    for s in sites:
        by_fde.setdefault(containing_fde(starts, ends, s), []).append(s)
    rows = []
    guard_corrected = 0
    for (fs, fe), ss in sorted(by_fde.items()):
        ins = objdump_range(fs, fe)
        pos = {a: i for i, (a, _) in enumerate(ins)}
        for s in sorted(ss):
            i = pos[s]
            dtor = find_dtor(ins, i)
            t, corrected = resolve_t(ins, i, fs)
            guard_corrected += 1 if corrected else 0
            if isinstance(t, int):
                # Canonical signed form: immediates arrive as the full 64-bit
                # two's-complement value (e.g. 0xffffffffffffeed0), so fold
                # them back to the negative offset they denote.
                if t >= (1 << 63):
                    t -= (1 << 64)
                t = f"-0x{-t:x}" if t < 0 else f"0x{t:x}"
            rows.append((s, fs, fe, dtor, t))
    out = Path(args.out) if args.out else OUT / "callers.tsv"
    with open(out, "w") as fh:
        fh.write("site\tfde_start\tfde_end\tdtor\ttls_offset\n")
        for s, fs, fe, dtor, t in sorted(rows):
            fh.write(f"0x{s:x}\t0x{fs:x}\t0x{fe:x}\t"
                     f"{f'0x{dtor:x}' if dtor is not None else ''}\t{t if t is not None else ''}\n")
    print(json.dumps({
        "sites": len(rows),
        "distinct_fdes": len(by_fde),
        "distinct_dtors": sorted({f"0x{r[3]:x}" for r in rows if r[3] is not None}),
        "tls_unresolved": sum(1 for r in rows if r[4] is None),
        "dtor_unresolved": sum(1 for r in rows if r[3] is None),
        "guard_corrected": guard_corrected,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
