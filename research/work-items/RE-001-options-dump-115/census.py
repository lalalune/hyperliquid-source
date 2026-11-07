#!/usr/bin/env python3
"""Reproduce every census in the RE-001-options-dump-115 packet.

Run from the repository root:
  python3 research/work-items/RE-001-options-dump-115/census.py

Reproduces, from work/hl-node-115.bin only:
  fields.tsv    -- the 93 leveled-log calls in the dump (0x60b50c0),
                   with level, format string and value-source tokens.
  enum-table.tsv -- the 65-entry CompressionType jump table at 0x96d4f0.
  levels.tsv    -- the log level at every direct call site of the
                   helper 0x5fceda0 (341 sites).
  callers.tsv   -- every direct call site of 0x60b50c0, 0x5fceda0,
                   0x5d8b3c0 and 0x5fceea0 (byte-level E8 rel32 scan).
  frames.txt    -- the five FDE ranges, parsed from readelf output.

Section map (readelf -S): .rodata vaddr == file offset; .text file
offset == vaddr - 0x1000.  The dump's format strings live in .rodata.
"""

import re
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"

DUMP_START = 0x60B50C0
DUMP_STOP = 0x60B79A6
HELPER = 0x5FCEDA0
HELPER_NOLEVEL = 0x5FCEEA0
ENUMFN = 0x5D8B3C0
ENUM_TABLE = 0x96D4F0
ENUM_TABLE_ENTRIES = 0x41

TEXT_VADDR = 0x1419300
TEXT_OFF = 0x1418300
TEXT_SIZE = 0x4FD7700

# Sites whose level is NOT set by `mov $imm,%edi` within the byte-scan
# window; resolved here by a targeted objdump window (see README).
#   0x605c6de: level from a variable byte (movzbl 0x0(%rbp),%edi).
#   0x61983ab, 0x6198572: `xor %edi,%edi` (level 0).
DYNAMIC_LEVEL_SITES = {0x605C6DE}
ZERO_LEVEL_SITES = {0x61983AB, 0x6198572}

INSN = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$")


def read_rodata_str(data, vaddr, limit=200):
    raw = data[vaddr:vaddr + limit]
    end = raw.find(b"\x00")
    return raw[:end if end >= 0 else limit].decode("latin1")


def objdump_range(start, stop):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={start:#x}",
         f"--stop-address={stop:#x}", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    ins = []
    for line in out.splitlines():
        m = INSN.match(line)
        if m:
            ins.append((int(m.group(1), 16), m.group(2).strip()))
    return ins


def parse_dump_fields(data):
    """Walk the dump once; one row per `call 5fceda0`."""
    ins = objdump_range(DUMP_START, DUMP_STOP)
    helper_idx = [i for i, (a, t) in enumerate(ins)
                  if t.startswith("call") and "5fceda0" in t]
    rows = []
    prev = 0
    for n, hi in enumerate(helper_idx):
        site = ins[hi][0]
        seg = ins[prev:hi]
        level = None
        fmt = None
        fmt_reg = None
        for _, u in seg:
            m = re.match(r"mov\s+\$0x([0-9a-f]+),%edi", u)
            if m:
                level = int(m.group(1), 16)
            m = re.match(r"lea\s+[^,]+,%rdx\s+#\s*([0-9a-f]+)", u)
            if m:
                fmt = read_rodata_str(data, int(m.group(1), 16))
                fmt_reg = "rdx"
        if fmt is None:
            for _, u in seg:
                for reg in ("r14", "r12"):
                    m = re.match(r"lea\s+[^,]+,%" + reg +
                                 r"\s+#\s*([0-9a-f]+)", u)
                    if m:
                        fmt = read_rodata_str(data, int(m.group(1), 16))
                        fmt_reg = reg
        if fmt is None:
            # Hoisted format: the loop at line 44 takes its format
            # from %r12, loaded once at 0x60b565e (before an earlier
            # call), and the loop body does `mov %r12,%rdx` at
            # 0x60b578f.  Scan backward for the most recent lea to
            # %r12 (then %r14) before this call site.
            for _, u in reversed(ins[:hi]):
                m = re.match(r"lea\s+[^,]+,%r12\s+#\s*([0-9a-f]+)", u)
                if m:
                    fmt = read_rodata_str(data, int(m.group(1), 16))
                    fmt_reg = "r12-hoisted"
                    break
                m = re.match(r"lea\s+[^,]+,%r14\s+#\s*([0-9a-f]+)", u)
                if m:
                    fmt = read_rodata_str(data, int(m.group(1), 16))
                    fmt_reg = "r14-hoisted"
                    break
        toks = []
        for _, u in seg:
            m = re.match(r"mov\s+(0x[0-9a-f]+)\(%rbx\),%([a-z0-9]+)", u)
            if m:
                toks.append(f"rbx{m.group(1)}->{m.group(2)}")
            m = re.match(r"(movzbl|movzbq|movsbl|movsbq)\s+"
                         r"(0x[0-9a-f]+)\(%rbx\),%([a-z0-9]+)", u)
            if m:
                toks.append(f"rbx{m.group(2)}[{m.group(1)}]->{m.group(3)}")
            m = re.match(r"movsd\s+(0x[0-9a-f]+)\(%rbx\),%xmm0", u)
            if m:
                toks.append(f"rbx{m.group(1)}[f64]->xmm0")
            m = re.match(r"cmpb\s+\$0x0,(0x[0-9a-f]+)\(%rbx\)", u)
            if m:
                toks.append(f"booltest:{m.group(1)}")
            if "call   *0x70(%rax)" in u:
                toks.append("NAMEGET:slot70")
            if "call   5d8b3c0" in u:
                toks.append("ENUMFN")
            if "call   *0x20(%rax)" in u:
                toks.append("SLOT20")
            if "call   *0x10(%rax)" in u:
                toks.append("SLOT10")
            m = re.match(r"lea\s+[^,]+,%rcx\s+#\s*([0-9a-f]+)", u)
            if m:
                toks.append("lit:" + read_rodata_str(
                    data, int(m.group(1), 16), 32))
            m = re.match(r"lea\s+[^,]+,%rax\s+#\s*([0-9a-f]+)", u)
            if m:
                toks.append("lit-rax:" + read_rodata_str(
                    data, int(m.group(1), 16), 32))
            if re.search(r"mov\s+\(%rdx,%r14,4\),%r8d", u):
                toks.append("vec-int-elem->r8d")
            if re.search(r"movzbl\s+\(%rax,%rcx,1\),%esi", u):
                toks.append("vec-u8-elem->esi")
        rows.append((n, site, level, fmt_reg, fmt, ";".join(toks)))
        prev = hi + 1
    return rows


def parse_enum_table(data):
    rows = []
    for i in range(ENUM_TABLE_ENTRIES):
        rel = struct.unpack_from("<i", data, ENUM_TABLE + i * 4)[0]
        target = ENUM_TABLE + rel
        rows.append((i, target))
    return rows


def byte_scan_callers(text):
    targets = {0x60B50C0: "dump", 0x5FCEDA0: "helper",
               0x5D8B3C0: "enumfn", 0x5FCEEA0: "helper-nolevel"}
    found = {k: [] for k in targets}
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel = struct.unpack_from("<i", text, i + 1)[0]
            ip = TEXT_VADDR + i
            for t in targets:
                if ip + 5 + rel == t:
                    found[t].append(ip)
    return found


def level_at_site(text, site):
    """Level for one helper call site, by backward `mov $imm,%edi` scan.

    Falls back to a targeted objdump window for the sites the byte
    scan cannot settle (documented above).
    """
    off = site - TEXT_VADDR
    for j in range(off - 5, max(0, off - 160), -1):
        if text[j] == 0xBF and j + 5 <= len(text):
            imm = struct.unpack_from("<I", text, j + 1)[0]
            if imm <= 10:
                return imm
    if site in ZERO_LEVEL_SITES:
        return 0
    if site in DYNAMIC_LEVEL_SITES:
        return -1  # dynamic: level from a variable byte
    # Last resort: targeted objdump window.
    ins = objdump_range(site - 0x140, site)
    for _, u in reversed(ins):
        m = re.match(r"mov\s+\$0x([0-9a-f]+),%edi", u)
        if m:
            return int(m.group(1), 16)
        if u == "xor    %edi,%edi":
            return 0
        if re.match(r"movzbl\s+.*,%edi", u):
            return -1
    return None


def parse_frames():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp",
         "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    fdes = []
    for line in out.splitlines():
        if "FDE" in line and "pc=" in line:
            pc = line.split("pc=")[1].strip()
            a, b = pc.split("..")
            fdes.append((int(a, 16), int(b, 16)))
    fdes.sort()
    want = [DUMP_START, HELPER, HELPER_NOLEVEL, ENUMFN, 0x5D954B0]
    rows = []
    for t in want:
        hit = [f for f in fdes if f[0] <= t < f[1]]
        assert len(hit) == 1, f"no unique FDE for {t:#x}: {hit}"
        rows.append(hit[0])
    return rows


def main():
    data = (ROOT / "work" / "hl-node-115.bin").read_bytes()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]

    fields = parse_dump_fields(data)
    with open(HERE / "fields.tsv", "w") as f:
        f.write("line\tsite\tlevel\tfmt_reg\tformat\ttokens\n")
        for n, site, level, reg, fmt, toks in fields:
            f.write(f"{n}\t{site:#x}\t{level}\t{reg}\t{fmt}\t{toks}\n")
    print(f"fields.tsv: {len(fields)} helper calls")

    enum_rows = parse_enum_table(data)
    names = {}
    # Arm names come from the enumfn excerpt's `lea literal,%rsi`.
    ins = objdump_range(ENUMFN, 0x5D8B4CB)
    arm_lit = {}
    for a, u in ins:
        m = re.search(r"lea\s+[^,]+,%rsi\s+#\s*([0-9a-f]+)", u)
        if m:
            arm_lit[a] = read_rodata_str(data, int(m.group(1), 16), 32)
    with open(HERE / "enum-table.tsv", "w") as f:
        f.write("index\ttarget\tname\n")
        for i, target in enum_rows:
            f.write(f"{i}\t{target:#x}\t{arm_lit.get(target, '')}\n")
    print(f"enum-table.tsv: {len(enum_rows)} entries, "
          f"{len(set(t for _, t in enum_rows))} distinct targets")

    callers = byte_scan_callers(text)
    with open(HERE / "callers.tsv", "w") as f:
        f.write("target\tsite\n")
        for t, sites in sorted(callers.items()):
            for s in sorted(sites):
                f.write(f"{t:#x}\t{s:#x}\n")
    for t, sites in sorted(callers.items()):
        print(f"callers of {t:#x}: {len(sites)}")

    levels = Counter()
    with open(HERE / "levels.tsv", "w") as f:
        f.write("site\tlevel\n")
        for s in sorted(callers[HELPER]):
            lv = level_at_site(text, s)
            assert lv is not None, f"no level for site {s:#x}"
            levels[lv] += 1
            f.write(f"{s:#x}\t{lv}\n")
    print("helper levels:", dict(sorted(levels.items())))

    frames = parse_frames()
    with open(HERE / "frames.txt", "w") as f:
        f.write("# FDE ranges for every function excerpted in this packet, "
                "from\n# readelf --debug-dump=frames-interp "
                "work/hl-node-115.bin\n")
        for a, b in frames:
            f.write(f"FDE pc={a:#x}..{b:#x}\n")
    print("frames.txt:", [f"{a:#x}..{b:#x}" for a, b in frames])
    return 0


if __name__ == "__main__":
    sys.exit(main())
