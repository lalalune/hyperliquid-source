"""Census for RE-001-stats-level-byte-115.

Whole-binary census of every byte access to offset +0x20 (the
StatisticsImpl stats_level_ byte) and of the callers of the three
timed-lock helpers, answering #3396's open unknown: which routine
writes the level byte at +0x20 besides the ctor, and which routines
read it as a gate.

Method (same family as the RE-001-registrar-map-115 packet):
  * FDE ranges from `readelf --debug-dump=frames-interp`.
  * One streaming `objdump -d` pass over the whole binary records:
      - every FDE that references a StatisticsImpl marker: a call,
        jump or lea to one of the 32 vtable slot targets, the ctor,
        the vtable address 0x64d2d88, or the "BasicStatistics"
        string at 0x432248;
      - every `movb $imm,0x20(%reg)` store and every
        `movzbl 0x20(%reg),%dst` load, with enclosing FDE;
      - every direct call to the timed helpers 0x606ca40,
        0x606ccb0, 0x606cf20, the TLS init 0x606dd10, the
        forwarder 0x5d48960 and the three thunks, with enclosing FDE.
  * `readelf -rW` records for the StatisticsImpl vtable RELATIVE
    region, the clock vtables and the perf-level GOT slot.

Writes stats-marked-fdes.tsv, level-writes.tsv, level-reads.tsv,
timer-callers.tsv, frames.txt and relocations.txt into this packet
directory.

Run from the repository root:
    python3 research/work-items/RE-001-stats-level-byte-115/census.py
"""

import bisect
import os
import re
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")
BIN_REL = "work/hl-node-115.bin"

# StatisticsImpl vtable slot targets (from #3396 vtables.tsv) + ctor.
SLOT_TARGETS = {
    0x6070EA0, 0x6071040, 0x609D760, 0x609DC40, 0x5D32560, 0x6095E70,
    0x6096790, 0x5D2E090, 0x60956F0, 0x609D0E0, 0x60986B0, 0x6095710,
    0x609DE80, 0x609D980, 0x606FA20, 0x5D32A30, 0x5D2E770, 0x606FA30,
    0x5D2CA10, 0x6070490, 0x6070610, 0x6070700, 0x606FBA0, 0x6070DC0,
    0x6070C50, 0x5D48960, 0x606FFD0, 0x606FEF0, 0x6070B30, 0x6070810,
    0x6076030, 0x606FA40, 0x6071A00,
}
MARKER_HEX = {("%x" % t) for t in SLOT_TARGETS} | {"64d2d88", "432248"}

TIMER_TARGETS = {
    0x606CA40: "mutex-lock",
    0x606CCB0: "condvar-wait",
    0x606CF20: "condvar-timedwait",
    0x606DD10: "tls-init",
    0x5D48960: "forwarder-slot-0xc8",
    0x606CA00: "thunk-lock",
    0x606CC70: "thunk-condwait",
    0x606CEE0: "thunk-time-math",
}

INSN_RE = re.compile(r"^\s*([0-9a-f]+):\t(?:[0-9a-f]{2} )+\s*\t(.*)$")
INSN_NORAW_RE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
CALL_RE = re.compile(r"\bcall\s+([0-9a-f]+)\s+<")
MOVB_RE = re.compile(r"movb\s+\$0x([0-9a-f]+),0x20\(%r([a-z0-9]+)\)")
MOVZBL_RE = re.compile(r"movzbl\s+0x20\(%r([a-z0-9]+)\),%([a-z0-9]+)")


def fde_map():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", BIN],
        capture_output=True, text=True, check=True).stdout
    fdes = []
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def is_marker_ref(text):
    for mk in MARKER_HEX:
        if mk in text:
            return True
    return False


def scan():
    fdes = fde_map()
    starts = [s for s, _ in fdes]

    def fde_of(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0:
            return None
        s, e = fdes[i]
        return (s, e) if addr < e else None

    marked = set()
    # An FDE is stats-marked if it IS a StatisticsImpl vtable slot
    # target / the ctor, or if it references one (call/jump/lea).
    for s, e in fdes:
        if s in SLOT_TARGETS:
            marked.add((s, e))
    writes = []   # (addr, fde, imm, reg)
    reads = []    # (addr, fde, reg, dst)
    calls = []    # (addr, fde, target, kind)
    proc = subprocess.Popen(["objdump", "-d", "--no-show-raw-insn", BIN_REL],
                            cwd=ROOT, stdout=subprocess.PIPE, text=True,
                            bufsize=1 << 20)
    for line in proc.stdout:
        m = INSN_NORAW_RE.match(line.rstrip("\n"))
        if not m:
            continue
        addr = int(m.group(1), 16)
        text = m.group(2)
        fde = fde_of(addr)
        if fde is None:
            continue
        if is_marker_ref(text):
            marked.add(fde)
        mb = MOVB_RE.search(text)
        if mb:
            writes.append((addr, fde, int(mb.group(1), 16), mb.group(2)))
        mz = MOVZBL_RE.search(text)
        if mz:
            reads.append((addr, fde, mz.group(1), mz.group(2)))
        cm = CALL_RE.search(text)
        if cm:
            tgt = int(cm.group(1), 16)
            if tgt in TIMER_TARGETS:
                calls.append((addr, fde, tgt, TIMER_TARGETS[tgt]))
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("objdump failed: %d" % proc.returncode)
    return fdes, marked, writes, reads, calls


def relocations():
    out = subprocess.run(["readelf", "-rW", BIN], capture_output=True,
                         text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        m = re.match(
            r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+(R_X86_64_\S+)\s+([0-9a-f]+)"
            r"(?:\s+(.*))?$", line)
        if not m:
            continue
        off = int(m.group(1), 16)
        add = m.group(3)
        sym = (m.group(4) or "").strip()
        keep = (
            0x64D2D78 <= off <= 0x64D2E90  # StatisticsImpl vtable + typeinfo
            or off in (0x64CE930, 0x64CED00, 0x64D2EB8, 0x64ED2B0,
                       0x64ED290, 0x64ED5D8)
            or add in {("%x" % t) for t in SLOT_TARGETS}
        )
        if keep:
            rows.append((off, m.group(2), add, sym))
    rows.sort()
    return rows


def main():
    fdes, marked, writes, reads, calls = scan()
    relocs = relocations()
    print("FDEs: %d" % len(fdes))
    print("stats-marked FDEs: %d" % len(marked))
    print("movb +0x20 stores: %d" % len(writes))
    print("movzbl +0x20 loads: %d" % len(reads))
    print("timer/forwarder calls: %d %s" % (
        len(calls), dict(Counter(c[3] for c in calls))))

    def w(name, header, rows):
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(header + "\n")
            for r in rows:
                fh.write("\t".join(str(v) for v in r) + "\n")

    w("stats-marked-fdes.tsv", "fde_start\tfde_end",
      [("%#x" % s, "%#x" % e) for s, e in sorted(marked)])
    # The level byte's writer/reader rows: every site in a
    # stats-marked FDE, plus every site in the StatisticsImpl code
    # region 0x606b000..0x6072000 (which also catches the three
    # timed-lock helpers -- they hold a Statistics* in a shared
    # holder and never name a StatisticsImpl symbol themselves).
    REGION = (0x606B000, 0x6072000)

    def scope_of(addr, fde):
        if fde in marked:
            return "marked"
        if REGION[0] <= addr < REGION[1]:
            return "region"
        return None

    w("level-writes.tsv", "site\tcontaining_fde\timm\tbase_reg\tscope",
      [("%#x" % a, "%#x..%#x" % f, "%#x" % i, r, scope_of(a, f))
       for a, f, i, r in sorted(writes)
       if r != "sp" and scope_of(a, f)])
    w("level-reads.tsv", "site\tcontaining_fde\tbase_reg\tdst_reg\tscope",
      [("%#x" % a, "%#x..%#x" % f, r, d, scope_of(a, f))
       for a, f, r, d in sorted(reads)
       if r != "sp" and scope_of(a, f)])
    w("timer-callers.tsv", "site\tcontaining_fde\ttarget\tkind",
      [("%#x" % a, "%#x..%#x" % f, "%#x" % t, k)
       for a, f, t, k in sorted(calls)])
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write("offset\ttype\taddend\tsymbol\n")
        for off, typ, add, sym in relocs:
            fh.write("%#x\t%s\t%s\t%s\n" % (off, typ, add, sym))

    # frames.txt: the packet windows.
    from export_excerpts import WINDOWS
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("window\tfde_start\tfde_end\n")
        fmap = {s: e for s, e in fdes}
        for name, start, stop in WINDOWS:
            s = int(start, 16)
            fh.write("%s\t%#x\t%#x\n" % (name, s, fmap[s]))
    print("wrote stats-marked-fdes.tsv (%d), level-writes.tsv, "
          "level-reads.tsv, timer-callers.tsv (%d), relocations.txt (%d)"
          % (len(marked), len(calls), len(relocs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
