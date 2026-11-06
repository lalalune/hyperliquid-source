#!/usr/bin/env python3
"""Static verifier for packet #276: the second bin_table_init caller FDE.

Byte reads only; never executes the binary. Checks, in order:
 1. target binary size + SHA-256
 2. .eh_frame FDE bounds for 0x63c9c80..0x63cb146, padding 10 to the
    next FDE 0x63cb150, gap 0 from the previous FDE 0x63c9650..0x63c9c80
 3. exhibit .hex bytes equal the binary slice (VA - 0x1000)
 4. strict mnemonic-line recount == 1179
 5. objdump-mnemonic call census: bin_table_init x8 (sole arg rdi = r12),
    lu-miss handler x8 (rdi rbp, rsi 0x6511a00, r8 1, r9 0),
    0x63637f0 / 0x63bd6c0 / 0x6363260 / 0x63d3080 x1 each (call),
    one __stack_chk_fail call; total 21 calls
 6. no ret in the FDE; 3 canary checks all jumping to the shared
    0x63cb0e5 __stack_chk_fail block; 3 tail-jump epilogues
 7. r12 provenance: lea 0x20(%rsp),%r12 at entry paths
 8. disjointness of the window against every prior claimed range
    (range-only collector; census/cited/survey metadata excluded)
 9. raw-e8 census for target 0x63d9880: this FDE 8, #275 FDE 10,
    no other FDE above 6 (so second place by sites is strict)
"""
import hashlib
import json
import os
import re
import struct
import sys
from glob import glob

PASS = 0
FAIL = 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def fail(msg):
    ok(False, msg)


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(ROOT, "research", "work-items",
                          "RE-001-node115-lu-bintableinit-caller-8sites")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
REC = os.path.join(PACKET_DIR, "records.json")
HEX = os.path.join(PACKET_DIR, "bintableinit_caller_8sites.hex")
OBJ = os.path.join(PACKET_DIR, "bintableinit_caller_8sites.objdump.txt")

START, END = 0x63C9C80, 0x63CB146
BIN_TABLE_INIT = 0x63D9880
LU_MISS = 0x63D9700
EXPECT_BYTES = END - START
EXPECT_STRICT = 1179

data = open(BIN, "rb").read()
ok(len(data) == 105896032, "binary size 105896032, got %d" % len(data))
ok(hashlib.sha256(data).hexdigest() ==
   "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
   "binary SHA-256")

# --- .eh_frame FDE bounds (PC-relative sdata4, fixed 4-byte range) ---
EH_OFF = 0xCA6ED8
EH_VMA = 0xCA6ED8
eh = data[EH_OFF:EH_OFF + 0x1100000]
off = 0
fdes = {}
while off < len(eh) - 8:
    ln = struct.unpack_from("<I", eh, off)[0]
    if ln in (0, 0xFFFFFFFF):
        break
    cie_id = struct.unpack_from("<I", eh, off + 4)[0]
    if cie_id != 0:
        init = struct.unpack_from("<i", eh, off + 8)[0]
        rng = struct.unpack_from("<I", eh, off + 12)[0]
        pc = EH_VMA + off + 8 + init
        fdes[pc] = pc + rng
    off += 4 + ln
ok(fdes.get(START) == END, ".eh_frame FDE 0x63c9c80..0x63cb146, got %s" %
   (hex(fdes.get(START, 0)) if START in fdes else "missing"))
ok(fdes.get(BIN_TABLE_INIT) == 0x63D9A64, "bin_table_init FDE end 0x63d9a64")
ok(fdes.get(LU_MISS) == 0x63D987B, "lu-miss FDE end 0x63d987b")
starts = sorted(fdes)
import bisect
nxt = starts[bisect.bisect_right(starts, END - 1)]
ok(nxt == 0x63CB150, "next FDE 0x63cb150, got %s" % hex(nxt))
ok(nxt - END == 10, "padding to next FDE == 10")
prev_end = max(e for e in fdes.values() if e <= START)
ok(prev_end == START, "previous FDE ends at START (gap 0), got %s" % hex(prev_end))

# --- exhibit bytes ---
raw = open(HEX, "rb").read()
ok(len(raw) == EXPECT_BYTES, "hex size %d, got %d" % (EXPECT_BYTES, len(raw)))
ok(raw == data[START - 0x1000:START - 0x1000 + EXPECT_BYTES],
   "hex bytes equal binary slice")

# --- objdump parse ---
lines = open(OBJ).read().splitlines()
ins = []
for line in lines:
    m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S+)(?:\s+(.*))?", line)
    if m:
        ins.append((int(m.group(1), 16), m.group(3), (m.group(4) or "").strip()))
strict = 0
for line in lines:
    if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", line):
        strict += 1
ok(strict == EXPECT_STRICT, "strict recount %d, got %d" % (EXPECT_STRICT, strict))
ok(all(START <= a < END for a, _, _ in ins), "all instructions inside FDE")

calls = [(i, a, op) for i, (a, mn, op) in enumerate(ins) if mn == "call"]
from collections import Counter
targets = Counter()
for _, _, op in calls:
    m = re.match(r"([0-9a-f]+)", op)
    targets[m.group(1) if m else op] += 1
ok(len(calls) == 21, "total calls == 21, got %d" % len(calls))
ok(targets["63d9880"] == 8, "bin_table_init calls == 8, got %d" % targets["63d9880"])
ok(targets["63d9700"] == 8, "lu-miss calls == 8, got %d" % targets["63d9700"])
ok(targets["63637f0"] == 1, "63637f0 call == 1")
ok(targets["63d3080"] == 1, "63d3080 call == 1")
ok(targets["63bd6c0"] == 1, "63bd6c0 call == 1")
ok(targets["6363260"] == 1, "6363260 call == 1")
ok(targets["63f0d70"] == 1, "stack_chk_fail == 1")
ok(sum(1 for _, mn, _ in ins if mn == "ret") == 0, "no ret in FDE")

# bin_table_init arg pattern: mov %r12,%rdi within 5 preceding instructions
bti_sites = [a for _, a, op in calls if op.startswith("63d9880")]
for site in bti_sites:
    idx = next(i for i, (a, _, _) in enumerate(ins) if a == site)
    window = ins[max(0, idx - 5):idx]
    good = any(mn == "mov" and op == "%r12,%rdi" for _, mn, op in window)
    ok(good, "bin_table_init site %s arg rdi = r12" % hex(site))

# lu-miss arg pattern within 12 preceding instructions
for site in [a for _, a, op in calls if op.startswith("63d9700")]:
    idx = next(i for i, (a, _, _) in enumerate(ins) if a == site)
    window = ins[max(0, idx - 12):idx]
    wtext = " ".join("%s %s" % (mn, op) for _, mn, op in window)
    ok("6511a00" in wtext and "mov $0x1,%r8d" in wtext
       and "xor %r9d,%r9d" in wtext and "mov %rbp,%rdi" in wtext,
       "lu-miss site %s arg pattern" % hex(site))

# canary checks + shared fail block + tail jumps
canary = [(i, a) for i, (a, mn, op) in enumerate(ins)
          if mn == "sub" and op == "%fs:0x28,%rax"]
ok(len(canary) == 3, "canary checks == 3, got %d" % len(canary))
for i, a in canary:
    nxt_ins = ins[i + 1]
    ok(nxt_ins[1] == "jne" and nxt_ins[2].startswith("63cb0e5"),
       "canary check %s jumps to 63cb0e5" % hex(a))
jmps = [(a, op) for a, mn, op in ins if mn == "jmp"]
for tgt in ("63637f0", "63bd6c0", "6363260"):
    ok(sum(1 for _, op in jmps if op.startswith(tgt)) == 1,
       "tail jmp to %s == 1" % tgt)
lea_r12 = [a for a, mn, op in ins
           if mn == "lea" and op == "0x20(%rsp),%r12"]
ok(len(lea_r12) == 2, "lea 0x20(%%rsp),%%r12 == 2, got %d" % len(lea_r12))
# lock-prefixed lines carry mnemonic 'lock' with the real op in operands;
# count raw lines containing 'lock sub' on +0x38 instead
lock_lines = [l for l in lines if "lock sub" in l and "0x38(" in l]
ok(len(lock_lines) == 2, "lock sub on +0x38 == 2, got %d" % len(lock_lines))
text = "\n".join(lines)


def has_ins(mn, prefix):
    return any(m == mn and op.startswith(prefix) for _, m, op in ins)


ok(has_ins("shr", "$0x1a,") and has_ins("and", "$0xf0,"),
   "top index (key>>0x1a)&0xf0")
ok(has_ins("shr", "$0x9,") and has_ins("and", "$0x1ffff8,"),
   "second level (key>>9)&0x1ffff8")
ok("65096c0" in text, "leaf table 0x65096c0 referenced")
ok("6727a00" in text, "second table 0x6727a00 referenced")
ok(has_ins("shr", "$0x30,") and has_ins("cmp", "$0x23,"),
   "leaf>>0x30 vs 0x23 gate")
ok("67144a0" in text, "global pointer 0x67144a0 referenced")

# --- records.json consistency ---
rec = json.load(open(REC))
ok(rec["exhibits"][0]["bytes"] == EXPECT_BYTES, "records bytes")
ok(rec["exhibits"][0]["strict"] == EXPECT_STRICT, "records strict")
ok(rec["fde"]["start"] == "0x63c9c80" and rec["fde"]["end"] == "0x63cb146",
   "records fde range")
ok(len(rec["call_census"]["bin_table_init"]["sites"]) == 8, "records bti sites")
ok(len(rec["call_census"]["lu_miss_handler"]["sites"]) == 8, "records miss sites")
ok(rec["call_census"]["bin_table_init"]["sites"] ==
   [hex(s) for s in bti_sites], "records bti sites match objdump")
ok(rec["call_census"]["lu_miss_handler"]["sites"] ==
   [hex(s) for s in [a for _, a, op in calls if op.startswith("63d9700")]],
   "records miss sites match objdump")

# --- disjointness ---
SKIP_SUB = ("cited", "census", "survey")
SKIP_EXACT = ("callers", "largest_caller_fde", "fde")


def hx(v):
    return v if isinstance(v, int) else int(v, 16)


def collect(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_EXACT or any(s in k for s in SKIP_SUB):
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else (
                    v.values() if isinstance(v, dict) else [])
                for e in items:
                    if isinstance(e, dict):
                        if "range" in e:
                            r = e["range"]
                            out.append((hx(r[0]), hx(r[1])) if isinstance(r, list)
                                       else tuple(int(x, 16) for x in r.split("..")))
                        elif "start" in e and "end" in e:
                            out.append((hx(e["start"]), hx(e["end"])))
            else:
                collect(v, out)
    elif isinstance(obj, list):
        for v in obj:
            collect(v, out)


roots = os.environ.get("HL276_PRIOR_ROOTS")
if roots:
    dirs = [os.path.join(r, "records.json") for r in roots.split(",")]
else:
    dirs = glob(os.path.join(ROOT, "research", "work-items", "*",
                             "records.json"))
    dirs += glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*"
                 "/records.json")
priors = []
for d in dirs:
    if "bintableinit-caller-8sites" in d:
        continue
    try:
        collect(json.load(open(d)), priors)
    except Exception:
        pass
bad = [(p) for p in priors if START < p[1] and p[0] < END]
ok(not bad, "window disjoint from %d prior ranges, overlaps %s" %
   (len(priors), bad[:3]))
for name, lo, hi in [("packet #232 merged FDE", 0x63B8820, 0x63B8D85),
                     ("packet #252 r28_wait", 0x63EC890, 0x63EC8A3),
                     ("packet #215 handler", 0x63D9700, 0x63D987B),
                     ("packet #261 tcache", 0x63721C0, 0x6372246),
                     ("packet #261 opt_prof", 0x63737C0, 0x6373846),
                     ("packet #262 bin_table_init", 0x63D9880, 0x63D9A64),
                     ("packet #269 xmalloc", 0x6378090, 0x637809A),
                     ("packet #261 0x634ebb0", 0x634EBB0, 0x634ECCD),
                     ("packet #275 caller FDE", 0x63CBA10, 0x63CCD22)]:
    ok(START >= hi or lo >= END, "window disjoint from %s" % name)

# --- raw-e8 census for bin_table_init target ---
census = {}
for pc, end in fdes.items():
    n = 0
    base = pc - 0x1000
    seg = data[base:base + (end - pc)]
    for i in range(len(seg) - 5):
        if seg[i] == 0xE8:
            rel = struct.unpack_from("<i", seg, i + 1)[0]
            if pc + i + 5 + rel == BIN_TABLE_INIT:
                n += 1
    if n:
        census[pc] = n
ok(census.get(START) == 8, "raw census this FDE == 8, got %s" %
   census.get(START))
ok(census.get(0x63CBA10) == 10, "raw census #275 FDE == 10")
others = [n for pc, n in census.items() if pc not in (START, 0x63CBA10)]
ok(not others or max(others) <= 6,
   "no other FDE above 6 raw candidates, max %s" % (max(others) if others else 0))

print("PASS: %d FAIL: %d" % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
