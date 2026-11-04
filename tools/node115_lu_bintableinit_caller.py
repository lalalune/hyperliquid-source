#!/usr/bin/env python3
"""Static verifier for packet #275: the bin_table_init caller FDE.

Byte reads only; never executes the binary. Checks, in order:
 1. target binary size + SHA-256
 2. .eh_frame FDE bounds for 0x63cba10..0x63ccd22
 3. exhibit .hex bytes equal the binary slice (VA - 0x1000)
 4. strict mnemonic-line recount == 1015
 5. objdump-mnemonic call census: bin_table_init x10 (sole arg lea
    0x60(%rsp)), lu-miss handler x10 (rsi 0x6511a00, r8 1, r9 0),
    trylock x3, unlock x4, single ret, one __stack_chk_fail call
 6. 0x60(%rsp) uses == 10, all lea
 7. disjointness of the window against every prior claimed range
    (range-only collector; census/cited/survey metadata excluded)
 8. raw-e8 census: this FDE has 10 candidates for 0x63d9880 and no
    other caller FDE exceeds 8 (upper bound, so the site-count
    "largest" claim holds even with raw-scan overcount)
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
                           "RE-001-node115-lu-bintableinit-caller")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
REC = os.path.join(PACKET_DIR, "records.json")
HEX = os.path.join(PACKET_DIR, "bintableinit_caller.hex")
OBJ = os.path.join(PACKET_DIR, "bintableinit_caller.objdump.txt")

START, END = 0x63CBA10, 0x63CCD22
BIN_TABLE_INIT = 0x63D9880
LU_MISS = 0x63D9700
EXPECT_BYTES = END - START
EXPECT_STRICT = 1015

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
ok(fdes.get(START) == END, ".eh_frame FDE 0x63cba10..0x63ccd22, got %s" %
   (hex(fdes.get(START, 0)) if START in fdes else "missing"))
ok(fdes.get(BIN_TABLE_INIT) == 0x63D9A64, "bin_table_init FDE end 0x63d9a64")
ok(fdes.get(LU_MISS) == 0x63D987B, "lu-miss FDE end 0x63d987b")

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
# strict recount uses the raw lines (address + bytes + tab + lowercase mnemonic)
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
ok(targets["63d9880"] == 10, "bin_table_init calls == 10, got %d" % targets["63d9880"])
ok(targets["63d9700"] == 10, "lu-miss calls == 10, got %d" % targets["63d9700"])
ok(targets["63f17b0"] == 3, "trylock == 3, got %d" % targets["63f17b0"])
ok(targets["63f0b70"] == 4, "unlock == 4, got %d" % targets["63f0b70"])
ok(targets["63f0d70"] == 1, "stack_chk_fail == 1")
ok(sum(1 for _, mn, _ in ins if mn == "ret") == 1, "single ret")

# bin_table_init arg pattern: a lea 0x60(%rsp),%R followed by mov %R,%rdi
# within the 5 preceding instructions (spills may sit between the mov
# and the call, e.g. site 0x63cc3ef)
bti_sites = [a for _, a, op in calls if op.startswith("63d9880")]
for site in bti_sites:
    idx = next(i for i, (a, _, _) in enumerate(ins) if a == site)
    window = ins[max(0, idx - 5):idx]
    good = False
    for j, (wa, wmn, wop) in enumerate(window):
        m = re.match(r"0x60\(%rsp\),(%\w+)", wop)
        if wmn == "lea" and m:
            reg = m.group(1)
            if any(mn2 == "mov" and op2 == "%s,%%rdi" % reg
                   for _, mn2, op2 in window[j:]):
                good = True
    ok(good, "bin_table_init site %s arg pattern lea 0x60(%%rsp) -> rdi"
       % hex(site))
uses60 = [(a, mn) for a, mn, op in ins if "0x60(%rsp)" in op]
ok(len(uses60) == 10 and all(mn == "lea" for _, mn in uses60),
   "0x60(%%rsp) uses == 10 lea, got %d" % len(uses60))

# lu-miss arg pattern in the 8 preceding instructions
for site in [a for _, a, op in calls if op.startswith("63d9700")]:
    idx = next(i for i, (a, _, _) in enumerate(ins) if a == site)
    window = ins[max(0, idx - 8):idx]
    wtext = " ".join("%s %s" % (mn, op) for _, mn, op in window)
    ok("6511a00" in wtext and "mov $0x1,%r8d" in wtext
       and "xor %r9d,%r9d" in wtext and "mov %rbx,%rdi" in wtext,
       "lu-miss site %s arg pattern" % hex(site))

# --- records.json consistency ---
rec = json.load(open(REC))
ok(rec["exhibits"][0]["bytes"] == EXPECT_BYTES, "records bytes")
ok(rec["exhibits"][0]["strict"] == EXPECT_STRICT, "records strict")
ok(rec["fde"]["start"] == "0x63cba10" and rec["fde"]["end"] == "0x63ccd22",
   "records fde range")
ok(len(rec["call_census"]["bin_table_init"]["sites"]) == 10, "records bti sites")
ok(len(rec["call_census"]["lu_miss_handler"]["sites"]) == 10, "records miss sites")
ok(rec["call_census"]["bin_table_init"]["sites"] ==
   [hex(s) for s in bti_sites], "records bti sites match objdump")

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


roots = os.environ.get("HL275_PRIOR_ROOTS")
if roots:
    dirs = [os.path.join(r, "records.json") for r in roots.split(",")]
else:
    dirs = glob(os.path.join(ROOT, "research", "work-items", "*",
                             "records.json"))
    dirs += glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*"
                 "/records.json")
priors = []
for d in dirs:
    if "bintableinit-caller" in d:
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
                     ("packet #261 0x634ebb0", 0x634EBB0, 0x634ECCD)]:
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
ok(census.get(START) == 10, "census: this FDE has 10 candidates")
others = max([n for pc, n in census.items() if pc != START] or [0])
ok(others <= 8, "census: no other caller exceeds 8, max %d" % others)

print("PASS: %d FAIL: %d" % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
