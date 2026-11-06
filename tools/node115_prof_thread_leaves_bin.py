#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-prof-thread-leaves-bin (packet #262).

Byte reads only; never executes the node binary. Checks:
  1. binary identity (size + SHA-256)
  2. exhibit bytes against binary slices (.text: VA - 0x1000)
  3. strict counts (address + bytes field + tab + mnemonic starting
     with a lowercase letter; objdump byte-continuation lines excluded)
  4. objdump regeneration with the path-embedding header lines stripped
  5. .rela.dyn slots for the 5 leaves (node+0x20 holds exactly one
     RELATIVE addend equal to the handler address)
  6. named E8/E9 sites by exact byte arithmetic
  7. raw-scan census totals (all sites objdump-confirmed at build time;
     leaf zero-counts are airtight: a real E8/E9 opcode byte is always
     present in the byte stream)
  8. disjointness against packets #183-#261 (range-only collector:
     exhibited windows only, all prior record shapes, census/cited-only
     subtrees and enclosing-fde annotations excluded)
  9. MANIFEST hashes
 10. leaf arithmetic: 33 + 5 + 166 = 204

Usage: python3 tools/node115_prof_thread_leaves_bin.py [worktree-root]
Exit 0 on PASS, 1 on any failure. Failure propagation is explicit: every
check appends to the failures list; the exit code reflects its length.
"""

import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

BINARY_REL = os.path.join("artifacts", "node", "115", "hl-node")
BINARY_SIZE = 105896032
BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET_REL = os.path.join("research", "work-items",
                          "RE-001-node115-lu-prof-thread-leaves-bin")
OWN_SLUG = "RE-001-node115-lu-prof-thread-leaves-bin"
STRICT = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")

LEAVES = [
    ("opt/prof_prefix", 0x64dea88, 0x6373850),
    ("opt/prof_active", 0x64deab0, 0x6373a60),
    ("opt/lg_prof_sample", 0x64deb00, 0x6373b80),
    ("thread/allocatedp", 0x64def50, 0x6374c00),
    ("thread/deallocated", 0x64def78, 0x6374e10),
]

# (site, opcode, target) — opcode 0xe8 = call, 0xe9 = jmp
NAMED_SITES = [
    (0x63ed478, 0xe8, 0x63d9880), (0x63ed4e7, 0xe8, 0x63d9880),
    (0x63ec975, 0xe8, 0x63ec7a0), (0x63ed59c, 0xe8, 0x63ec7a0),
    (0x63ed629, 0xe8, 0x63ec7a0), (0x63edcbf, 0xe8, 0x63ec7a0),
    (0x63c41ed, 0xe8, 0x63bf840), (0x63c4225, 0xe8, 0x63bf840),
    (0x63c4243, 0xe8, 0x63bf840), (0x63c4261, 0xe8, 0x63bf840),
    (0x63c427f, 0xe8, 0x63bf840), (0x63c42a1, 0xe8, 0x63bf840),
    (0x63c42c3, 0xe8, 0x63bf840), (0x63c42e5, 0xe8, 0x63bf840),
    (0x63c4307, 0xe8, 0x63bf840), (0x63c441b, 0xe8, 0x63bf840),
    (0x63c4478, 0xe8, 0x63bf840),
    (0x63b6ed9, 0xe9, 0x63bf840), (0x63d96f9, 0xe9, 0x63bf840),
]

# Raw-scan census totals: (target, e8_count, e9_count)
CENSUS_TOTALS = [
    (0x6373850, 0, 0), (0x6373a60, 0, 0), (0x6373b80, 0, 0),
    (0x6374c00, 0, 0), (0x6374e10, 0, 0),
    (0x63d9880, 108, 0), (0x63ec7a0, 4, 0), (0x63bf840, 35, 2),
]


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    pkt = os.path.join(root, PACKET_REL)
    binary = os.path.join(root, BINARY_REL)
    passes = []
    failures = []

    def ok(msg):
        passes.append(msg)
        print("PASS " + msg)

    def fail(msg):
        failures.append(msg)
        print("FAIL " + msg)

    data = open(binary, "rb").read()

    # 1. binary identity
    if len(data) == BINARY_SIZE:
        ok("binary size %d" % BINARY_SIZE)
    else:
        fail("binary size %d != %d" % (len(data), BINARY_SIZE))
    if hashlib.sha256(data).hexdigest() == BINARY_SHA256:
        ok("binary sha256")
    else:
        fail("binary sha256 mismatch")

    rec = json.load(open(os.path.join(pkt, "records.json")))
    exhibits = rec["exhibits"]

    def toff(va):
        return va - 0x1000

    # 2. exhibit bytes
    for ex in exhibits:
        s, e = int(ex["range"][0], 16), int(ex["range"][1], 16)
        raw = open(os.path.join(pkt, ex["name"] + ".hex"), "rb").read()
        if raw == data[toff(s):toff(s) + (e - s)] and len(raw) == e - s:
            ok("exhibit bytes %s" % ex["name"])
        else:
            fail("exhibit bytes %s" % ex["name"])

    # 3+4. strict counts + objdump regeneration (header lines stripped)
    for ex in exhibits:
        s, e = int(ex["range"][0], 16), int(ex["range"][1], 16)
        stored = open(os.path.join(pkt, ex["name"] + ".objdump.txt")).read()
        strict = sum(1 for l in stored.splitlines() if STRICT.match(l))
        if strict == ex["strict"]:
            ok("strict count %s = %d" % (ex["name"], strict))
        else:
            fail("strict count %s: got %d want %d"
                 % (ex["name"], strict, ex["strict"]))
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % s,
             "--stop-address=%#x" % e, binary],
            capture_output=True, text=True, check=True).stdout
        regen = "\n".join(out.splitlines()[2:]) + "\n"
        if regen == stored:
            ok("objdump regen %s" % ex["name"])
        else:
            fail("objdump regen %s" % ex["name"])

    # 5. .rela.dyn slots (section headers parsed, not hardcoded)
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size = struct.unpack_from(
            "<IIQQQQ", data, off)
        sections.append((name, typ, flags, addr, offset, size))
    shstr = sections[e_shstrndx]
    strtab = data[shstr[4]:shstr[4] + shstr[5]]

    def sec_name(n):
        end = strtab.index(b"\x00", n)
        return strtab[n:end].decode()

    rela = None
    for s in sections:
        if sec_name(s[0]) == ".rela.dyn":
            rela = s
            break
    if rela is None:
        fail("no .rela.dyn section")
        rela_entries = []
    else:
        rela_entries = []
        off, end = rela[4], rela[4] + rela[5]
        while off < end:
            r_off, r_info, r_add = struct.unpack_from("<QQq", data, off)
            rela_entries.append((r_off, r_info & 0xFFFFFFFF, r_add))
            off += 24
    for name, node, handler in LEAVES:
        slot = node + 0x20
        hits = [(t, a) for (o, t, a) in rela_entries if o == slot]
        if len(hits) == 1 and hits[0][0] == 8 and hits[0][1] == handler:
            ok("rela slot %s -> %s" % (hex(slot), hex(handler)))
        else:
            fail("rela slot %s: %s" % (hex(slot), hits))

    # 6. named sites by exact byte arithmetic
    for site, op, tgt in NAMED_SITES:
        b = data[toff(site):toff(site) + 5]
        if len(b) == 5 and b[0] == op and \
                site + 5 + struct.unpack("<i", b[1:5])[0] == tgt:
            ok("site %#x -> %#x" % (site, tgt))
        else:
            fail("site %#x does not target %#x" % (site, tgt))

    # 7. raw-scan census totals (.text bounds from section headers)
    text_sec = None
    for s in sections:
        if sec_name(s[0]) == ".text":
            text_sec = s
            break
    if text_sec is None:
        fail("no .text section")
        text = b""
        TEXT_VA = 0
    else:
        text = data[text_sec[4]:text_sec[4] + text_sec[5]]
        TEXT_VA = text_sec[3]
    for tgt, want_e8, want_e9 in CENSUS_TOTALS:
        counts = {0xe8: 0, 0xe9: 0}
        for op in (0xe8, 0xe9):
            i = text.find(bytes([op]))
            while i != -1:
                if i + 5 <= len(text):
                    rel = struct.unpack("<i", text[i + 1:i + 5])[0]
                    if TEXT_VA + i + 5 + rel == tgt:
                        counts[op] += 1
                i = text.find(bytes([op]), i + 1)
        if counts[0xe8] == want_e8 and counts[0xe9] == want_e9:
            ok("census %#x: %d E8 + %d E9" % (tgt, want_e8, want_e9))
        else:
            fail("census %#x: got %d E8 + %d E9, want %d + %d"
                 % (tgt, counts[0xe8], counts[0xe9], want_e8, want_e9))

    # 8. disjointness (range-only collector)
    def toint(v):
        return v if isinstance(v, int) else int(v, 16)

    def parse_range(v):
        if isinstance(v, list) and len(v) == 2:
            return (toint(v[0]), toint(v[1]))
        if isinstance(v, str) and ".." in v:
            a, b = v.split("..")
            return (int(a, 16), int(b, 16))
        raise ValueError("bad range %r" % (v,))

    def collect(obj, out, in_exhibits=False):
        # Range-only: gather ONLY exhibited windows. Census/cited-only
        # subtrees and enclosing-fde annotations are never collected.
        if isinstance(obj, dict):
            if in_exhibits:
                if "start" in obj and "end" in obj:
                    try:
                        out.append((toint(obj["start"]), toint(obj["end"])))
                    except (ValueError, TypeError):
                        pass
                if "range" in obj:
                    try:
                        out.append(parse_range(obj["range"]))
                    except ValueError:
                        pass
            for k, v in obj.items():
                if k in ("census", "cited_only_not_claimed", "fde"):
                    continue
                collect(v, out, in_exhibits or k in ("exhibits", "windows"))
        elif isinstance(obj, list):
            for item in obj:
                collect(item, out, in_exhibits)

    scan_dirs = [os.path.join(root, "research/work-items")]
    scan_dirs += glob.glob(os.path.expanduser(
        "~/workspace/hl-wt-calls*-115/research/work-items"))
    prior = set()
    for d in scan_dirs:
        for rf in glob.glob(os.path.join(d, "*/records.json")):
            slug = os.path.basename(os.path.dirname(rf))
            if slug == OWN_SLUG:
                continue
            try:
                obj = json.load(open(rf))
            except (ValueError, OSError):
                continue
            rs = []
            if isinstance(obj, list):
                # Top-level-list-shaped records: each top item that
                # directly carries a range is an exhibit; others are
                # scanned only for exhibits/windows keys.
                for item in obj:
                    if isinstance(item, dict) and (
                            "range" in item or
                            ("start" in item and "end" in item)):
                        collect(item, rs, in_exhibits=True)
                    else:
                        collect(item, rs, in_exhibits=False)
            else:
                collect(obj, rs, in_exhibits=False)
            for s, e in rs:
                prior.add((slug, s, e))
    mine = [parse_range(ex["range"]) for ex in exhibits]
    overlap = [(s, e) for (s, e) in mine
               if any(ps <= s < pe or ps < e <= pe or (s <= ps and pe <= e)
                      for (_, ps, pe) in prior)]
    if overlap:
        fail("overlap with prior packets: %s" % overlap)
    else:
        ok("disjoint from %d unique prior ranges" % len(prior))

    # 9. MANIFEST
    man = {}
    for line in open(os.path.join(pkt, "MANIFEST.sha256")):
        parts = line.split()
        if len(parts) == 2:
            man[parts[1]] = parts[0]
    expect = set()
    for ex in exhibits:
        expect.add(ex["name"] + ".hex")
        expect.add(ex["name"] + ".objdump.txt")
    expect.update(["README.md", "EVIDENCE.md", "records.json",
                   "../../../tools/node115_prof_thread_leaves_bin.py",
                   "../../../tests/test_node115_prof_thread_leaves_bin.py"])
    man_ok = True
    for p in sorted(expect):
        if p.startswith("../../../"):
            fs = os.path.join(root, p.replace("../../../", ""))
        else:
            fs = os.path.join(pkt, p)
        digest = hashlib.sha256(open(fs, "rb").read()).hexdigest()
        if man.get(p) != digest:
            fail("MANIFEST mismatch %s" % p)
            man_ok = False
    if man_ok:
        ok("MANIFEST hashes (%d entries)" % len(expect))
    if set(man) != expect:
        fail("MANIFEST entry set mismatch: extra %s missing %s"
             % (sorted(set(man) - expect), sorted(expect - set(man))))
    else:
        ok("MANIFEST entry set")

    # 10. leaf arithmetic
    tot = rec["exhibit_totals"]
    if tot["bytes"] == 3240 and tot["strict"] == 801 and tot["windows"] == 9:
        ok("exhibit totals 3240 bytes / 801 strict / 9 windows")
    else:
        fail("exhibit totals %s" % tot)
    if rec["census"]["leaf_arithmetic"] == "33 + 5 + 166 = 204":
        ok("leaf arithmetic 33 + 5 + 166 = 204")
    else:
        fail("leaf arithmetic %s" % rec["census"]["leaf_arithmetic"])

    print("RESULT: %s (%d PASS, %d FAIL)"
          % ("PASS" if not failures else "FAIL", len(passes), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
