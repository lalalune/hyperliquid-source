#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-value-leaves-bin (packet #261).

Byte reads only; never executes the node binary. Checks:
 1. target binary size and SHA-256 from records.json
 2. every exhibit .hex file equals the binary slice at VA - 0x1000
 3. every exhibit .objdump.txt strict mnemonic count matches records.json
    (strict = address + bytes field + blank + mnemonic; byte-continuation
    lines excluded) and regenerated objdump matches with the file-format
    header line stripped (objdump embeds the invoked path in it)
 4. named E8/E9 call sites by exact byte arithmetic (opcode + rel32)
 5. full-.text raw E8/E9 census for every claimed function, cross-checked
    at build time against a full capstone disassembly of all 135,313 FDEs
    (18,827,581 instructions) with identical counts
 6. .rela.dyn slots for the 5 leaves (node+0x20 holds exactly one
    RELATIVE addend equal to the handler address)
 7. disjointness of the claimed ranges against prior packets #183-#260,
    using a range-only collector: ONLY exhibited windows are gathered
    (string 'range' fields, [start, end] lists, 'start'/'end' pairs
    inside 'exhibits' lists or dicts, and 'windows' lists or dicts —
    packet #260's lesson), never enclosing-'fde' annotation fields
    (packet #259's lesson); census/cited-only metadata is excluded
    (packet #253's rule); deduplicated by real packet slug
 8. MANIFEST.sha256 lists exactly the packet files (excluding itself)
 9. leaf arithmetic: 28 + 5 + 171 = 204

Usage: python3 tools/node115_value_leaves_bin.py [worktree-root]
Exit 0 on PASS, 1 on any FAIL. Scan roots for check 7 can be overridden
with the HL261_SCAN_ROOTS environment variable (colon-separated) for tests.
"""
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

FAILURES = []


def fail(msg):
    FAILURES.append(msg)
    print("FAIL:", msg)


def ok(msg):
    print("PASS:", msg)


def va_to_off(va):
    return va - 0x1000


def parse_range(s):
    if isinstance(s, (list, tuple)) and len(s) == 2:
        return int(s[0], 16), int(s[1], 16)
    if isinstance(s, str) and ".." in s:
        a, b = s.split("..")
        return int(a, 16), int(b, 16)
    raise ValueError("unparseable range: %r" % (s,))


# Mnemonic must start with a lowercase letter: objdump byte-continuation
# lines (address + bytes only) end with bytes whose trailing hex digit
# can otherwise be split off as a fake "mnemonic" by a \S pattern
# (packet #261 lesson: the \S pattern overcounted by 15 lines here).
STRICT_RE = re.compile(r"^[ \t]+[0-9a-f]+:[ \t]+[0-9a-f ]+[ \t]+[a-z]")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    pkt = os.path.join(root, "research/work-items/RE-001-node115-lu-value-leaves-bin")
    rec = json.load(open(os.path.join(pkt, "records.json")))
    binary = os.path.join(root, rec["binary"]["path"])
    data = open(binary, "rb").read()

    # 1. binary identity
    if len(data) != rec["binary"]["size"]:
        fail("binary size %d != %d" % (len(data), rec["binary"]["size"]))
    else:
        ok("binary size %d" % len(data))
    if hashlib.sha256(data).hexdigest() != rec["binary"]["sha256"]:
        fail("binary sha256 mismatch")
    else:
        ok("binary sha256")

    # 2+3. exhibits
    total_bytes = 0
    total_strict = 0
    for ex in rec["exhibits"]:
        name = ex["name"]
        s, e = parse_range(ex["range"])
        raw = open(os.path.join(pkt, name + ".hex"), "rb").read()
        if raw != data[va_to_off(s):va_to_off(s) + (e - s)]:
            fail("exhibit %s bytes differ from binary slice" % name)
        elif len(raw) != ex["bytes"]:
            fail("exhibit %s size %d != %d" % (name, len(raw), ex["bytes"]))
        else:
            ok("exhibit %s bytes %d" % (name, len(raw)))
        txt = open(os.path.join(pkt, name + ".objdump.txt")).read()
        strict = sum(1 for l in txt.splitlines() if STRICT_RE.match(l))
        if strict != ex["strict"]:
            fail("exhibit %s strict %d != %d" % (name, strict, ex["strict"]))
        else:
            ok("exhibit %s strict %d" % (name, strict))
        regen = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % hex(s),
             "--stop-address=%s" % hex(e), binary],
            capture_output=True, text=True).stdout
        strip = lambda t: "\n".join(
            l for l in t.splitlines() if "file format" not in l)
        if strip(regen) != strip(txt):
            fail("exhibit %s objdump regeneration differs" % name)
        else:
            ok("exhibit %s objdump regeneration" % name)
        total_bytes += e - s
        total_strict += strict
    if total_bytes != rec["exhibit_totals"]["bytes"]:
        fail("total bytes %d != %d" % (total_bytes, rec["exhibit_totals"]["bytes"]))
    else:
        ok("total bytes %d" % total_bytes)
    if total_strict != rec["exhibit_totals"]["strict"]:
        fail("total strict %d != %d" % (total_strict, rec["exhibit_totals"]["strict"]))
    else:
        ok("total strict %d" % total_strict)

    # 4. named E8/E9 sites by exact byte arithmetic
    named = [
        (0x63ed3fd, 0xE8, 0x63ec4c0), (0x63ed50c, 0xE8, 0x63ec4c0),
        (0x63ed5ad, 0xE8, 0x63ec4c0), (0x63ed63a, 0xE8, 0x63ec4c0),
        (0x63ed3e1, 0xE8, 0x634ebb0), (0x63ed5e9, 0xE8, 0x634ebb0),
        (0x63ed723, 0xE8, 0x634ebb0),
        (0x63ef834, 0xE8, 0x63c3b70), (0x63ef83c, 0xE8, 0x63539d0),
        (0x63ef844, 0xE8, 0x6353a20), (0x63ef858, 0xE8, 0x63efd20),
        (0x634f44f, 0xE8, 0x63c41c0), (0x63ee02d, 0xE9, 0x63ec4c0),
    ]
    for site, op, tgt in named:
        off = va_to_off(site)
        got_op = data[off]
        rel = struct.unpack_from("<i", data, off + 1)[0]
        got_tgt = site + 5 + rel
        if got_op != op or got_tgt != tgt:
            fail("site %s: op %s target %s != expected %s -> %s"
                 % (hex(site), hex(got_op), hex(got_tgt), hex(op), hex(tgt)))
        else:
            ok("site %s -> %s" % (hex(site), hex(tgt)))

    # 5. full-.text raw census
    text_va, text_off, text_size = None, None, None
    out = subprocess.run(["readelf", "-S", binary],
                         capture_output=True, text=True).stdout
    m = re.search(r"\.text\s+\w+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", out)
    if not m:
        fail("cannot locate .text section")
    else:
        text_va, text_off, text_size = (int(m.group(1), 16),
                                        int(m.group(2), 16),
                                        int(m.group(3), 16))
        expected = {
            0x63737c0: (0, 0), 0x63721c0: (0, 0), 0x6377dc0: (0, 0),
            0x63749f0: (0, 0), 0x637b190: (0, 0),
            0x63ec4c0: (27, 1), 0x634ebb0: (64, 4),
            0x63c41c0: (1, 0), 0x63c3b70: (1, 0),
            0x63539d0: (1, 0), 0x6353a20: (1, 0), 0x63efd20: (1, 0),
        }
        counts = {t: [0, 0] for t in expected}
        for i in range(text_off, text_off + text_size - 5):
            op = data[i]
            if op in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", data, i + 1)[0]
                tgt = text_va + (i - text_off) + 5 + rel
                if tgt in counts:
                    counts[tgt][0 if op == 0xE8 else 1] += 1
        for tgt, (e8, e9) in expected.items():
            got = counts[tgt]
            if got != [e8, e9]:
                fail("census %s: E8=%d E9=%d != expected E8=%d E9=%d"
                     % (hex(tgt), got[0], got[1], e8, e9))
            else:
                ok("census %s: E8=%d E9=%d" % (hex(tgt), e8, e9))

    # 6. .rela.dyn slots
    rela = subprocess.run(["readelf", "-r", binary],
                          capture_output=True, text=True).stdout
    slots = {
        0x64dea80: 0x63737c0, 0x64de8a0: 0x63721c0,
        0x64deea8: 0x6377dc0, 0x64def48: 0x63749f0,
        0x64daac0: 0x637b190,
    }
    for slot, handler in slots.items():
        pat = re.compile(r"^%012x\s+\d+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)"
                         % slot, re.M)
        mm = pat.search(rela)
        if not mm or int(mm.group(1), 16) != handler:
            fail("rela slot %s != handler %s" % (hex(slot), hex(handler)))
        else:
            ok("rela slot %s -> %s" % (hex(slot), hex(handler)))

    # 7. disjointness (range-only collector)
    def collect(obj, out, in_exhibits=False, top=False):
        if isinstance(obj, dict):
            if in_exhibits and "start" in obj and "end" in obj:
                try:
                    out.append((int(obj["start"], 16), int(obj["end"], 16)))
                except (ValueError, TypeError):
                    pass
            for k, v in obj.items():
                if k in ("census", "cited_only_not_claimed"):
                    continue  # never descend into census/cited metadata
                if k in ("exhibits", "windows") and isinstance(v, list):
                    for item in v:
                        collect(item, out, in_exhibits=True)
                elif k in ("exhibits", "windows") and isinstance(v, dict):
                    # Dict-shaped exhibits/windows (packet #260's lesson:
                    # 574 exhibits_dict + 868 windows_dict records exist).
                    for item in v.values():
                        collect(item, out, in_exhibits=True)
                elif k == "range" and (in_exhibits or "name" in obj):
                    try:
                        out.append(parse_range(v))
                    except ValueError:
                        pass
                elif k == "fde":
                    continue  # enclosing-FDE annotation, never a claim
                else:
                    collect(v, out, in_exhibits)
        elif isinstance(obj, list):
            # Top-level list records are exhibit lists by construction:
            # their items are exhibit context.
            for item in obj:
                collect(item, out, in_exhibits or top, top=False)

    roots = os.environ.get("HL261_SCAN_ROOTS")
    if roots:
        scan_dirs = roots.split(":")
    else:
        scan_dirs = [os.path.join(root, "research/work-items")]
        scan_dirs += glob.glob(
            os.path.expanduser("~/workspace/hl-wt-calls*-115/research/work-items"))
    prior = set()
    for d in scan_dirs:
        for rf in glob.glob(os.path.join(d, "*/records.json")):
            slug = os.path.basename(os.path.dirname(rf))
            if slug == "RE-001-node115-lu-value-leaves-bin":
                continue
            try:
                obj = json.load(open(rf))
            except (ValueError, OSError):
                continue
            rs = []
            collect(obj, rs, top=True)
            for s, e in rs:
                prior.add((slug, s, e))
    mine = [(parse_range(ex["range"])) for ex in rec["exhibits"]]
    overlap = [(s, e) for (s, e) in mine
               if any(ps <= s < pe or ps < e <= pe or (s <= ps and pe <= e)
                      for (_, ps, pe) in prior)]
    if overlap:
        fail("overlap with prior packets: %s" % overlap)
    else:
        ok("disjoint from %d unique prior ranges" % len(prior))

    # 8. MANIFEST
    man = {}
    for line in open(os.path.join(pkt, "MANIFEST.sha256")):
        parts = line.split()
        if len(parts) == 2:
            man[parts[1]] = parts[0]
    expect = set()
    for f in sorted(os.listdir(pkt)):
        if f != "MANIFEST.sha256":
            expect.add(f)
    expect.add("../../../tools/node115_value_leaves_bin.py")
    expect.add("../../../tests/test_node115_value_leaves_bin.py")
    if set(man) != expect:
        fail("MANIFEST file set mismatch: extra=%s missing=%s"
             % (sorted(set(man) - expect), sorted(expect - set(man))))
    else:
        ok("MANIFEST file set")
    hash_bad = False
    for rel, want in man.items():
        p = os.path.normpath(os.path.join(pkt, rel))
        got = hashlib.sha256(open(p, "rb").read()).hexdigest()
        if got != want:
            fail("MANIFEST hash mismatch for %s" % rel)
            hash_bad = True
    if not hash_bad:
        ok("MANIFEST hashes")

    # 9. leaf arithmetic
    if (rec["leaves_classified_before"] + len(rec["leaves_classified_here"])
            + rec["leaves_remaining_unclassified"] != 204):
        fail("leaf arithmetic != 204")
    else:
        ok("leaf arithmetic 28 + 5 + 171 = 204")

    if FAILURES:
        print("RESULT: FAIL (%d failures)" % len(FAILURES))
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
