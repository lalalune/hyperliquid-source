#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-tls-state-continue (packet #260).

Byte reads only; never executes the node binary. Checks:
 1. target binary size and SHA-256 from records.json
 2. every exhibit .hex file equals the binary slice at VA - 0x1000
 3. every exhibit .objdump.txt strict mnemonic count matches records.json
    (strict = address + bytes field + blank + mnemonic; byte-continuation
    lines excluded)
 4. claimed E8/E9 call sites by exact byte arithmetic (opcode + rel32)
 5. the 0x63ef5e0 census by raw scan over the code window
    (0x6300000..0x6500000; cross-checked at build time against a full-file
    scan with identical counts)
 6. the 0x6712440 site list by exact byte checks at each site, plus the
    neighbouring-base lea site bytes
 7. disjointness of the claimed ranges against prior packets #183-#259,
    using a range-only collector: ONLY exhibited 'range' fields inside
    'exhibits' lists are gathered, never enclosing-'fde' annotation fields
    (packet #259's lesson); census/cited-only metadata is excluded
    (packet #253's rule)
 8. MANIFEST.sha256 lists exactly the packet files (excluding itself)

Usage: python3 tools/node115_tls_state_continue.py [worktree-root]
Exit 0 on PASS, 1 on any FAIL. Scan roots for check 7 can be overridden
with the HL260_SCAN_ROOTS environment variable (colon-separated) for tests.
"""
import hashlib
import json
import os
import re
import struct
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
        try:
            a = s[0] if isinstance(s[0], int) else int(str(s[0]), 16)
            b = s[1] if isinstance(s[1], int) else int(str(s[1]), 16)
        except ValueError:
            return None
        return (a, b)
    if not isinstance(s, str):
        return None
    m = re.fullmatch(r"0x([0-9a-f]+)\.\.0x([0-9a-f]+)", s.strip())
    if not m:
        return None
    return (int(m.group(1), 16), int(m.group(2), 16))


STRICT_RE = re.compile(
    r"^[ \t]+[0-9a-f]+:[ \t]+[0-9a-f ]+[ \t]+[a-z]")


def strict_count(objdump_text):
    return sum(1 for line in objdump_text.splitlines()
               if STRICT_RE.match(line))


def check_e8_e9(data, site, opcode, target):
    """Verify bytes at site are opcode (0xE8 call / 0xE9 jmp) + rel32."""
    off = va_to_off(site)
    if data[off] != opcode:
        return False
    rel = struct.unpack("<i", data[off + 1:off + 5])[0]
    return site + 5 + rel == target


def check_rip_ref(data, site, opcodes, target):
    """Verify a RIP-relative instruction at site resolves to target.

    opcodes: tuple of expected leading bytes (REX + opcode), e.g.
    (0x48, 0x8d) for lea; the modrm byte must be mod=00, rm=101.
    Returns True on match.
    """
    off = va_to_off(site)
    for i, b in enumerate(opcodes):
        if data[off + i] != b:
            return False
    modrm = data[off + len(opcodes)]
    if (modrm & 0xC7) != 0x05:
        return False
    disp = struct.unpack("<i", data[off + len(opcodes) + 1:
                                   off + len(opcodes) + 5])[0]
    ins_len = len(opcodes) + 1 + 4
    return site + ins_len + disp == target


def check_rip_store(data, site, target):
    """Check the specific store/load/cmp forms used at the 0x6712440 sites.

    Each site's opcode bytes are checked individually by the caller via
    check_rip_ref with the right prefix; this helper handles the
    mov-store form 48 89 /r and mov-load form 48 8b /r and cmp form
    48 83 3d, which all share modrm mod=00 rm=101.
    """
    return check_rip_ref(data, site, (0x48, 0x89), target) or \
        check_rip_ref(data, site, (0x48, 0x8b), target) or \
        check_rip_ref(data, site, (0x48, 0x83), target)


def raw_call_scan(data, lo, hi, target):
    """Raw E8/E9 scan over the file window for VA range [lo, hi)."""
    base_off = va_to_off(lo)
    buf = data[base_off:va_to_off(hi)]
    e8 = e9 = 0
    for i in range(len(buf) - 5):
        op = buf[i]
        if op not in (0xE8, 0xE9):
            continue
        rel = struct.unpack("<i", buf[i + 1:i + 5])[0]
        if lo + i + 5 + rel == target:
            if op == 0xE8:
                e8 += 1
            else:
                e9 += 1
    return e8, e9


def parse_pair(a, b):
    try:
        x = a if isinstance(a, int) else int(str(a), 16)
        y = b if isinstance(b, int) else int(str(b), 16)
    except ValueError:
        return None
    return (x, y)


def collect_exhibit_ranges(obj):
    """Exhibit-only collector.

    Gathers ONLY exhibited windows, never enclosing-'fde' annotation
    fields (packet #259's lesson) and never census/cited-only metadata
    (packet #253's rule). Handles every records shape seen in the lu
    chain and the merged tree:
      - exhibits as a list of dicts with 'range' (string or [start, end])
      - exhibits as a list of dicts with 'start' + 'end'
      - exhibits as a dict of such dicts
      - windows as a list of dicts with 'start' + 'end'
    """
    out = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key == "exhibits":
                if isinstance(val, list):
                    items = val
                elif isinstance(val, dict):
                    items = list(val.values())
                else:
                    items = []
                for item in items:
                    if isinstance(item, dict):
                        if "range" in item:
                            r = parse_range(item["range"])
                            if r:
                                out.append(r)
                        elif "start" in item and "end" in item:
                            r = parse_pair(item["start"], item["end"])
                            if r:
                                out.append(r)
                    out.extend(collect_exhibit_ranges(item))
            elif key == "windows" and isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and \
                            "start" in item and "end" in item:
                        r = parse_pair(item["start"], item["end"])
                        if r:
                            out.append(r)
                    out.extend(collect_exhibit_ranges(item))
            else:
                out.extend(collect_exhibit_ranges(val))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(collect_exhibit_ranges(item))
    return out


def overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    pkt = os.path.join(root,
                       "research/work-items/RE-001-node115-lu-tls-state-continue")
    rec_path = os.path.join(pkt, "records.json")
    if not os.path.isfile(rec_path):
        print("FAIL: records.json missing at", rec_path)
        return 1
    rec = json.load(open(rec_path))
    bin_path = os.path.join(root, "artifacts/node/115/hl-node")
    data = open(bin_path, "rb").read()

    # 1. binary identity
    b = rec["binary"]
    if len(data) != b["size"]:
        fail(f"binary size {len(data)} != {b['size']}")
    else:
        ok("binary size")
    sha = hashlib.sha256(data).hexdigest()
    if sha != b["sha256"]:
        fail("binary sha256 mismatch")
    else:
        ok("binary sha256")

    # 2-3. exhibits
    mine = []
    for ex in rec["exhibits"]:
        name = ex["name"]
        r = parse_range(ex["range"])
        if not r:
            fail(f"{name}: unparsable range {ex['range']}")
            continue
        s, e = r
        mine.append((s, e))
        raw = open(os.path.join(pkt, name + ".hex"), "rb").read()
        if len(raw) != e - s:
            fail(f"{name}: hex length {len(raw)} != {e - s}")
        elif raw != data[va_to_off(s):va_to_off(e)]:
            fail(f"{name}: hex bytes differ from binary slice")
        else:
            ok(f"{name}: hex bytes match binary")
        odt = open(os.path.join(pkt, name + ".objdump.txt"),
                   "r", errors="replace").read()
        sc = strict_count(odt)
        if sc != ex["strict"]:
            fail(f"{name}: strict count {sc} != {ex['strict']}")
        else:
            ok(f"{name}: strict count {sc}")
        if ex["bytes"] != e - s:
            fail(f"{name}: records bytes {ex['bytes']} != {e - s}")
    if len(mine) != len(rec["exhibits"]):
        fail("exhibit count mismatch")
    tot_b = sum(e - s for s, e in mine)
    tot_s = sum(ex["strict"] for ex in rec["exhibits"])
    if (tot_b, tot_s) != (rec["exhibit_totals"]["bytes"],
                          rec["exhibit_totals"]["strict"]):
        fail(f"exhibit totals {(tot_b, tot_s)} != records "
             f"{rec['exhibit_totals']}")
    else:
        ok(f"exhibit totals {tot_b} bytes / {tot_s} strict")
    for i in range(len(mine)):
        for j in range(i + 1, len(mine)):
            if overlaps(mine[i], mine[j]):
                fail(f"self-overlap {mine[i]} vs {mine[j]}")
    if not any("self-overlap" in f for f in FAILURES):
        ok("no self-overlap")

    # 4. small call-site censuses by exact byte arithmetic
    cen = rec["census"]
    site_checks = [
        ("list_insert E8", 0x63ef7a5, 0xE8, 0x63ef410),
        ("list_insert E9", 0x63efd14, 0xE9, 0x63ef410),
        ("list_reset E8", 0x6350002, 0xE8, 0x63efce0),
        ("disable_slow E8a", 0x636e2f8, 0xE8, 0x63ed070),
        ("disable_slow E8b", 0x63ef84c, 0xE8, 0x63ed070),
        ("enable_slow E8a", 0x636e29c, 0xE8, 0x63ed090),
        ("enable_slow E8b", 0x63ed89b, 0xE8, 0x63ed090),
        ("ec900 E9a", 0x63ed080, 0xE9, 0x63ec900),
        ("ec900 E9b", 0x63ee269, 0xE9, 0x63ec900),
        ("ec900 E9c", 0x63ee31e, 0xE9, 0x63ec900),
        ("latch E8", 0x634eea7, 0xE8, 0x63c4140),
        ("ef640 E8a", 0x6367edd, 0xE8, 0x63ef640),
        ("ef640 E8b", 0x63ef869, 0xE8, 0x63ef640),
        ("ef640 E8c", 0x63ef981, 0xE8, 0x63ef640),
        ("ef640 E8d", 0x63efa58, 0xE8, 0x63ef640),
        ("ef640 E8e", 0x63efb02, 0xE8, 0x63ef640),
        ("interval_read E8", 0x63ef12a, 0xE8, 0x63c3a90),
    ]
    for label, site, opcode, target in site_checks:
        if check_e8_e9(data, site, opcode, target):
            ok(f"site {label} {hex(site)} -> {hex(target)}")
        else:
            fail(f"site {label} {hex(site)} -> {hex(target)} byte check")

    # 5. ef5e0 census by raw scan over the code window
    e8, e9 = raw_call_scan(data, 0x6300000, 0x6500000, 0x63ef5e0)
    want = cen["tls_state_refresh_0x63ef5e0"]
    if (e8, e9) != (want["E8"], want["E9"]):
        fail(f"ef5e0 census raw scan {(e8, e9)} != "
             f"({want['E8']}, {want['E9']})")
    else:
        ok(f"ef5e0 census E8 {e8} E9 {e9}")

    # 6. interval-value site list by exact byte checks
    iv = cen["interval_value_0x6712440"]
    # lea site (REX.W + 8d, modrm rm=101)
    if check_rip_ref(data, 0x6376813, (0x48, 0x8d), 0x6712440):
        ok("interval lea site 0x6376813")
    else:
        fail("interval lea site 0x6376813 byte check")
    # cmp site: 48 83 modrm(/7, mod=00, rm=101) disp32 imm8
    off = va_to_off(0x63c3a94)
    if data[off:off + 2] == bytes([0x48, 0x83]) and \
            (data[off + 2] & 0xC7) == 0x05 and \
            ((data[off + 2] >> 3) & 7) == 7:
        disp = struct.unpack("<i", data[off + 3:off + 7])[0]
        if 0x63c3a94 + 8 + disp == 0x6712440:
            ok("interval cmp site 0x63c3a94")
        else:
            fail("interval cmp site 0x63c3a94 disp")
    else:
        fail("interval cmp site 0x63c3a94 opcode")
    # store site: 48 89 35 disp32
    if check_rip_ref(data, 0x63c417e, (0x48, 0x89), 0x6712440):
        ok("interval store site 0x63c417e")
    else:
        fail("interval store site 0x63c417e byte check")
    # load site: 48 8b 35 disp32
    if check_rip_ref(data, 0x63c437a, (0x48, 0x8b), 0x6712440):
        ok("interval load site 0x63c437a")
    else:
        fail("interval load site 0x63c437a byte check")
    # neighbouring-base lea sites (REX variants + 8d)
    lea_sites = [
        (0x636d893, 0x48, 0x6712438), (0x6376a33, 0x48, 0x6712438),
        (0x63c37d2, 0x4c, 0x6712400), (0x63c421e, 0x48, 0x6712460),
        (0x63c4701, 0x48, 0x6712460), (0x63c47a0, 0x48, 0x6712460),
        (0x63c49f0, 0x48, 0x6712460), (0x63c6c5c, 0x4c, 0x6712438),
        (0x63c6dde, 0x48, 0x6712438), (0x63ce257, 0x48, 0x6712438),
        (0x63ce56c, 0x48, 0x6712438), (0x63ce6ed, 0x4c, 0x6712438),
        (0x63cfa5c, 0x48, 0x6712438), (0x63d4dbb, 0x48, 0x6712438),
        (0x63d6eb1, 0x4c, 0x6712438),
    ]
    bad = 0
    for site, rex, base in lea_sites:
        if not check_rip_ref(data, site, (rex, 0x8d), base):
            fail(f"neighbour lea site {hex(site)} -> {hex(base)}")
            bad += 1
    if bad == 0:
        ok("neighbour lea sites 15/15")
    if iv["indirect_offset_stores"]["hits"] != 0:
        fail("indirect_offset_stores hits must be 0")

    # 7. disjointness against prior packets (range-only collector)
    roots_env = os.environ.get("HL260_SCAN_ROOTS")
    if roots_env:
        roots = roots_env.split(":")
        seen_names = None
    else:
        own_items = os.path.join(root, "research/work-items")
        roots = [own_items]
        seen_names = set(os.listdir(own_items)) \
            if os.path.isdir(own_items) else set()
        home = os.path.expanduser("~")
        ws = os.path.join(home, "workspace")
        if os.path.isdir(ws):
            for d in sorted(os.listdir(ws)):
                if d.startswith("hl-wt-calls"):
                    roots.append(os.path.join(ws, d,
                                              "research/work-items"))
    prior = set()
    nrec = 0
    own_real = os.path.realpath(rec_path)
    for ri, rdir in enumerate(roots):
        if not os.path.isdir(rdir):
            continue
        for d in sorted(os.listdir(rdir)):
            # For other worktrees, skip directories already present in
            # this worktree's merged tree (same merged packets, different
            # checkout paths); only genuinely new packet dirs are read.
            if ri > 0 and seen_names is not None and d in seen_names:
                continue
            rp = os.path.join(rdir, d, "records.json")
            if not os.path.isfile(rp):
                continue
            if os.path.realpath(rp) == own_real:
                continue
            try:
                obj = json.load(open(rp))
            except Exception:
                continue
            nrec += 1
            prior.update(collect_exhibit_ranges(obj))
    print(f"prior records scanned: {nrec}, unique prior ranges: "
          f"{len(prior)}")
    bad = 0
    for s, e in mine:
        for ps, pe in prior:
            if overlaps((s, e), (ps, pe)):
                fail(f"overlap with prior range "
                     f"{hex(ps)}..{hex(pe)} for mine {hex(s)}..{hex(e)}")
                bad += 1
    if bad == 0:
        ok("disjoint from prior packets (range-only collector)")

    # 8. MANIFEST lists exactly the packet files (excluding itself);
    # tools/tests entries use ../../../ paths and must resolve
    man_path = os.path.join(pkt, "MANIFEST.sha256")
    if not os.path.isfile(man_path):
        fail("MANIFEST.sha256 missing")
    else:
        listed = set()
        for line in open(man_path):
            parts = line.split()
            if len(parts) == 2:
                listed.add(parts[1])
        local = {f for f in listed if not f.startswith("../")}
        external = {f for f in listed if f.startswith("../")}
        actual = set(f for f in os.listdir(pkt)
                     if f != "MANIFEST.sha256")
        if local != actual:
            fail(f"MANIFEST local mismatch: listed-only {local - actual}, "
                 f"missing {actual - local}")
        else:
            ok("MANIFEST local file list matches packet dir")
        missing_ext = [f for f in external
                       if not os.path.isfile(os.path.join(pkt, f))]
        if missing_ext:
            fail(f"MANIFEST external entries missing: {missing_ext}")
        else:
            ok(f"MANIFEST external entries resolve ({len(external)})")

    # leaf arithmetic
    if rec["leaves_classified_before"] + \
            len(rec["leaves_classified_here"]) + \
            rec["leaves_remaining_unclassified"] != 204:
        fail("leaf arithmetic != 204")
    else:
        ok("leaf arithmetic 23 + 5 + 176 = 204")

    if FAILURES:
        print(f"RESULT: FAIL ({len(FAILURES)} failures)")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
