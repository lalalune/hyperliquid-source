#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-2sites-walk-60rsp.

Byte reads only; never executes the binary. ROOT is the worktree root
(parent of the tools/ directory holding this script), so the same script
verifies a temp copy with a mirrored layout (binary symlinked in).
"""
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from bisect import bisect_right

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("HL_NODE_BIN", os.path.join(ROOT, "artifacts/node/115/hl-node"))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-bintableinit-caller-2sites-walk-60rsp")
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-walk-60rsp"

EXPECTED_SIZE = 105896032
EXPECTED_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOW = (0x6361320, 0x63620DA)
PREV_FDE = (0x63612B0, 0x636131A)
NEXT_FDE = (0x63620E0, 0x6362130)
BTI_SITES = ["6361a28", "6361c06"]
MISS_SITES = ["6361de8", "6361edc", "636201d", "63620d0"]
MISS_REJOINS = {"6361de8": "6361422", "6361edc": "6361947",
                "636201d": "6361a53", "63620d0": "6361c31"}

passes, fails = [], []


def check(name, ok, detail=""):
    (passes if ok else fails).append(name)
    print(("PASS " if ok else "FAIL ") + name + ((" -- " + detail) if detail else ""))


def uleb(data, pos):
    result, shift = 0, 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def sleb(data, pos):
    result, shift = 0, 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result -= (1 << shift)
            break
    return result, pos


ENC_SIZE = {0x01: None, 0x02: 2, 0x03: 4, 0x04: 8, 0x09: None,
            0x0A: 2, 0x0B: 4, 0x0C: 8, 0x00: 8}


def enc_value(data, pos, enc):
    fmt = enc & 0x0F
    if fmt == 0x01:
        return uleb(data, pos)
    if fmt == 0x09:
        return sleb(data, pos)
    size = ENC_SIZE[fmt]
    return int.from_bytes(data[pos:pos + size], "little", signed=(fmt >= 0x0A)), pos + size


def parse_eh_frame(data, base_va):
    """CIE pointer is relative to the CIE_id field (rec+4, not rec).
    Version-1 CIEs carry the return-address register as a single byte.
    Code/data alignment and return-address register come BEFORE the 'z'
    augmentation data. CIE offsets are hex."""
    fdes, cies, pos, n = [], {}, 0, len(data)
    while pos + 8 <= n:
        length = struct.unpack("<I", data[pos:pos + 4])[0]
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            length = struct.unpack("<Q", data[pos + 4:pos + 12])[0]
            hdr = 12
        else:
            hdr = 4
        rec_end = pos + hdr + length
        cie_id = struct.unpack("<I", data[pos + hdr:pos + hdr + 4])[0]
        if cie_id == 0:
            body = pos + hdr + 4
            version = data[body]
            body += 1
            aug_end = data.index(b"\x00", body)
            aug = data[body:aug_end].decode("latin1")
            body = aug_end + 1
            _, body = uleb(data, body)
            _, body = sleb(data, body)
            if version == 1:
                body += 1
            else:
                _, body = uleb(data, body)
            fde_enc = None
            if aug.startswith("z"):
                _, body = uleb(data, body)
                q = body
                for ch in aug[1:]:
                    if ch == "R":
                        fde_enc = data[q]
                        q += 1
                    elif ch == "P":
                        penc = data[q]
                        q += 1
                        _, q = enc_value(data, q, penc)
                    elif ch == "L":
                        q += 1
                    elif ch == "b":
                        q += 1
                    elif ch == "e":
                        q += 2
                    else:
                        raise ValueError("unknown aug %r" % ch)
                body = q
            cies[pos] = fde_enc
        else:
            cie_addr = (pos + hdr) - cie_id
            fde_enc = cies.get(cie_addr)
            if fde_enc != 0x1B:
                raise ValueError("unexpected FDE encoding %r at %#x" % (fde_enc, pos))
            field = pos + hdr + 4
            loc = struct.unpack("<i", data[field:field + 4])[0] + field + base_va
            rng = struct.unpack("<I", data[field + 4:field + 8])[0]
            fdes.append((loc, loc + rng))
        pos = rec_end
    return fdes


STRICT = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t([a-z]\S*)(.*)$")


def main():
    blob = open(BIN, "rb").read()
    check("binary size", len(blob) == EXPECTED_SIZE, str(len(blob)))
    check("binary sha256", hashlib.sha256(blob).hexdigest() == EXPECTED_SHA)

    e_shoff = struct.unpack("<Q", blob[0x28:0x30])[0]
    e_shentsize, e_shnum = struct.unpack("<HH", blob[0x3A:0x3E])
    e_shstrndx = struct.unpack("<H", blob[0x3E:0x40])[0]

    def sh(i):
        o = e_shoff + i * e_shentsize
        return struct.unpack("<IIQQQQIIQQ", blob[o:o + 64])

    _, _, _, _, stroff, _strsize, _, _, _, _ = sh(e_shstrndx)

    def nm(n):
        e = blob.index(b"\x00", stroff + n)
        return blob[stroff + n:e].decode()

    sections = {}
    for i in range(e_shnum):
        name, _typ, _flags, addr, off, size, _link, _info, _align, entsize = sh(i)
        sections[nm(name)] = (addr, off, size, entsize)

    eh_addr, eh_off, eh_size, _ = sections[".eh_frame"]
    fdes = sorted(parse_eh_frame(blob[eh_off:eh_off + eh_size], eh_addr))
    check("window FDE present", WINDOW in fdes)
    check("prev FDE bounds", PREV_FDE in fdes)
    check("next FDE bounds", NEXT_FDE in fdes)
    check("gap before 6", WINDOW[0] - PREV_FDE[1] == 6)
    check("padding after 6", NEXT_FDE[0] - WINDOW[1] == 6)

    def toff(va):
        return va - 0x1000

    gap = blob[toff(PREV_FDE[1]):toff(WINDOW[0])]
    pad = blob[toff(WINDOW[1]):toff(NEXT_FDE[0])]
    check("gap bytes int3", gap == b"\xcc" * 6, gap.hex())
    check("padding bytes int3", pad == b"\xcc" * 6, pad.hex())

    hexpath = os.path.join(PACKET, "bintableinit_caller_walk_60rsp_2sites.hex")
    raw = open(hexpath, "rb").read()
    check("exhibit bytes", raw == blob[toff(WINDOW[0]):toff(WINDOW[1])],
          "%d bytes" % len(raw))
    check("exhibit size 3514", len(raw) == 3514)

    txt = open(os.path.join(PACKET, "bintableinit_caller_walk_60rsp_2sites.objdump.txt")).read().splitlines()
    strict = [l for l in txt if STRICT.match(l)]
    check("strict recount 737", len(strict) == 737, str(len(strict)))

    def tgt_of(line):
        m = STRICT.match(line)
        addr = int(m.group(1), 16)
        byts = bytes.fromhex(m.group(2).replace(" ", ""))
        if len(byts) < 5 or byts[0] != 0xE8:
            return None
        return addr + 5 + struct.unpack("<i", byts[1:5])[0]

    calls = [l for l in strict if re.search(r"\tcall\s", l)]
    bti = [l for l in calls if tgt_of(l) == 0x63D9880]
    miss = [l for l in calls if tgt_of(l) == 0x63D9700]
    ret = [l for l in strict if re.search(r"\tret\s*$", l)]
    bsr = [l for l in strict if re.search(r"\tbsr\s", l)]
    lock = [l for l in strict if re.search(r"\tlock sub\s", l)]
    check("call census 42", len(calls) == 42, str(len(calls)))
    check("bin_table_init count 2", len(bti) == 2)
    check("bin_table_init sites exact",
          [STRICT.match(l).group(1) for l in bti] == BTI_SITES)
    check("lu-miss count 4", len(miss) == 4)
    check("lu-miss sites exact",
          [STRICT.match(l).group(1) for l in miss] == MISS_SITES)
    check("ret count 0", len(ret) == 0)
    check("bsr count 0", len(bsr) == 0)
    check("lock sub count 0", len(lock) == 0)

    def line_at(addr):
        for l in strict:
            if STRICT.match(l).group(1) == addr:
                return l
        return None

    def window_lines(addr, n):
        idx = next(i for i, l in enumerate(strict) if STRICT.match(l).group(1) == addr)
        return strict[max(0, idx - n):idx + 1]

    # Site 1: call at 6361a28, mov %r14,%rdi just above, lea 0x60(%rsp) sets r14.
    check("site1 call line", line_at("6361a28") is not None and "63d9880" in line_at("6361a28"))
    check("site1 rdi from r14",
          any(re.search(r"mov\s+%r14,%rdi", l) for l in window_lines("6361a28", 6)))
    check("site1 stack temp lea",
          line_at("63619ec") is not None and "lea" in line_at("63619ec") and "0x60(%rsp)" in line_at("63619ec"))
    check("site1 null-entry branch",
          line_at("63613be") is not None and "je" in line_at("63613be") and "63619e7" in line_at("63613be"))
    # Site 2: call at 6361c06, mov %r14,%rdi just above, je on low-bit test.
    check("site2 call line", line_at("6361c06") is not None and "63d9880" in line_at("6361c06"))
    check("site2 rdi from r14",
          any(re.search(r"mov\s+%r14,%rdi", l) for l in window_lines("6361c06", 6)))
    check("site2 low-bit branch",
          line_at("6361a67") is not None and "je" in line_at("6361a67") and "6361bef" in line_at("6361a67"))
    # Miss sites: rsi = lea 0x6511a00 above, jmp to expected rejoin within 4 strict lines after.
    for site, rejoin in MISS_REJOINS.items():
        idx = next(i for i, l in enumerate(strict) if STRICT.match(l).group(1) == site)
        above = strict[max(0, idx - 12):idx + 1]
        after = strict[idx + 1:idx + 5]
        check("miss %s rsi table" % site,
              any("lea" in l and "6511a00" in l for l in above))
        check("miss %s rejoin %s" % (site, rejoin),
              any(re.search(r"\tjmp\s", l) and rejoin in l for l in after))
    # Canary: stored at 0x1e8(%rsp), checked at 6361750, fail -> stack_chk_fail call.
    check("canary stored",
          line_at("6361350") is not None and "0x1e8(%rsp)" in line_at("6361350"))
    check("canary check",
          line_at("6361761") is not None and "jne" in line_at("6361761") and "6361c74" in line_at("6361761"))
    check("stack_chk_fail call",
          line_at("6361c74") is not None and "63f0d70" in line_at("6361c74"))
    # Exit: exactly one jmp leaving the window, canary-checked epilogue before it.
    outside = []
    for l in strict:
        m = STRICT.match(l)
        if m.group(3) == "jmp":
            t = m.group(4).strip().split()[0]
            if re.match(r"^[0-9a-f]+$", t) and not (WINDOW[0] <= int(t, 16) < WINDOW[1]):
                outside.append((m.group(1), t))
    check("single outside jmp", outside == [("6361784", "63bffe0")], str(outside))
    epi = window_lines("6361784", 14)
    check("exit epilogue", any("add" in l and "$0x1f8,%rsp" in l for l in epi))
    # Phase-1 walk + drain sweep spot checks.
    check("phase1 table lea",
          line_at("63613b4") is not None and "0x1b0(%rbx)" in line_at("63613b4"))
    check("phase1 top index",
          line_at("63613f8") is not None and "shr" in line_at("63613f8") and "$0x1a" in line_at("63613f8"))
    check("phase1 ordinary 63bd6c0 call",
          line_at("636143f") is not None and re.search(r"\tcall\s", line_at("636143f")) and "63bd6c0" in line_at("636143f"))
    check("drain outer table lea",
          line_at("63614a9") is not None and "6711b40" in line_at("63614a9"))
    check("drain parallel array lea",
          line_at("6361493") is not None and "6511780" in line_at("6361493"))
    check("drain loop head",
          line_at("63614d0") is not None and "mov" in line_at("63614d0") and "(%rcx)" in line_at("63614d0"))
    check("drain splice", line_at("6361789") is not None and "mov" in line_at("6361789"))
    check("gate byte phase1",
          line_at("6361425") is not None and "lea" in line_at("6361425") and "6713606" in line_at("6361425"))
    check("gate byte stack walk",
          line_at("6361a56") is not None and "lea" in line_at("6361a56") and "6713606" in line_at("6361a56"))
    check("node table 6727a00",
          any("6727a00" in l for l in strict))

    # Records consistency.
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    w = rec["window"]
    check("records window", w["range"] == "0x6361320..0x63620da" and w["bytes"] == 3514
          and w["strict_lines"] == 737 and w["calls_total"] == 42 and w["ret"] == 0
          and w["bsr"] == 0 and w["lock_sub"] == 0)
    check("records sites",
          [s["site"] for s in rec["bin_table_init_sites"]] == ["0x6361a28", "0x6361c06"]
          and [s["site"] for s in rec["lu_miss_sites"]] == ["0x6361de8", "0x6361edc", "0x636201d", "0x63620d0"])

    # .rela.dyn census from section headers (24-byte entries; type 8 = RELATIVE).
    rela_addr, rela_off, rela_size, rela_entsize = sections[".rela.dyn"]
    total = rela_size // rela_entsize
    relative = 0
    for i in range(total):
        o = rela_off + i * rela_entsize
        _off, info, _add = struct.unpack("<QQq", blob[o:o + 24])
        if (info & 0xFFFFFFFF) == 8:
            relative += 1
    check("rela.dyn total 60723", total == 60723, str(total))
    check("rela.dyn relative 59534", relative == 59534, str(relative))
    plt_addr, plt_off, plt_size, plt_entsize = sections[".rela.plt"]
    check("rela.plt 278", plt_size // plt_entsize == 278, str(plt_size // plt_entsize))

    # Disjointness: range-only collector, decimal-int forms accepted, 0 skipped.
    SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde")

    def num(x):
        if isinstance(x, int):
            return x
        if isinstance(x, str):
            return int(x, 16)
        raise ValueError("bad num %r" % (x,))

    def collect(obj, out, skipped):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in SKIP_KEYS or k == "fde":
                    continue
                if k in ("exhibits", "windows"):
                    items = v if isinstance(v, list) else v.values() if isinstance(v, dict) else []
                    for e in items:
                        if not isinstance(e, dict):
                            continue
                        try:
                            if "range" in e:
                                r = e["range"]
                                out.append((num(r[0]), num(r[1])) if isinstance(r, list)
                                           else tuple(num(x) for x in r.split("..")))
                            elif "start" in e and "end" in e:
                                out.append((num(e["start"]), num(e["end"])))
                        except Exception:
                            skipped[0] += 1
                else:
                    collect(v, out, skipped)
        elif isinstance(obj, list):
            for v in obj:
                collect(v, out, skipped)

    priors, skipped = [], [0]
    files = sorted(set(glob.glob(os.path.join(ROOT, "research/work-items/*/records.json")) +
                       glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json")))
    for f in files:
        try:
            collect(json.load(open(f)), priors, skipped)
        except Exception:
            skipped[0] += 1
    # Self-exclusion by exact window equality only (never by slug).
    priors = [p for p in priors if p != WINDOW]
    overlaps = [(s, e) for (s, e) in priors if WINDOW[0] < e and s < WINDOW[1]]
    check("disjointness NONE", not overlaps, str(overlaps[:3]))
    check("collector skipped 0", skipped[0] == 0, str(skipped[0]))
    print("prior ranges scanned: %d" % len(priors))

    # Slug check: committed tree must not contain the slug; any same-slug
    # worktree dir must carry the same window (own copy only).
    out = subprocess.run(["git", "ls-tree", "HEAD", "--name-only", "research/work-items/"],
                         capture_output=True, text=True, cwd=ROOT).stdout
    check("slug absent from committed tree", SLUG not in out)
    same_slug_elsewhere = False
    for d in glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/" + SLUG + "/records.json"):
        try:
            r2 = json.load(open(d))
            w2 = r2.get("window", {})
            rng = w2.get("range")
            if rng and rng != "0x6361320..0x63620da":
                same_slug_elsewhere = True
        except Exception:
            same_slug_elsewhere = True
    check("no conflicting same-slug packet", not same_slug_elsewhere)

    # Raw-e8 census: byte scan of .text for e8 with rel32 target 0x63d9880,
    # grouped by enclosing FDE (sorted list + bisect). Raw is an upper bound.
    text_addr, text_off, text_size, _ = sections[".text"]
    text = blob[text_off:text_off + text_size]
    starts = [s for (s, _e) in fdes]
    counts = {}
    pos = 0
    while True:
        i = text.find(b"\xe8", pos)
        if i < 0:
            break
        if i + 5 <= len(text):
            rel = struct.unpack("<i", text[i + 1:i + 5])[0]
            va = text_addr + i
            if va + 5 + rel == 0x63D9880:
                j = bisect_right(starts, va) - 1
                if j >= 0:
                    key = fdes[j]
                    counts[key] = counts.get(key, 0) + 1
        pos = i + 1
    total_raw = sum(counts.values())
    from collections import Counter
    tiers = Counter(counts.values())
    check("raw-e8 total 108", total_raw == 108, str(total_raw))
    check("raw-e8 tiers",
          dict(tiers) == {10: 1, 8: 1, 6: 2, 5: 1, 4: 8, 2: 12, 1: 17}, str(dict(tiers)))
    check("raw-e8 this FDE 2", counts.get(WINDOW, 0) == 2)

    # MANIFEST digests.
    man_ok = True
    man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
    for line in man:
        if not line.strip():
            continue
        digest, path = line.split(None, 1)
        path = path.strip().lstrip("*")
        full = os.path.normpath(os.path.join(PACKET, path))
        if not os.path.exists(full) or hashlib.sha256(open(full, "rb").read()).hexdigest() != digest:
            man_ok = False
    check("MANIFEST digests", man_ok, "%d entries" % len([l for l in man if l.strip()]))

    print("PASS count: %d, FAIL count: %d" % (len(passes), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
