#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-2sites-walk-10rsp.

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
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-bintableinit-caller-2sites-walk-10rsp")
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-walk-10rsp"

EXPECTED_SIZE = 105896032
EXPECTED_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOW = (0x636B940, 0x636BD90)
PREV_FDE = (0x636B8F0, 0x636B937)
NEXT_FDE = (0x636BD90, 0x636C49C)
BTI_SITES = ["636baf8", "636bb5d"]
MISS_SITES = ["636bcee", "636bd81"]
MISS_REJOINS = {"636bcee": "636ba38", "636bd81": "636b9f5"}

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
    check("gap before 9", WINDOW[0] - PREV_FDE[1] == 9)
    check("padding after 0", NEXT_FDE[0] - WINDOW[1] == 0)

    def toff(va):
        return va - 0x1000

    gap = blob[toff(PREV_FDE[1]):toff(WINDOW[0])]
    check("gap bytes int3", gap == b"\xcc" * 9, gap.hex())

    hexpath = os.path.join(PACKET, "bintableinit_caller_walk_10rsp_2sites.hex")
    raw = open(hexpath, "rb").read()
    check("exhibit bytes", raw == blob[toff(WINDOW[0]):toff(WINDOW[1])],
          "%d bytes" % len(raw))
    check("exhibit size 1104", len(raw) == 1104)

    txt = open(os.path.join(PACKET, "bintableinit_caller_walk_10rsp_2sites.objdump.txt")).read().splitlines()
    strict = [l for l in txt if STRICT.match(l)]
    check("strict recount 228", len(strict) == 228, str(len(strict)))

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
    locksub = [l for l in strict if re.search(r"\tlock sub\s", l)]
    lockadd = [l for l in strict if re.search(r"\tlock add\s", l)]
    check("call census 6", len(calls) == 6, str(len(calls)))
    check("bin_table_init count 2", len(bti) == 2)
    check("bin_table_init sites exact",
          [STRICT.match(l).group(1) for l in bti] == BTI_SITES)
    check("lu-miss count 2", len(miss) == 2)
    check("lu-miss sites exact",
          [STRICT.match(l).group(1) for l in miss] == MISS_SITES)
    check("ret count 1", len(ret) == 1)
    check("ret site 636ba87",
          ret and STRICT.match(ret[0]).group(1) == "636ba87")
    check("bsr count 1", len(bsr) == 1)
    check("bsr site 636bab9",
          bsr and STRICT.match(bsr[0]).group(1) == "636bab9")
    check("lock sub count 0", len(locksub) == 0)
    check("lock add count 1", len(lockadd) == 1)
    check("lock add site 636ba57",
          lockadd and STRICT.match(lockadd[0]).group(1) == "636ba57")

    def line_at(addr):
        for l in strict:
            if STRICT.match(l).group(1) == addr:
                return l
        return None

    def window_lines(addr, n):
        idx = next(i for i, l in enumerate(strict) if STRICT.match(l).group(1) == addr)
        return strict[max(0, idx - n):idx + 1]

    def lines_after(addr, n):
        idx = next(i for i, l in enumerate(strict) if STRICT.match(l).group(1) == addr)
        return strict[idx + 1:idx + 1 + n]

    # Site 1: block 636baf0, lea 0x10(%rsp) into r12, mov r12->rdi, call.
    check("site1 block lea",
          line_at("636baf0") is not None and "lea" in line_at("636baf0") and "0x10(%rsp)" in line_at("636baf0"))
    check("site1 rdi from r12",
          line_at("636baf5") is not None and re.search(r"mov\s+%r12,%rdi", line_at("636baf5")))
    check("site1 call line", line_at("636baf8") is not None and "63d9880" in line_at("636baf8"))
    check("site1 null-context branch",
          line_at("636b9b7") is not None and "je" in line_at("636b9b7") and "636baf0" in line_at("636b9b7"))
    check("site1 rejoin",
          any(re.search(r"\tjmp\s", l) and "636b9bd" in l for l in lines_after("636baf8", 2)))
    # Site 2: block 636bb50, lea 0x10(%rsp) into rdx, mov rdx->rdi, call.
    check("site2 block lea",
          line_at("636bb50") is not None and "lea" in line_at("636bb50") and "0x10(%rsp)" in line_at("636bb50"))
    check("site2 rdi from rdx",
          line_at("636bb55") is not None and re.search(r"mov\s+%rdx,%rdi", line_at("636bb55")))
    check("site2 call line", line_at("636bb5d") is not None and "63d9880" in line_at("636bb5d"))
    check("site2 null-context branch",
          line_at("636ba11") is not None and "je" in line_at("636ba11") and "636bb50" in line_at("636ba11"))
    check("site2 rejoin",
          any(re.search(r"\tjmp\s", l) and "636ba17" in l for l in lines_after("636bb5d", 2)))
    # Miss sites: rsi = lea 0x6511a00 above, jmp to expected rejoin within 4 strict lines after.
    for site, rejoin in MISS_REJOINS.items():
        idx = next(i for i, l in enumerate(strict) if STRICT.match(l).group(1) == site)
        above = strict[max(0, idx - 12):idx + 1]
        after = strict[idx + 1:idx + 5]
        check("miss " + site + " rsi table",
              any("lea" in l and "6511a00" in l for l in above))
        check("miss " + site + " rejoin " + rejoin,
              any(re.search(r"\tjmp\s", l) and rejoin in l for l in after))
    # Frame + canary: sub $0x1a8, canary at 0x198(%rsp), check -> stack_chk_fail.
    check("frame sub",
          line_at("636b950") is not None and "sub" in line_at("636b950") and "$0x1a8,%rsp" in line_at("636b950"))
    check("canary stored",
          line_at("636b967") is not None and "0x198(%rsp)" in line_at("636b967"))
    check("canary check",
          line_at("636ba6d") is not None and "jne" in line_at("636ba6d") and "636bd8b" in line_at("636ba6d"))
    check("stack_chk_fail call",
          line_at("636bd8b") is not None and "63f0d70" in line_at("636bd8b"))
    # Exit: exactly one ret, no jmp leaves the window, epilogue before the ret.
    outside = []
    for l in strict:
        m = STRICT.match(l)
        if m.group(3) == "jmp":
            t = m.group(4).strip().split()[0]
            if re.match(r"^[0-9a-f]+$", t) and not (WINDOW[0] <= int(t, 16) < WINDOW[1]):
                outside.append((m.group(1), t))
    check("no outside jmp", outside == [], str(outside))
    epi = window_lines("636ba87", 14)
    check("exit epilogue", any("add" in l and "$0x1a8,%rsp" in l for l in epi))
    # Entry gate: size > 0x1000 -> size-class block; else threshold table byte.
    check("size gate",
          line_at("636b975") is not None and "cmp" in line_at("636b975") and "$0x1000" in line_at("636b975"))
    check("size gate branch",
          line_at("636b97c") is not None and "ja" in line_at("636b97c") and "636ba90" in line_at("636b97c"))
    check("threshold table lea",
          line_at("636b982") is not None and "lea" in line_at("636b982") and "67277c0" in line_at("636b982"))
    check("threshold byte load",
          line_at("636b991") is not None and "movzbl" in line_at("636b991"))
    check("helper call",
          line_at("636b99c") is not None and re.search(r"\tcall\s", line_at("636b99c")) and "6364880" in line_at("636b99c"))
    check("key from helper",
          line_at("636b9a1") is not None and re.search(r"mov\s+%rax,%rbx", line_at("636b9a1")))
    # Size-class block: movabs, bsr, 0xe8 fallback, rejoin at 636b996.
    check("sizeclass movabs",
          line_at("636ba90") is not None and "0x7000000000000000" in line_at("636ba90"))
    check("sizeclass bsr",
          line_at("636bab9") is not None and "bsr" in line_at("636bab9"))
    check("sizeclass fallback",
          line_at("636bbb8") is not None and "$0xe8" in line_at("636bbb8"))
    check("sizeclass rejoin",
          line_at("636bae2") is not None and "jmp" in line_at("636bae2") and "636b996" in line_at("636bae2"))
    # Walk: table lea, top index, high bits, second level, node table, field extract.
    check("walk table lea",
          line_at("636b9ad") is not None and "0x1b0(%rbp)" in line_at("636b9ad"))
    check("walk top index",
          line_at("636b9c3") is not None and "shr" in line_at("636b9c3") and "$0x1a" in line_at("636b9c3"))
    check("walk high bits",
          line_at("636b9c7") is not None and "0xffffffffc0000000" in line_at("636b9c7"))
    check("walk second level",
          line_at("636b9e8") is not None and "shr" in line_at("636b9e8") and "$0x9" in line_at("636b9e8"))
    check("node table 6727a00",
          line_at("636b9f8") is not None and "6727a00" in line_at("636b9f8"))
    check("node value shift",
          line_at("636ba06") is not None and "shr" in line_at("636ba06") and "$0x30" in line_at("636ba06"))
    check("field extract",
          line_at("636ba3b") is not None and "shl" in line_at("636ba3b") and "$0x10" in line_at("636ba3b"))
    check("field mask",
          line_at("636ba43") is not None and "0xffffffffffffff80" in line_at("636ba43"))
    check("index table 65096c0",
          line_at("636b957") is not None and "65096c0" in line_at("636b957"))
    # Scans: slot 0/1 compares and a reversed-operand compare in each scan.
    check("scan1 slot0",
          line_at("636bb08") is not None and "cmp" in line_at("636bb08") and "0x100(%rsi)" in line_at("636bb08"))
    check("scan1 slot1",
          line_at("636bc17") is not None and "cmp" in line_at("636bc17") and "0x110(%rsi)" in line_at("636bc17"))
    check("scan1 reversed cmp",
          line_at("636bd21") is not None and re.search(r"cmp\s+%r15,0x140\(%rsi\)", line_at("636bd21")))
    check("scan2 slot0",
          line_at("636bb70") is not None and "cmp" in line_at("636bb70") and "0x100(%rdx)" in line_at("636bb70"))
    check("scan2 slot1",
          line_at("636bbc8") is not None and "cmp" in line_at("636bbc8") and "0x110(%rdx)" in line_at("636bbc8"))
    check("scan2 reversed cmp",
          line_at("636bc65") is not None and re.search(r"cmp\s+%r15,0x120\(%rdx\)", line_at("636bc65")))

    # Records consistency.
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    w = rec["window"]
    check("records window", w["range"] == "0x636b940..0x636bd90" and w["bytes"] == 1104
          and w["strict_lines"] == 228 and w["calls_total"] == 6 and w["ret"] == 1
          and w["bsr"] == 1 and w["lock_sub"] == 0)
    check("records sites",
          [s["site"] for s in rec["bin_table_init_sites"]] == ["0x636baf8", "0x636bb5d"]
          and [s["site"] for s in rec["lu_miss_sites"]] == ["0x636bcee", "0x636bd81"])

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
            if rng and rng != "0x636b940..0x636bd90":
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
