#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-giveback-drivers.

Byte reads only; the node binary is never executed. objdump is used
solely to regenerate disassembly text for comparison (as in prior
packets); all semantic checks are re-derived from bytes.
"""
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-giveback-drivers")
BIN = os.path.join(ROOT, "artifacts/node/115/hl-node")

FAILURES = []


def check(name, ok, detail=""):
    print(("ok: " if ok else "FAIL: ") + name + ((" " + detail) if detail else ""))
    if not ok:
        FAILURES.append(name)


def elf_sections(data):
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[0x3A:0x40])
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        nm, typ, flags, addr, off, size, link, info, align, entsz = struct.unpack(
            "<IIQQQQIIQQ", data[o:o + 64])
        secs.append((nm, typ, addr, off, size, entsz))
    strtab_off = secs[e_shstrndx][3]

    def sname(n):
        e = data.index(b"\0", strtab_off + n)
        return data[strtab_off + n:e].decode()

    return {sname(s[0]): s for s in secs}


def va_to_off(sec, va):
    return va - sec[2] + sec[3]


def objdump_range(lo, hi):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(lo),
         "--stop-address=%s" % hex(hi), BIN],
        capture_output=True, text=True).stdout
    return [l for l in out.splitlines() if re.match(r"\s*[0-9a-f]+:", l)]


def parse_insns(lines):
    insns = []
    for line in lines:
        m = re.match(r"\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)\s*(.*)", line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2), m.group(3)))
    return insns


def strict_lines(lines):
    # mnemonic-line count: address + bytes field + tab + mnemonic.
    # objdump byte-continuation lines carry no mnemonic and are excluded.
    return [l for l in lines if re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t\S+", l)]


def eh_frame_fdes(data, eh):
    off, size = eh[3], eh[4]
    pos, end = off, off + size
    fde_enc = None
    out = {}

    def uleb(p):
        r = 0
        s = 0
        while True:
            b = data[p]
            p += 1
            r |= (b & 0x7F) << s
            if not (b & 0x80):
                break
            s += 7
        return r, p

    def sleb(p):
        r = 0
        s = 0
        while True:
            b = data[p]
            p += 1
            r |= (b & 0x7F) << s
            s += 7
            if not (b & 0x80):
                if b & 0x40:
                    r -= (1 << s)
                break
        return r, p

    while pos < end:
        ln = struct.unpack("<I", data[pos:pos + 4])[0]
        if ln == 0:
            break
        cie_id = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        body = pos + 8
        if cie_id == 0:
            aug_end = data.index(b"\0", body + 1)
            aug = data[body + 1:aug_end].decode("latin1")
            p = aug_end + 1
            _, p = uleb(p)
            _, p = sleb(p)
            _, p = uleb(p)
            if "z" in aug:
                alen, p2 = uleb(p)
                q = p2
                if "R" in aug:
                    fde_enc = data[q]
                p = p2 + alen
        else:
            if fde_enc == 0x1B:
                iloc = body + struct.unpack("<i", data[body:body + 4])[0]
                rng = struct.unpack("<I", data[body + 4:body + 8])[0]
                out[iloc] = rng
        pos += 4 + ln
    return out


def main():
    data = open(BIN, "rb").read()
    secs = elf_sections(data)
    text = secs[".text"]
    rela = secs[".rela.dyn"]
    rec = json.load(open(os.path.join(PACKET, "records.json")))

    import hashlib
    check("binary sha", hashlib.sha256(data).hexdigest() == rec["binary_sha256"])
    check("binary size", len(data) == rec["binary_bytes"],
          str(len(data)))

    fdes = {
        "A": (0x63B7900, 0x63B7EE6),
        "B": (0x63B7EF0, 0x63B8157),
        "D": (0x63B81B0, 0x63B8517),
    }
    fde_map = eh_frame_fdes(data, secs[".eh_frame"])
    for name, (lo, hi) in fdes.items():
        check("FDE %s bounds" % name, fde_map.get(lo) == hi - lo,
              "%s..%s" % (hex(lo), hex(hi)))
        r = rec["fdes"][name]
        check("FDE %s records size" % name,
              int(r["range"][0], 16) == lo and int(r["range"][1], 16) == hi
              and r["bytes"] == hi - lo)

    entries = {
        "A": bytes.fromhex("4157"),
        "B": bytes.fromhex("f30f1efa"),
        "D": bytes.fromhex("4157"),
    }
    for name, (lo, hi) in fdes.items():
        got = data[va_to_off(text, lo):va_to_off(text, lo) + len(entries[name])]
        check("FDE %s entry bytes" % name, got == entries[name], got.hex())
    pads = [(0x63B7EE6, 0x63B7EF0), (0x63B8157, 0x63B8160),
            (0x63B81AB, 0x63B81B0), (0x63B8517, 0x63B8520)]
    for lo, hi in pads:
        chunk = data[va_to_off(text, lo):va_to_off(text, hi)]
        check("int3 padding %s..%s" % (hex(lo), hex(hi)),
              chunk == b"\xcc" * (hi - lo), "%d bytes" % len(chunk))

    total_bytes = 0
    total_strict = 0
    for name, e in rec["exhibits"].items():
        lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
        raw = data[va_to_off(text, lo):va_to_off(text, hi)]
        hexlines = "".join(open(os.path.join(PACKET, name + ".hex")).read().split())
        check("%s length" % name, len(raw) == e["bytes"])
        check("%s bytes" % name, bytes.fromhex(hexlines) == raw)
        regen = objdump_range(lo, hi)
        stored = [l for l in open(os.path.join(PACKET, name + ".objdump.txt")).read().splitlines() if l.strip()]
        check("%s objdump regeneration" % name, regen == stored)
        check("%s strict" % name, len(strict_lines(regen)) == e["strict"],
              str(len(strict_lines(regen))))
        total_bytes += len(raw)
        total_strict += len(strict_lines(regen))
        inside = any(lo >= flo and hi <= fhi for flo, fhi in fdes.values())
        check("%s inside an FDE" % name, inside)
    check("exhibits total bytes", total_bytes == rec["exhibits_total_bytes"],
          str(total_bytes))
    check("exhibits total strict", total_strict == rec["exhibits_total_strict"],
          str(total_strict))

    # ret sites per FDE (objdump parse, range-restricted)
    expected_rets = {
        "A": [0x63B7AB5], "B": [], "D": [0x63B84D4],
    }
    for name, (lo, hi) in fdes.items():
        rets = [a for a, mn, _ in parse_insns(objdump_range(lo, hi)) if mn == "ret"]
        check("FDE %s ret sites" % name, rets == expected_rets[name],
              str([hex(r) for r in rets]))

    # jump targets internal, except B's PLT tail jmp
    for name, (lo, hi) in fdes.items():
        bad = []
        for a, mn, ops in parse_insns(objdump_range(lo, hi)):
            if mn.startswith("j"):
                tm = re.search(r"\b([0-9a-f]{6,})\s*<", ops)
                if tm:
                    t = int(tm.group(1), 16)
                    if not (lo <= t < hi):
                        if not (name == "B" and a == 0x63B8125 and t == 0x63F0B70):
                            bad.append((hex(a), mn, hex(t)))
        check("FDE %s jump targets internal" % name, not bad, str(bad))

    # give-back E8 sites: raw scan + objdump confirmation
    giveback = 0x63D8E70
    text_bytes = data[text[3]:text[3] + text[4]]
    text_va = text[2]
    raw_e8 = []
    for i in range(len(text_bytes) - 5):
        if text_bytes[i] == 0xE8:
            rel = struct.unpack("<i", text_bytes[i + 1:i + 5])[0]
            if text_va + i + 5 + rel == giveback:
                raw_e8.append(text_va + i)
    confirmed = []
    for site in raw_e8:
        lines = objdump_range(site, site + 16)
        for a, mn, ops in parse_insns(lines):
            if a == site and mn == "call" and "63d8e70" in ops:
                confirmed.append(site)
    expected = [int(s, 16) for s in rec["census"]["e8_to_giveback"]]
    check("census E8 confirmed", confirmed == expected,
          str([hex(s) for s in confirmed]))
    # rel32 of each expected site, direct from bytes
    for site in expected:
        o = va_to_off(text, site)
        rel = struct.unpack("<i", data[o + 1:o + 5])[0]
        check("E8 site %s rel32" % hex(site),
              data[o] == 0xE8 and site + 5 + rel == giveback)
    # E9 scan to give-back: expect none
    raw_e9 = []
    for i in range(len(text_bytes) - 5):
        if text_bytes[i] == 0xE9:
            rel = struct.unpack("<i", text_bytes[i + 1:i + 5])[0]
            if text_va + i + 5 + rel == giveback:
                raw_e9.append(text_va + i)
    check("census E9 empty", raw_e9 == [], str(raw_e9))
    # rip-relative LEA scan to give-back: expect none
    lea_hits = []
    for i in range(len(text_bytes) - 7):
        if text_bytes[i] in (0x48, 0x4C, 0x49, 0x4D) and text_bytes[i + 1] == 0x8D \
                and (text_bytes[i + 2] & 0xC7) == 0x05:
            rel = struct.unpack("<i", text_bytes[i + 3:i + 7])[0]
            if text_va + i + 7 + rel == giveback:
                lea_hits.append(text_va + i)
    check("census LEA empty", lea_hits == [], str(lea_hits))
    # .rela.dyn addends
    n = rela[4] // rela[5]
    total = 0
    hits = 0
    for i in range(n):
        o = rela[3] + i * rela[5]
        r_off, r_info, r_add = struct.unpack("<QQq", data[o:o + 24])
        total += 1
        if r_add == giveback:
            hits += 1
    check("rela.dyn entries", total == rec["census"]["rela_dyn_total"], str(total))
    check("census GOT empty", hits == 0, str(hits))

    # key flag-store bytes (post-call +0x13 writes)
    key_bytes = {
        0x63B7B06: "66896b13", 0x63B7D1B: "6644896313",
        0x63B7D99: "664589542413", 0x63B7E8B: "6641895c2413",
        0x63B7E43: "410f95442413", 0x63B7C6E: "0f954313",
        0x63B7FD1: "0f954513", 0x63B80B3: "6644894d13",
        0x63B8364: "410f954613", 0x63B842B: "6645895e13",
    }
    for site, hx in key_bytes.items():
        got = data[va_to_off(text, site):va_to_off(text, site) + len(bytes.fromhex(hx))]
        check("flag store %s" % hex(site), got == bytes.fromhex(hx), got.hex())
    # no +0x12 store anywhere in the four FDEs (objdump mnemonic scan)
    bad12 = []
    for name, (lo, hi) in fdes.items():
        for line in objdump_range(lo, hi):
            if re.search(r"0x12\(", line):
                bad12.append((name, line.strip()))
    check("no +0x12 store in drivers", not bad12, str(bad12[:3]))

    # disjointness against merged tree + prior worktree records
    mine = []
    for e in rec["exhibits"].values():
        mine.append((int(e["range"][0], 16), int(e["range"][1], 16)))
    for lo, hi in fdes.values():
        mine.append((lo, hi))
    others = []
    search_roots = [os.path.join(ROOT, "research/work-items")]
    for n in range(235, 245):
        search_roots.append(os.path.expanduser(
            "~/workspace/hl-wt-calls%d-115/research/work-items" % n))
    for root in search_roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            if "records.json" not in files:
                continue
            if os.path.abspath(dirpath).endswith("RE-001-node115-lu-giveback-drivers"):
                continue
            try:
                r = json.load(open(os.path.join(dirpath, "records.json")))
            except Exception:
                continue
            ex = r.get("exhibits", r) if isinstance(r, dict) else r
            items = ex.items() if isinstance(ex, dict) else enumerate(ex)
            for _k, v in items:
                try:
                    rg = v["range"]
                    others.append((int(rg[0], 16), int(rg[1], 16)))
                except Exception:
                    continue
            if isinstance(r, dict) and "fde" in r and isinstance(r["fde"], dict):
                try:
                    rg = r["fde"]["range"]
                    others.append((int(rg[0], 16), int(rg[1], 16)))
                except Exception:
                    pass
    overlaps = []
    for mlo, mhi in mine:
        for olo, ohi in others:
            if mlo < ohi and olo < mhi:
                overlaps.append((hex(mlo), hex(olo)))
    check("no neighbour overlap", not overlaps, str(overlaps[:5]))

    # MANIFEST coverage
    man_path = os.path.join(PACKET, "MANIFEST.sha256")
    man_lines = [l for l in open(man_path).read().splitlines() if l.strip()]
    check("MANIFEST entries", len(man_lines) == 15, str(len(man_lines)))
    import hashlib as _hl
    man_ok = True
    for line in man_lines:
        digest, rel = line.split(None, 1)
        rel = rel.strip()
        p = os.path.normpath(os.path.join(PACKET, rel))
        if not os.path.isfile(p) or _hl.sha256(open(p, "rb").read()).hexdigest() != digest:
            man_ok = False
    check("MANIFEST hashes match", man_ok)

    if FAILURES:
        print("verifier: FAILED (%d)" % len(FAILURES))
        return 1
    print("verifier: all checks passed (%d exhibits, %d bytes, %d strict, "
          "census %d E8 sites, MANIFEST 15 entries)"
          % (len(rec["exhibits"]), total_bytes, total_strict, len(expected)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
