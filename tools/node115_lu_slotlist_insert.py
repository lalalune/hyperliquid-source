#!/usr/bin/env python3
"""Static verifier for packet #247 (node #115 lu per-slot list insert).

Byte reads only; the node binary is never executed.
Checks: binary SHA/size, exhibit bytes, objdump regeneration, strict
counts, FDE bounds, entry bytes, ret sites, call rel32, key bytes,
jump targets internal, no flag-displacement reads or writes, full
census, neighbour disjointness, MANIFEST.
Exit 0 only when every check passes.
"""
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-slotlist-insert")
BINARY = os.path.join(ROOT, "artifacts/node/115/hl-node")

FAILURES = []


def check(name, ok, detail=""):
    print(("ok: " if ok else "FAIL: ") + name + ("" if ok else " " + str(detail)))
    if not ok:
        FAILURES.append(name)


def off(va):
    return va - 0x1000


def objdump_lines(lo, hi):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(lo),
         "--stop-address=%s" % hex(hi), BINARY],
        capture_output=True, text=True, check=True).stdout
    return [l for l in out.splitlines() if re.match(r"^\s*[0-9a-f]+:\t", l)]


def mnemonic(line):
    parts = line.split("\t")
    if len(parts) < 3:
        return None
    return parts[2].split()[0] if parts[2].split() else None


def jump_target(line):
    m = re.search(r"\b([0-9a-f]{6,})\b", line.split("\t")[-1])
    return int(m.group(1), 16) if m else None


def rel32_call(site):
    o = off(site)
    with open(BINARY, "rb") as f:
        f.seek(o)
        b = f.read(5)
    if b[0] != 0xE8:
        return None
    return site + 5 + struct.unpack("<i", b[1:5])[0]


def rel32_jump(site, width):
    o = off(site)
    with open(BINARY, "rb") as f:
        f.seek(o)
        b = f.read(width)
    if width == 6:
        if b[0] != 0x0F:
            return None
        return site + 6 + struct.unpack("<i", b[2:6])[0]
    if width == 5:
        if b[0] != 0xE9:
            return None
        return site + 5 + struct.unpack("<i", b[1:5])[0]
    if width == 2:
        if b[0] != 0xEB and not (0x70 <= b[0] <= 0x7F):
            return None
        return site + 2 + struct.unpack("<b", b[1:2])[0]
    return None


def main():
    with open(os.path.join(PACKET, "records.json")) as f:
        rec = json.load(f)
    with open(BINARY, "rb") as f:
        raw = f.read()
    check("binary sha",
          hashlib.sha256(raw).hexdigest() == rec["binary_sha256"])
    check("binary size", len(raw) == rec["binary_bytes"], len(raw))

    exhibits = rec["exhibits"]
    total_bytes = 0
    total_strict = 0
    ranges = []
    for name, e in sorted(exhibits.items()):
        lo = int(e["range"][0], 16)
        hi = int(e["range"][1], 16)
        with open(os.path.join(PACKET, name + ".hex")) as f:
            hexs = "".join(f.read().split())
        data = bytes.fromhex(hexs)
        check(name + " length", len(data) == e["bytes"], len(data))
        check(name + " bytes", raw[off(lo):off(hi)] == data)
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            stored = f.read()
        regen = "\n".join(objdump_lines(lo, hi)) + "\n"
        check(name + " objdump regeneration", stored == regen)
        strict = sum(1 for l in objdump_lines(lo, hi) if l.count("\t") >= 2)
        check(name + " strict", strict == e["strict"], strict)
        check(name + " inside FDE",
              int(rec["fde"][0], 16) <= lo and hi <= int(rec["fde"][1], 16))
        total_bytes += len(data)
        total_strict += strict
        ranges.append((lo, hi, name))
    check("exhibits total bytes", total_bytes == rec["exhibits_total_bytes"],
          total_bytes)
    check("exhibits total strict", total_strict == rec["exhibits_total_strict"],
          total_strict)
    ranges.sort()
    for (lo1, hi1, n1), (lo2, hi2, n2) in zip(ranges, ranges[1:]):
        check("exhibits pairwise disjoint %s/%s" % (n1, n2), hi1 <= lo2)

    lo = int(rec["fde"][0], 16)
    hi = int(rec["fde"][1], 16)
    check("FDE size", hi - lo == rec["fde_bytes"], hi - lo)
    check("FDE entry push rbp, no endbr64",
          raw[off(lo):off(lo) + 4] == bytes.fromhex("554889fd"))
    check("padding before FDE is int3",
          raw[off(0x63d88c4):off(lo)] == b"\xcc" * 12)
    check("next FDE starts at hi with endbr64",
          raw[off(hi):off(hi) + 4] == bytes.fromhex("f30f1efa"))

    full = objdump_lines(lo, hi)
    rets = []
    calls = []
    jumps_ok = True
    for line in full:
        m = mnemonic(line)
        addr = int(line.split(":")[0].strip(), 16)
        if m == "ret":
            rets.append(hex(addr))
        elif m == "call":
            calls.append(jump_target(line))
        elif m in ("jmp", "je", "jne", "jb", "jae", "ja", "jbe", "js", "jns",
                   "jle", "jg", "jge", "jl", "jnp", "jp"):
            t = jump_target(line)
            if t is None or not (lo <= t < hi):
                jumps_ok = False
    check("two ret sites", rets == rec["ret_sites"], rets)
    check("one internal call", sorted(calls) == sorted(
        [int(x, 16) for x in rec["internal_calls"]]), calls)
    check("jump targets internal", jumps_ok)
    check("call 0x63d894e -> size mapper",
          rel32_call(0x63d894e) == 0x63e8bf0)
    check("jne nonzero -> size arm 0x63d8940",
          rel32_jump(0x63d88e3, 2) == 0x63d8940)
    check("je slot zero -> empty 0x63d89c0",
          rel32_jump(0x63d88fc, 6) == 0x63d89c0)
    check("jb overflow -> stub 0x63d89f8",
          rel32_jump(0x63d8963, 6) == 0x63d89f8)
    check("jmp size -> shared slot load 0x63d88ed",
          rel32_jump(0x63d89b5, 5) == 0x63d88ed)
    check("jmp overflow -> slot number 0x63d89a5",
          rel32_jump(0x63d89fe, 2) == 0x63d89a5)
    check("size input mov 0xb0",
          raw[off(0x63d8940):off(0x63d8940) + 7] == bytes.fromhex("488bbe b0000000".replace(" ", "")))
    check("size input sub rax",
          raw[off(0x63d8947):off(0x63d8947) + 3] == bytes.fromhex("4829c7"))
    check("size input shl 12",
          raw[off(0x63d894a):off(0x63d894a) + 4] == bytes.fromhex("48c1e70c"))
    check("overflow stub r10d = 0x18e",
          raw[off(0x63d89f8):off(0x63d89f8) + 6] == bytes.fromhex("41ba8e010000"))
    check("zero slot load",
          raw[off(0x63d88f4):off(0x63d88f4) + 5] == bytes.fromhex("488b44d508"))
    check("bitmap set or bytes",
          raw[off(0x63d89d9):off(0x63d89d9) + 8] == bytes.fromhex("4e099cd588140000"))
    check("self-link movups",
          raw[off(0x63d89e1):off(0x63d89e1) + 4] == bytes.fromhex("0f114340"))
    check("splice first store [block+0x48] := block",
          raw[off(0x63d8902):off(0x63d8902) + 4] == bytes.fromhex("48895b48"))
    check("splice slot store",
          raw[off(0x63d892e):off(0x63d892e) + 5] == bytes.fromhex("48895cd508"))
    flag_pats = ["0x11(", "0x12(", "0x13(", "0x14(", "0x20(", "0x23("]
    flag_lines = [l for l in full
                  if any(p in l for p in flag_pats)]
    check("no flag-displacement reads or writes", flag_lines == [], flag_lines[:2])

    # Census: raw .text scan, objdump-confirmed, rel32-verified.
    text_off, text_size, text_va = 0x1418300, 0x4fd7700, 0x1419300
    text = raw[text_off:text_off + text_size]
    e8 = []
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            t = text_va + i + 5 + struct.unpack("<i", text[i + 1:i + 5])[0]
            if t == lo:
                e8.append(text_va + i)
    e8_conf = []
    for site in e8:
        lines = objdump_lines(site - 16, site + 8)
        for l in lines:
            if int(l.split(":")[0].strip(), 16) == site and mnemonic(l) == "call":
                e8_conf.append(site)
    check("census E8", e8_conf == [int(x, 16) for x in rec["census"]["e8_to_fde"]],
          [hex(s) for s in e8_conf])
    check("census E8 rel32 0x63d9247", rel32_call(0x63d9247) == lo)
    check("census E8 rel32 0x63d967f", rel32_call(0x63d967f) == lo)
    e9 = []
    for i in range(len(text) - 5):
        if text[i] == 0xE9:
            t = text_va + i + 5 + struct.unpack("<i", text[i + 1:i + 5])[0]
            if t == lo:
                e9.append(text_va + i)
    check("census E9 empty", e9 == [], [hex(s) for s in e9])
    lea = []
    for i in range(len(text) - 7):
        if text[i] in (0x48, 0x4C, 0x49, 0x4D) and text[i + 1] == 0x8D \
                and (text[i + 2] & 0xC7) == 0x05:
            t = text_va + i + 7 + struct.unpack("<i", text[i + 3:i + 7])[0]
            if t == lo:
                lea.append(text_va + i)
    check("census LEA empty", lea == [], [hex(s) for s in lea])
    rela_off, rela_n = 0x6BE8, 60723
    addends = 0
    for i in range(rela_n):
        add = struct.unpack("<q", raw[rela_off + i * 24 + 16:rela_off + i * 24 + 24])[0]
        if add == lo:
            addends += 1
    check("rela.dyn 60723 entries", rela_n == rec["census"]["rela_dyn_entries"])
    check("census GOT empty", addends == rec["census"]["rela_dyn_addend_hits"],
          addends)

    # Neighbour disjointness over the merged tree + prior worktrees.
    def collect_ranges(path):
        try:
            with open(path) as f:
                r = json.load(f)
        except Exception:
            return []
        out = []
        if isinstance(r, dict):
            if "fde" in r and isinstance(r["fde"], list) and len(r["fde"]) == 2:
                try:
                    out.append((int(r["fde"][0], 16), int(r["fde"][1], 16)))
                except Exception:
                    pass
            if "insert_fde" in r and isinstance(r["insert_fde"], dict):
                try:
                    out.append((int(r["insert_fde"]["start"], 16),
                                int(r["insert_fde"]["end"], 16)))
                except Exception:
                    pass
            ex = r.get("exhibits")
            items = ex.items() if isinstance(ex, dict) else (
                enumerate(ex) if isinstance(ex, list) else [])
            for _, e in items:
                try:
                    out.append((int(e["range"][0], 16), int(e["range"][1], 16)))
                except Exception:
                    pass
        return out
    total = 0
    overlaps = []
    paths = glob.glob(os.path.join(ROOT, "research/work-items/*/records.json"))
    paths += glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json")
    for path in sorted(set(paths)):
        if "lu-slotlist-insert" in path:
            continue
        for (a, b) in collect_ranges(path):
            total += 1
            if a < hi and lo < b:
                overlaps.append((path, hex(a), hex(b)))
            for (elo, ehi, ename) in ranges:
                if a < ehi and elo < b:
                    overlaps.append((path, hex(a), hex(b), ename))
    print("note: disjointness ranges checked %d" % total)
    check("no neighbour overlap", overlaps == [], overlaps[:3])

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        man = f.read().strip().splitlines()
    check("MANIFEST 17 entries", len(man) == 17, len(man))
    man_ok = True
    for line in man:
        h, path = line.split(None, 1)
        fullp = os.path.normpath(os.path.join(PACKET, path.strip().lstrip("*")))
        try:
            with open(fullp, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            man_ok = False
            continue
        if digest != h:
            man_ok = False
    check("MANIFEST hashes match", man_ok)

    if FAILURES:
        print("verifier: FAILED (%d checks)" % len(FAILURES))
        sys.exit(1)
    print("verifier: all checks passed (6 excerpts, 285 bytes, 74 strict, "
          "census 2 E8 sites, MANIFEST 17 entries)")


if __name__ == "__main__":
    main()
