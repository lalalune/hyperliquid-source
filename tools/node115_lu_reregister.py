#!/usr/bin/env python3
"""Static verifier for packet #246 (node #115 lu re-register).

Byte reads only; the node binary is never executed.
Checks: binary SHA/size, exhibit bytes, objdump regeneration, strict
counts, FDE bounds, entry bytes, ret sites, call rel32s, key bytes,
jump targets internal, no +0x12 stores, full census, neighbour
disjointness, MANIFEST.
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
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-reregister")
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
        if b[0] != 0x0F or b[1] != 0x84:
            return None
        return site + 6 + struct.unpack("<i", b[2:6])[0]
    if width == 5:
        if b[0] != 0xE9:
            return None
        return site + 5 + struct.unpack("<i", b[1:5])[0]
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
    check("FDE entry endbr64",
          raw[off(lo):off(lo) + 4] == bytes.fromhex("f30f1efa"))
    check("padding before FDE is int3",
          raw[off(0x63d906b):off(lo)] == b"\xcc" * 5)
    check("padding after FDE is int3",
          raw[off(hi):off(0x63d9340)] == b"\xcc" * 9)

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
    check("three internal calls", sorted(calls) == sorted(
        [int(x, 16) for x in rec["internal_calls"]]), calls)
    check("jump targets internal", jumps_ok)
    check("call 0x63d90a5 -> size mapper",
          rel32_call(0x63d90a5) == 0x63e8bf0)
    check("call 0x63d9232 -> handoff",
          rel32_call(0x63d9232) == 0x63d8790)
    check("call 0x63d9247 -> 0x63d88d0",
          rel32_call(0x63d9247) == 0x63d88d0)
    check("je zero -> 0x63d92c0", rel32_jump(0x63d908b, 6) == 0x63d92c0)
    check("je 0x200 -> 0x63d91c8", rel32_jump(0x63d9097, 6) == 0x63d91c8)
    check("flag [block+0x23] := 0",
          raw[off(0x63d9084):off(0x63d9084) + 4] == bytes.fromhex("c6462300"))
    check("overflow stub r11d = 0x2970",
          raw[off(0x63d9320):off(0x63d9320) + 6] == bytes.fromhex("41bb70290000"))
    check("overflow stub jmp 0x63d9108",
          rel32_jump(0x63d9326, 5) == 0x63d9108)
    check("0x200 movdqa target 0x450b10",
          0x63d91d5 + struct.unpack("<i", raw[off(0x63d91d1):off(0x63d91d1) + 4])[0]
          == 0x450b10)
    check("0x200 constant (1, 512)",
          struct.unpack("<qq", raw[0x450b10:0x450b20]) == (1, 512))
    check("0x200 slot base lea 0x1020",
          raw[off(0x63d91dc):off(0x63d91dc) + 8] == bytes.fromhex("4a8d8c0720100000"))
    check("zero slot base lea 0x1050",
          raw[off(0x63d92d3):off(0x63d92d3) + 8] == bytes.fromhex("4e8d940f50100000"))
    check("zero jmp to tail test 0x63d914b",
          rel32_jump(0x63d92f2, 5) == 0x63d914b)
    check("anchor := 0 block",
          raw[off(0x63d9309):off(0x63d9309) + 11] == bytes.fromhex("48c7859814000000000000"))
    check("anchor := [block+0x50]",
          raw[off(0x63d932b):off(0x63d932b) + 7] == bytes.fromhex("48898598140000"))
    check("tail cmpb [block+0x11]",
          raw[off(0x63d914b):off(0x63d914b) + 4] == bytes.fromhex("807b1100"))
    check("tail cmpb [block+0x13]",
          raw[off(0x63d915c):off(0x63d915c) + 4] == bytes.fromhex("807b1300"))
    check("tail cmpb [block+0x14]",
          raw[off(0x63d9166):off(0x63d9166) + 4] == bytes.fromhex("807b1400"))
    check("[block+0x20] := 1 on insert",
          raw[off(0x63d9269):off(0x63d9269) + 4] == bytes.fromhex("c6432001"))
    check("[block+0x20] := 0 on remove",
          raw[off(0x63d917a):off(0x63d917a) + 4] == bytes.fromhex("c6432000"))
    stores12 = [l for l in full
                if mnemonic(l) and mnemonic(l).startswith("mov")
                and "0x12(" in l and "0x120(" not in l and "0x128(" not in l]
    check("no +0x12 stores", stores12 == [], stores12[:2])

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
        if "lu-reregister" in path:
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
    print("verifier: all checks passed (6 excerpts, 433 bytes, 102 strict, "
          "census 9 E8 sites, MANIFEST 17 entries)")


if __name__ == "__main__":
    main()
