#!/usr/bin/env python3
"""Static verifier for packet #250 (node #115 lu merge callers).

Byte reads only; the node binary is never executed.
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
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-merge-callers")
BINARY = os.path.join(ROOT, "artifacts/node/115/hl-node")

FAILURES = []


def check(name, ok, detail=""):
    print("%s: %s%s" % ("ok" if ok else "FAIL", name,
                        (" (%s)" % detail) if detail != "" else ""))
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


def rel32(site, raw, want_kind):
    o = off(site)
    if want_kind == "call" and raw[o] != 0xE8:
        return None
    if want_kind == "jmp" and raw[o] != 0xE9:
        return None
    return site + 5 + struct.unpack("<i", raw[o + 1:o + 5])[0]


def main():
    with open(os.path.join(PACKET, "records.json")) as f:
        rec = json.load(f)
    with open(BINARY, "rb") as f:
        raw = f.read()
    check("binary sha",
          hashlib.sha256(raw).hexdigest() == rec["binary_sha256"])
    check("binary size", len(raw) == rec["binary_bytes"])

    # Exhibits: length, bytes, objdump regeneration, strict, inside an FDE.
    fdes = []
    for key in ("callerA", "callerB"):
        lo, hi = (int(x, 16) for x in rec[key]["fde"])
        fdes.append((lo, hi))
    for name, e in rec["exhibits"].items():
        lo, hi = int(e["range"][0], 16), int(e["range"][1], 16)
        with open(os.path.join(PACKET, name + ".hex")) as f:
            hexs = "".join(f.read().split())
        check("%s length" % name, len(bytes.fromhex(hexs)) == e["bytes"])
        check("%s bytes" % name, raw[off(lo):off(hi)] == bytes.fromhex(hexs))
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            stored = f.read()
        check("%s objdump regeneration" % name,
              stored == "\n".join(objdump_lines(lo, hi)) + "\n")
        strict = sum(1 for l in objdump_lines(lo, hi) if l.count("\t") >= 2)
        check("%s strict" % name, strict == e["strict"], strict)
        check("%s inside FDE" % name,
              any(lo >= flo and hi <= fhi for flo, fhi in fdes))
    check("exhibits total bytes",
          sum(e["bytes"] for e in rec["exhibits"].values())
          == rec["exhibits_total_bytes"])
    check("exhibits total strict",
          sum(e["strict"] for e in rec["exhibits"].values())
          == rec["exhibits_total_strict"])
    ranges = [(int(e["range"][0], 16), int(e["range"][1], 16))
              for e in rec["exhibits"].values()]
    for i in range(len(ranges)):
        for j in range(i + 1, len(ranges)):
            a1, b1 = ranges[i]
            a2, b2 = ranges[j]
            check("exhibits pairwise disjoint %d/%d" % (i, j),
                  b1 <= a2 or b2 <= a1)

    # FDE bounds, entries, padding.
    a_lo, a_hi = fdes[0]
    b_lo, b_hi = fdes[1]
    check("FDE size callerA", a_hi - a_lo == 82, a_hi - a_lo)
    check("FDE size callerB", b_hi - b_lo == 300, b_hi - b_lo)
    check("FDE entry callerA endbr64",
          raw[off(a_lo):off(a_lo) + 4] == bytes.fromhex("f30f1efa"))
    check("FDE entry callerB endbr64",
          raw[off(b_lo):off(b_lo) + 4] == bytes.fromhex("f30f1efa"))
    check("no padding before callerA (prev FDE ends with ret)",
          raw[off(a_lo) - 1] == 0xC3)
    check("padding between A and B is int3",
          raw[off(a_hi):off(b_lo)] == b"\xcc" * 14)
    check("padding after callerB is int3",
          raw[off(b_hi):off(b_hi) + 4] == b"\xcc" * 4)
    check("next FDE after B starts with endbr64",
          raw[off(b_hi) + 4:off(b_hi) + 8] == bytes.fromhex("f30f1efa"))
    check("callerA ret site",
          raw[off(0x63b91d1)] == 0xC3)
    b_lines = objdump_lines(b_lo, b_hi)
    b_mnems = [mnemonic(l) for l in b_lines if mnemonic(l)]
    check("callerB has no ret mnemonic", "ret" not in b_mnems)
    check("callerB tail jmp to unlock plt",
          rel32(0x63b92d4, raw, "jmp") == 0x63f0b70)

    # Internal calls of B.
    for site, tgt in [(0x63b920c, 0x63f17b0), (0x63b9247, 0x63f17b0),
                      (0x63b92e3, 0x63bf680), (0x63b92fb, 0x63bf680),
                      (0x63b92b7, 0x63f0b70)]:
        check("call %s -> %s" % (hex(site), hex(tgt)),
              rel32(site, raw, "call") == tgt)
    # Merge calls.
    for site in (0x63b9190, 0x63b9272):
        check("merge call %s -> 0x63d8b20" % hex(site),
              rel32(site, raw, "call") == 0x63d8b20)
    # Internal jump targets of B lie inside B (tail jmp excluded: PLT).
    for l in b_lines:
        mn = mnemonic(l)
        if mn in ("jne", "je", "jmp"):
            rest = l.split("\t")[-1].strip()
            m = re.search(r"\b(0x[0-9a-f]+)\s*$", rest)
            if m:
                tgt = int(m.group(1), 16)
                check("jump target internal %s" % hex(tgt),
                      b_lo <= tgt < b_hi or tgt == 0x63f0b70, hex(tgt))
    # Key bytes: flag stores.
    check("flag clear +0xa8",
          raw[off(0x63b92b0):off(0x63b92b0) + 7]
          == bytes.fromhex("c683a800000000"))
    check("flag clear +0x118",
          raw[off(0x63b92bf):off(0x63b92bf) + 7]
          == bytes.fromhex("c6831801000000"))
    check("flag set +0x118 on wait path",
          raw[off(0x63b92e8):off(0x63b92e8) + 7]
          == bytes.fromhex("c6831801000001"))
    check("flag set +0xa8 on wait path",
          raw[off(0x63b9300):off(0x63b9300) + 7]
          == bytes.fromhex("c683a800000001"))
    # Counters: exact addq $1 instruction bytes at the four slots.
    for addr, slot, hx in [(0x63b9219, "+0xe8", "488383e800000001"),
                           (0x63b922a, "+0xd8", "488383d800000001"),
                           (0x63b9254, "+0x78", "4883437801"),
                           (0x63b925f, "+0x68", "4883436801")]:
        n = len(bytes.fromhex(hx))
        check("counter addq $1 %s" % slot,
              raw[off(addr):off(addr) + n] == bytes.fromhex(hx))

    # Census: sites rel32-confirmed; E9/LEA/rela from records + rescan.
    for site, tgt in [("0x63a734e", 0x63b9180), ("0x63c0ad3", 0x63b91e0)]:
        s = int(site, 16)
        check("census E8 rel32 %s" % site, rel32(s, raw, "call") == tgt)
    check("census E9 empty", rec["census"]["e9_to_callers"] == [])
    check("census LEA empty", rec["census"]["lea_to_callers"] == [])
    check("census rela.dyn entries",
          rec["census"]["rela_dyn_entries"] == 60723)
    rela_off, rela_size = 0x6BE8, 0x163CC8
    hits = 0
    for i in range(rela_size // 24):
        o = rela_off + i * 24
        addend = struct.unpack("<q", raw[o + 16:o + 24])[0]
        if addend in (0x63b9180, 0x63b91e0):
            hits += 1
    check("rela.dyn rescan hits 0", hits == 0, hits)

    # Neighbour disjointness against merged + prior worktree records,
    # deduplicated by path string; ranges deduplicated as a set.
    pair_re = re.compile(r"0x([0-9a-fA-F]+)\s*\.\.\s*0x([0-9a-fA-F]+)")
    ranges2 = set()
    paths = glob.glob(os.path.join(ROOT, "research/work-items/*/records.json"))
    paths += glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json")
    for p in sorted(set(paths)):
        if "lu-merge-callers" in p:
            continue
        try:
            with open(p) as f:
                rec2 = json.load(f)
        except Exception:
            continue
        stack = [rec2]
        while stack:
            o2 = stack.pop()
            if isinstance(o2, dict):
                for k, v in o2.items():
                    if k in ("range", "fde") and isinstance(v, str):
                        for a, b in pair_re.findall(v):
                            ranges2.add((int(a, 16), int(b, 16)))
                    elif k in ("range", "fde") and isinstance(v, list) and len(v) == 2:
                        try:
                            ranges2.add((int(str(v[0]), 16), int(str(v[1]), 16)))
                        except Exception:
                            pass
                    else:
                        stack.append(v)
            elif isinstance(o2, list):
                stack.extend(o2)
    over = []
    for (flo, fhi) in fdes:
        for (a, b) in ranges2:
            if a < fhi and flo < b:
                over.append((hex(a), hex(b)))
    check("no neighbour overlap", over == [], over[:3])
    print("note: disjointness ranges checked %d" % len(ranges2))

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        man_lines = [l.split() for l in f.read().splitlines() if l.strip()]
    check("MANIFEST 15 entries", len(man_lines) == 15, len(man_lines))
    man_ok = True
    for h, rel in man_lines:
        p = os.path.normpath(os.path.join(PACKET, rel))
        if not os.path.exists(p) or hashlib.sha256(open(p, "rb").read()).hexdigest() != h:
            man_ok = False
    check("MANIFEST hashes match", man_ok)

    if FAILURES:
        print("verifier: FAILED (%s)" % ", ".join(FAILURES))
        sys.exit(1)
    print("verifier: all checks passed (5 excerpts, 382 bytes, 86 strict, "
          "census 2 E8 sites, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
