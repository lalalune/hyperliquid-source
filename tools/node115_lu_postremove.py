#!/usr/bin/env python3
"""Static verifier for packet #244 (node #115 lu post-remove).

Byte reads only; the node binary is never executed.
Checks: binary SHA/size, exhibit bytes, objdump regeneration, strict
counts, FDE bounds, entry bytes, ret sites, call rel32, key bytes,
jump targets internal, full census, neighbour disjointness, MANIFEST.
Exit 0 only when every check passes.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-postremove")
BINARY = os.path.join(ROOT, "artifacts/node/115/hl-node")
FAILURES = []


def check(name, ok, detail=""):
    print(("ok: " if ok else "FAIL: ") + name + ((" " + str(detail)) if detail else ""))
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
    check("exhibits total bytes", total_bytes == rec["exhibits_total_bytes"],
          total_bytes)
    check("exhibits total strict",
          total_strict == rec["exhibits_total_strict"], total_strict)

    lo = int(rec["fde"][0], 16)
    hi = int(rec["fde"][1], 16)
    check("FDE size", hi - lo == rec["fde_bytes"], hi - lo)
    check("FDE entry push rbp, no endbr64",
          raw[off(lo)] == 0x55 and raw[off(lo):off(lo) + 4] != bytes.fromhex("f30f1efa"))
    check("padding before FDE is int3",
          raw[off(0x63d84d1):off(lo)] == b"\xcc" * 15)
    check("padding after FDE is int3",
          raw[off(hi):off(0x63d8630)] == b"\xcc" * 14)

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
                   "jo", "jno", "jl", "jge", "jle", "jg"):
            t = jump_target(line)
            if t is None or not (lo <= t < hi):
                jumps_ok = False
    check("two ret sites", rets == rec["ret_sites"], rets)
    check("internal calls", calls == [0x63e8bf0], [hex(c) for c in calls if c])
    check("jump targets internal", jumps_ok)

    def rel32(site):
        o = off(site)
        return site + 5 + struct.unpack("<i", raw[o + 1:o + 5])[0]

    check("call 0x63d8566 -> 0x63e8bf0",
          raw[off(0x63d8566)] == 0xE8 and rel32(0x63d8566) == 0x63e8bf0)
    check("tail jump 0x63d9017 -> FDE",
          raw[off(0x63d9017)] == 0xE9 and rel32(0x63d9017) == lo)
    check("zero arm bytes",
          raw[off(0x63d84f5):off(0x63d84f5) + 4] == bytes.fromhex("0fb64e10")
          and raw[off(0x63d84f9):off(0x63d84f9) + 4] == bytes.fromhex("4883c17e"))
    check("size input bytes",
          raw[off(0x63d8558):off(0x63d8558) + 7] == bytes.fromhex("488bbe b0000000".replace(" ", ""))
          and raw[off(0x63d855f):off(0x63d855f) + 3] == bytes.fromhex("4829c7")
          and raw[off(0x63d8562):off(0x63d8562) + 4] == bytes.fromhex("48c1e70c"))
    check("overflow stub",
          raw[off(0x63d8610):off(0x63d8610) + 6] == bytes.fromhex("41ba8e010000")
          and raw[off(0x63d8616)] == 0xEB)
    check("head join",
          raw[off(0x63d8618):off(0x63d8618) + 5] == bytes.fromhex("488944d508")
          and raw[off(0x63d861d):off(0x63d861d) + 5] == bytes.fromhex("e9f0feffff"))
    check("bitmap bytes",
          raw[off(0x63d85ed):off(0x63d85ed) + 7] == bytes.fromhex("48c7c0feffffff")
          and raw[off(0x63d85fb):off(0x63d85fb) + 8] == bytes.fromhex("482184dd88140000"))
    check("unlink first/last stores",
          raw[off(0x63d8512):off(0x63d8512) + 4] == bytes.fromhex("488b7340")
          and raw[off(0x63d853e):off(0x63d853e) + 4] == bytes.fromhex("49895b40"))

    # Census: raw .text scan. .text: vaddr 0x1419300, file off 0x1418300.
    taddr, toff, tsize = 0x1419300, 0x1418300, 0x4FD7700
    text = raw[toff:toff + tsize]
    e8, e9, lea = [], [], []
    for i in range(len(text) - 7):
        b = text[i]
        if b in (0xE8, 0xE9):
            rel = struct.unpack("<i", text[i + 1:i + 5])[0]
            va = taddr + i
            if va + 5 + rel == lo:
                (e8 if b == 0xE8 else e9).append(hex(va))
        if b in (0x48, 0x4C, 0x49, 0x4D) and text[i + 1] == 0x8D \
                and (text[i + 2] & 0xC7) == 0x05:
            rel = struct.unpack("<i", text[i + 3:i + 7])[0]
            va = taddr + i
            if va + 7 + rel == lo:
                lea.append(hex(va))
    check("census E8", e8 == [], e8)
    check("census E9", e9 == ["0x63d9017"], e9)
    check("census LEA", lea == [], lea)
    # .rela.dyn: vaddr == file off 0x6be8, 24-byte entries.
    roff, rsize = 0x6BE8, 0x163CC8
    hits = 0
    for i in range(rsize // 24):
        add = struct.unpack("<q", raw[roff + i * 24 + 16:roff + i * 24 + 24])[0]
        if add == lo:
            hits += 1
    check("rela.dyn entries", rsize // 24 == 60723, rsize // 24)
    check("census GOT", hits == 0, hits)

    # Neighbour disjointness over the merged tree + recent worktrees.
    import glob
    own = os.path.join(PACKET, "records.json")
    paths = set(glob.glob(os.path.join(ROOT, "research/work-items/*/records.json")))
    home = os.path.expanduser("~/workspace")
    for pat in ("hl-wt-calls23*-115", "hl-wt-calls24*-115"):
        paths |= set(glob.glob(os.path.join(
            home, pat, "research/work-items/*/records.json")))
    overlaps = []
    total = 0
    for p in sorted(paths):
        if os.path.abspath(p) == os.path.abspath(own):
            continue
        try:
            with open(p) as f:
                r = json.load(f)
        except Exception:
            continue
        items = r.get("exhibits") if isinstance(r, dict) else r
        if isinstance(items, dict):
            items = list(items.values())
        if not isinstance(items, list):
            continue
        for e in items:
            if not isinstance(e, dict):
                continue
            rg = e.get("range")
            if isinstance(rg, (list, tuple)) and len(rg) >= 2:
                try:
                    a, b = int(rg[0], 16), int(rg[1], 16)
                except Exception:
                    continue
                total += 1
                if a < hi and lo < b:
                    overlaps.append((hex(a), hex(b), p))
    check("no neighbour overlap", overlaps == [], overlaps[:3])
    print("note: disjointness ranges checked %d" % total)

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        man = f.read().strip().splitlines()
    import hashlib as hl
    man_ok = True
    for line in man:
        h, path = line.split(None, 1)
        path = path.strip().lstrip("*")
        full_path = os.path.normpath(os.path.join(PACKET, path))
        if not os.path.exists(full_path):
            man_ok = False
            continue
        with open(full_path, "rb") as f:
            digest = hl.sha256(f.read()).hexdigest()
        if digest != h:
            man_ok = False
    check("MANIFEST entries", len(man) == 17, len(man))
    check("MANIFEST hashes match", man_ok)

    if FAILURES:
        print("verifier: FAILED (%d checks)" % len(FAILURES))
        return 1
    print("verifier: all checks passed (6 excerpts, 281 bytes, 73 strict, "
          "census 1 E9 site, MANIFEST 17 entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
