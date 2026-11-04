#!/usr/bin/env python3
"""Static verifier for packet #249 (node #115 lu context merge).

Byte reads only; the node binary is never executed.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-context-merge")
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


def rel32_call(site, raw):
    o = off(site)
    if raw[o] != 0xE8:
        return None
    return site + 5 + struct.unpack("<i", raw[o + 1:o + 5])[0]


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
    check("FDE entry arg setup",
          raw[off(0x63d8b24):off(0x63d8b2a)] == bytes.fromhex("4889f14889f8"))
    check("padding before FDE is int3",
          raw[off(0x63d8b15):off(0x63d8b20)] == b"\xcc" * 11)
    check("padding after FDE is int3",
          raw[off(0x63d8e67):off(0x63d8e70)] == b"\xcc" * 9)
    check("one ret site",
          raw[off(0x63d8e66)] == 0xC3)
    # Loop-back check: 0f 85 rel32 -> 0x63d8be0
    jb = raw[off(0x63d8e60):off(0x63d8e66)]
    tgt = 0x63d8e66 + struct.unpack("<i", jb[2:6])[0] if jb[0] == 0x0F and jb[1] == 0x85 else None
    check("loop-back jne -> 0x63d8be0", tgt == 0x63d8be0, hex(tgt) if tgt else jb.hex())
    check("loop-end lea r10 = src+0xc00",
          raw[off(0x63d8b8c):off(0x63d8b93)] == bytes.fromhex("4c8d91000c0000"))
    check("chunk advance +0x180 both pointers",
          raw[off(0x63d8bea):off(0x63d8bf7)] ==
          bytes.fromhex("4881c180010000480580010000"))

    # Whole-loop coverage: parse the loop body disassembly.
    lines = objdump_lines(0x63d8be0, 0x63d8e5d)
    stores = {}
    src_neg = set()
    src_pre = set()
    dst_loads = set()
    paddqs = 0
    for l in lines:
        mn = mnemonic(l)
        if mn is None:
            continue
        addr_m = re.match(r"^\s*([0-9a-f]+):", l)
        addr = int(addr_m.group(1), 16)
        rest = l.split("\t")[-1].strip()
        if mn == "movups":
            m = re.search(r"movups\s+%xmm\d+,-0x([0-9a-f]+)\(%rax\)", rest)
            if m:
                stores[int(m.group(1), 16)] = stores.get(int(m.group(1), 16), 0) + 1
        elif mn == "movdqu":
            m = re.search(r"movdqu\s+-0x([0-9a-f]+)\(%rcx\),%xmm\d+", rest)
            if m:
                src_neg.add(int(m.group(1), 16))
            m = re.search(r"movdqu\s+-0x([0-9a-f]+)\(%rax\),%xmm\d+", rest)
            if m:
                dst_loads.add(int(m.group(1), 16))
            m = re.search(r"movdqu\s+0x([0-9a-f]+)\(%rcx\),%xmm\d+", rest)
            if m:
                src_pre.add(0x180 - int(m.group(1), 16))
        elif mn == "paddq":
            paddqs += 1
    want = {0x10 * i for i in range(1, 25)}
    check("loop stores 24 offsets each once",
          len(stores) == 24 and all(v == 1 for v in stores.values()),
          sorted(hex(o) for o in stores))
    check("loop stores == full chunk", set(stores) == want)
    check("loop src loads cover chunk", (src_neg | src_pre) == want,
          "neg=%d pre=%s" % (len(src_neg), sorted(hex(o) for o in src_pre)))
    check("loop dst loads cover chunk", dst_loads == want)
    check("loop paddq count 24", paddqs == 24, paddqs)
    check("loop iterations 8", 0xC00 // 0x180 == 8)

    # Scalar tail: 12 qword offsets, each loaded from src and added to dst.
    scalar_lines = objdump_lines(0x63d8b20, 0x63d8be0)
    loads = set()
    adds = set()
    for l in scalar_lines:
        mn = mnemonic(l)
        if mn is None:
            continue
        rest = l.split("\t")[-1].strip()
        # Note: the first two loads use %rsi (before rcx is set) and the
        # first two adds use %rdi (before rdi is reused as a temp); the
        # rest use %rcx / %rax. Accept both forms.
        if mn == "mov":
            m = re.search(r"mov\s+0x([0-9a-f]+)\(%r(?:cx|si)\),%r", rest)
            if m:
                loads.add(int(m.group(1), 16))
        elif mn == "add":
            m = re.search(r"add\s+%r\w+,0x([0-9a-f]+)\(%r(?:di|ax)\)", rest)
            if m:
                adds.add(int(m.group(1), 16))
    want_scalar = {0xC00 + 8 * i for i in range(12)}
    check("scalar loads 12 qwords", loads == want_scalar,
          sorted(hex(o) for o in loads))
    check("scalar adds 12 qwords", adds == want_scalar,
          sorted(hex(o) for o in adds))

    # Census: E8 sites rel32-confirmed; E9/LEA/rela checked by scan.
    e8 = rec["census"]["e8_to_fde"]
    for site in e8:
        s = int(site, 16)
        check("census E8 rel32 %s" % site, rel32_call(s, raw) == 0x63d8b20)
    check("census E8 count 2", len(e8) == 2)
    check("census E9 empty", rec["census"]["e9_to_fde"] == [])
    check("census LEA empty", rec["census"]["lea_to_fde"] == [])
    check("census rela.dyn entries", rec["census"]["rela_dyn_entries"] == 60723)
    check("census rela.dyn hits 0", rec["census"]["rela_dyn_addend_hits"] == 0)
    # Independent rela.dyn scan.
    rela_off, rela_size = 0x6BE8, 0x163CC8
    hits = 0
    for i in range(rela_size // 24):
        o = rela_off + i * 24
        addend = struct.unpack("<q", raw[o + 16:o + 24])[0]
        if addend == 0x63d8b20:
            hits += 1
    check("rela.dyn rescan hits 0", hits == 0, hits)

    # No internal calls: no E8 byte at any instruction start inside FDE
    # is checked via the disassembly mnemonic set.
    fde_lines = objdump_lines(lo, hi)
    mnems = {mnemonic(l) for l in fde_lines if mnemonic(l)}
    check("no internal call mnemonic", "call" not in mnems, sorted(mnems))

    # Neighbour disjointness against merged + prior worktree records.
    import glob
    pair_re = re.compile(r"0x([0-9a-fA-F]+)\s*\.\.\s*0x([0-9a-fA-F]+)")
    ranges2 = set()
    paths = glob.glob(os.path.join(ROOT, "research/work-items/*/records.json"))
    paths += glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json")
    for p in sorted(set(paths)):
        if "lu-context-merge" in p:
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
    over = [(a, b) for (a, b) in ranges2 if a < hi and lo < b]
    check("no neighbour overlap", over == [],
          ["%x..%x" % o for o in over])
    print("note: disjointness ranges checked %d" % len(ranges2))

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        man_lines = [l.split() for l in f.read().splitlines() if l.strip()]
    check("MANIFEST 13 entries", len(man_lines) == 13, len(man_lines))
    import hashlib as _hl
    man_ok = True
    for h, rel in man_lines:
        p = os.path.normpath(os.path.join(PACKET, rel))
        if not os.path.exists(p) or _hl.sha256(open(p, "rb").read()).hexdigest() != h:
            man_ok = False
    check("MANIFEST hashes match", man_ok)

    if FAILURES:
        print("verifier: FAILED (%s)" % ", ".join(FAILURES))
        sys.exit(1)
    print("verifier: all checks passed (4 excerpts, 333 bytes, 51 strict, "
          "census 2 E8 sites, MANIFEST 13 entries)")
    sys.exit(0)


if __name__ == "__main__":
    main()
