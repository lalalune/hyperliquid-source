#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-leaf-write-class (packet #258).

Byte reads only; the node binary is never executed. Coordinate rules:
.text file offset = VA - 0x1000; .data.rel.ro/.got = VA - 0x2000;
.rodata = VA as-is. Strict counts are mnemonic lines (address + bytes
field + tab + mnemonic); objdump byte-continuation lines are excluded.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

DEFAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = DEFAULT_ROOT
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-node115-lu-leaf-write-class")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
RECORDS = os.path.join(PACKET, "records.json")

EXPECT_SIZE = 105896032
EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
STRICT_PAT = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")

ok = True


def check(name, cond, detail=""):
    global ok
    if cond:
        print(f"PASS {name}")
    else:
        print(f"FAIL {name} {detail}")
        ok = False


def strict_count(path):
    n = 0
    with open(path) as f:
        for line in f:
            if STRICT_PAT.match(line):
                n += 1
    return n


def strip_header(text):
    # objdump's header embeds the invoked path, so strip it by content,
    # not by the exact path string (the saved files were made with a
    # relative path; the verifier runs with an absolute one).
    out = []
    for line in text.splitlines():
        if "file format elf64-x86-64" in line:
            continue
        if line.startswith("Disassembly of section"):
            continue
        out.append(line)
    return "\n".join(out).strip()


def rel32_target(data, call_va):
    off = call_va - 0x1000
    rel = struct.unpack("<i", data[off + 1: off + 5])[0]
    return call_va + 5 + rel


def parse_hex(s):
    if isinstance(s, str):
        try:
            return int(s.strip(), 16)
        except ValueError:
            return None
    if isinstance(s, int):
        return s
    return None


def collect(node, out):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("census", "cited_only_not_claimed"):
                continue
            if k in ("range", "fde") and isinstance(v, (list, tuple)) and len(v) >= 2:
                a, b = parse_hex(v[0]), parse_hex(v[1])
                if a is not None and b is not None and b > a:
                    out.append((a, b))
            else:
                collect(v, out)
    elif isinstance(node, list):
        for it in node:
            collect(it, out)


def main():
    global ok, ROOT, PACKET, BIN, RECORDS
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=DEFAULT_ROOT)
    args = ap.parse_args()
    ROOT = args.root
    PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-node115-lu-leaf-write-class")
    BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
    RECORDS = os.path.join(PACKET, "records.json")
    with open(BIN, "rb") as f:
        data = f.read()
    check("binary size", len(data) == EXPECT_SIZE, f"got {len(data)}")
    check("binary sha256", hashlib.sha256(data).hexdigest() == EXPECT_SHA)

    with open(RECORDS) as f:
        rec = json.load(f)
    exhibits = rec["exhibits"]
    total_b = 0
    total_s = 0
    mine = []
    for e in exhibits:
        name = e["name"]
        a, b = int(e["range"][0], 16), int(e["range"][1], 16)
        raw = open(os.path.join(PACKET, name + ".hex"), "rb").read()
        check(f"{name} bytes", raw == data[a - 0x1000: a - 0x1000 + (b - a)] and len(raw) == b - a,
              f"len {len(raw)} want {b - a}")
        sc = strict_count(os.path.join(PACKET, name + ".objdump.txt"))
        check(f"{name} strict count", sc == e["strict"], f"got {sc} want {e['strict']}")
        # objdump regeneration with header stripped
        out = subprocess.run(["objdump", "-d", f"--start-address={hex(a)}",
                              f"--stop-address={hex(b)}", BIN],
                             capture_output=True, text=True).stdout
        saved = open(os.path.join(PACKET, name + ".objdump.txt")).read()
        check(f"{name} objdump regeneration", strip_header(out) == strip_header(saved))
        total_b += b - a
        total_s += e["strict"]
        mine.append((a, b))
    check("exhibit totals", total_b == rec["exhibit_totals"]["bytes"] and total_s == rec["exhibit_totals"]["strict"],
          f"got {total_b}B/{total_s} want {rec['exhibit_totals']}")

    # rel32 call-target spot checks: (site, expected target)
    spots = [
        (0x63a5986, 0x63f17b0),  # arenas.create trylock PLT
        (0x63a59fc, 0x63a5550),  # arenas.create routine
        (0x63779e1, 0x63ee0a0),  # tcache.create routine
        (0x63778d7, 0x63ee2a0),  # tcache.destroy routine
        (0x636d652, 0x63b6ee0),  # hooks.install routine
        (0x6376d77, 0x63b70b0),  # hooks.remove routine
        (0x637782b, 0x63d4ad8),  # log_start routine
        (0x63777d4, 0x63d4bbe),  # log_stop routine
        (0x636def6, 0x63c3e20),  # prof.active write routine
        (0x6368e57, 0x63f17b0),  # completion trylock PLT
        (0x63efa95, 0x63f0cf0),  # tls.install pthread_setspecific PLT
    ]
    for site, want in spots:
        got = rel32_target(data, site)
        check(f"call target {hex(site)}", got == want, f"got {hex(got)} want {hex(want)}")

    # profbyte writer bytes spot checks
    check("profbyte clear bytes", data[0x634c043 - 0x1000: 0x634c043 - 0x1000 + 4] == bytes([0x41, 0xC6, 0x00, 0x00]))
    check("profbyte set bytes", data[0x634d09a - 0x1000: 0x634d09a - 0x1000 + 3] == bytes([0xC6, 0x03, 0x01]))
    check("profbyte latch bytes", data[0x63c41a0 - 0x1000: 0x63c41a0 - 0x1000 + 7] == bytes([0xC6, 0x05, 0x5F, 0xF4, 0x34, 0x00, 0x01]))

    # E8/E9 direct-call census (raw scan over the executable LOAD segment)
    lo, hi = 0x1418300, 0x1418300 + 0x4FD88A0

    def va_of(off):
        return off + 0x1000

    targets = {
        "arenas.create": 0x63A5950, "tcache.create": 0x6377950, "tcache.destroy": 0x63778B0,
        "hooks.install": 0x636D5F0, "hooks.remove": 0x6376D50, "prof.log_start": 0x63777F0,
        "prof.log_stop": 0x63777C0, "thread.prof.active": 0x636DE60,
        "tls_slow": 0x63EF8E0, "completion": 0x6368E40,
    }
    inv = {v: k for k, v in targets.items()}
    found = {k: {"E8": [], "E9": []} for k in targets}
    for off in range(lo, hi - 5):
        byte = data[off]
        if byte in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", data, off + 1)[0]
            tgt = va_of(off) + 5 + rel
            if tgt in inv:
                found[inv[tgt]]["E8" if byte == 0xE8 else "E9"].append(va_of(off))
    cen = rec["census"]
    for leaf, entry in cen["leaf_handler_direct_entries"].items():
        dkey = {"experimental.hooks.install": "hooks.install",
                "experimental.hooks.remove": "hooks.remove"}.get(leaf, leaf)
        check(f"{leaf} direct entries", found[dkey]["E8"] == [] and found[dkey]["E9"] == [],
              f"E8={found[dkey]['E8']} E9={found[dkey]['E9']}")
    tls = cen["tls_slow_callers"]
    check("tls_slow census", len(found["tls_slow"]["E8"]) == len(tls["E8"]) and
          len(found["tls_slow"]["E9"]) == len(tls["E9"]),
          f"got E8={len(found['tls_slow']['E8'])} E9={len(found['tls_slow']['E9'])}")
    comp = cen["completion_callers"]
    check("completion census", len(found["completion"]["E8"]) == len(comp["E8"]) and
          len(found["completion"]["E9"]) == len(comp["E9"]),
          f"got E8={len(found['completion']['E8'])} E9={len(found['completion']['E9'])}")

    # rela.dyn slots for the eight leaf handlers (readelf)
    rela = subprocess.run(["readelf", "-r", BIN], capture_output=True, text=True).stdout
    rela_map = {}
    for line in rela.splitlines():
        m = re.match(r"^\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if m:
            # readelf zero-pads offsets/addends; compare as integers.
            rela_map.setdefault(int(m.group(2), 16), []).append(int(m.group(1), 16))
    for leaf, entry in cen["leaf_handler_direct_entries"].items():
        h = int(entry["handler"], 16)
        slot = int(entry["rela_slot"], 16)
        got = rela_map.get(h, [])
        check(f"{leaf} rela slot", got == [slot], f"got {[hex(g) for g in got]} want [{hex(slot)}]")

    # disjointness vs all prior packets (merged tree + prior worktrees)
    paths = set()
    for p in glob.glob(os.path.join(ROOT, "research", "work-items", "*", "records.json")):
        paths.add(os.path.realpath(p))
    for p in glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json"):
        paths.add(os.path.realpath(p))
    paths.discard(os.path.realpath(RECORDS))
    claimed = []
    for p in sorted(paths):
        try:
            with open(p) as f:
                prior = json.load(f)
        except Exception:
            continue
        collect(prior, claimed)
    uniq = sorted(set(claimed))
    overlaps = []
    for a, b in mine:
        for x, y in uniq:
            if x < b and a < y:
                overlaps.append((hex(a), hex(b), hex(x), hex(y)))
    check("disjointness", not overlaps, f"overlaps={overlaps}")
    print(f"INFO claimed ranges scanned: {len(uniq)}")

    # MANIFEST entries (sha256 of every listed file, MANIFEST itself excluded)
    man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
    n_entries = 0
    for line in man:
        line = line.strip()
        if not line:
            continue
        digest, rel = line.split(None, 1)
        rel = rel.lstrip("*")
        if rel == "MANIFEST.sha256":
            continue
        full = os.path.normpath(os.path.join(PACKET, rel))
        with open(full, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != digest:
            check(f"MANIFEST {rel}", False, f"got {actual}")
        n_entries += 1
    check("MANIFEST entries", n_entries > 0, f"counted {n_entries}")
    print(f"INFO manifest entries: {n_entries}")

    if ok:
        print("ALL CHECKS PASSED")
        return 0
    print("CHECKS FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
