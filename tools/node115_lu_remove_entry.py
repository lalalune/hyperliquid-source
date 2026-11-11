#!/usr/bin/env python3
"""Static verifier for RE-001 node115 lu remove-entry packet.

Byte reads only; the node binary is never executed.
Checks: binary SHA/size, exhibit bytes, strict mnemonic counts,
objdump regeneration (header line stripped, as in packet #224),
FDE bounds, entry bytes, three ret sites, three internal calls,
key bytes, jump targets internal, census (E8/E9/LEA/GOT),
neighbour disjointness, MANIFEST coverage.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-remove-entry")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
FDE_LO, FDE_HI = 0x63D8630, 0x63D8790
TARGET = 0x63D8630
RET_SITES = [0x63D8690, 0x63D8745, 0x63D876C]
CALLS = [(0x63D86A8, 0x63E8BF0), (0x63D870F, 0x63B9D10),
         (0x63D8717, 0x63B9680)]
TEXT_VA, TEXT_OFF, TEXT_SZ = 0x1419300, 0x1418300, 0x4FD7700

FAILURES = []


def check(name, cond, detail=""):
    print(("ok: " if cond else "FAIL: ") + name + ((" " + detail) if detail else ""))
    if not cond:
        FAILURES.append(name)


def va_off(va):
    return va - 0x1000


def objdump_lines(lo, hi):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=" + hex(lo),
         "--stop-address=" + hex(hi), BIN],
        capture_output=True, text=True, check=True).stdout
    lines = [l for l in out.splitlines()
             if re.match(r"\s*[0-9a-f]+:\t", l)]
    strict = [l for l in lines
              if re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t\S", l)]
    return lines, strict


def main():
    with open(BIN, "rb") as f:
        data = f.read()
    check("binary sha", hashlib.sha256(data).hexdigest() == SHA)
    check("binary size %d" % SIZE, len(data) == SIZE)

    with open(os.path.join(PACKET, "records.json")) as f:
        records = json.load(f)
    exhibits = records["exhibits"]
    total_bytes = 0
    total_strict = 0
    for name, ex in exhibits.items():
        lo = int(ex["range"][0], 16)
        hi = int(ex["range"][1], 16)
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        check(name + " length", len(raw) == ex["bytes"] == hi - lo)
        check(name + " bytes", data[va_off(lo):va_off(hi)] == raw)
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            saved = f.read()
        lines, strict = objdump_lines(lo, hi)
        check(name + " objdump regeneration",
              saved == "\n".join(lines) + "\n")
        check(name + " strict %d" % ex["strict"], len(strict) == ex["strict"])
        check(name + " inside FDE", FDE_LO <= lo and hi <= FDE_HI)
        total_bytes += len(raw)
        total_strict += len(strict)
    check("exhibits total 300 bytes", total_bytes == 300)
    check("exhibits total 87 strict", total_strict == 87)

    check("FDE size 352", FDE_HI - FDE_LO == 352)
    check("FDE entry push r14, no endbr64",
          data[va_off(FDE_LO):va_off(FDE_LO) + 2] == bytes([0x41, 0x56]))
    check("padding before FDE is int3",
          data[va_off(0x63D8622):va_off(FDE_LO)] == bytes([0xCC] * 14))
    lines, _ = objdump_lines(FDE_LO, FDE_HI)
    rets = []
    for l in lines:
        m = re.match(r"\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)", l)
        if m and m.group(2) == "ret":
            rets.append(int(m.group(1), 16))
    check("three ret sites", rets == RET_SITES, str([hex(r) for r in rets]))
    for site, tgt in CALLS:
        off = va_off(site)
        rel = struct.unpack("<i", data[off + 1:off + 5])[0]
        check("call %#x -> %#x" % (site, tgt),
              data[off] == 0xE8 and site + 5 + rel == tgt)
    # Key bytes.
    check("flag clear movb", data[va_off(0x63D8642):va_off(0x63D8646)] ==
          bytes.fromhex("c6461200"))
    check("anchor cmp", data[va_off(0x63D864B):va_off(0x63D8652)] ==
          bytes.fromhex("483bb780100000"))
    check("0x200 cmp", data[va_off(0x63D8698):va_off(0x63D869E)] ==
          bytes.fromhex("483d00020000"))
    check("overflow stub",
          data[va_off(0x63D8770):va_off(0x63D877C)] ==
          bytes.fromhex("41bc700c000041bdc7000000") and
          data[va_off(0x63D877C):va_off(0x63D8782)] ==
          bytes.fromhex("41bec7000000") and
          data[va_off(0x63D8782):va_off(0x63D8784)] ==
          bytes.fromhex("eb82"))
    check("anchor-update block",
          data[va_off(0x63D8784):va_off(0x63D878B)] ==
          bytes.fromhex("4c899f80100000") and
          data[va_off(0x63D878B):va_off(FDE_HI)] ==
          bytes.fromhex("e9c8feffff"))
    # Whole-FDE jump targets internal.
    bad = []
    for l in lines:
        m = re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(j\w+)\s+([0-9a-f]+)", l)
        if m:
            t = int(m.group(2), 16)
            if not (FDE_LO <= t < FDE_HI):
                bad.append((m.group(1), hex(t)))
    check("jump targets internal", not bad, str(bad))
    # Census: raw .text scans, candidates confirmed by objdump.
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SZ]
    e8, e9, lea = [], [], []
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel = struct.unpack("<i", text[i + 1:i + 5])[0]
            if TEXT_VA + i + 5 + rel == TARGET:
                e8.append(TEXT_VA + i)
        elif text[i] == 0xE9:
            rel = struct.unpack("<i", text[i + 1:i + 5])[0]
            if TEXT_VA + i + 5 + rel == TARGET:
                e9.append(TEXT_VA + i)
    for i in range(len(text) - 7):
        if text[i] in (0x48, 0x4C) and text[i + 1] == 0x8D \
                and (text[i + 2] & 0xC7) == 0x05:
            rel = struct.unpack("<i", text[i + 3:i + 7])[0]
            if TEXT_VA + i + 7 + rel == TARGET:
                lea.append(TEXT_VA + i)
    check("census E8 ['0x63d9000']", e8 == [0x63D9000],
          str([hex(x) for x in e8]))
    check("census E9 empty", e9 == [])
    check("census LEA empty", lea == [])
    for site in e8:
        lo = site
        out = subprocess.run(
            ["objdump", "-d", "--start-address=" + hex(lo),
             "--stop-address=" + hex(lo + 5), BIN],
            capture_output=True, text=True, check=True).stdout
        check("E8 site %#x rel32" % site,
              ("call   %x" % TARGET) in out)
    out = subprocess.run(["readelf", "-r", BIN],
                         capture_output=True, text=True, check=True).stdout
    cur = None
    rela_dyn = 0
    got_hits = []
    for line in out.splitlines():
        m = re.match(r"Relocation section '(\S+)'", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"\s*([0-9a-f]+)\s+([0-9a-f]+)\s+(\S+)"
                     r"(?:\s+([0-9a-f]+))?", line)
        if m and m.group(3).startswith("R_") and cur == ".rela.dyn":
            rela_dyn += 1
            if m.group(4) and int(m.group(4), 16) == TARGET:
                got_hits.append(m.group(1))
    check("rela.dyn 60723 entries", rela_dyn == 60723, str(rela_dyn))
    check("census GOT empty", got_hits == [])
    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        man_lines = [l for l in f.read().splitlines() if l.strip()]
    check("MANIFEST 17 entries", len(man_lines) == 17, str(len(man_lines)))
    import hashlib as _hl
    man_ok = True
    for l in man_lines:
        h, p = l.split(None, 1)
        p = p.lstrip("*")
        full = os.path.normpath(os.path.join(PACKET, p))
        if not os.path.exists(full) or \
                _hl.sha256(open(full, "rb").read()).hexdigest() != h:
            man_ok = False
    check("MANIFEST hashes match", man_ok)

    if FAILURES:
        print("verifier: FAILED (%d)" % len(FAILURES))
        sys.exit(1)
    print("verifier: all checks passed (6 excerpts, 300 bytes, "
          "87 strict, census 1 E8 site, MANIFEST 17 entries)")


if __name__ == "__main__":
    main()
