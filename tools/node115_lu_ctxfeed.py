#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-ctxfeed.

Checks, all read-only (the node binary is never executed):
  - binary SHA-256 and size for node #115
  - 5 claimed excerpts byte-match the binary at their VAs
  - strict mnemonic counts agree with records.json
  - key bytes: entry endbr64, gate jne, generation dispatch,
    three feed calls to 0x6363660, three collect calls to 0x6363560,
    single ret site
  - outgoing census: exactly 50 direct E8 calls in the FDE, with the
    expected per-target breakdown (parsed from objdump, not raw bytes,
    so immediates cannot fake a call)
  - incoming census: 56 direct E8 callers of 0x63e9cd0 across .text
    (byte scan; every candidate was objdump-confirmed during analysis)
  - GOT: 0 .rela.dyn addends equal to 0x63e9cd0 (60,723 entries)
  - FDE bounds 0x63e9cd0..0x63ead50 (4224 bytes)
  - MANIFEST.sha256 15/15 entries
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACKET = os.path.join(HERE, "..", "research", "work-items",
                      "RE-001-node115-lu-ctxfeed")
BIN = os.path.join(HERE, "..", "artifacts", "node", "115", "hl-node")

EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032
FDE_START, FDE_END = 0x63E9CD0, 0x63EAD50
TARGET = 0x63E9CD0
FEED = 0x6363660
COLLECT = 0x6363560
EXPECT_FEED = [0x63EA135, 0x63EA495, 0x63EAAD3]
EXPECT_COLLECT = [0x63EAB9E, 0x63EAC11, 0x63EACF9]
EXPECT_OUTGOING = {
    0x6360ED0: 1, 0x63612B0: 7, 0x6362130: 1, 0x6363560: 3,
    0x6363660: 3, 0x63B6C50: 1, 0x63BD5A0: 15, 0x63BD640: 7,
    0x63BF680: 3, 0x63E9160: 1, 0x63E94A0: 1, 0x63F0B70: 3,
    0x63F0D70: 1, 0x63F17B0: 3,
}
EXPECT_INCOMING = 56
EXPECT_RELA = 60723


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def va_to_off(va):
    return va - 0x1000


def main():
    with open(BIN, "rb") as f:
        data = f.read()
    if len(data) != EXPECT_SIZE:
        fail(f"binary size {len(data)} != {EXPECT_SIZE}")
    if hashlib.sha256(data).hexdigest() != EXPECT_SHA:
        fail("binary sha mismatch")
    print(f"binary sha ok ({EXPECT_SIZE} bytes)")

    with open(os.path.join(PACKET, "records.json")) as f:
        rec = json.load(f)

    total_bytes = 0
    total_strict = 0
    for name, ex in sorted(rec["exhibits"].items()):
        start = int(ex["range"][0], 16)
        end = int(ex["range"][1], 16)
        with open(os.path.join(PACKET, name + ".hex")) as f:
            claimed = bytes.fromhex("".join(f.read().split()))
        if len(claimed) != ex["bytes"] or len(claimed) != end - start:
            fail(f"{name}: length {len(claimed)} != range {end - start}")
        got = data[va_to_off(start):va_to_off(start) + len(claimed)]
        if got != claimed:
            fail(f"{name}: bytes differ from binary at {hex(start)}")
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            strict = 0
            for line in f:
                m = re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+?\t(.*)$", line)
                if m and m.group(1).strip():
                    strict += 1
        if strict != ex["strict"]:
            fail(f"{name}: strict {strict} != {ex['strict']}")
        total_bytes += len(claimed)
        total_strict += strict
    print(f"exhibits ok: {len(rec['exhibits'])} excerpts, {total_bytes} bytes, "
          f"{total_strict} strict")

    # Key bytes.
    if data[va_to_off(0x63E9CD0):va_to_off(0x63E9CD0) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    if data[va_to_off(0x63E9D37)] != 0x75:
        fail("gate branch is not jne")
    if data[va_to_off(0x63E9D5A)] != 0xC3:
        fail("ret site is not ret")
    for site in EXPECT_FEED:
        o = va_to_off(site)
        if data[o] != 0xE8:
            fail(f"feed site {hex(site)} is not E8")
        tgt = site + 5 + struct.unpack("<i", data[o + 1:o + 5])[0]
        if tgt != FEED:
            fail(f"feed site {hex(site)} targets {hex(tgt)}")
    for site in EXPECT_COLLECT:
        o = va_to_off(site)
        if data[o] != 0xE8:
            fail(f"collect site {hex(site)} is not E8")
        tgt = site + 5 + struct.unpack("<i", data[o + 1:o + 5])[0]
        if tgt != COLLECT:
            fail(f"collect site {hex(site)} targets {hex(tgt)}")
    print("key bytes ok: entry, gate, ret, 3 feed, 3 collect")

    # Outgoing census from objdump (immediates cannot fake a call).
    r = subprocess.run(["objdump", "-d",
                        f"--start-address={hex(FDE_START)}",
                        f"--stop-address={hex(FDE_END)}", BIN],
                       capture_output=True, text=True)
    if r.returncode != 0:
        fail("objdump failed on FDE range")
    outgoing = {}
    ret_sites = []
    for line in r.stdout.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t[0-9a-f ]+?\tcall\s+([0-9a-f]+)", line)
        if m:
            outgoing[int(m.group(2), 16)] = outgoing.get(int(m.group(2), 16), 0) + 1
        m2 = re.match(r"\s*([0-9a-f]+):\t[0-9a-f ]+?\tret\s*$", line)
        if m2:
            ret_sites.append(int(m2.group(1), 16))
    if outgoing != EXPECT_OUTGOING:
        fail(f"outgoing census differs: {outgoing}")
    if ret_sites != [0x63E9D5A]:
        fail(f"ret sites differ: {[hex(x) for x in ret_sites]}")
    print(f"census ok: outgoing 50 E8, ret 1 site")

    # Incoming census: byte scan of .text for E8 rel32 -> TARGET.
    sec = subprocess.run(["readelf", "-SW", BIN],
                         capture_output=True, text=True).stdout
    text = None
    for line in sec.splitlines():
        if ".text" in line and "PROGBITS" in line:
            parts = line.split()
            idx = parts.index(".text")
            text = (int(parts[idx + 2], 16), int(parts[idx + 3], 16),
                    int(parts[idx + 4], 16))
    if text is None:
        fail("no .text section")
    addr, off, size = text
    incoming = 0
    for va in range(addr, addr + size - 5):
        o = off + (va - addr)
        if data[o] == 0xE8:
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            if va + 5 + rel == TARGET:
                incoming += 1
    if incoming != EXPECT_INCOMING:
        fail(f"incoming callers {incoming} != {EXPECT_INCOMING}")
    print(f"incoming ok: {incoming} E8 callers")

    # GOT census via .rela.dyn addends.
    rel = subprocess.run(["readelf", "-rW", BIN],
                         capture_output=True, text=True).stdout
    in_dyn = False
    total = 0
    got = 0
    for line in rel.splitlines():
        if "Relocation section '.rela.dyn'" in line:
            in_dyn = True
            continue
        if in_dyn and line.startswith("Relocation section"):
            break
        if in_dyn:
            m = re.match(r"\s*[0-9a-f]+\s+([0-9a-f]+)\s+\S+", line)
            if m:
                total += 1
                if int(m.group(1), 16) == TARGET:
                    got += 1
    if total != EXPECT_RELA:
        fail(f".rela.dyn entries {total} != {EXPECT_RELA}")
    if got != 0:
        fail(f"GOT references {got} != 0")
    print(f"got ok: 0 references, {total} rela entries")

    # FDE bounds: endbr64 at start and at next function.
    if data[va_to_off(FDE_START):va_to_off(FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("FDE start is not endbr64")
    if data[va_to_off(FDE_END):va_to_off(FDE_END) + 4] != bytes.fromhex("f30f1efa"):
        fail("FDE end is not next endbr64")
    print(f"FDE bounds ok: {hex(FDE_START)}..{hex(FDE_END)} "
          f"({FDE_END - FDE_START}B)")

    # MANIFEST.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        entries = [l.split() for l in f if l.strip()]
    ok = 0
    for digest, path in entries:
        full = os.path.normpath(os.path.join(PACKET, path))
        with open(full, "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() == digest:
                ok += 1
            else:
                fail(f"MANIFEST mismatch: {path}")
    if ok != len(entries):
        fail("MANIFEST incomplete")
    print(f"MANIFEST ok: {ok}/{len(entries)} entries")
    print(f"verifier: all checks passed ({len(rec['exhibits'])} excerpts, "
          f"{total_strict} strict, outgoing 50 E8, incoming {incoming}, "
          f"MANIFEST {ok} entries)")


if __name__ == "__main__":
    main()
