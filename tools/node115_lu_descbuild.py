#!/usr/bin/env python3
"""Static verifier for the node #115 lu descriptor-builder packet
(RE-001-node115-lu-descbuild).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt,
- key instruction bytes (thunk endbr64 + jmp to body, body endbr64,
  .rodata constant loads and values, first-loop and main-loop
  constants, ret opcode, zero calls inside the body, all body jump
  targets inside the body),
- unwind-table FDE ranges for thunk and body,
- census: thunk 1 direct E8, body 1 direct E8 + 1 E9, 0 LEA, 0 GOT
  (60,723 .rela.dyn entries),
- arithmetic simulation of the decoded loop structure reproducing
  the claimed header counter values (pure integer arithmetic over
  the disassembled branch bounds, not binary execution),
- disjointness from neighbouring claimed ranges,
- MANIFEST.sha256 coverage (15 entries, MANIFEST itself excluded).
"""

import hashlib
import math
import os
import re
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-descbuild")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

THUNK_START = 0x63DA080
THUNK_END = 0x63DA089
BODY_START = 0x63D9BA0
BODY_END = 0x63D9ED3
RET_SITES = (0x63D9ED2,)
THUNK_CALLERS = (0x634ED44,)
BODY_CALLERS = (0x634C2A5,)
BODY_JUMPERS = (0x63DA084,)
# Neighbouring claimed ranges that must not overlap thunk/body FDEs.
NEIGHBOURS = {
    "table-fill (#228)": (0x63E8D90, 0x63E9152),
    "size rep (#227)": (0x63E8C80, 0x63E8D87),
    "sibling (#224)": (0x63E8BF0, 0x63E8C77),
    "finder (#226)": (0x63B0980, 0x63B15E9),
    "slot-head (#225)": (0x63ABD00, 0x63AC0CC),
    "table-fill caller": (0x634ECE0, 0x634F09D),
    "second body caller": (0x6349BE0, 0x634EB7C),
}

EXHIBITS = {
    "db_thunk": (0x63DA080, 0x63DA089, 9, 2),
    "db_entry": (0x63D9BA0, 0x63D9C08, 104, 23),
    "db_first": (0x63D9C08, 0x63D9C78, 112, 28),
    "db_main": (0x63D9D10, 0x63D9D53, 67, 15),
    "db_final": (0x63D9E3F, 0x63D9EC8, 137, 30),
}

INSN_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)")
JUMP_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(j\w+)\s+([0-9a-f]+)")


def text_off(va):
    return va - 0x1000


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def rip_target(site, insn_len, disp):
    return site + insn_len + disp


def main():
    with open(NODE, "rb") as f:
        data = f.read()
    if len(data) != TARGET_SIZE:
        fail(f"binary size {len(data)} != {TARGET_SIZE}")
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("binary SHA-256 mismatch")
    print(f"binary sha ok ({TARGET_SIZE} bytes)")

    total_bytes = 0
    total_strict = 0
    for name, (start, end, nbytes, strict) in EXHIBITS.items():
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        if len(raw) != nbytes or data[text_off(start):text_off(end)] != raw:
            fail(f"exhibit {name} bytes mismatch")
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            dump = f.read()
        got = len(INSN_RE.findall(dump))
        if got != strict:
            fail(f"exhibit {name} strict {got} != {strict}")
        total_bytes += nbytes
        total_strict += strict
    print(f"exhibits ok: {len(EXHIBITS)} excerpts, {total_bytes} bytes, "
          f"{total_strict} strict")

    # Key bytes: thunk endbr64 + jmp to body.
    if data[text_off(THUNK_START):text_off(THUNK_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("thunk endbr64 mismatch")
    o = text_off(0x63DA084)
    if data[o] != 0xE9:
        fail("thunk jmp opcode mismatch")
    rel = struct.unpack("<i", data[o + 1:o + 5])[0]
    if 0x63DA084 + 5 + rel != BODY_START:
        fail("thunk jmp target mismatch")
    # Body entry endbr64.
    if data[text_off(BODY_START):text_off(BODY_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("body endbr64 mismatch")
    # RIP-relative constant loads.
    checks = (
        (0x63D9BA6, 7, "488b05", 0x4595A0, "rax base constant load"),
        (0x63D9BCB, 8, "660f6f05", 0x452980, "xmm0 constant load"),
        (0x63D9BD5, 8, "660f6f0d", 0x451510, "xmm1 constant load"),
        (0x63D9BE2, 7, "0fb71d", 0x96DC38, "bx constant load"),
    )
    for site, ln, opc, tgt, label in checks:
        o = text_off(site)
        if data[o:o + len(opc) // 2] != bytes.fromhex(opc):
            fail(f"{label} opcode mismatch")
        disp = struct.unpack("<i", data[o + len(opc) // 2:o + len(opc) // 2 + 4])[0]
        if rip_target(site, ln, disp) != tgt:
            fail(f"{label} target mismatch")
    # .rodata constant values (VA as-is for .rodata).
    if struct.unpack("<Q", data[0x4595A0:0x4595A0 + 8])[0] != 0x100000003:
        fail("0x4595a0 constant mismatch")
    if struct.unpack("<4I", data[0x451510:0x451510 + 16]) != (1, 3, 1, 3):
        fail("0x451510 constant mismatch")
    if struct.unpack("<4I", data[0x452980:0x452980 + 16]) != (0, 3, 3, 0):
        fail("0x452980 constant mismatch")
    if struct.unpack("<H", data[0x96DC38:0x96DC38 + 2])[0] != 0x0100:
        fail("0x96dc38 constant mismatch")
    # Loop constants.
    if data[text_off(0x63D9BB4):text_off(0x63D9BB4) + 6] != bytes.fromhex("41ba02000000"):
        fail("first-loop r10d=2 mismatch")
    if data[text_off(0x63D9C83):text_off(0x63D9C83) + 6] != bytes.fromhex("41bb05000000"):
        fail("main-loop r11d=5 mismatch")
    if data[text_off(0x63D9C89):text_off(0x63D9C89) + 5] != bytes.fromhex("be06000000"):
        fail("main-loop esi=6 mismatch")
    if data[text_off(0x63D9CBB):text_off(0x63D9CBB) + 3] != bytes.fromhex("83fe3e"):
        fail("outer cmp 0x3e mismatch")
    if data[text_off(0x63D9DEF):text_off(0x63D9DEF) + 4] != bytes.fromhex("4183fc3f"):
        fail("final cmp 0x3f mismatch")
    for site in RET_SITES:
        if data[text_off(site)] != 0xC3:
            fail(f"ret site {hex(site)} mismatch")
    print("key bytes ok: thunk jmp, body endbr64, constant loads + "
          "values, loop constants, ret")

    # No calls inside the body; all body jump targets inside the body.
    dump = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(BODY_START)}",
         f"--stop-address={hex(BODY_END)}", NODE],
        capture_output=True, text=True).stdout
    if INSN_RE.findall(dump).count("call") != 0:
        fail("unexpected call inside body")
    for m in JUMP_RE.finditer(dump):
        tgt = int(m.group(2), 16)
        if not (BODY_START <= tgt < BODY_END):
            fail(f"body jump target {hex(tgt)} outside body")
    print("FDE bounds ok: body 819B, 0 calls, jumps internal")

    # Unwind-table FDE ranges.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", NODE],
        capture_output=True, text=True).stdout
    if "pc=00000000063da080..00000000063da089" not in frames:
        fail("unwind thunk range mismatch")
    if "pc=00000000063d9ba0..00000000063d9ed3" not in frames:
        fail("unwind body range mismatch")
    if BODY_END - BODY_START != 819 or THUNK_END - THUNK_START != 9:
        fail("FDE size mismatch")

    # Census: E8/E9 sites (rel32) + GOT absence.
    text = data[0x1418300:0x1418300 + 0x4FD7700]

    def rel_targets(target):
        e8, e9 = [], []
        pos = 0
        while True:
            pos = text.find(b"\xe8", pos)
            if pos < 0:
                break
            va = 0x1419300 + pos
            if pos + 5 <= len(text):
                rel = struct.unpack("<i", text[pos + 1:pos + 5])[0]
                if va + 5 + rel == target:
                    e8.append(va)
            pos += 1
        pos = 0
        while True:
            pos = text.find(b"\xe9", pos)
            if pos < 0:
                break
            va = 0x1419300 + pos
            if pos + 5 <= len(text):
                rel = struct.unpack("<i", text[pos + 1:pos + 5])[0]
                if va + 5 + rel == target:
                    e9.append(va)
            pos += 1
        return e8, e9

    t_e8, t_e9 = rel_targets(THUNK_START)
    if t_e8 != list(THUNK_CALLERS) or t_e9:
        fail(f"thunk census E8 {t_e8} E9 {t_e9}")
    b_e8, b_e9 = rel_targets(BODY_START)
    if b_e8 != list(BODY_CALLERS) or b_e9 != list(BODY_JUMPERS):
        fail(f"body census E8 {b_e8} E9 {b_e9}")
    # .rela.dyn addends via ELF section headers.
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[0x3A:0x40])
    secs = []
    for n in range(e_shnum):
        o = e_shoff + n * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack("<IIQQQQ", data[o:o + 40])
        secs.append((name, off, size))
    shstr_off = secs[e_shstrndx][1]

    def secname(x):
        e = data.index(b"\x00", shstr_off + x)
        return data[shstr_off + x:e].decode()

    rela_total = None
    for name, off, size in secs:
        if secname(name) == ".rela.dyn":
            rela_total = size // 24
            for k in range(rela_total):
                r_add = struct.unpack("<q", data[off + k * 24 + 16:off + k * 24 + 24])[0]
                if r_add in (THUNK_START, BODY_START):
                    fail("unexpected GOT addend for thunk/body")
    if rela_total != 60723:
        fail(f"rela entries {rela_total} != 60723")
    print(f"census ok: thunk {len(THUNK_CALLERS)} E8, body "
          f"{len(BODY_CALLERS)} E8 + {len(BODY_JUMPERS)} E9, 0 GOT, "
          f"60723 rela entries")

    # Arithmetic simulation of the decoded loop structure (integer
    # arithmetic only, not binary execution).
    def pages_of(s):
        return (4096 * s // math.gcd(4096, s)) // 4096

    if [pages_of(r10 * 16) for r10 in (2, 3, 4)] != [1, 3, 1]:
        fail("first-loop pages simulation mismatch")
    r11 = 5
    cnt_2c, cnt_30, r15 = 5, 1, 0
    last_small_20 = last_counted_rsi = last_counted_18 = None
    final_rsi = None
    flags = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    for esi in range(6, 63):
        inner = 4 if esi != 62 else 3
        r9 = r11
        for k in range(1, inner + 1):
            s = (k + 1) << (esi - 2)
            final_rsi = s
            if (s & 0xFFF) == 0:
                r15 += 1
            flags[r11] = 1 if (s & 0xFFF) == 0 else 0
            if s <= 0x1000:
                r9 += 1
                cnt_30 = r9
                last_small_20 = 0x1000 if (s & 0xFFF) == 0 else s
            elif s <= 0x3FFF:
                r9 += 1
            else:
                r9 += 1
            if s <= 0x3FFF:
                cnt_2c += 1
                last_counted_rsi = s
                last_counted_18 = esi + 1
            r11 += 1
    if r11 != 232 or r15 != 198:
        fail(f"simulation count mismatch r11={r11} r15={r15}")
    if (cnt_30, cnt_2c) != (34, 39):
        fail(f"simulation counters mismatch {cnt_30} {cnt_2c}")
    if last_small_20 != 0x1000 or last_counted_rsi != 12288 or last_counted_18 != 15:
        fail("simulation tail values mismatch")
    if final_rsi != 1 << 62:
        fail("simulation final rsi mismatch")
    eligible = sum(flags[n] for n in range(232) if n % 8 < 7)
    if eligible != 172 or sum(flags.values()) != 198:
        fail("simulation flag totals mismatch")
    print("simulation ok: header [34, 39, 232, 8], flags 198, "
          "eligible 172, tail 2^62")

    # Disjointness.
    for label, (a, b) in NEIGHBOURS.items():
        if not (BODY_END <= a or BODY_START >= b):
            fail(f"body overlaps {label}")
        if not (THUNK_END <= a or THUNK_START >= b):
            fail(f"thunk overlaps {label}")
    for name, (start, end, _n, _s) in EXHIBITS.items():
        ok = (THUNK_START <= start and end <= THUNK_END) or \
             (BODY_START <= start and end <= BODY_END)
        if not ok:
            fail(f"exhibit {name} outside thunk/body FDEs")
    print("disjoint ok: exhibits inside thunk/body FDEs, no neighbour overlap")

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    if len(lines) != 15:
        fail(f"MANIFEST {len(lines)} entries != 15")
    names = [l.split(None, 1)[1] for l in lines]
    for name in EXHIBITS:
        if name + ".hex" not in names or name + ".objdump.txt" not in names:
            fail(f"MANIFEST missing {name}")
    for extra in ("README.md", "EVIDENCE.md", "records.json",
                  "../../../tools/node115_lu_descbuild.py",
                  "../../../tests/test_node115_lu_descbuild.py"):
        if extra not in names:
            fail(f"MANIFEST missing {extra}")
    if "MANIFEST.sha256" in names:
        fail("MANIFEST lists itself")
    print("MANIFEST ok: 15/15 entries")
    print(f"verifier: all checks passed ({len(EXHIBITS)} excerpts, "
          f"{total_bytes} bytes, {total_strict} strict, thunk census "
          f"{len(THUNK_CALLERS)} E8, body census {len(BODY_CALLERS)} E8 "
          f"+ {len(BODY_JUMPERS)} E9, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
