#!/usr/bin/env python3
"""Static verifier for the node #115 lu loop-driver packet
(RE-001-node115-lu-driver).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt
  (address + bytes field + tab + mnemonic; objdump byte-continuation
  lines carry no mnemonic and are excluded),
- key instruction bytes (entry endbr64, single ret opcode, int3
  padding after the FDE, guard cmp, flag-byte init, three loop-call
  rel32s, gate-call rel32, completion-call rel32, accumulate /
  remaining / done-compare stores, contention jmp targets,
  contention-flag stores, return-value load),
- FDE bounds (0x63b8d90..0x63b8fd1, 577 bytes) and that every
  direct branch target in the FDE lies inside the FDE,
- census: 0 direct E8, 0 E9, 1 LEA (0x63b90ea), 0 GOT
  (60,723 .rela.dyn entries),
- disjointness from neighbouring claimed ranges,
- MANIFEST.sha256 coverage (17 entries, MANIFEST itself excluded).
"""

import hashlib
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-driver")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_START = 0x63B8D90
FDE_END = 0x63B8FD1
RET_SITES = (0x63B8DE7,)
CALLS = {
    0x63B8E1A: 0x63B81B0,  # loop caller, round 1
    0x63B8E49: 0x63F17B0,  # pthread_mutex_trylock@plt (context+0xf0)
    0x63B8E95: 0x63B81B0,  # loop caller, round 2
    0x63B8EC2: 0x63B85F0,  # gate (cited, not claimed)
    0x63B8EEA: 0x63F17B0,  # pthread_mutex_trylock@plt (context+0x80)
    0x63B8F1A: 0x63D94B0,  # completion helper (cited, not claimed)
    0x63B8F2C: 0x63F0B70,  # pthread_mutex_unlock@plt (context+0x80)
    0x63B8F4D: 0x63B81B0,  # loop caller, round 3
    0x63B8F62: 0x63F0B70,  # pthread_mutex_unlock@plt (context+0xf0)
    0x63B8F7D: 0x63F0B70,  # pthread_mutex_unlock@plt (early-exit path)
    0x63B8F95: 0x63BF680,  # contention helper (context+0xb0)
    0x63B8FB5: 0x63BF680,  # contention helper (context+0x40)
    0x63B8FCC: 0x63F0D70,  # __stack_chk_fail@plt
}
# Neighbouring claimed ranges that must not overlap this FDE.
NEIGHBOURS = {
    "single-shot caller (#232)": (0x63B8820, 0x63B8D85),
    "loop caller (#233)": (0x63B81B0, 0x63B8517),
    "tiny wrapper (adjacent)": (0x63B8160, 0x63B81AB),
    "next function": (0x63B8FE0, 0x63B9180),
    "class-search (#230)": (0x63D9340, 0x63D945B),
    "class-merge (#231)": (0x63B9690, 0x63B99C8),
    "finder (#226)": (0x63B0980, 0x63B15E9),
    "slot-head (#225)": (0x63ABD00, 0x63AC0CC),
    "release (#224)": (0x63B0780, 0x63B0980),
    "size rep (#227)": (0x63E8C80, 0x63E8D87),
    "table-fill (#228)": (0x63E8D90, 0x63E9152),
    "descbuild thunk (#229)": (0x63DA080, 0x63DA089),
    "descbuild body (#229)": (0x63D9BA0, 0x63D9ED3),
}

EXHIBITS = {
    "dr_entry": (0x63B8D90, 0x63B8DF0, 96, 28),
    "dr_call1": (0x63B8DF0, 0x63B8E31, 65, 20),
    "dr_lock2": (0x63B8E31, 0x63B8E76, 69, 12),
    "dr_call2": (0x63B8E76, 0x63B8EB3, 61, 17),
    "dr_gate": (0x63B8EB3, 0x63B8ED0, 29, 7),
    "dr_call3": (0x63B8F10, 0x63B8F6A, 90, 22),
}

EXPECTED_LEA = ["0x63b90ea"]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")
BRANCH_RE = re.compile(r"\t(jmp|je|jne|ja|jb|jae|jbe|js|jns|jo|jno)\s+([0-9a-f]+)")


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def read_node():
    with open(NODE, "rb") as f:
        return f.read()


def main():
    data = read_node()
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("binary SHA-256 mismatch")
    if len(data) != TARGET_SIZE:
        fail("binary size mismatch")
    if FDE_END - FDE_START != 577:
        fail("FDE size mismatch")
    off = lambda va: va - 0x1000
    # Entry is endbr64.
    if data[off(FDE_START):off(FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    for site in RET_SITES:
        if data[off(site)] != 0xC3:
            fail("ret site %s is not 0xc3" % hex(site))
    if data[off(FDE_END):off(FDE_END) + 15] != bytes.fromhex("cc" * 15):
        fail("bytes after FDE are not int3 padding")
    if data[off(0x63B8FE0):off(0x63B8FE0) + 4] != bytes.fromhex("f30f1efa"):
        fail("next function does not start with endbr64")
    for site, target in CALLS.items():
        if data[off(site)] != 0xE8:
            fail("call site %s is not E8" % hex(site))
        rel = struct.unpack_from("<i", data, off(site) + 1)[0]
        if site + 5 + rel != target:
            fail("call site %s does not target %s" % (hex(site), hex(target)))
    # Guard: cmp %rdx,0x15f8(%rsi) at 0x63b8db9.
    if data[off(0x63B8DB9):off(0x63B8DB9) + 7] != bytes.fromhex("483996f8150000"):
        fail("guard cmp bytes mismatch")
    # Flag-byte init: movb $0x0,0x37(%rsp) at 0x63b8df8.
    if data[off(0x63B8DF8):off(0x63B8DF8) + 5] != bytes.fromhex("c644243700"):
        fail("flag-byte init bytes mismatch")
    # Round 1 accumulate: mov %rax,%r15 at 0x63b8e22.
    if data[off(0x63B8E22):off(0x63B8E22) + 3] != bytes.fromhex("4989c7"):
        fail("round-1 accumulate bytes mismatch")
    # Round 1 done compare: cmp %rax,%rbx at 0x63b8e25.
    if data[off(0x63B8E25):off(0x63B8E25) + 3] != bytes.fromhex("4839c3"):
        fail("round-1 done-compare bytes mismatch")
    # Round 2 remaining: sub %r15,%r8 at 0x63b8e8a.
    if data[off(0x63B8E8A):off(0x63B8E8A) + 3] != bytes.fromhex("4d29f8"):
        fail("round-2 remaining bytes mismatch")
    # Round 2 accumulate: add %rax,%r15 at 0x63b8e9c.
    if data[off(0x63B8E9C):off(0x63B8E9C) + 3] != bytes.fromhex("4901c7"):
        fail("round-2 accumulate bytes mismatch")
    # Gate test: test %rax,%rax at 0x63b8ec7.
    if data[off(0x63B8EC7):off(0x63B8EC7) + 3] != bytes.fromhex("4885c0"):
        fail("gate test bytes mismatch")
    # Round 3 remaining: sub %r15,%rbx at 0x63b8f17.
    if data[off(0x63B8F17):off(0x63B8F17) + 3] != bytes.fromhex("4c29fb"):
        fail("round-3 remaining bytes mismatch")
    # Contention flag sets: movb $0x1,0x118(%r14) at 0x63b8f9a;
    # movb $0x1,0xa8(%r14) at 0x63b8fba.
    if data[off(0x63B8F9A):off(0x63B8F9A) + 8] != bytes.fromhex("41c6861801000001"):
        fail("second-mutex contention flag bytes mismatch")
    if data[off(0x63B8FBA):off(0x63B8FBA) + 8] != bytes.fromhex("41c686a800000001"):
        fail("first-mutex contention flag bytes mismatch")
    # Contention rejoins: jmp 0x63b8e56 at 0x63b8fa2;
    # jmp 0x63b8efc at 0x63b8fc7 (no second trylock on either path).
    for site, target in ((0x63B8FA2, 0x63B8E56), (0x63B8FC7, 0x63B8EFC)):
        if data[off(site)] != 0xE9:
            fail("contention rejoin at %s is not E9" % hex(site))
        rel = struct.unpack_from("<i", data, off(site) + 1)[0]
        if site + 5 + rel != target:
            fail("contention rejoin at %s does not target %s" % (hex(site), hex(target)))
    # Return-value load: mov %r15,%rax at 0x63b8dda.
    if data[off(0x63B8DDA):off(0x63B8DDA) + 3] != bytes.fromhex("4c89f8"):
        fail("return load bytes mismatch")
    for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        if len(raw) != nbytes:
            fail("%s byte length %d != %d" % (name, len(raw), nbytes))
        if raw != data[off(start):off(start) + nbytes]:
            fail("%s bytes do not match binary" % name)
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            strict = sum(1 for line in f if STRICT_RE.match(line))
        if strict != nstrict:
            fail("%s strict count %d != %d" % (name, strict, nstrict))
    # FDE-wide disassembly checks via objdump (byte reads only).
    import subprocess
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(FDE_START),
         "--stop-address=%s" % hex(FDE_END), NODE],
        capture_output=True, text=True, check=True).stdout
    rets = [l for l in out.splitlines() if re.search(r"\tret\s*$", l)]
    if len(rets) != 1:
        fail("expected exactly 1 ret in FDE, found %d" % len(rets))
    for line in out.splitlines():
        m = BRANCH_RE.search(line)
        if m and not (FDE_START <= int(m.group(2), 16) < FDE_END):
            fail("branch target %s outside FDE" % m.group(2))
    # Census: whole-.text scan for E8/E9/LEA resolving to FDE_START.
    # .text: file range [0x1418300, 0x1418300 + 0x4fd7700), VA = off + 0x1000.
    t_off, t_size = 0x1418300, 0x4FD7700
    e8, e9, lea = [], [], []
    for o in range(t_off, t_off + t_size - 7):
        va = o + 0x1000
        b = data[o]
        if b in (0xE8, 0xE9):
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            if va + 5 + rel == FDE_START:
                (e8 if b == 0xE8 else e9).append(va)
        if 0x48 <= b <= 0x4F and data[o + 1] == 0x8D \
                and (data[o + 2] & 0xC7) == 0x05:
            rel = struct.unpack("<i", data[o + 3:o + 7])[0]
            if va + 7 + rel == FDE_START:
                lea.append(va)
    if e8:
        fail("unexpected E8 sites: %s" % [hex(x) for x in e8])
    if e9:
        fail("unexpected E9 sites: %s" % [hex(x) for x in e9])
    if [hex(x) for x in lea] != EXPECTED_LEA:
        fail("LEA census mismatch: %s" % [hex(x) for x in lea])
    # .rela.dyn addend scan (file offset 0x6be8, 60,723 entries).
    ro, n = 0x6BE8, 60723
    for i in range(n):
        _off, _info, add = struct.unpack_from("<QQq", data, ro + i * 24)
        if add == FDE_START:
            fail("rela addend hits FDE start")
    for label, (s, e) in NEIGHBOURS.items():
        if not (e <= FDE_START or s >= FDE_END):
            fail("FDE overlaps %s" % label)
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        entries = [line.split() for line in f if line.strip()]
    if len(entries) != 17:
        fail("MANIFEST has %d entries, expected 17" % len(entries))
    names = [path for _digest, path in entries]
    if "MANIFEST.sha256" in names:
        fail("MANIFEST lists itself")
    for digest, path in entries:
        with open(os.path.normpath(os.path.join(PACKET, path)), "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != digest:
                fail("MANIFEST mismatch for %s" % path)
    print("verifier: all checks passed (6 excerpts, 410 bytes, 106 strict, "
          "census 0 E8 / 0 E9 / 1 LEA, MANIFEST 17/17)")


if __name__ == "__main__":
    main()
