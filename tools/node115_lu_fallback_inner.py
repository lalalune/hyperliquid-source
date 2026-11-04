#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-fallback-inner.

Reads only bytes of artifacts/node/115/hl-node. Never executes the node.
Checks: binary size + SHA-256, 5 excerpt regenerations, strict mnemonic
counts, key-byte sites, whole-.text census (E8/E9/LEA + .rela.dyn GOT),
disjointness from prior packets' exhibits, MANIFEST hashes.

Usage: python3 tools/node115_lu_fallback_inner.py   (exit 0 = all pass)
"""

import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-fallback-inner")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

EXPECT_SIZE = 105896032
EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# name, start VA, end VA, strict mnemonic lines
EXCERPTS = [
    ("inner_head", 0x635FB50, 0x635FB90, 20),
    ("inner_branch", 0x635FC30, 0x635FC76, 17),
    ("inner_call", 0x635FBAD, 0x635FBE5, 13),
    ("gate_cont", 0x636063A, 0x636066F, 12),
    ("gate_tail", 0x6360680, 0x636069A, 8),
]

# address, expected bytes (hex)
KEY_BYTES = [
    (0x635FB50, "41574989"),      # inner FDE start: push r15; mov rdx,r15 (no endbr64)
    (0x635FB6D, "807c245000"),    # cmpb $0x0,0x50(%rsp) -- 7th-arg test
    (0x635FB83, "e8281c0900"),    # call pthread_mutex_trylock@plt (main path)
    (0x635FB90, "4983473801"),    # addq $0x1,0x38(%r15)  C+0x38
    (0x635FB9B, "4983472801"),    # addq $0x1,0x28(%r15)  C+0x28
    (0x635FBA0, "49895f30"),      # mov %rbx,0x30(%r15)  C+0x30 = thread
    (0x635FBAD, "488d05041f3b00"),  # lea .bss 0x6711ab8
    (0x635FBB4, "41b902000000"),  # mov $0x2,%r9d
    (0x635FBC2, "4129d1"),        # sub %edx,%r9d  (mode = 2 - bss byte)
    (0x635FBC5, "488db5b0290000"),  # lea seg+0x29b0 (= obj+0x18)
    (0x635FBD8, "e8c31d0600"),    # call workerA 0x63c19a0
    (0x635FBE5, "4d8ba7e8060000"),  # mov 0x6e8(%r15),%r12  (C+0x6e8)
    (0x635FBEC, "41c6476800"),    # movb $0x0,0x68(%r15)  flag clear
    (0x635FC19, "e892f8ffff"),    # call tail route 0x635f4b0
    (0x635FC30, "4c8d7240"),      # lea 0x40(%rdx),%r14  (branch path mutex)
    (0x635FC37, "e8741b0900"),    # call pthread_mutex_trylock@plt (branch)
    (0x635FC68, "41b901000000"),  # mov $0x1,%r9d  (workerB mode)
    (0x635FC71, "e8ba1c0600"),    # call workerB 0x63c1930
    (0x635FCC0, "41c6476801"),    # movb $0x1,0x68(%r15)  flag set
    (0x635FCC9, "b801000000"),    # mov $0x1,%eax  (only nonzero return)
    (0x635FCE3, "e898f90500"),    # call lock-wait 0x63bf680
    (0x6360610, "f30f1efa"),      # fallback FDE start endbr64
    (0x6360620, "488b86400f0100"),  # mov [seg+0x10f40],%rax (gate load)
    (0x636062C, "488d1585143b00"),  # lea .bss 0x6711ab8
    (0x636063A, "8b8350340100"),  # mov [seg+0x13450],%eax (segment counter)
    (0x6360640, "488d3561143b00"),  # lea divisor .bss 0x6711aa8
    (0x6360649, "4c8d0d50143b00"),  # lea table .bss 0x6711aa0
    (0x6360650, "48f736"),        # divq (%rsi)
    (0x6360662, "450fb690ac000000"),  # movzbl table+0xac
    (0x6360684, "488d93c80e0100"),  # lea seg+0x10ec8 (tail-route C arg)
    (0x636068E, "31c9"),           # xor %ecx,%ecx (tail-route arg4 = 0)
    (0x6360695, "e916eeffff"),    # jmp tail route 0x635f4b0
    (0x63606A4, "488b8ec01c0100"),  # mov [seg+0x11cc0],%rcx
    (0x63606B5, "6a01"),           # push $0x1 (inner 7th arg)
    (0x63606B7, "4c8d86e8290000"),  # lea seg+0x29e8
    (0x63606BE, "e88df4ffff"),    # call inner 0x635fb50
    (0x6361244, "6a00"),           # push $0x0 (caller 0x6361170 stack7)
    (0x6360FF1, "4152"),           # push %r10 (caller 0x6360ed0 stack7)
    (0x635F4B0, "41574156"),      # tail-route FDE start (no endbr64)
]

# target VA -> (expected E8 sites, expected E9 sites)
CENSUS = {
    0x635FB50: ([0x63606BE, 0x6361009, 0x6361258], []),
    0x6360610: ([0x63607FE, 0x636130E, 0x6361806, 0x636183E, 0x6361886,
                 0x63628A5, 0x6363ACC, 0x6364E3E, 0x63BCCB6, 0x63BD526,
                 0x63BD6AE, 0x63BD816], []),
    0x635F4B0: ([0x635FC19, 0x6361129], [0x6360695]),
    0x63C19A0: ([0x635FBD8, 0x6360F7C, 0x63611EF, 0x63C1BFC], []),
    0x63C1930: ([0x635FC71, 0x63610A4], []),
}

# Prior packets' exhibit ranges (start, end); this packet must not overlap.
PRIOR_RANGES = [
    # #202
    (0x635DE30, 0x635DEC6), (0x5A8E3C0, 0x5A8E493),
    (0x5A8C9F0, 0x5A8CA2C), (0x5A8C110, 0x5A8C14C),
    # #203
    (0x635C6D0, 0x635C886), (0x635CDF8, 0x635CE47), (0x635CCE8, 0x635CD7F),
    # #204
    (0x63EAEF0, 0x63EAF7E), (0x63EB9D0, 0x63EBA48),
    (0x63BD640, 0x63BD687), (0x63EC019, 0x63EC068),
    # #205
    (0x63C0340, 0x63C03E8), (0x63BD687, 0x63BD6B3),
    (0x63612E6, 0x6361313), (0x6360610, 0x636063A),
]


def parse_sections(data):
    """Return {name: (addr, offset, size)} for .text and .rela.dyn."""
    assert data[:4] == b"\x7fELF"
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize = struct.unpack("<H", data[0x3A:0x3C])[0]
    e_shnum = struct.unpack("<H", data[0x3C:0x3E])[0]
    e_shstrndx = struct.unpack("<H", data[0x3E:0x40])[0]
    headers = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, _flags, addr, offset, size = struct.unpack(
            "<IIQQQQ", data[off:off + 40])
        headers.append((name, typ, addr, offset, size))
    shstr_off = headers[e_shstrndx][3]
    out = {}
    for name_off, _typ, addr, offset, size in headers:
        end = data.index(b"\x00", shstr_off + name_off)
        name = data[shstr_off + name_off:end].decode()
        if name in (".text", ".rela.dyn"):
            out[name] = (addr, offset, size)
    return out


def strict_count(objdump_path):
    """Strict mnemonic lines: addr + bytes + tab + letter-start mnemonic."""
    import re
    n = 0
    with open(objdump_path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3 and re.match(r"[a-z]", parts[2].strip()[:1]):
                n += 1
    return n


def main():
    failures = []
    with open(BIN, "rb") as f:
        data = f.read()
    if len(data) != EXPECT_SIZE:
        failures.append(f"size {len(data)} != {EXPECT_SIZE}")
    if hashlib.sha256(data).hexdigest() != EXPECT_SHA:
        failures.append("sha256 mismatch")
    secs = parse_sections(data)
    text_addr, text_off, text_size = secs[".text"]
    rela_addr, rela_off, rela_size = secs[".rela.dyn"]
    text = data[text_off:text_off + text_size]

    def va_bytes(va, n):
        return data[text_off + (va - text_addr):text_off + (va - text_addr) + n]

    for name, start, end, want_strict in EXCERPTS:
        raw = data[text_off + (start - text_addr):text_off + (end - text_addr)]
        with open(os.path.join(PACKET, name + ".hex"), encoding="utf-8") as f:
            if bytes.fromhex("".join(f.read().split())) != raw:
                failures.append(f"{name}.hex regeneration mismatch")
        got_strict = strict_count(os.path.join(PACKET, name + ".objdump.txt"))
        if got_strict != want_strict:
            failures.append(f"{name} strict {got_strict} != {want_strict}")
        for (ps, pe) in PRIOR_RANGES:
            if start < pe and ps < end:
                failures.append(f"{name} overlaps prior {hex(ps)}..{hex(pe)}")

    for va, want_hex in KEY_BYTES:
        got = va_bytes(va, len(bytes.fromhex(want_hex))).hex()
        if got != want_hex:
            failures.append(f"key bytes {hex(va)}: {got} != {want_hex}")

    # Census: byte scan for E8/E9 rel32 and rip-relative LEA.
    for tgt, (want_e8, want_e9) in CENSUS.items():
        e8, e9, lea = [], [], []
        for op, acc in ((0xE8, e8), (0xE9, e9)):
            idx = text.find(bytes([op]))
            while idx != -1 and idx + 5 <= len(text):
                rel = struct.unpack("<i", text[idx + 1:idx + 5])[0]
                if text_addr + idx + 5 + rel == tgt:
                    acc.append(text_addr + idx)
                idx = text.find(bytes([op]), idx + 1)
        for rex in (0x48, 0x49, 0x4C, 0x4D):
            idx = text.find(bytes([rex, 0x8D]))
            while idx != -1 and idx + 7 <= len(text):
                if (text[idx + 2] & 0xC7) == 0x05:
                    disp = struct.unpack("<i", text[idx + 3:idx + 7])[0]
                    if text_addr + idx + 7 + disp == tgt:
                        lea.append(text_addr + idx)
                idx = text.find(bytes([rex, 0x8D]), idx + 1)
        if sorted(e8) != sorted(want_e8):
            failures.append(f"census E8 {hex(tgt)}: {[hex(x) for x in e8]}")
        if sorted(e9) != sorted(want_e9):
            failures.append(f"census E9 {hex(tgt)}: {[hex(x) for x in e9]}")
        if lea:
            failures.append(f"census LEA {hex(tgt)}: {[hex(x) for x in lea]}")

    # GOT: .rela.dyn RELATIVE (type 8) addends must not equal any target.
    rela = data[rela_off:rela_off + rela_size]
    for i in range(0, len(rela) - 23, 24):
        _off, info, addend = struct.unpack("<QQq", rela[i:i + 24])
        if (info & 0xFFFFFFFF) == 8 and addend in CENSUS:
            failures.append(f"GOT RELATIVE addend equals {hex(addend)}")

    # MANIFEST hashes.
    manifest = os.path.join(PACKET, "MANIFEST.sha256")
    with open(manifest, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            want, path = line.split("  ", 1)
            full = os.path.normpath(os.path.join(PACKET, path))
            with open(full, "rb") as g:
                if hashlib.sha256(g.read()).hexdigest() != want:
                    failures.append(f"MANIFEST mismatch {path}")

    if failures:
        print("verifier: FAIL")
        for msg in failures:
            print(" -", msg)
        return 1
    print("verifier: all checks passed (5 excerpts, %d key-byte sites, "
          "census %d E8 sites, MANIFEST 15/15)"
          % (len(KEY_BYTES), sum(len(v[0]) for v in CENSUS.values())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
