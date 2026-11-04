#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-tail-route.

Reads only bytes of artifacts/node/115/hl-node. Never executes the node.
Checks: binary size + SHA-256, 5 excerpt regenerations, strict mnemonic
counts, key-byte sites, whole-.text census (E8/E9/LEA + .rela.dyn GOT),
disjointness from prior packets' exhibits, MANIFEST hashes.

Usage: python3 tools/node115_lu_tail_route.py   (exit 0 = all pass)
"""

import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-tail-route")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

EXPECT_SIZE = 105896032
EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# name, start VA, end VA, strict mnemonic lines
EXCERPTS = [
    ("tail_lookup", 0x635F4E0, 0x635F50B, 10),
    ("tail_pred", 0x635F523, 0x635F53E, 7),
    ("tail_accum", 0x635F678, 0x635F68D, 5),
    ("tail_drain", 0x635F610, 0x635F637, 6),
    ("tail_callsite", 0x635FBE5, 0x635FC1E, 15),
]

# address, expected bytes (hex)
KEY_BYTES = [
    (0x635F4B0, "41574156"),      # tail FDE start: push r15/r14 (no endbr64)
    (0x635F4B6, "4989cd"),        # mov %rcx,%r13  (arg4)
    (0x635F4BB, "4989d4"),        # mov %rdx,%r12  (C)
    (0x635F4C1, "4889fd"),        # mov %rdi,%rbp  (thread)
    (0x635F4C9, "488d0dd8253b00"),  # lea divisor .bss 0x6711aa8
    (0x635F4E0, "8b8650340100"),  # mov 0x13450(%rsi),%eax (segment counter)
    (0x635F4E6, "488d35b3253b00"),  # lea table base .bss 0x6711aa0
    (0x635F4ED, "48f731"),        # divq (%rcx)
    (0x635F4F8, "48c1e304"),      # shl $0x4,%rbx (stride 208 = 13*16)
    (0x635F4FF, "4c8d7378"),      # lea 0x78(%rbx),%r14 (entry mutex)
    (0x635F506, "e8a5220900"),    # call pthread_mutex_trylock@plt (entry)
    (0x635F50F, "4883437001"),    # addq $0x1,0x70(%rbx) (entry count)
    (0x635F51A, "4883436001"),    # addq $0x1,0x60(%rbx) (entry owner-change)
    (0x635F51F, "48896b68"),      # mov %rbp,0x68(%rbx) (entry owner)
    (0x635F523, "4889df"),        # mov %rbx,%rdi (predicate arg)
    (0x635F526, "e865a20000"),    # call predicate 0x6369790
    (0x635F52F, "c683a000000000"),  # movb $0x0,0xa0(%rbx) (entry flag clear)
    (0x635F540, "c683a000000001"),  # movb $0x1,0xa0(%rbx) (entry flag set)
    (0x635F570, "0fb6bbac000000"),  # movzbl 0xac(%rbx),%edi (table byte)
    (0x635F580, "4d8d7c2440"),    # lea 0x40(%r12),%r15 (C mutex)
    (0x635F588, "e823220900"),    # call pthread_mutex_trylock@plt (C)
    (0x635F595, "498344243801"),  # addq $0x1,0x38(%r12) (C count)
    (0x635F59B, "493b6c2430"),    # cmp 0x30(%r12),%rbp (C owner)
    (0x635F5A2, "498344242801"),  # addq $0x1,0x28(%r12) (C owner-change)
    (0x635F5A8, "49896c2430"),    # mov %rbp,0x30(%r12) (C owner)
    (0x635F5AD, "4d8b442478"),    # mov 0x78(%r12),%r8 (C+0x78 gate)
    (0x635F5B5, "0f8ea5000000"),  # jle (C+0x78 <= 0 skip)
    (0x635F5BB, "488dbbb0000000"),  # lea 0xb0(%rbx),%rdi (entry+0xb0)
    (0x635F5C7, "e8c4050600"),    # call 0x63bfb90
    (0x635F5D2, "e889050600"),    # call 0x63bfb60
    (0x635F5E7, "e814060600"),    # call 0x63bfc00 (gating return)
    (0x635F5F8, "e843060600"),    # call 0x63bfc40
    (0x635F5FD, "4d85ed"),        # test %r13,%r13 (arg4)
    (0x635F602, "41c644246800"),  # movb $0x0,0x68(%r12) (C flag clear)
    (0x635F610, "4881bbb800000000040000"),  # cmpq $0x400,0xb8(%rbx)
    (0x635F621, "48c783b800000000000000"),  # movq $0x0,0xb8(%rbx)
    (0x635F632, "e869a10000"),    # call drain 0x63697a0 (threshold)
    (0x635F640, "31f6"),          # xor %esi,%esi (drain arg NULL)
    (0x635F645, "e856a10000"),    # call drain 0x63697a0 (byte set)
    (0x635F650, "41c644246801"),  # movb $0x1,0x68(%r12) (C flag set)
    (0x635F678, "4c89ea"),        # mov %r13,%rdx (arg4 to accumulator)
    (0x635F681, "e86aa00400"),    # call accumulator 0x63a96f0
    (0x635F686, "480183b8000000"),  # add %rax,0xb8(%rbx)
    (0x635FBE5, "4d8ba7e8060000"),  # mov 0x6e8(%r15),%r12 (C+0x6e8)
    (0x635FBEC, "41c6476800"),    # movb $0x0,0x68(%r15) (C flag clear)
    (0x635FBF5, "e8760f0900"),    # call pthread_mutex_unlock@plt (C)
    (0x635FC03, "4584c9"),        # test %r9b,%r9b (runtime byte gate)
    (0x635FC08, "4584f6"),        # test %r14b,%r14b (6th-arg gate)
    (0x635FC19, "e892f8ffff"),    # call tail route 0x635f4b0
    (0x6360F93, "48894c2418"),    # mov %rcx,0x18(%rsp) (caller spill)
    (0x6361050, "4c89442418"),    # mov %r8,0x18(%rsp) (caller overwrite)
    (0x6361119, "488b4c2418"),    # mov 0x18(%rsp),%rcx (forwarded arg4)
    (0x6361129, "e882e3ffff"),    # call tail route 0x635f4b0
    (0x6360695, "e916eeffff"),    # jmp tail route 0x635f4b0 (gate)
]

# target VA -> (expected E8 sites, expected E9 sites)
CENSUS = {
    0x635F4B0: ([0x635FC19, 0x6361129], [0x6360695]),
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
    # #206
    (0x635FB50, 0x635FB90), (0x635FC30, 0x635FC76),
    (0x635FBAD, 0x635FBE5), (0x636063A, 0x636066F), (0x6360680, 0x636069A),
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
