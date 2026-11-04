#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-free-dealloc.

Reads bytes only; never executes the node binary. Verifies:
- binary identity (size + SHA-256)
- shipped hex excerpts equal the binary bytes at their ranges
- strict mnemonic-line counts of the shipped objdump excerpts
- the whole-binary census: 0 direct E8 / 0 E9 / 0 LEA / 0 absolute
  references for the free target and both sibling field drops;
  exactly 46 / 27 / 141 FF 15 call sites through their RELATIVE
  .got slots; 98,976 FF 15 sites through the shared deallocator slot
- the RELATIVE relocation entries for all four slots
- spot-checked GOT site bytes resolving to their slots
- key instruction bytes: buffer-free call, field-drop calls,
  dealloc sizes, lock-dec tails, deallocator guards, free-list
  push, body rets, slow-path jump
- the claimed ranges are disjoint from prior packets' claimed FDEs
Exit 0 on success, nonzero with a message on the first failure.
"""
import hashlib
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-free-dealloc"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

BIN_SIZE = 105896032
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

FREE = 0x5A8E3C0
DROP9F0 = 0x5A8C9F0
DROP110 = 0x5A8C110
DEALLOC = 0x635DE30
FREE_SLOT = 0x64E7278
SLOT9F0 = 0x64E7270
SLOT110 = 0x64E7208
DEALLOC_SLOT = 0x64DF4A0
SLOW_PATH = 0x635C6D0

EXCERPTS = [
    # (hex file, objdump file, start VA, end VA, strict count)
    ("free.hex", "free.objdump.txt", 0x5A8E3C0, 0x5A8E493, 59),
    ("drop9f0.hex", "drop9f0.objdump.txt", 0x5A8C9F0, 0x5A8CA2C, 21),
    ("drop110.hex", "drop110.objdump.txt", 0x5A8C110, 0x5A8C14C, 21),
    ("dealloc.hex", "dealloc.objdump.txt", 0x635DE30, 0x635DEC6, 29),
]

# Prior packets' claimed FDE ranges; this packet must not overlap them.
PRIOR_RANGES = [
    (0x4FAC710, 0x4FAC7E0),  # #200 acquire
    (0x4FB52E0, 0x4FB5440),  # #194 gate-release
    (0x4DA86A0, 0x4DA8860),  # #195 completion
    (0x4DA6C80, 0x4DA6D70),  # #200 cell resolver
    (0x2AC0F60, 0x2AC0FB0),  # #201 wrapper
    (0x2ACE08B, 0x2ACE0EC),  # #201 acquire excerpt
    (0x2ACEB52, 0x2ACEBA0),  # #201 release excerpt
]

# Spot GOT sites: (site VA, expected 6 bytes, slot VA, name)
GOT_SPOTS = [
    (0x2A9E182, bytes.fromhex("ff15f090a403"), FREE_SLOT, "free"),
    (0x2AA5A8F, bytes.fromhex("ff15e317a403"), FREE_SLOT, "free"),
    (0x5A4C137, bytes.fromhex("ff153bb1a900"), FREE_SLOT, "free"),
    (0x5A621EC, bytes.fromhex("ff158650a800"), FREE_SLOT, "free"),
    (0x2A9E163, bytes.fromhex("ff150791a403"), SLOT9F0, "drop9f0"),
    (0x2AA1799, bytes.fromhex("ff15d15aa403"), SLOT9F0, "drop9f0"),
    (0x5A39828, bytes.fromhex("ff1542daaa00"), SLOT9F0, "drop9f0"),
    (0x5A6CF93, bytes.fromhex("ff15d7a2a700"), SLOT9F0, "drop9f0"),
    (0x2A94D88, bytes.fromhex("ff157a24a503"), SLOT110, "drop110"),
    (0x2A9E1B6, bytes.fromhex("ff154c90a403"), SLOT110, "drop110"),
    (0x5A3D9D3, bytes.fromhex("ff152f98aa00"), SLOT110, "drop110"),
    (0x5A62200, bytes.fromhex("ff150250a800"), SLOT110, "drop110"),
    (0x141960A, bytes.fromhex("ff15905e0c05"), DEALLOC_SLOT, "dealloc"),
    (0x14198EA, bytes.fromhex("ff15b05b0c05"), DEALLOC_SLOT, "dealloc"),
    (0x14218E3, bytes.fromhex("ff15b7db0b05"), DEALLOC_SLOT, "dealloc"),
    (0x143A5A0, bytes.fromhex("ff15fa4e0a05"), DEALLOC_SLOT, "dealloc"),
]

# Key instruction bytes: (VA, expected bytes, label)
KEY_BYTES = [
    (0x5A8E426, bytes.fromhex("ff157410a500"), "free buffer-free call"),
    (0x5A8E469, bytes.fromhex("f048ff4b08"), "free lock dec"),
    (0x5A8E470, bytes.fromhex("be38000000"), "free dealloc size 0x38"),
    (0x5A8E483, bytes.fromhex("ff251710a500"), "free tail jmp to dealloc"),
    (0x5A8E492, b"\xc3", "free body ret"),
    (0x5A8C9FB, bytes.fromhex("e81040fcff"), "drop9f0 field call"),
    (0x5A8CA0D, bytes.fromhex("be800b0000"), "drop9f0 dealloc size 0xb80"),
    (0x5A8CA1E, bytes.fromhex("ff257c2aa500"), "drop9f0 tail jmp to dealloc"),
    (0x5A8CA2B, b"\xc3", "drop9f0 body ret"),
    (0x5A8C11B, bytes.fromhex("e8e010fcff"), "drop110 field call"),
    (0x5A8C12D, bytes.fromhex("bec8000000"), "drop110 dealloc size 0xc8"),
    (0x5A8C13E, bytes.fromhex("ff255c33a500"), "drop110 tail jmp to dealloc"),
    (0x5A8C14B, b"\xc3", "drop110 body ret"),
    (0x635DE30, bytes.fromhex("f30f1efa"), "dealloc endbr64"),
    (0x635DE34, bytes.fromhex("4881fe00100000"), "dealloc size guard"),
    (0x635DE41, bytes.fromhex("85d2"), "dealloc third-arg guard"),
    (0x635DE49, bytes.fromhex("f7c7ff0f0000"), "dealloc alignment guard"),
    (0x635DEAE, bytes.fromhex("498d51f8"), "dealloc head decrement"),
    (0x635DEB9, bytes.fromhex("498979f8"), "dealloc free-list push"),
    (0x635DEC5, b"\xc3", "dealloc body ret"),
    (0x635DED0, bytes.fromhex("e9fbe7ffff"), "dealloc slow-path jump"),
]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def text_bytes(data, va, n):
    # .text file offset = VA - 0x1000
    off = va - 0x1000
    return data[off:off + n]


def main():
    data = BIN.read_bytes()
    if len(data) != BIN_SIZE:
        fail(f"binary size {len(data)} != {BIN_SIZE}")
    if hashlib.sha256(data).hexdigest() != BIN_SHA256:
        fail("binary SHA-256 mismatch")
    print(f"binary OK: {BIN_SIZE} bytes, sha256 {BIN_SHA256[:16]}...")

    # Excerpts: hex bytes + strict objdump counts.
    for hex_name, dump_name, start, end, want_count in EXCERPTS:
        raw = bytes.fromhex((PACKET / hex_name).read_text().strip())
        if raw != text_bytes(data, start, end - start):
            fail(f"{hex_name} bytes differ from binary at {start:#x}")
        lines = (PACKET / dump_name).read_text().splitlines()
        count = sum(1 for ln in lines if STRICT_RE.match(ln))
        if count != want_count:
            fail(f"{dump_name} strict count {count} != {want_count}")
        print(f"{hex_name}: {len(raw)} bytes at {start:#x}..{end:#x}, "
              f"strict {count} OK")
    for _, _, start, end, _ in EXCERPTS:
        for p0, p1 in PRIOR_RANGES:
            if start < p1 and p0 < end:
                fail(f"excerpt {start:#x}..{end:#x} overlaps prior {p0:#x}..{p1:#x}")
    print("excerpts disjoint from prior claimed FDEs OK")

    # Key instruction bytes.
    for va, want, label in KEY_BYTES:
        if text_bytes(data, va, len(want)) != want:
            fail(f"{label} at {va:#x} mismatch")
    # Slow-path jump target.
    disp = struct.unpack_from("<i", text_bytes(data, 0x635DED0, 5), 1)[0]
    if 0x635DED0 + 5 + disp != SLOW_PATH:
        fail("slow-path jump target mismatch")
    print(f"key instruction bytes OK: {len(KEY_BYTES)} checks")

    # Spot GOT sites resolve to their slots.
    for site, want, slot, name in GOT_SPOTS:
        got = text_bytes(data, site, 6)
        if got != want:
            fail(f"GOT spot {site:#x} bytes {got.hex()} != {want.hex()}")
        disp = struct.unpack_from("<i", got, 2)[0]
        if site + 6 + disp != slot:
            fail(f"GOT spot {site:#x} resolves wrong")
    print(f"GOT spot sites OK: {len(GOT_SPOTS)}")

    # ELF sections for the relocation / data scans.
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    secs = [struct.unpack_from("<IIQQQQ", data, e_shoff + i * e_shentsize)
            for i in range(e_shnum)]
    shstr_off = secs[e_shstrndx][4]

    def secname(n):
        end = data.index(b"\x00", shstr_off + n)
        return data[shstr_off + n:end].decode()

    S = {}
    for s in secs:
        S[secname(s[0])] = s
    text = S[".text"]
    taddr, toff, tsize = text[3], text[4], text[5]
    t = data[toff:toff + tsize]

    def va_of(i):
        return taddr + i

    # RELATIVE relocations for all four slots.
    rela = S[".rela.dyn"]
    found = {}
    for j in range(0, rela[5], 24):
        roff, info, add = struct.unpack_from("<QQq", data, rela[4] + j)
        if roff in (FREE_SLOT, SLOT9F0, SLOT110, DEALLOC_SLOT):
            found[roff] = (info & 0xFFFFFFFF, add)
    want_rela = {FREE_SLOT: (8, FREE), SLOT9F0: (8, DROP9F0),
                 SLOT110: (8, DROP110), DEALLOC_SLOT: (8, DEALLOC)}
    if found != want_rela:
        fail(f"RELATIVE relocations mismatch: {found}")
    print("RELATIVE relocations OK: free/drop9f0/drop110/dealloc slots")

    # Whole-binary negative census for the three drops.
    def scan_e(e8_not_e9, target):
        pat = b"\xe8" if e8_not_e9 else b"\xe9"
        hits, i = [], t.find(pat)
        while i != -1:
            if i + 5 <= len(t):
                rel = struct.unpack_from("<i", t, i + 1)[0]
                if va_of(i) + 5 + rel == target:
                    hits.append(va_of(i))
            i = t.find(pat, i + 1)
        return hits

    def scan_lea(target):
        hits = []
        for rex in (0x48, 0x4C):
            i = t.find(bytes([rex, 0x8D]))
            while i != -1:
                if i + 7 <= len(t) and (t[i + 2] & 0xC7) == 0x05:
                    disp = struct.unpack_from("<i", t, i + 3)[0]
                    if va_of(i) + 7 + disp == target:
                        hits.append(va_of(i))
                i = t.find(bytes([rex, 0x8D]), i + 1)
        return hits

    def scan_ff15(slot):
        hits, i = [], t.find(b"\xff\x15")
        while i != -1:
            if i + 6 <= len(t):
                disp = struct.unpack_from("<i", t, i + 2)[0]
                if va_of(i) + 6 + disp == slot:
                    hits.append(va_of(i))
            i = t.find(b"\xff\x15", i + 2)
        return hits

    for target, name in ((FREE, "free"), (DROP9F0, "drop9f0"),
                         (DROP110, "drop110")):
        e8, e9, lea = scan_e(True, target), scan_e(False, target), scan_lea(target)
        if e8 or e9 or lea:
            fail(f"{name} direct census not zero: E8={e8} E9={e9} LEA={lea}")
        abs_hits = []
        for dname in (".data.rel.ro", ".rodata", ".data", ".got", ".got.plt",
                      ".gcc_except_table", ".eh_frame", ".eh_frame_hdr"):
            s = S[dname]
            blob = data[s[4]:s[4] + s[5]]
            pat = struct.pack("<Q", target)
            j = blob.find(pat)
            while j != -1:
                abs_hits.append((dname, hex(s[3] + j)))
                j = blob.find(pat, j + 1)
        if abs_hits:
            fail(f"{name} absolute data refs not zero: {abs_hits}")
        print(f"{name}: 0 E8, 0 E9, 0 LEA, 0 absolute refs OK")

    want_ff15 = {FREE_SLOT: 46, SLOT9F0: 27, SLOT110: 141,
                 DEALLOC_SLOT: 98976}
    for slot, want in want_ff15.items():
        got = scan_ff15(slot)
        if len(got) != want:
            fail(f"FF 15 count for slot {slot:#x}: {len(got)} != {want}")
        print(f"FF 15 sites via slot {slot:#x}: {len(got)} OK")

    print("VERIFIER OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
