#!/usr/bin/env python3
"""Static verifier for the node #115 lu class-search packet
(RE-001-node115-lu-classsearch).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt
  (address + bytes field + tab + mnemonic; objdump byte-continuation
  lines carry no mnemonic and are excluded),
- key instruction bytes (entry endbr64, sizerep call rel32, huge
  threshold movabs, bitmap lea at record +0x400, single ret opcode,
  tail-jump rel32 to the consumer, huge-path mask, class-64 compare),
- FDE bounds (0x63d9340..0x63d945b, 283 bytes), one internal call,
  all other jump targets inside the FDE,
- census: 2 direct E8, 0 E9, 0 LEA, 0 GOT (60,723 .rela.dyn entries),
- disjointness from neighbouring claimed ranges,
- MANIFEST.sha256 coverage (15 entries, MANIFEST itself excluded).
"""

import hashlib
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-classsearch")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_START = 0x63D9340
FDE_END = 0x63D945B
RET_SITES = (0x63D9418,)
INTERNAL_CALLS = {0x63D934B: 0x63E8C80}
TAIL_JUMP = {0x63D940A: 0x63B9690}
CALLERS = (0x63B827F, 0x63B8918)
# Neighbouring claimed ranges that must not overlap this FDE.
NEIGHBOURS = {
    "finder (#226)": (0x63B0980, 0x63B15E9),
    "slot-head (#225)": (0x63ABD00, 0x63AC0CC),
    "release (#224)": (0x63B0780, 0x63B0980),
    "size rep (#227)": (0x63E8C80, 0x63E8D87),
    "sibling (#224)": (0x63E8BF0, 0x63E8C77),
    "table-fill (#228)": (0x63E8D90, 0x63E9152),
    "descbuild thunk (#229)": (0x63DA080, 0x63DA089),
    "descbuild body (#229)": (0x63D9BA0, 0x63D9ED3),
    "consumer (cited)": (0x63B9690, 0x63B9C00),
    "caller 1 (cited)": (0x63B8160, 0x63B81AB),
    "caller 2 (cited)": (0x63B8820, 0x63B8D85),
}

EXHIBITS = {
    "cs_entry": (0x63D9340, 0x63D9350, 16, 5),
    "cs_index": (0x63D9366, 0x63D93A2, 60, 16),
    "cs_test": (0x63D93A2, 0x63D93BC, 26, 6),
    "cs_scan": (0x63D93E4, 0x63D940F, 43, 13),
    "cs_huge": (0x63D9420, 0x63D944B, 43, 9),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def read_node():
    with open(NODE, "rb") as f:
        return f.read()


def va_to_off(data, va):
    # .text file offset = VA - 0x1000 for this node image.
    return va - 0x1000


def elf_sections(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    hdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
        hdrs.append((name, typ, flags, addr, offset, size))
    str_off = hdrs[e_shstrndx][4]
    out = {}
    for name, typ, flags, addr, offset, size in hdrs:
        end = data.index(b"\x00", str_off + name)
        out[data[str_off + name:end].decode()] = (addr, offset, size)
    return out


def main():
    data = read_node()
    sha = hashlib.sha256(data).hexdigest()
    if sha != TARGET_SHA:
        fail("binary sha mismatch: %s" % sha)
    if len(data) != TARGET_SIZE:
        fail("binary size mismatch: %d" % len(data))
    print("binary sha ok (%d bytes)" % len(data))

    total_bytes = 0
    total_strict = 0
    for name, (start, end, nbytes, nstrict) in sorted(EXHIBITS.items()):
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        if len(raw) != nbytes:
            fail("%s length %d != %d" % (name, len(raw), nbytes))
        got = data[va_to_off(data, start):va_to_off(data, start) + nbytes]
        if got != raw:
            fail("%s bytes mismatch at %s" % (name, hex(start)))
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            lines = f.read().splitlines()
        strict = sum(1 for line in lines if STRICT_RE.match(line))
        if strict != nstrict:
            fail("%s strict %d != %d" % (name, strict, nstrict))
        total_bytes += nbytes
        total_strict += nstrict
    print("exhibits ok: %d excerpts, %d bytes, %d strict" % (len(EXHIBITS), total_bytes, total_strict))

    def byte_at(va):
        return data[va_to_off(data, va)]

    def rel32_target(site):
        off = va_to_off(data, site)
        return site + 5 + struct.unpack_from("<i", data, off + 1)[0]

    if data[va_to_off(data, FDE_START):va_to_off(data, FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry endbr64 missing")
    for site, tgt in INTERNAL_CALLS.items():
        if byte_at(site) != 0xE8 or rel32_target(site) != tgt:
            fail("internal call at %s does not target %s" % (hex(site), hex(tgt)))
    for site, tgt in TAIL_JUMP.items():
        if byte_at(site) != 0xE9 or rel32_target(site) != tgt:
            fail("tail jump at %s does not target %s" % (hex(site), hex(tgt)))
    for site in RET_SITES:
        if byte_at(site) != 0xC3:
            fail("ret opcode missing at %s" % hex(site))
    # Key bytes: huge threshold movabs, bitmap leas, huge mask, class-64 cmp.
    if data[va_to_off(data, 0x63D9353):va_to_off(data, 0x63D9353) + 10] != bytes.fromhex("48b80000000000000070"):
        fail("huge threshold movabs mismatch")
    if data[va_to_off(data, 0x63D937C):va_to_off(data, 0x63D937C) + 7] != bytes.fromhex("4c8d8b00040000"):
        fail("bitmap lea mismatch")
    if data[va_to_off(data, 0x63D9434):va_to_off(data, 0x63D9434) + 4] != bytes.fromhex("4983e280"):
        fail("huge mask mismatch")
    if data[va_to_off(data, 0x63D93F9):va_to_off(data, 0x63D93F9) + 3] != bytes.fromhex("83ff40"):
        fail("class-64 compare mismatch")
    print("key bytes ok: endbr64, sizerep call, threshold, bitmap lea, ret, tail jump, huge mask, class-64 cmp")

    if FDE_END - FDE_START != 283:
        fail("FDE size mismatch")
    if byte_at(0x63D945B) != 0xCC:
        fail("int3 padding expected after FDE")
    print("FDE bounds ok: class-search 283B")

    secs = elf_sections(data)
    tva, toff, tsize = secs[".text"]
    rva, roff, rsize = secs[".rela.dyn"]
    e8, e9, lea = [], [], []
    for va in range(tva, tva + tsize - 7):
        o = toff + (va - tva)
        b = data[o]
        if b == 0xE8:
            if va + 5 + struct.unpack_from("<i", data, o + 1)[0] == FDE_START:
                e8.append(va)
        elif b == 0xE9:
            if va + 5 + struct.unpack_from("<i", data, o + 1)[0] == FDE_START:
                e9.append(va)
        elif b == 0x48 and data[o + 1] == 0x8D and (data[o + 2] & 0xC7) == 0x05:
            if va + 7 + struct.unpack_from("<i", data, o + 3)[0] == FDE_START:
                lea.append(va)
    if tuple(e8) != CALLERS:
        fail("census E8 mismatch: %s" % [hex(x) for x in e8])
    if e9 or lea:
        fail("census E9/LEA not empty: %s %s" % (e9, lea))
    got = 0
    for i in range(rsize // 24):
        add = struct.unpack_from("<q", data, roff + i * 24 + 16)[0]
        if add == FDE_START:
            got += 1
    if got:
        fail("GOT addend hits not empty")
    print("census ok: class-search %d E8, 0 E9, 0 LEA, 0 GOT, %d rela entries"
          % (len(e8), rsize // 24))

    for label, (s, e) in NEIGHBOURS.items():
        if FDE_START < e and s < FDE_END:
            fail("FDE overlaps neighbour %s" % label)
    for name, (start, end, _n, _s) in EXHIBITS.items():
        if not (FDE_START <= start and end <= FDE_END):
            fail("exhibit %s outside FDE" % name)
    print("disjoint ok: exhibits inside FDE, no neighbour overlap")

    import hashlib as _hl
    manifest = os.path.join(PACKET, "MANIFEST.sha256")
    with open(manifest) as f:
        entries = [line.split() for line in f if line.strip()]
    if len(entries) != 15:
        fail("MANIFEST entries %d != 15" % len(entries))
    for digest, path in entries:
        full = os.path.normpath(os.path.join(PACKET, path))
        with open(full, "rb") as f:
            if _hl.sha256(f.read()).hexdigest() != digest:
                fail("MANIFEST mismatch: %s" % path)
    print("MANIFEST ok: 15/15 entries")
    print("verifier: all checks passed (%d excerpts, %d bytes, %d strict, census %d E8 sites, MANIFEST 15 entries)"
          % (len(EXHIBITS), total_bytes, total_strict, len(e8)))


if __name__ == "__main__":
    main()
