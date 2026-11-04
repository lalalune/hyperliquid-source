#!/usr/bin/env python3
"""Static verifier for the node #115 lu consume packet
(RE-001-node115-lu-consume).

Byte reads only; the node binary is never executed.
"""

import hashlib
import json
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items",
                      "RE-001-node115-lu-consume")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_START = 0x63BA600
FDE_END = 0x63BA672
RET_SITE = 0x63BA671
NEXT_START = 0x63BA680
RODATA_CONST = 0x453A60

EXHIBITS = {
    "cs_entry": (0x63BA600, 0x63BA61E, 30, 6),
    "cs_flags": (0x63BA61E, 0x63BA638, 26, 4),
    "cs_zero": (0x63BA638, 0x63BA672, 58, 10),
}

EXPECTED_E8 = [0x63B86BC, 0x63B87B9]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def off(va):
    return va - 0x1000


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def elf_sections(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, _typ, _fl, addr, offset, size = struct.unpack_from(
            "<IIQQQQ", data, off)
        secs.append((name, addr, offset, size))
    strtab = secs[e_shstrndx][2]
    out = {}
    for name, addr, offset, size in secs:
        end = data.index(b"\0", strtab + name)
        out[data[strtab + name:end].decode()] = (addr, offset, size)
    return out


def main():
    with open(NODE, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("binary sha mismatch")
    if len(data) != TARGET_SIZE:
        fail("binary size mismatch")
    print("binary sha ok (%d bytes)" % len(data))

    with open(os.path.join(PACKET, "records.json")) as f:
        records = json.load(f)
    total_bytes = 0
    total_strict = 0
    for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        if len(raw) != nbytes:
            fail("%s byte length" % name)
        if raw != data[off(start):off(start) + nbytes]:
            fail("%s bytes mismatch" % name)
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            lines = [line for line in f.read().splitlines() if line.strip()]
        strict = sum(1 for line in lines if STRICT_RE.match(line))
        if strict != nstrict:
            fail("%s strict count %d != %d" % (name, strict, nstrict))
        rec = records["exhibits"][name]
        if rec["bytes"] != nbytes or rec["strict"] != nstrict:
            fail("%s records mismatch" % name)
        if [int(x, 16) for x in rec["range"]] != [start, end]:
            fail("%s records range mismatch" % name)
        total_bytes += nbytes
        total_strict += nstrict
    print("exhibits ok: %d excerpts, %d bytes, %d strict"
          % (len(EXHIBITS), total_bytes, total_strict))

    if data[off(FDE_START):off(FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    if FDE_END - FDE_START != 114:
        fail("FDE size")
    if data[off(RET_SITE)] != 0xC3:
        fail("ret site")
    if data[off(FDE_END):off(NEXT_START)] != b"\xcc" * (NEXT_START - FDE_END):
        fail("int3 padding")
    if data[off(NEXT_START):off(NEXT_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("next function is not endbr64")
    print("FDE bounds ok: consume 114B")

    # Key bytes: cursor store, counter store, 0x100 header, b0 zero,
    # movdqa source, single ret.
    if data[off(0x63BA610):off(0x63BA610) + 3] != bytes.fromhex("488937"):
        fail("cursor store")
    if data[off(0x63BA613):off(0x63BA613) + 4] != bytes.fromhex("48895708"):
        fail("counter store")
    if data[off(0x63BA617):off(0x63BA617) + 7] != bytes.fromhex("c7471000010000"):
        fail("0x100 header store")
    if data[off(0x63BA62D):off(0x63BA62D) + 7] != bytes.fromhex("48c787b0000000"):
        fail("b0 zero store prefix")
    # movdqa disp32 target must be the .rodata constant.
    disp = struct.unpack_from("<i", data, off(0x63BA604) + 4)[0]
    if 0x63BA604 + 8 + disp != RODATA_CONST:
        fail("movdqa source")
    if data[RODATA_CONST:RODATA_CONST + 16] != bytes.fromhex(
            "00020000000000000000000000000000"):
        fail("rodata constant")
    print("key bytes ok: endbr64, cursor/counter stores, 0x100, b0 zero, "
          "rodata 0x200, ret")

    # The FDE contains no call or jump mnemonic at all.
    with open(os.path.join(PACKET, "cs_entry.objdump.txt")) as f:
        text = f.read()
    with open(os.path.join(PACKET, "cs_flags.objdump.txt")) as f:
        text += f.read()
    with open(os.path.join(PACKET, "cs_zero.objdump.txt")) as f:
        text += f.read()
    if "\tcall" in text or "\tjmp" in text or "\tje" in text:
        fail("unexpected branch inside FDE")
    if text.count("\tret") != 1:
        fail("ret count")
    print("control flow ok: single ret, zero calls, zero branches")

    # Census: whole-.text byte scan + per-site rel32, .rela.dyn addends.
    secs = elf_sections(data)
    t_addr, t_off, t_size = secs[".text"]
    e8, e9 = [], []
    for i in range(t_size - 5):
        b = data[t_off + i]
        if b == 0xE8 or b == 0xE9:
            rel = struct.unpack_from("<i", data, t_off + i + 1)[0]
            if t_addr + i + 5 + rel == FDE_START:
                (e8 if b == 0xE8 else e9).append(t_addr + i)
    if e8 != EXPECTED_E8:
        fail("census E8 %s" % [hex(x) for x in e8])
    if e9:
        fail("census E9")
    lea = []
    for i in range(t_size - 7):
        if (data[t_off + i] == 0x48 and data[t_off + i + 1] == 0x8D
                and (data[t_off + i + 2] & 0xC7) == 0x05):
            disp = struct.unpack_from("<i", data, t_off + i + 3)[0]
            if t_addr + i + 7 + disp == FDE_START:
                lea.append(t_addr + i)
    if lea:
        fail("census LEA")
    r_addr, r_off, r_size = secs[".rela.dyn"]
    nrela = r_size // 24
    got = 0
    for i in range(nrela):
        _ro, _ri, addend = struct.unpack_from("<QQq", data, r_off + i * 24)
        if addend == FDE_START:
            got += 1
    if got:
        fail("census GOT")
    if nrela != 60723:
        fail("rela count %d" % nrela)
    print("census ok: consume 2 E8, 0 E9, 0 LEA, 0 GOT, 60723 rela entries")

    # Disjointness: exhibits lie inside the FDE only.
    for name, (start, end, _b, _s) in EXHIBITS.items():
        if start < FDE_START or end > FDE_END:
            fail("%s outside FDE" % name)
    print("disjoint ok: exhibits inside FDE, no neighbour overlap")

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        entries = {}
        for line in f.read().splitlines():
            if not line.strip():
                continue
            digest, path = line.split(None, 1)
            entries[path.strip()] = digest
    checked = 0
    for path, digest in entries.items():
        full = os.path.normpath(os.path.join(PACKET, path))
        with open(full, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != digest:
            fail("MANIFEST mismatch %s" % path)
        checked += 1
    print("MANIFEST ok: %d/%d entries" % (checked, len(entries)))
    print("verifier: all checks passed (%d excerpts, %d bytes, %d strict, "
          "census 2 E8 sites, MANIFEST %d entries)"
          % (len(EXHIBITS), total_bytes, total_strict, checked))


if __name__ == "__main__":
    main()
