#!/usr/bin/env python3
"""Static verifier for the node #115 lu block register packet
(RE-001-node115-lu-blockreg).

Byte reads only; the node binary is never executed.
"""

import glob
import hashlib
import json
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items",
                      "RE-001-node115-lu-blockreg")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_START = 0x63D94B0
FDE_END = 0x63D96DB
RET_SITE = 0x63D95FE
ANCHOR_START = 0x63D94A0
ANCHOR_END = 0x63D94AC
ANCHOR_RET = 0x63D94AB
RODATA_CONST = 0x450B10

EXHIBITS = {
    "cm_anchor": (0x63D94A0, 0x63D94AC, 12, 3),
    "cm_entry": (0x63D94B0, 0x63D94DD, 45, 12),
    "cm_main": (0x63D94DD, 0x63D958B, 174, 40),
    "cm_tail": (0x63D958B, 0x63D95FF, 116, 29),
    "cm_200": (0x63D9600, 0x63D9664, 100, 18),
    "cm_zero": (0x63D9690, 0x63D96C7, 55, 10),
}

EXPECTED_E8 = [0x63B8C1D, 0x63B8F1A]
EXPECTED_ANCHOR_E8 = [0x63B76F9, 0x63B77DA, 0x63B79B1, 0x63B7A13,
                      0x63B7D47, 0x63B80E0, 0x63B8488, 0x63B8A99,
                      0x63B8B0C]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")
JUMP_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t(j\w+)\s+([0-9a-f]+)")
CALL_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\tcall\s+([0-9a-f]+)",
                     re.MULTILINE)

JUMPS = {"ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
         "jmp", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge",
         "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo",
         "js", "jz"}


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
        o = e_shoff + i * e_shentsize
        name, _typ, _fl, addr, offset, size = struct.unpack_from(
            "<IIQQQQ", data, o)
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

    # FDE bounds: entry endbr64, size, single ret, int3 padding,
    # anchor getter bytes.
    if data[off(FDE_START):off(FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    if FDE_END - FDE_START != 555:
        fail("FDE size")
    if data[off(RET_SITE)] != 0xC3:
        fail("ret site")
    if data[off(FDE_END):off(FDE_END) + 5] != b"\xcc" * 5:
        fail("int3 padding after FDE")
    if data[off(ANCHOR_START):off(ANCHOR_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("anchor entry is not endbr64")
    if ANCHOR_END - ANCHOR_START != 12:
        fail("anchor size")
    if data[off(ANCHOR_RET)] != 0xC3:
        fail("anchor ret site")
    if data[off(ANCHOR_END):off(FDE_START)] != b"\xcc" * 4:
        fail("int3 padding between anchor and FDE")
    print("FDE bounds ok: block register 555B, anchor getter 12B")

    # Key bytes: dispatch load, flag store, size call, helper calls,
    # overflow stub, rodata constant.
    if data[off(0x63D94C0):off(0x63D94C0) + 4] != bytes.fromhex("488b4668"):
        fail("dispatch load [block+0x68]")
    if data[off(0x63D94C4):off(0x63D94C4) + 4] != bytes.fromhex("c6462401"):
        fail("flag store [block+0x24] := 1")
    if data[off(0x63D94E5)] != 0xE8:
        fail("size call opcode")
    rel = struct.unpack_from("<i", data, off(0x63D94E5) + 1)[0]
    if 0x63D94E5 + 5 + rel != 0x63E8BF0:
        fail("size call target")
    if data[off(0x63D966A)] != 0xE8:
        fail("handoff call opcode")
    rel = struct.unpack_from("<i", data, off(0x63D966A) + 1)[0]
    if 0x63D966A + 5 + rel != 0x63D8790:
        fail("handoff call target")
    if data[off(0x63D967F)] != 0xE8:
        fail("second handoff call opcode")
    rel = struct.unpack_from("<i", data, off(0x63D967F) + 1)[0]
    if 0x63D967F + 5 + rel != 0x63D88D0:
        fail("second handoff call target")
    if data[off(0x63D96D0):off(0x63D96D0) + 6] != bytes.fromhex("41bb70290000"):
        fail("overflow slot constant")
    if data[off(0x63D96D6)] != 0xE9:
        fail("overflow jmp opcode")
    rel = struct.unpack_from("<i", data, off(0x63D96D6) + 1)[0]
    if 0x63D96D6 + 5 + rel != 0x63D9548:
        fail("overflow jmp target")
    if data[RODATA_CONST:RODATA_CONST + 16] != bytes.fromhex(
            "01000000000000000002000000000000"):
        fail("rodata constant (1, 2)")
    print("key bytes ok: endbr64, dispatch, flag store, size call, "
          "handoff calls, overflow stub, rodata (1, 2), ret")

    # Control flow: all exhibited jump targets inside the FDE,
    # one ret in the main FDE, one ret in the anchor, one call
    # in the exhibits (the size call).
    text = ""
    for name in EXHIBITS:
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            text += f.read()
    for line in text.splitlines():
        m = JUMP_RE.match(line)
        if m and m.group(1) in JUMPS:
            tgt = int(m.group(2), 16)
            if not (FDE_START <= tgt < FDE_END):
                fail("jump target outside FDE: %s" % hex(tgt))
    calls = CALL_RE.findall(text)
    if calls != ["63e8bf0"]:
        fail("exhibited calls %s" % calls)
    if text.count("\tret") != 2:
        fail("ret count (main + anchor)")
    print("control flow ok: jumps internal, single main ret, "
          "one exhibited call (size)")

    # Census: whole-.text byte scan + per-site rel32, .rela.dyn addends.
    secs = elf_sections(data)
    t_addr, t_off, t_size = secs[".text"]
    for target, expected, label in ((FDE_START, EXPECTED_E8, "block register"),
                                    (ANCHOR_START, EXPECTED_ANCHOR_E8, "anchor")):
        e8, e9 = [], []
        for i in range(t_size - 5):
            b = data[t_off + i]
            if b == 0xE8 or b == 0xE9:
                rel = struct.unpack_from("<i", data, t_off + i + 1)[0]
                if t_addr + i + 5 + rel == target:
                    (e8 if b == 0xE8 else e9).append(t_addr + i)
        if e8 != expected:
            fail("census E8 %s %s" % (label, [hex(x) for x in e8]))
        if e9:
            fail("census E9 %s" % label)
        lea = []
        for i in range(t_size - 7):
            if (data[t_off + i] in (0x48, 0x4C)
                    and data[t_off + i + 1] == 0x8D
                    and (data[t_off + i + 2] & 0xC7) == 0x05):
                disp = struct.unpack_from("<i", data, t_off + i + 3)[0]
                if t_addr + i + 7 + disp == target:
                    lea.append(t_addr + i)
        if lea:
            fail("census LEA %s" % label)
    r_addr, r_off, r_size = secs[".rela.dyn"]
    nrela = r_size // 24
    got = 0
    for i in range(nrela):
        _ro, _ri, addend = struct.unpack_from("<QQq", data, r_off + i * 24)
        if addend in (FDE_START, ANCHOR_START):
            got += 1
    if got:
        fail("census GOT")
    if nrela != 60723:
        fail("rela count %d" % nrela)
    print("census ok: block register 2 E8, anchor 9 E8, 0 E9, 0 LEA, "
          "0 GOT, 60723 rela entries")

    # Disjointness: exhibits inside their FDE only, and no overlap
    # with any other claimed range in the worktree.
    for name, (start, end, _b, _s) in EXHIBITS.items():
        if name == "cm_anchor":
            if start < ANCHOR_START or end > ANCHOR_END:
                fail("%s outside anchor FDE" % name)
        elif start < FDE_START or end > FDE_END:
            fail("%s outside FDE" % name)
    own = os.path.join(PACKET, "records.json")
    for path in glob.glob(os.path.join(REPO, "research", "work-items",
                                       "*", "records.json")):
        if os.path.abspath(path) == os.path.abspath(own):
            continue
        try:
            with open(path) as f:
                rec = json.load(f)
        except Exception:
            continue
        ex = rec.get("exhibits", []) if isinstance(rec, dict) else rec
        items = []
        if isinstance(ex, dict):
            items = list(ex.items())
        elif isinstance(ex, list):
            items = [(e.get("name", "?"), e) for e in ex
                     if isinstance(e, dict)]
        for _n, e in items:
            r = e.get("range")
            if not r:
                continue
            try:
                lo, hi = int(r[0], 16), int(r[1], 16)
            except Exception:
                continue
            for mlo, mhi in ((ANCHOR_START, ANCHOR_END),
                             (FDE_START, FDE_END)):
                if lo < mhi and mlo < hi:
                    fail("overlap with %s" % path)
    print("disjoint ok: exhibits inside FDEs, no neighbour overlap")

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
