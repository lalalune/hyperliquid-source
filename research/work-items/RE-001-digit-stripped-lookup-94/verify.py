#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-digit-stripped-lookup-94/verify.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. This script checks semantic records only: the target
digest, the window/callee/helper/caller carve ranges and SHAs, the
int3 padding, the direct-call targets re-derived from raw encodings,
the table address, hash seed and size threshold immediates, the PLT
stubs with their GOT slots, the FDE records, the caller censuses
(full disassembly scans for direct calls and tail jumps, plus a
whole-file qword scan), the library-hash vectors, and the packet
manifest hashes. It never lists instruction mnemonics: the raw
disassembly lives in window.objdump.txt, callee.objdump.txt,
helper.objdump.txt, caller.objdump.txt and plt.objdump.txt, and the
byte content of those excerpts is checked against the binary by the
independent checker in tools/foundation_digit_stripped_lookup.py.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))


class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping only."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", data, 0x36)
        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, _flags, p_offset, p_vaddr, _paddr,
             p_filesz, _memsz, _align) = struct.unpack_from(
                "<IIQQQQQQ", data, off)
            if p_type == 1:
                self.loads.append((p_vaddr, p_offset, p_filesz))

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x not in any PT_LOAD segment" % va)

    def offset_to_va(self, off):
        for vaddr, offset, filesz in self.loads:
            if offset <= off < offset + filesz:
                return vaddr + (off - offset)
        raise ValueError("file offset %#x not in any PT_LOAD segment" % off)

    def read(self, va, size):
        return self.data[self.va_to_offset(va):self.va_to_offset(va) + size]

    def sha(self, va, size):
        return hashlib.sha256(self.read(va, size)).hexdigest()


def call_target(elf, site):
    """Resolve a direct rel32 call at site to its target."""
    b = elf.read(site, 5)
    if b[0] != 0xE8:
        raise ValueError("not a direct call at %#x: %s" % (site, b.hex()))
    (rel,) = struct.unpack_from("<i", b, 1)
    return site + 5 + rel


def scan_direct_callers(elf, text_off, text_size, target):
    """All direct rel32 call sites in the .text file range to target."""
    found = []
    blob = elf.data[text_off:text_off + text_size]
    for i in range(text_size - 5):
        if blob[i] == 0xE8:
            (rel,) = struct.unpack_from("<i", blob, i + 1)
            site_va = elf.offset_to_va(text_off + i)
            if site_va + 5 + rel == target:
                found.append(site_va)
    return found


def scan_tail_jumps(elf, text_off, text_size, target):
    """All rel32 tail-jump sites in the .text file range to target."""
    found = []
    blob = elf.data[text_off:text_off + text_size]
    for i in range(text_size - 5):
        if blob[i] == 0xE9:
            (rel,) = struct.unpack_from("<i", blob, i + 1)
            site_va = elf.offset_to_va(text_off + i)
            if site_va + 5 + rel == target:
                found.append(site_va)
    return found


def text_range(binary):
    """File offset and size of .text (from section headers)."""
    out = subprocess.run(["readelf", "-S", binary], capture_output=True,
                         text=True, check=True).stdout
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "] .text " in line:
            parts = line.split()
            off = int(parts[4], 16)
            size = int(lines[i + 1].split()[0], 16)
            return off, size
    raise ValueError(".text section not found")


def hash_bytes(data, seed):
    """MurmurHash64A as used by libstdc++ _Hash_bytes."""
    mask = (1 << 64) - 1
    m = 0xC6A4A7935BD1E995
    r = 47
    n = len(data)
    h = (seed ^ ((n * m) & mask)) & mask
    i = 0
    while i + 8 <= n:
        k = int.from_bytes(data[i:i + 8], "little")
        k = (k * m) & mask
        k ^= k >> r
        k = (k * m) & mask
        h ^= k
        h = (h * m) & mask
        i += 8
    rem = data[i:]
    if rem:
        k = 0
        for j, b in enumerate(rem):
            k |= b << (8 * j)
        h ^= k
        h = (h * m) & mask
    h ^= h >> r
    h = (h * m) & mask
    h ^= h >> r
    return h


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    args = ap.parse_args(argv)
    with open(os.path.join(PACKET_DIR, "records.json")) as f:
        rec = json.load(f)
    errors = []
    with open(args.binary, "rb") as f:
        data = f.read()
    elf = Elf(data)
    tgt = rec["target"]
    if hashlib.sha256(data).hexdigest() != tgt["sha256"]:
        errors.append("target digest mismatch")
    if len(data) != tgt["size"]:
        errors.append("target size mismatch: %d" % len(data))

    # Carve ranges, SHAs, padding.
    for key in ("window", "callee", "nibble_helper", "caller_sample"):
        fn = rec[key]
        start = int(fn["start_va"], 16)
        end = int(fn["end_va_exclusive"], 16)
        if elf.sha(start, end - start) != fn["sha256"]:
            errors.append("%s carve SHA mismatch" % key)
        if end - start != fn["bytes"]:
            errors.append("%s byte count mismatch" % key)
        nxt = int(fn["next_fde_start"], 16)
        pad = elf.read(end, nxt - end)
        if len(pad) != fn["padding_bytes"] or any(c != 0xCC for c in pad):
            errors.append("%s padding mismatch" % key)

    # Direct calls.
    for call in rec["window_calls"] + rec["callee_calls"]:
        site = int(call["site"], 16)
        try:
            if call_target(elf, site) != int(call["target"], 16):
                errors.append("call %s target mismatch" % call["site"])
        except ValueError as e:
            errors.append(str(e))

    # Table address: rip-relative lea at 0x514e1e7 must resolve to the
    # recorded table address.
    lea = elf.read(0x514E1E7, 7)
    if lea[:3] != bytes.fromhex("488d1d"):
        errors.append("table lea encoding mismatch")
    else:
        (disp,) = struct.unpack_from("<i", lea, 3)
        if 0x514E1E7 + 7 + disp != int(rec["table"]["address"], 16):
            errors.append("table lea target mismatch")

    # Hash seed immediate and size threshold immediate.
    if elf.read(0x514E2AA, 5) != bytes.fromhex("ba07690fc7"):
        errors.append("hash seed immediate mismatch")
    if elf.read(0x514E1EE, 5) != bytes.fromhex("48837b1814"):
        errors.append("size threshold immediate mismatch")

    # Relocations via readelf.
    relocs = subprocess.run(["readelf", "-r", args.binary],
                            capture_output=True, text=True, check=True).stdout
    for plt in rec["plt"]:
        stub = int(plt["stub"], 16)
        b = elf.read(stub, 6)
        if b[0] != 0xFF or b[1] != 0x25:
            errors.append("PLT stub %s encoding mismatch" % plt["stub"])
            continue
        (disp,) = struct.unpack_from("<i", b, 2)
        if stub + 6 + disp != int(plt["got_slot"], 16):
            errors.append("PLT stub %s slot mismatch" % plt["stub"])
        slot_hex = plt["got_slot"][2:]
        plines = [l for l in relocs.splitlines()
                  if l.startswith("00000" + slot_hex)]
        if (len(plines) != 1 or "R_X86_64_JUMP_SLO" not in plines[0]):
            errors.append("PLT relocation for %s not found" % plt["stub"])
    with open(os.path.join(PACKET_DIR, "relocations.txt")) as f:
        for line in f:
            line = line.strip()
            if line and line not in relocs:
                errors.append("relocation line not in binary: %s" % line)

    # FDE lines verbatim.
    frames = subprocess.run(["readelf", "--debug-dump=frames", args.binary],
                            capture_output=True, text=True, check=True).stdout
    with open(os.path.join(PACKET_DIR, "frames.txt")) as f:
        for line in f:
            line = line.strip()
            if line and line not in frames:
                errors.append("FDE line not in binary: %s" % line)

    # Censuses: full .text direct-call and tail-jump scans.
    toff, tsize = text_range(args.binary)
    cens = rec["censuses"]
    got = scan_direct_callers(elf, toff, tsize,
                              int(rec["window"]["start_va"], 16))
    if got != [int(x, 16) for x in cens["window_direct_callers"]]:
        errors.append("window census mismatch: %s" % [hex(x) for x in got])
    got = scan_tail_jumps(elf, toff, tsize,
                          int(rec["window"]["start_va"], 16))
    if got != [int(x, 16) for x in cens["window_tail_jumps"]]:
        errors.append("window tail-jump census mismatch: %s"
                      % [hex(x) for x in got])
    target = int(rec["window"]["start_va"], 16)
    qrefs = []
    for off in range(0, len(data) - 8, 8):
        (v,) = struct.unpack_from("<Q", data, off)
        if v == target:
            qrefs.append(off)
    if qrefs != [int(x, 16) for x in cens["window_qword_references"]]:
        errors.append("window qword census mismatch: %s" % qrefs)

    # Library-hash vectors.
    hv = rec["hash_vectors"]
    seed = int(hv["seed"], 16)
    for vec in hv["vectors"]:
        got = hash_bytes(vec["input"].encode(), seed)
        if got != int(vec["hash"], 16):
            errors.append("hash vector mismatch for %r" % vec["input"])

    # Manifest hashes.
    with open(os.path.join(PACKET_DIR, "MANIFEST.sha256")) as f:
        for line in f:
            parts = line.split()
            if len(parts) != 2:
                continue
            digest, name = parts
            path = os.path.join(PACKET_DIR, name)
            if name == "MANIFEST.sha256":
                continue
            with open(path, "rb") as pf:
                if hashlib.sha256(pf.read()).hexdigest() != digest:
                    errors.append("manifest hash mismatch: %s" % name)

    if errors:
        print("FAILED")
        for e in errors:
            print(" - " + e)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
