#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-string-build-move-94/verify.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. This script checks semantic records only: the target
digest, the function/callee carve ranges and SHAs, the int3 padding,
the branch/call targets re-derived from raw encodings, the FDE
records, the caller census and the callee census (full .text byte
scans for e8 rel32 calls and e9 rel32 jumps; the same scan
reproduces the merged #1321 packet's 20-site census of 0x514b4f0
exactly), and the packet manifest hashes. It never lists
instruction mnemonics: the raw disassembly lives in
window.objdump.txt and callee.objdump.txt, and the byte content of
those excerpts is checked against the binary by the independent
checker in tools/foundation_string_build_move.py.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))


class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping plus .text section."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", data, 0x36)
        (self.e_shoff,) = struct.unpack_from("<Q", data, 0x28)
        (self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
            "<HHH", data, 0x3A)
        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, _flags, p_offset, p_vaddr, _paddr,
             p_filesz, _memsz, _align) = struct.unpack_from(
                "<IIQQQQQQ", data, off)
            if p_type == 1:
                self.loads.append((p_vaddr, p_offset, p_filesz))
        self.text = None
        if self.e_shoff and self.e_shnum:
            str_off = self.e_shoff + self.e_shstrndx * self.e_shentsize
            (shstr_off,) = struct.unpack_from("<Q", data, str_off + 0x18)
            for i in range(self.e_shnum):
                off = self.e_shoff + i * self.e_shentsize
                (name_idx, _type, _flags, addr, offset, size) = struct.unpack_from(
                    "<IIQQQQ", data, off)
                end = data.index(b"\x00", shstr_off + name_idx)
                name = data[shstr_off + name_idx:end].decode()
                if name == ".text":
                    self.text = (addr, offset, size)
                    break

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x not in any PT_LOAD segment" % va)

    def read(self, va, size):
        off = self.va_to_offset(va)
        return self.data[off:off + size]

    def text_scan(self, opcode, target):
        """All .text sites where an opcode rel32 lands on target."""
        if self.text is None:
            raise ValueError(".text section not found")
        addr, offset, size = self.text
        seg = self.data[offset:offset + size]
        hits = []
        for i in range(len(seg) - 4):
            if seg[i] != opcode:
                continue
            (disp,) = struct.unpack_from("<i", seg, i + 1)
            if addr + i + 5 + disp == target:
                hits.append(addr + i)
        return hits


def rel_target(elf, site, length):
    raw = elf.read(site, length)
    if length == 2:
        (disp,) = struct.unpack_from("<b", raw, 1)
    elif length == 5:
        (disp,) = struct.unpack_from("<i", raw, 1)
    elif length == 6:
        (disp,) = struct.unpack_from("<i", raw, 2)
    else:
        raise ValueError("unsupported branch length %d" % length)
    return site + length + disp


def check(records_path, binary_path, packet_dir=None):
    """Return a list of errors; empty means ALL CHECKS PASSED."""
    errors = []
    if packet_dir is None:
        packet_dir = os.path.dirname(os.path.abspath(records_path))
    try:
        with open(records_path) as f:
            rec = json.load(f)
    except (OSError, ValueError) as exc:
        return ["cannot read records.json: %s" % exc]
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        return ["cannot read binary: %s" % exc]
    if hashlib.sha256(data).hexdigest() != rec["target"]["sha256"]:
        errors.append("target digest mismatch")
    if len(data) != rec["target"]["size"]:
        errors.append("target size mismatch")
    elf = Elf(data)
    for key in ("function", "callee"):
        part = rec[key]
        s = int(part["start_va"], 16)
        e = int(part["end_va_exclusive"], 16)
        blob = elf.read(s, e - s)
        if len(blob) != part["bytes"]:
            errors.append("%s byte count mismatch" % key)
        if hashlib.sha256(blob).hexdigest() != part["sha256"]:
            errors.append("%s SHA mismatch" % key)
        pad = elf.read(e, part["padding_bytes"])
        if pad != b"\xcc" * part["padding_bytes"]:
            errors.append("%s padding is not int3" % key)
    for branch in rec["branches"]:
        site = int(branch["site"], 16)
        want = int(branch["target"], 16)
        if rel_target(elf, site, branch["length"]) != want:
            errors.append("branch %s target mismatch" % branch["site"])
    for call in rec["calls"]:
        site = int(call["site"], 16)
        want = int(call["target"], 16)
        if rel_target(elf, site, 5) != want:
            errors.append("call %s target mismatch" % call["site"])
    try:
        with open(os.path.join(packet_dir, "frames.txt")) as f:
            frames = f.read()
    except OSError as exc:
        errors.append("cannot read frames.txt: %s" % exc)
        frames = ""
    for key in ("function", "callee"):
        part = rec[key]
        want = "pc=%016x..%016x" % (
            int(part["start_va"], 16), int(part["end_va_exclusive"], 16))
        if want not in frames:
            errors.append("%s FDE line missing from frames.txt" % key)
    try:
        func_va = int(rec["function"]["start_va"], 16)
        for opcode, label in ((0xE8, "call"), (0xE9, "tail jump")):
            found = set(elf.text_scan(opcode, func_va))
            want = set(int(s, 16) for s in
                       rec["caller_census"]["direct_sites" if opcode == 0xE8
                                             else "tail_jump_sites"])
            if found != want:
                errors.append("caller %s census mismatch: found %s, want %s" % (
                    label, sorted(hex(v) for v in found),
                    sorted(hex(v) for v in want)))
        callee_va = int(rec["callee"]["start_va"], 16)
        found = set(elf.text_scan(0xE8, callee_va))
        want = set(int(s, 16) for s in rec["callee_census"]["direct_sites"])
        if found != want:
            errors.append("callee census mismatch: found %s, want %s" % (
                sorted(hex(v) for v in found), sorted(hex(v) for v in want)))
    except ValueError as exc:
        errors.append("census scan failed: %s" % exc)
    try:
        with open(os.path.join(packet_dir, "MANIFEST.sha256")) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                digest, name = line.split(None, 1)
                path = os.path.join(packet_dir, name.strip())
                with open(path, "rb") as pf:
                    actual = hashlib.sha256(pf.read()).hexdigest()
                if actual != digest:
                    errors.append("MANIFEST mismatch for %s" % name)
    except OSError as exc:
        errors.append("cannot verify MANIFEST: %s" % exc)
    return errors


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    ap.add_argument("--records",
                    default=os.path.join(PACKET_DIR, "records.json"))
    args = ap.parse_args(argv)
    errors = check(args.records, args.binary, PACKET_DIR)
    if errors:
        for err in errors:
            print("FAIL: %s" % err)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
