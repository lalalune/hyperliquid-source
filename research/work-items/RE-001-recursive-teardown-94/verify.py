#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-recursive-teardown-94/verify.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. This script checks semantic records only: the target
digest, the function carve range and SHA, the int3 padding, the PLT
delete stub carve and SHA, the branch/call targets re-derived from
raw encodings, the FDE record, the caller census (a byte-level .text
scan for e8/e9 rel32 targeting the function, cross-checked at build
time against a linear objdump -d sweep, which agreed exactly), and
the packet manifest hashes. It never lists instruction mnemonics:
the raw disassembly lives in window.objdump.txt, plt.objdump.txt and
callers.objdump.txt, and the byte content of those excerpts is
checked against the binary by the independent checker in
tools/foundation_recursive_teardown.py.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_VA = 0x514BF60


class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping plus section headers."""

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
        (self.e_shoff,) = struct.unpack_from("<Q", data, 0x28)
        (self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
            "<HHH", data, 0x3a)
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            vals = struct.unpack_from("<IIQQQQIIQQ", data, off)
            self.sections.append(vals)
        shstr = self.sections[self.e_shstrndx]
        self.shstr_off = shstr[4]

    def section_name(self, sec):
        start = self.shstr_off + sec[0]
        end = self.data.index(b"\0", start)
        return self.data[start:end].decode()

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x not in any PT_LOAD segment" % va)

    def read(self, va, size):
        off = self.va_to_offset(va)
        return self.data[off:off + size]

    def text_range(self):
        for sec in self.sections:
            if self.section_name(sec) == ".text":
                return sec[3], sec[5]
        raise ValueError("no .text section")


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
    func = rec["function"]
    s = int(func["start_va"], 16)
    e = int(func["end_va_exclusive"], 16)
    blob = elf.read(s, e - s)
    if len(blob) != func["bytes"]:
        errors.append("function byte count mismatch")
    if hashlib.sha256(blob).hexdigest() != func["sha256"]:
        errors.append("function SHA mismatch")
    pad = elf.read(e, func["padding_bytes"])
    if pad != b"\xcc" * func["padding_bytes"]:
        errors.append("function padding is not int3")
    plt = rec["plt_delete"]
    ps = int(plt["start_va"], 16)
    pblob = elf.read(ps, plt["bytes"])
    if hashlib.sha256(pblob).hexdigest() != plt["sha256"]:
        errors.append("PLT stub SHA mismatch")
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
    want = "pc=%016x..%016x" % (s, e)
    if want not in frames:
        errors.append("function FDE line missing from frames.txt")
    try:
        with open(os.path.join(packet_dir, "relocations.txt")) as f:
            relocs = f.read()
    except OSError as exc:
        errors.append("cannot read relocations.txt: %s" % exc)
        relocs = ""
    if plt["got_slot"][2:] not in relocs or "_ZdlPvm" not in relocs:
        errors.append("PLT GOT relocation missing from relocations.txt")
    # Caller census: byte-level .text scan for e8/e9 rel32 to the target.
    try:
        taddr, tsize = elf.text_range()
        tblob = elf.read(taddr, tsize)
        found_calls = set()
        found_jmps = set()
        for op, dest in ((0xE8, found_calls), (0xE9, found_jmps)):
            idx = 0
            while True:
                j = tblob.find(bytes([op]), idx)
                if j < 0:
                    break
                if j + 5 <= len(tblob):
                    (disp,) = struct.unpack_from("<i", tblob, j + 1)
                    va = taddr + j
                    if va + 5 + disp == TARGET_VA:
                        dest.add(va)
                idx = j + 1
    except (ValueError, struct.error) as exc:
        errors.append("census scan failed: %s" % exc)
        found_calls = found_jmps = None
    if found_calls is not None:
        want = set(int(v, 16) for v in rec["caller_census"]["direct_sites"])
        if found_calls != want:
            errors.append("caller census mismatch: found %s, want %s" % (
                sorted(hex(v) for v in found_calls),
                sorted(hex(v) for v in want)))
    if found_jmps is not None:
        want = set(int(v, 16) for v in rec["caller_census"]["tail_jump_sites"])
        if found_jmps != want:
            errors.append("tail-jump census mismatch: found %s, want %s" % (
                sorted(hex(v) for v in found_jmps),
                sorted(hex(v) for v in want)))
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
