#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-blockcache-dispatch-getters-94/verify.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node when that file is a
real ELF, and to the digest-verified work copy work/hl-node-94.bin
when it is still an LFS pointer. This script checks semantic records
only: the target digest, the getter/callee carve ranges and SHAs,
the int3 padding, the lookup call targets re-derived from raw
encodings, the sentinel rip-relative resolutions, the null-lookup
jump targets, the indirect dispatch call encodings, the FDE
records, the caller censuses (full disassembly scans for direct
calls and tail jumps, plus a whole-file qword scan), and the packet
manifest hashes. It never lists instruction mnemonics: the raw
disassembly lives in getter70.objdump.txt, getter78.objdump.txt,
getter98.objdump.txt and callee.objdump.txt.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
WORK_BINARY = os.path.join("work", "hl-node-94.bin")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

DISPATCH_ENCODINGS = {
    "0x514e7e0": {"0x514e83b": "ff5070", "0x514e853": "ffd2",
                  "0x514e860": "ffd0"},
    "0x514e870": {"0x514e8cb": "ff5078", "0x514e8e3": "ffd2",
                  "0x514e8f0": "ffd0"},
    "0x514e900": {"0x514e967": "ff9098000000", "0x514e983": "ffd2",
                  "0x514e990": "ffd0"},
}


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


def section_range(binary, name):
    """File offset and size of a section (from readelf output)."""
    out = subprocess.run(["readelf", "-S", binary], capture_output=True,
                         text=True, check=True).stdout
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "] %s " % name in line:
            parts = line.split()
            off = int(parts[4], 16)
            size = int(lines[i + 1].split()[0], 16)
            return off, size
    raise ValueError("section %s not found" % name)


def resolve_binary(explicit):
    if explicit:
        return explicit
    repo = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    default = os.path.join(repo, DEFAULT_BINARY)
    try:
        with open(default, "rb") as f:
            head = f.read(4)
        if head == b"\x7fELF":
            return default
    except OSError:
        pass
    return os.path.join(repo, WORK_BINARY)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=None)
    args = ap.parse_args(argv)
    binary = resolve_binary(args.binary)
    with open(os.path.join(PACKET_DIR, "records.json")) as f:
        rec = json.load(f)
    errors = []
    with open(binary, "rb") as f:
        data = f.read()
    elf = Elf(data)
    tgt = rec["target"]
    if hashlib.sha256(data).hexdigest() != tgt["sha256"]:
        errors.append("target digest mismatch")
    if len(data) != tgt["size"]:
        errors.append("target size mismatch: %d" % len(data))

    # Carve ranges, SHAs, padding.
    functions = list(rec["getters"]) + [rec["callee"]]
    for fn in functions:
        start = int(fn["start_va"], 16)
        end = int(fn["end_va_exclusive"], 16)
        if elf.sha(start, end - start) != fn["sha256"]:
            errors.append("%s carve SHA mismatch" % fn["start_va"])
        if end - start != fn["bytes"]:
            errors.append("%s byte count mismatch" % fn["start_va"])
        nxt = int(fn["next_fde_start"], 16)
        pad = elf.read(end, nxt - end) if nxt > end else b""
        if len(pad) != fn["padding_bytes"] or any(c != 0xCC for c in pad):
            errors.append("%s padding mismatch" % fn["start_va"])

    # Lookup calls, sentinel resolutions, null arms, dispatch calls.
    for g in rec["getters"]:
        site = int(g["lookup_call_site"], 16)
        try:
            if call_target(elf, site) != int(g["lookup_target"], 16):
                errors.append("lookup call %s target mismatch"
                              % g["lookup_call_site"])
        except ValueError as e:
            errors.append(str(e))
        check = int(g["sentinel_check_sites"][0], 16)
        b = elf.read(check, 7)
        if b[:3] != bytes.fromhex("483b15"):
            errors.append("%s sentinel cmp encoding mismatch"
                          % g["sentinel_check_sites"][0])
        else:
            (disp,) = struct.unpack_from("<i", b, 3)
            if check + 7 + disp != int(g["sentinel_cell"], 16):
                errors.append("%s sentinel cell mismatch"
                              % g["sentinel_check_sites"][0])
        null_site = int(g["null_lookup_site"], 16)
        jb = elf.read(null_site, 2)
        if jb[0] != 0x74:
            errors.append("%s null arm is not a je" % g["null_lookup_site"])
        else:
            (off8,) = struct.unpack_from("<b", jb, 1)
            if null_site + 2 + off8 != int(g["null_lookup_target"], 16):
                errors.append("%s null arm target mismatch"
                              % g["null_lookup_site"])
        for site_hex, want in DISPATCH_ENCODINGS[g["start_va"]].items():
            site = int(site_hex, 16)
            got = elf.read(site, len(bytes.fromhex(want))).hex()
            if got != want:
                errors.append("dispatch call %s encoding mismatch: %s"
                              % (site_hex, got))
        if sorted(g["dispatch_call_sites"]) != sorted(
                DISPATCH_ENCODINGS[g["start_va"]].keys()):
            errors.append("%s dispatch site list mismatch" % g["start_va"])

    # FDE records via the .eh_frame section.
    eh_off, _eh_size = section_range(binary, ".eh_frame")
    for fn in functions:
        sec_off = int(fn["fde_section_offset"], 16)
        pos = eh_off + sec_off
        (length, cie_field) = struct.unpack_from("<II", data, pos)
        if length != int(fn["fde_length"], 16):
            errors.append("%s FDE length mismatch" % fn["start_va"])
        cie_off = (sec_off + 4) - cie_field
        if cie_off != int(fn["fde_cie_offset"], 16):
            errors.append("%s FDE CIE mismatch" % fn["start_va"])

    # Censuses: direct calls, tail jumps, whole-file qwords.
    text_off, text_size = section_range(binary, ".text")
    blob = data[text_off:text_off + text_size]
    for g in rec["getters"]:
        target = int(g["start_va"], 16)
        for opcode, kind in ((b"\xe8", "direct callers"),
                             (b"\xe9", "tail jumps")):
            hits = []
            i = blob.find(opcode)
            while 0 <= i <= text_size - 5:
                (rel,) = struct.unpack_from("<i", blob, i + 1)
                va = elf.offset_to_va(text_off + i)
                if va + 5 + rel == target:
                    hits.append(hex(va))
                i = blob.find(opcode, i + 1)
            key = ("getter_direct_callers" if kind == "direct callers"
                   else "getter_tail_jumps")
            if hits != rec["censuses"][key][g["start_va"]]:
                errors.append("%s %s mismatch: %s"
                              % (g["start_va"], kind, hits))
        pat = struct.pack("<Q", target)
        qhits = []
        i = data.find(pat)
        while i >= 0:
            qhits.append(hex(i))
            i = data.find(pat, i + 1)
        if qhits != rec["censuses"]["getter_qword_references"][g["start_va"]]:
            errors.append("%s qword references mismatch: %s"
                          % (g["start_va"], qhits))

    # Relocations note.
    with open(os.path.join(PACKET_DIR, "relocations.txt")) as f:
        first = f.readline()
    if not first.startswith("# No PLT"):
        errors.append("relocations.txt note mismatch")

    # Packet manifest hashes.
    manifest = os.path.join(PACKET_DIR, "MANIFEST.sha256")
    if os.path.exists(manifest):
        with open(manifest) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                want, name = line.split(None, 1)
                path = os.path.join(PACKET_DIR, name)
                with open(path, "rb") as pf:
                    got = hashlib.sha256(pf.read()).hexdigest()
                if got != want:
                    errors.append("manifest mismatch for %s" % name)

    if errors:
        print("CHECKS FAILED")
        for e in errors:
            print("FAIL: %s" % e)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
