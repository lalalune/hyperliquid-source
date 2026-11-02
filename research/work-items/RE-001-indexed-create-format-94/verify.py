#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-indexed-create-format-94/verify.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node when that file is a
real ELF, and to the digest-verified work copy work/hl-node-94.bin
when it is still an LFS pointer. This script checks semantic records
only: the target digest, every carve range and SHA, the int3 padding,
the FDE records, the direct call targets, the rip-relative literal
resolutions, the gate encodings, the canary sequence, the PLT stub
GOT resolutions, the caller censuses, the excerpt regeneration and
the packet manifest hashes. It never lists instruction mnemonics:
the raw disassembly lives in the packet's *.objdump.txt files.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
WORK_BINARY = os.path.join("work", "hl-node-94.bin")
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


def lea_target(elf, site):
    """Resolve a rip-relative lea at site (7 bytes) to its target."""
    b = elf.read(site, 7)
    if b[0] != 0x48 or b[1] != 0x8D:
        raise ValueError("not a rip-relative lea at %#x: %s" % (site, b.hex()))
    (rel,) = struct.unpack_from("<i", b, 3)
    return site + 7 + rel


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

    # Carve ranges, SHAs, padding, FDE records.
    functions = [rec["window"], rec["landing_pad"]] + list(
        rec["callees"].values())
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
    eh_off, _eh_size = section_range(binary, ".eh_frame")
    for fn in functions:
        sec_off = int(fn["fde_section_offset"], 16)
        pos = eh_off + sec_off
        (length, cie_field) = struct.unpack_from("<II", data, pos)
        if length != int(fn["fde_length"], 16):
            errors.append("%s FDE length mismatch" % fn["start_va"])
        if (sec_off + 4) - cie_field != int(fn["fde_cie_offset"], 16):
            errors.append("%s FDE CIE mismatch" % fn["start_va"])

    # Direct call targets.
    win = rec["window"]
    for site_hex, want_hex in win["call_sites"].items():
        site = int(site_hex, 16)
        try:
            if call_target(elf, site) != int(want_hex, 16):
                errors.append("call %s target mismatch" % site_hex)
        except ValueError as e:
            errors.append(str(e))

    # Rip-relative literal resolutions and literal bytes.
    for site_hex, want_hex in win["literal_lea_sites"].items():
        site = int(site_hex, 16)
        try:
            if lea_target(elf, site) != int(want_hex, 16):
                errors.append("lea %s target mismatch" % site_hex)
        except ValueError as e:
            errors.append(str(e))
    for va_hex, want in win["literals"].items():
        got = elf.read(int(va_hex, 16), len(want) + 1)
        if got != want.encode() + b"\x00":
            errors.append("literal %s mismatch: %r" % (va_hex, got))

    # Gate encodings: parser-fail je, trailing jne, index jge,
    # status cmpb + je, and the count/container loads.
    gates = win["gates"]
    b = elf.read(int(gates["parser_fail_je"], 16), 2)
    if b[0] != 0x74 or int(gates["parser_fail_je"], 16) + 2 + struct.unpack(
            "<b", b[1:2])[0] != int(gates["fail_target"], 16):
        errors.append("parser-fail je mismatch")
    b = elf.read(int(gates["trailing_jne"], 16), 6)
    if b[0] != 0x0F or b[1] != 0x85 or int(gates["trailing_jne"], 16) + 6 + \
            struct.unpack_from("<i", b, 2)[0] != int(
                gates["gate_fail_target"], 16):
        errors.append("trailing jne mismatch")
    b = elf.read(int(gates["index_cmp"], 16), 6)
    if b.hex() != "3b8578070000":
        errors.append("index cmp encoding mismatch: %s" % b.hex())
    b = elf.read(int(gates["index_jge"], 16), 2)
    if b[0] != 0x7D or int(gates["index_jge"], 16) + 2 + struct.unpack(
            "<b", b[1:2])[0] != int(gates["gate_fail_target"], 16):
        errors.append("index jge mismatch")
    b = elf.read(int(gates["status_cmpb"], 16), 5)
    if b.hex() != "807c243000":
        errors.append("status cmpb encoding mismatch: %s" % b.hex())
    b = elf.read(int(gates["status_je"], 16), 2)
    if b[0] != 0x74 or int(gates["status_je"], 16) + 2 + struct.unpack(
            "<b", b[1:2])[0] != int(gates["format_target"], 16):
        errors.append("status je mismatch")
    if elf.read(int(gates["container_load"], 16), 7).hex() != "488b8588070000":
        errors.append("container load encoding mismatch")
    if elf.read(int(gates["field_load"], 16), 4).hex() != "488b7030":
        errors.append("field load encoding mismatch")

    # Canary sequence.
    if elf.read(int(win["canary_load"], 16), 9).hex() != "64488b042528000000":
        errors.append("canary fs load encoding mismatch")
    if elf.read(int(win["canary_store"], 16), 8).hex() != "48898424a8000000":
        errors.append("canary store encoding mismatch")
    if elf.read(int(win["canary_check_load"], 16), 8).hex() != "488b8424a8000000":
        errors.append("canary check load encoding mismatch")
    if elf.read(int(win["canary_check_sub"], 16), 9).hex() != "64482b042528000000":
        errors.append("canary check sub encoding mismatch")

    # PLT stub GOT resolutions.
    for stub_hex, got_hex in win["plt_got"].items():
        stub = int(stub_hex, 16)
        b = elf.read(stub, 6)
        if b[0] != 0xFF or b[1] != 0x25:
            errors.append("PLT stub %s encoding mismatch" % stub_hex)
        else:
            (disp,) = struct.unpack_from("<i", b, 2)
            if stub + 6 + disp != int(got_hex, 16):
                errors.append("PLT stub %s GOT mismatch" % stub_hex)

    # Censuses: direct calls, tail jumps, whole-file qwords.
    text_off, text_size = section_range(binary, ".text")
    blob = data[text_off:text_off + text_size]
    target = int(win["start_va"], 16)
    for opcode, kind, key in ((b"\xe8", "direct callers", "direct_callers"),
                              (b"\xe9", "tail jumps", "tail_jumps")):
        hits = []
        i = blob.find(opcode)
        while 0 <= i <= text_size - 5:
            (rel,) = struct.unpack_from("<i", blob, i + 1)
            va = elf.offset_to_va(text_off + i)
            if va + 5 + rel == target:
                hits.append(hex(va))
            i = blob.find(opcode, i + 1)
        if hits != rec["censuses"][key]:
            errors.append("window %s mismatch: %s" % (kind, hits))
    pat = struct.pack("<Q", target)
    qhits = []
    i = data.find(pat)
    while i >= 0:
        qhits.append(hex(i))
        i = data.find(pat, i + 1)
    if qhits != rec["censuses"]["qword_references"]:
        errors.append("window qword references mismatch: %s" % qhits)

    # Excerpt regeneration byte-for-byte.
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable,
                        os.path.join(PACKET_DIR, "export_excerpts.py"),
                        "--binary", binary, "--out", tmp],
                       check=True, capture_output=True, text=True)
        for name in rec["excerpts"]:
            with open(os.path.join(PACKET_DIR, name), "rb") as f:
                have = f.read()
            with open(os.path.join(tmp, name), "rb") as f:
                want = f.read()
            if have != want:
                errors.append("excerpt %s regeneration mismatch" % name)

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
