#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-level-report-94/verify.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. This script checks semantic records only: the target
digest, the function/cleanup/trampoline/sum carve ranges and SHAs,
the int3 padding, the branch/call targets re-derived from raw
encodings, the PLT stubs with their GOT slots, the FDE records, the
header literal reconstructed from its three .rodata stores, the line
format, the throw message and the MiB scale constant, the caller
censuses (full disassembly scan for direct calls), and the packet
manifest hashes. It never lists instruction mnemonics: the raw
disassembly lives in window.objdump.txt, cleanup.objdump.txt,
trampoline.objdump.txt, sum.objdump.txt and plt.objdump.txt, and the
byte content of those excerpts is checked against the binary by the
independent checker in tools/foundation_level_report.py.
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

PART_KEYS = ("function", "cleanup", "trampoline", "sum")


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

    def read(self, va, size):
        off = self.va_to_offset(va)
        return self.data[off:off + size]

    def cstr(self, va):
        off = self.va_to_offset(va)
        end = self.data.index(b"\x00", off)
        return self.data[off:end]


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


def objdump_census(binary_path, target_hex):
    """Direct e8 call sites for target, from a full objdump listing."""
    result = subprocess.run(["objdump", "-d", binary_path],
                            capture_output=True, text=True)
    if result.returncode != 0:
        return None
    found = set()
    for line in result.stdout.splitlines():
        if ("\tcall   %s " % target_hex) in line or \
                ("\tcall   %s\t" % target_hex) in line:
            addr = line.split(":", 1)[0].strip()
            found.add(int(addr, 16))
    return found


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
    for key in PART_KEYS:
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
    for entry in rec["plt"]:
        sva = int(entry["stub_va"], 16)
        raw = elf.read(sva, 6)
        if raw[0] != 0xFF or raw[1] != 0x25:
            errors.append("PLT stub %s: not an indirect jmp" % entry["stub_va"])
            continue
        (disp,) = struct.unpack_from("<i", raw, 2)
        if sva + 6 + disp != int(entry["got_va"], 16):
            errors.append("PLT stub %s GOT mismatch" % entry["stub_va"])
    # Header literal: replay the three stack stores from .rodata.
    buf = bytearray(64)
    for store in rec["header"]["stores"]:
        raw = elf.read(int(store["rodata_va"], 16), store["bytes"])
        buf[store["buffer_offset"]:store["buffer_offset"] + store["bytes"]] = raw
    literal = bytes(buf).split(b"\x00")[0].decode()
    if literal != rec["header"]["literal"]:
        errors.append("header literal reconstruction mismatch")
    if len(rec["header"]["literal"]) != rec["header"]["length"]:
        errors.append("header literal length mismatch")
    if elf.cstr(int(rec["line_format"]["va"], 16)).decode() != \
            rec["line_format"]["format"]:
        errors.append("line format string mismatch")
    if elf.cstr(int(rec["throw"]["va"], 16)).decode() != \
            rec["throw"]["message"]:
        errors.append("throw message mismatch")
    (scale,) = struct.unpack_from(
        "<d", elf.read(int(rec["scale"]["va"], 16), 8))
    if scale != rec["scale"]["value"]:
        errors.append("MiB scale constant mismatch")
    try:
        with open(os.path.join(packet_dir, "frames.txt")) as f:
            frames = f.read()
    except OSError as exc:
        errors.append("cannot read frames.txt: %s" % exc)
        frames = ""
    for key in PART_KEYS:
        part = rec[key]
        want = "pc=%016x..%016x" % (
            int(part["start_va"], 16), int(part["end_va_exclusive"], 16))
        if want not in frames:
            errors.append("%s FDE line missing from frames.txt" % key)
    for target_hex, want_key in (("514c580", "function_direct_sites"),
                                 ("51cbcd0", "trampoline_direct_sites")):
        found = objdump_census(binary_path, target_hex)
        if found is None:
            errors.append("objdump census failed for %s" % target_hex)
            continue
        want = set(int(s, 16)
                   for s in rec["caller_census"][want_key])
        if found != want:
            errors.append("caller census mismatch for %s: found %s, want %s"
                          % (target_hex, sorted(hex(v) for v in found),
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
