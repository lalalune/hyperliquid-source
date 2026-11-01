#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-list-teardown-94/verify.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. This script checks semantic records only: the target
digest, the function carve range and SHA, the int3 padding, the
branch/call/tail-jump targets re-derived from raw encodings, the
PLT GOT slot values, the FDE record, the caller census (a full
disassembly scan for direct calls and tail jumps to the function;
both expected sets are empty), and the packet manifest hashes. It
never lists instruction mnemonics: the raw disassembly lives in
window.objdump.txt and plt.objdump.txt, and the byte content of
those excerpts is checked against the binary by the independent
checker in tools/foundation_list_teardown.py.
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

    def read(self, va, size):
        off = self.va_to_offset(va)
        return self.data[off:off + size]


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
    for jump in rec["tail_jumps"]:
        site = int(jump["site"], 16)
        want = int(jump["target"], 16)
        if rel_target(elf, site, 5) != want:
            errors.append("tail jump %s target mismatch" % jump["site"])
    for name, plt in rec["plt"].items():
        slot = int(plt["got_slot"], 16)
        want = int(plt["got_file_value"], 16)
        (actual,) = struct.unpack("<Q", elf.read(slot, 8))
        if actual != want:
            errors.append("%s GOT file value mismatch" % name)
    try:
        with open(os.path.join(packet_dir, "frames.txt")) as f:
            frames = f.read()
    except OSError as exc:
        errors.append("cannot read frames.txt: %s" % exc)
        frames = ""
    want = "pc=%016x..%016x" % (s, e)
    if want not in frames:
        errors.append("function FDE line missing from frames.txt")
    # Caller census: full disassembly scan for direct calls and tail
    # jumps to the function; both expected sets are empty.
    try:
        result = subprocess.run(["objdump", "-d", binary_path],
                                capture_output=True, text=True)
        if result.returncode != 0:
            errors.append("objdump census failed")
            found_calls = found_jmps = None
        else:
            found_calls = set()
            found_jmps = set()
            for line in result.stdout.splitlines():
                if "\tcall   514bd40 " in line or "\tcall   514bd40\t" in line:
                    addr = line.split(":", 1)[0].strip()
                    found_calls.add(int(addr, 16))
                if "\tjmp    514bd40 " in line or "\tjmp    514bd40\t" in line:
                    addr = line.split(":", 1)[0].strip()
                    found_jmps.add(int(addr, 16))
    except OSError as exc:
        errors.append("objdump census failed: %s" % exc)
        found_calls = found_jmps = None
    if found_calls is not None:
        want = set(int(x, 16) for x in rec["caller_census"]["direct_sites"])
        if found_calls != want:
            errors.append("caller census mismatch: found %s, want %s" % (
                sorted(hex(v) for v in found_calls),
                sorted(hex(v) for v in want)))
    if found_jmps is not None:
        want = set(int(x, 16) for x in rec["caller_census"]["tail_jump_sites"])
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
