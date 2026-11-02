#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-range-sum-94/verify.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. This script checks semantic records only: the target
digest, the function/callee carve ranges and SHAs, the int3 padding,
the branch/call targets re-derived from raw encodings, the FDE
records, the caller census (a full disassembly scan for direct calls
to the function; the expected set is empty), and the packet manifest
hashes. It never lists instruction mnemonics: the raw disassembly
lives in window.objdump.txt and callee.objdump.txt, and the byte
content of those excerpts is checked against the binary by the
independent checker in tools/foundation_range_sum.py.
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

# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    "README.md", "callee.objdump.txt", "export_excerpts.py",
    "frames.txt", "records.json", "verify.py", "window.objdump.txt",
})


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
    # Caller census: full disassembly scan for direct calls to the entry.
    try:
        result = subprocess.run(["objdump", "-d", binary_path],
                                capture_output=True, text=True)
        if result.returncode != 0:
            errors.append("objdump census failed")
            found = None
        else:
            found = set()
            for line in result.stdout.splitlines():
                if "\tcall   514bc60 " in line or "\tcall   514bc60\t" in line:
                    addr = line.split(":", 1)[0].strip()
                    found.add(int(addr, 16))
    except OSError as exc:
        errors.append("objdump census failed: %s" % exc)
        found = None
    if found is not None:
        want = set(int(s, 16) for s in rec["caller_census"]["direct_sites"])
        if found != want:
            errors.append("caller census mismatch: found %s, want %s" % (
                sorted(hex(v) for v in found), sorted(hex(v) for v in want)))
    # The manifest pins every packet file except itself, so the listed
    # set must equal the pinned packet files and the files actually
    # present (the admission check the RE-012/RE-009 packet verifiers
    # spell out). Hashing only the listed rows admits an unlisted
    # payload, a duplicated row, a symlinked entry, or an evidence file
    # deleted together with its row.
    manifest = os.path.join(packet_dir, "MANIFEST.sha256")
    if not os.path.exists(manifest):
        errors.append("MANIFEST.sha256 missing")
        return errors
    listed = {}
    try:
        with open(manifest) as f:
            for line in f:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) != 2:
                    errors.append(
                        "malformed manifest line: %r" % line.strip())
                    continue
                digest, name = parts
                if name in listed:
                    errors.append("manifest lists %s twice" % name)
                    continue
                listed[name] = digest
    except OSError as exc:
        errors.append("cannot verify MANIFEST: %s" % exc)
        return errors
    present = set()
    for entry in sorted(os.listdir(packet_dir)):
        path = os.path.join(packet_dir, entry)
        if os.path.islink(path):
            errors.append("packet entry is a symlink: %s" % entry)
        elif os.path.isdir(path):
            if entry != "__pycache__" or not all(
                    name.endswith(".pyc")
                    and not os.path.islink(os.path.join(path, name))
                    for name in os.listdir(path)):
                errors.append("unexpected directory in packet: %s" % entry)
        else:
            present.add(entry)
    present.discard("MANIFEST.sha256")
    if set(listed) != PACKET_FILES:
        errors.append(
            "manifest file set differs from the pinned packet files: "
            "missing rows %s, unexpected rows %s"
            % (sorted(PACKET_FILES - set(listed)),
               sorted(set(listed) - PACKET_FILES)))
    if set(listed) != present:
        errors.append(
            "manifest file set differs from packet contents: "
            "unlisted %s, missing %s"
            % (sorted(present - set(listed)),
               sorted(set(listed) - present)))
    for name, digest in sorted(listed.items()):
        if name not in present:
            continue
        try:
            with open(os.path.join(packet_dir, name), "rb") as pf:
                actual = hashlib.sha256(pf.read()).hexdigest()
        except OSError as exc:
            errors.append("cannot verify MANIFEST: %s" % exc)
            continue
        if actual != digest:
            errors.append("MANIFEST mismatch for %s" % name)
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
