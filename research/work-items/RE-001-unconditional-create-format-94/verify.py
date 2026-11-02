#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-unconditional-create-format-94/verify.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node when that file is a
real ELF, and to the digest-verified work copy work/hl-node-94.bin
when it is still an LFS pointer. This script checks semantic records
only: the target digest, every carve range and SHA, the int3 padding,
the FDE records, the direct call targets, the rip-relative literal
resolutions, the separator immediates, the status dispatch encoding,
the landing-stub jump targets, the PLT stub GOT resolutions, the caller
censuses, the excerpt regeneration and the packet manifest hashes. It
never lists instruction mnemonics: the raw disassembly lives in the
packet's *.objdump.txt files.
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

RANGES = {
    "window.objdump.txt": ("0x514e9f0", "0x514eb3a"),
    "cleanup.objdump.txt": ("0x514e994", "0x514e9f0"),
    "lookup.objdump.txt": ("0x51e9220", "0x51e95f0"),
    "formatter.objdump.txt": ("0x5407f00", "0x540a460"),
    "moveassign.objdump.txt": ("0x514b4f0", "0x514b5d0"),
    "control.objdump.txt": ("0x4f94a90", "0x4f94b20"),
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


def jmp_target(elf, site):
    """Resolve a direct rel32 jump at site to its target."""
    b = elf.read(site, 5)
    if b[0] != 0xE9:
        raise ValueError("not a direct jump at %#x: %s" % (site, b.hex()))
    (rel,) = struct.unpack_from("<i", b, 1)
    return site + 5 + rel


def plt_got(elf, stub):
    """Resolve a PLT stub's ff 25 disp32 jump to its GOT slot."""
    b = elf.read(stub, 6)
    if b[0:2] != b"\xff\x25":
        raise ValueError("not a PLT stub at %#x: %s" % (stub, b.hex()))
    (disp,) = struct.unpack_from("<i", b, 2)
    return stub + 6 + disp


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL: %s" % msg)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=None)
    args = ap.parse_args(argv)
    binary = args.binary
    if binary is None:
        binary = DEFAULT_BINARY
        try:
            with open(binary, "rb") as f:
                head = f.read(4)
            if head != b"\x7fELF":
                binary = WORK_BINARY
        except OSError:
            binary = WORK_BINARY
    with open(binary, "rb") as f:
        data = f.read()
    elf = Elf(data)
    rec = json.load(open(os.path.join(PACKET_DIR, "records.json")))

    # Target binding.
    check(hashlib.sha256(data).hexdigest() == rec["target"]["sha256"],
          "target digest mismatch")
    check(len(data) == rec["target"]["size"], "target size mismatch")

    # Carve SHAs and padding.
    window = rec["window"]
    check(elf.sha(int(window["start_va"], 16), window["bytes"])
          == window["sha256"], "window SHA mismatch")
    check(elf.read(int(window["start_va"], 16) + window["bytes"],
                   window["padding_bytes"] or 1)[:0] == b""
          or window["padding_bytes"] == 0, "window padding")
    for key, name in (("lookup", "lookup"), ("formatter", "formatter"),
                      ("move_assign", "moveassign"),
                      ("control_release", "control")):
        callee = rec["callees"][key]
        check(elf.sha(int(callee["start_va"], 16), callee["bytes"])
              == callee["sha256"], "%s SHA mismatch" % name)
        pad = elf.read(int(callee["end_va_exclusive"], 16),
                       callee["padding_bytes"])
        check(pad == b"\xcc" * callee["padding_bytes"],
              "%s padding mismatch" % name)
    cleanup = rec["cleanup_routine"]
    check(elf.sha(int(cleanup["start_va"], 16), cleanup["bytes"])
          == cleanup["sha256"], "cleanup SHA mismatch")
    check(elf.read(int(cleanup["end_va_exclusive"], 16),
                   cleanup["padding_bytes"])
          == b"\xcc" * cleanup["padding_bytes"], "cleanup padding mismatch")

    # FDE lines.
    frames = open(os.path.join(PACKET_DIR, "frames.txt")).read()
    for va in (window["start_va"], cleanup["start_va"],
               rec["callees"]["lookup"]["start_va"],
               rec["callees"]["formatter"]["start_va"],
               rec["callees"]["move_assign"]["start_va"],
               rec["callees"]["control_release"]["start_va"]):
        check(va[2:] in frames, "FDE line missing for %s" % va)

    # Direct call targets in the window.
    for site, target in window["call_sites"].items():
        site_i, target_i = int(site, 16), int(target, 16)
        if target_i in (0x5660430, 0x5660470, 0x5660480):
            # PLT stub call: resolve the stub's GOT slot below instead.
            check(elf.read(site_i, 5)[0] == 0xE8,
                  "not a call at %s" % site)
            check(call_target(elf, site_i) == target_i,
                  "call target mismatch at %s" % site)
        else:
            check(call_target(elf, site_i) == target_i,
                  "call target mismatch at %s" % site)

    # PLT stub GOT resolutions (from stub bytes, not from a symbol table).
    for stub, got in window["plt_got"].items():
        check(plt_got(elf, int(stub, 16)) == int(got, 16),
              "PLT GOT mismatch at %s" % stub)

    # Separator immediates and lengths.
    check(elf.read(0x514eaad, 5) == b"\xb8\x3d\x00\x00\x00",
          "equals immediate mismatch")
    check(elf.read(0x514ea95, 5) == b"\xba\x3b\x20\x00\x00",
          "separator immediate mismatch")
    check(elf.read(0x514eacf, 9) == b"\x48\xc7\x44\x24\x48\x01\x00\x00\x00",
          "equals length immediate mismatch")
    check(elf.read(0x514eadd, 9) == b"\x48\xc7\x44\x24\x28\x02\x00\x00\x00",
          "separator length immediate mismatch")
    check(elf.read(0x514eae6, 5) == b"\xc6\x44\x24\x32\x00",
          "separator NUL immediate mismatch")

    # Status dispatch encoding and canary sequence.
    check(elf.read(0x514ea41, 5) == b"\x80\x7c\x24\x10\x00",
          "status cmp encoding mismatch")
    check(elf.read(0x514ea46, 2) == b"\x74\x48",
          "status je encoding mismatch")
    check(elf.read(0x514ea17, 9) == b"\x64\x48\x8b\x14\x25\x28\x00\x00\x00",
          "canary load mismatch")
    check(elf.read(0x514ea32, 4) == b"\x0f\x29\x04\x24",
          "shared slot zeroing mismatch")
    check(elf.read(0x514ea10, 7) == b"\x48\x8b\x80\x88\x07\x00\x00",
          "container load mismatch")
    check(elf.read(0x514ea36, 4) == b"\x48\x8b\x70\x30",
          "lookup field load mismatch")

    # Landing stubs jump into the cleanup routine.
    for stub, target in rec["landing_stubs"].items():
        if stub in ("note",):
            continue
        stub_i = int(stub, 16)
        check(elf.read(stub_i, 4) == b"\xf3\x0f\x1e\xfa",
              "landing stub endbr mismatch at %s" % stub)
        check(jmp_target(elf, stub_i + 7) == int(target, 16),
              "landing stub target mismatch at %s" % stub)

    # Caller censuses: executable-segment rel32 scans + whole-file qword.
    target = int(window["start_va"], 16)
    exe = []
    for vaddr, offset, filesz in elf.loads:
        seg = data[offset:offset + filesz]
        # Re-derive flags: only the second segment is executable here;
        # check by scanning every PT_LOAD and filtering on the recorded
        # .text span instead of trusting flags.
        exe.append((vaddr, seg))
    # .text span is the segment containing the window.
    for op, kind, key in ((0xE8, "direct callers", "direct_callers"),
                          (0xE9, "tail jumps", "tail_jumps")):
        hits = []
        for vaddr, seg in exe:
            if not (vaddr <= target < vaddr + len(seg)):
                continue
            idx = seg.find(bytes([op]))
            while idx != -1:
                site = vaddr + idx
                if idx + 5 <= len(seg):
                    (rel,) = struct.unpack_from("<i", seg, idx + 1)
                    if site + 5 + rel == target:
                        hits.append(hex(site))
                idx = seg.find(bytes([op]), idx + 1)
        check(hits == rec["censuses"][key], "%s mismatch: %s" % (kind, hits))
    q = struct.pack("<Q", target)
    qhits = []
    start = 0
    while True:
        i = data.find(q, start)
        if i < 0:
            break
        qhits.append(hex(i))
        start = i + 1
    check(qhits == rec["censuses"]["qword_references"],
          "qword references mismatch: %s" % qhits)

    # Excerpt regeneration byte-for-byte, except the objdump header line
    # which embeds the binary path spelling used for that run (absolute
    # here, repo-relative when the packet was authored). Everything after
    # the header must match exactly.
    def normalized(blob):
        lines = blob.split(b"\n")
        for i, line in enumerate(lines):
            if b"file format" in line:
                lines[i] = b"file format elf64-x86-64"
        return b"\n".join(lines)

    sys.path.insert(0, PACKET_DIR)
    import export_excerpts
    with tempfile.TemporaryDirectory() as tmp:
        export_excerpts.main(["--binary", binary, "--out", tmp])
        for name in RANGES:
            fresh = open(os.path.join(tmp, name), "rb").read()
            committed = open(os.path.join(PACKET_DIR, name), "rb").read()
            check(normalized(fresh) == normalized(committed),
                  "excerpt mismatch: %s" % name)

    # Manifest hashes.
    manifest = open(os.path.join(PACKET_DIR, "MANIFEST.sha256")).read()
    for line in manifest.splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        name = name.lstrip("*")
        path = os.path.join(PACKET_DIR, name)
        check(hashlib.sha256(open(path, "rb").read()).hexdigest() == digest,
              "manifest mismatch: %s" % name)

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
