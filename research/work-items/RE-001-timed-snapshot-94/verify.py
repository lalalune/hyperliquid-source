#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-timed-snapshot-94/verify.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node when that file is a
real ELF, and to the digest-verified work copy work/hl-node-94.bin
when it is still an LFS pointer. Excerpt regeneration compares
byte-for-byte against the stored excerpts, so invoke it from the
repository root with the path spelled as ``work/hl-node-94.bin``:
objdump prints the given path in its header line, and an absolute
path would differ from the stored spelling. This script checks semantic records
only: the target digest, every carve range and SHA, the int3 padding,
the direct call targets, the rip-relative sentinel resolutions, the
PLT stub GOT resolutions, the caller censuses, the landing-stub jump
targets, the excerpt regeneration and the packet manifest hashes. It
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
    "window.objdump.txt": ("0x514f270", "0x514f71a"),
    "cleanup.objdump.txt": ("0x514f224", "0x514f270"),
    "ctor.objdump.txt": ("0x514def0", "0x514df30"),
    "timestamp_set.objdump.txt": ("0x514df30", "0x514df40"),
    "counter_inc.objdump.txt": ("0x514df40", "0x514df50"),
    "snapshot_callee.objdump.txt": ("0x514ed50", "0x514f224"),
    "caller.objdump.txt": ("0x514fd94", "0x514fdc0"),
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


def jump_target(elf, site):
    """Resolve a direct rel32 jump at site to its target."""
    b = elf.read(site, 5)
    if b[0] != 0xE9:
        raise ValueError("not a direct jump at %#x: %s" % (site, b.hex()))
    (rel,) = struct.unpack_from("<i", b, 1)
    return site + 5 + rel


def plt_got(elf, stub):
    """Resolve a PLT stub's GOT slot from its jmp-indirect bytes."""
    b = elf.read(stub, 6)
    if b[0] != 0xFF or b[1] != 0x25:
        raise ValueError("not a jmp-indirect PLT stub at %#x" % stub)
    (disp,) = struct.unpack_from("<i", b, 2)
    return stub + 6 + disp


def rip_target(elf, site, length):
    """Resolve a rip-relative operand at the end of an instruction."""
    b = elf.read(site, length)
    (disp,) = struct.unpack_from("<i", b, length - 4)
    return site + length + disp


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

    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    with open(os.path.join(PACKET_DIR, "records.json")) as f:
        rec = json.load(f)

    # Target binding.
    target = rec["target"]
    check(hashlib.sha256(data).hexdigest() == target["sha256"],
          "target digest mismatch")
    check(len(data) == target["size"], "target size mismatch")

    # Carve ranges and padding.
    window = rec["window"]
    check(elf.sha(int(window["start_va"], 16), window["bytes"])
          == window["sha256"], "window SHA mismatch")
    check(elf.read(int(window["end_va_exclusive"], 16),
                   window["padding_bytes"])
          == b"\xcc" * window["padding_bytes"], "window padding mismatch")
    cleanup = rec["cleanup_routine"]
    check(elf.sha(int(cleanup["start_va"], 16), cleanup["bytes"])
          == cleanup["sha256"], "cleanup SHA mismatch")
    check(elf.read(int(cleanup["end_va_exclusive"], 16),
                   cleanup["padding_bytes"])
          == b"\xcc" * cleanup["padding_bytes"], "cleanup padding mismatch")
    for key in ("ctor", "timestamp_set", "counter_inc", "snapshot_callee"):
        callee = rec["callees"][key]
        check(elf.sha(int(callee["start_va"], 16), callee["bytes"])
              == callee["sha256"], "%s SHA mismatch" % key)
        check(elf.read(int(callee["end_va_exclusive"], 16),
                       callee["padding_bytes"])
              == b"\xcc" * callee["padding_bytes"],
              "%s padding mismatch" % key)

    # FDE lines.
    frames = open(os.path.join(PACKET_DIR, "frames.txt")).read()
    for va in (window["start_va"], cleanup["start_va"],
               rec["callees"]["ctor"]["start_va"],
               rec["callees"]["timestamp_set"]["start_va"],
               rec["callees"]["counter_inc"]["start_va"],
               rec["callees"]["snapshot_callee"]["start_va"]):
        check(va[2:] in frames, "FDE line missing for %s" % va)

    # Direct call targets in the window.
    for site, target_va in window["call_sites"].items():
        site_i, target_i = int(site, 16), int(target_va, 16)
        check(call_target(elf, site_i) == target_i,
              "call target mismatch at %s" % site)

    # PLT stub GOT resolutions (from stub bytes, not a symbol table).
    for stub, got in window["plt_got"].items():
        check(plt_got(elf, int(stub, 16)) == int(got, 16),
              "PLT GOT mismatch at %s" % stub)

    # Sentinel cells via rip-relative resolution.
    clock = rec["clock_chain"]
    check(rip_target(elf, int(clock["first_compare"], 16), 7)
          == int(clock["sentinel_cell"], 16),
          "clock sentinel resolution mismatch")
    consumer = rec["consumer_chain"]
    check(rip_target(elf, int(consumer["first_compare"], 16), 7)
          == int(consumer["sentinel_cell"], 16),
          "consumer sentinel resolution mismatch")

    # Threshold immediates.
    thr = rec["thresholds"]
    check(elf.read(0x514f2b6, 4) == b"\xea\x01\x00\x00",
          "count-limit mask mismatch")
    check(elf.read(0x514f2c7, 4) == b"\x80\xfe\x21\x0a",
          "time-limit mask mismatch")
    check(thr["flag_zero"]["count_limit"] == 0x1f4
          and thr["flag_zero"]["time_limit"] == 180000000,
          "flag-zero thresholds mismatch")
    check(thr["flag_nonzero"]["count_limit"] == 10
          and thr["flag_nonzero"]["time_limit"] == 10000000,
          "flag-nonzero thresholds mismatch")

    # Canary load encoding.
    check(elf.read(0x514f289, 9) == b"\x64\x48\x8b\x04\x25\x28\x00\x00\x00",
          "canary load mismatch")

    # Landing stubs: endbr64, mov %rax to a register, direct jump.
    for stub, dest in rec["landing_stubs"].items():
        if stub == "note":
            continue
        stub_i, dest_i = int(stub, 16), int(dest, 16)
        check(elf.read(stub_i, 4) == b"\xf3\x0f\x1e\xfa",
              "landing stub endbr64 mismatch at %s" % stub)
        check(jump_target(elf, stub_i + 7) == dest_i,
              "landing stub jump mismatch at %s" % stub)

    # Caller census: full executable-segment direct-rel32 scans and
    # whole-file qword scan.
    text_start = None
    for vaddr, offset, filesz in elf.loads:
        chunk = data[offset:offset + filesz]
        if vaddr <= 0x514f270 < vaddr + filesz:
            text_start, text = vaddr, chunk
            break
    else:
        raise SystemExit("no PT_LOAD segment contains the window")
    target_va = int(window["start_va"], 16)

    def scan_rel32(opcode):
        out = []
        i = 0
        while True:
            i = text.find(bytes([opcode]), i)
            if i < 0:
                break
            if i + 5 <= len(text):
                (rel,) = struct.unpack_from("<i", text, i + 1)
                if text_start + i + 5 + rel == target_va:
                    out.append(text_start + i)
            i += 1
        return out

    check(scan_rel32(0xE8) == [int(s, 16) for s in
                               rec["caller_census"]["direct_callers"]],
          "direct caller census mismatch")
    check(scan_rel32(0xE9) == [], "tail jump census mismatch")
    qword = struct.pack("<Q", target_va)
    check(data.find(qword) < 0, "qword reference found")

    # Excerpt regeneration byte-for-byte.
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            [sys.executable,
             os.path.join(PACKET_DIR, "export_excerpts.py"),
             "--binary", binary, "--out", tmp],
            capture_output=True, text=True)
        check(result.returncode == 0,
              "export_excerpts failed: %s" % result.stderr.strip())
        for name in RANGES:
            with open(os.path.join(tmp, name)) as f:
                fresh = f.read()
            with open(os.path.join(PACKET_DIR, name)) as f:
                stored = f.read()
            check(fresh == stored, "excerpt mismatch: %s" % name)

    # Manifest hashes.
    manifest = open(os.path.join(PACKET_DIR, "MANIFEST.sha256")).read()
    for line in manifest.strip().splitlines():
        digest, name = line.split(None, 1)
        name = name.lstrip("*")
        with open(os.path.join(PACKET_DIR, name), "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        check(actual == digest, "manifest mismatch: %s" % name)

    if failures:
        print("FAILED:")
        for msg in failures:
            print(" - %s" % msg)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
