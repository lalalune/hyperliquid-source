#!/usr/bin/env python3
"""RE-001: string build-and-move over node #94 (function 0x514bdf0).

The target function builds a temporary string on the stack via the
shared producer callee 0x51cd470, move-assigns it into its second
argument with 0x514b4f0 (the move-assign bound by the merged #1321
packet), destroys the temporary, and returns 1.  Read directly from
the bytes in research/work-items/RE-001-string-build-move-94/window.objdump.txt:

    chain = [rdi + 0x788]; source = [chain + 0x30]
    temp = producer(source, flags 1, 1)   # callee 0x51cd470, writes
                                          # the string at its 1st arg
    move_assign(out, temp)                # 0x514b4f0: out := temp's
                                          # contents; temp keeps old out
    if temp.pointer == temp + 0x10:       # inline/SSO storage
        pass                              # nothing to free
    else:
        operator_delete(temp.pointer, temp.capacity + 1)
    return 1                              # canary failure aborts
                                          # via __stack_chk_fail instead

The producer's own contents are NOT modelled here: its 4075 bytes
are a separate work item, and the model takes the produced string
as an input, exactly as the entry receives it from the callee.  The
move-assign internals are likewise #1321's claim, reused here, not
re-claimed: the model states only the entry-level contract (out
ends up equal to the produced string) plus the disposal rule, which
is fully determined by the entry's own bytes.

Stdlib only.  ``check_packet`` verifies a packet directory against a
node #94 binary; it returns a list of error strings (empty = pass).
"""

import hashlib
import json
import os
import re
import struct
import sys

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
FUNC_START = 0x514BDF0
FUNC_END = 0x514BE75
CALLEE_START = 0x51CD470
CALLEE_END = 0x51CE45B
MASK64 = (1 << 64) - 1


def temp_dispose(temp_pointer, temp_base, capacity):
    """The entry's temporary-destruction rule.

    ``temp_base`` is the temporary's own address (rsp in the bytes),
    ``temp_pointer`` is the qword at temp + 0x0, ``capacity`` the
    qword at temp + 0x10.  Return ``None`` when nothing is freed
    (inline/SSO storage: pointer == temp + 0x10), otherwise the size
    passed to operator delete, ``(capacity + 1) mod 2**64``.
    """
    if temp_pointer == (temp_base + 0x10) & MASK64:
        return None
    return (capacity + 1) & MASK64


def string_build_move(produced):
    """The entry-level contract: ``(1, out)`` with out == produced.

    ``produced`` is the byte string the producer callee wrote into
    the temporary (bytes, so no encoding is claimed).  The return
    value is 1 on every returning path; a canary mismatch aborts
    via __stack_chk_fail and never returns, so it has no model
    value here.
    """
    return 1, bytes(produced)


# ---------------------------------------------------------------------------
# Packet checker (used by tests/test_foundation_string_build_move.py)
# ---------------------------------------------------------------------------

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


def _rel_target(elf, site, length):
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


_INSN_LINE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\t")


def _check_excerpt_bytes(elf, path, errors, label):
    """Every instruction line's bytes must match the binary at its VA."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError as exc:
        errors.append("cannot read %s excerpt: %s" % (label, exc))
        return
    checked = 0
    for line in lines:
        m = _INSN_LINE.match(line)
        if not m:
            continue
        va = int(m.group(1), 16)
        raw = bytes(int(tok, 16) for tok in m.group(2).split())
        try:
            actual = elf.read(va, len(raw))
        except ValueError:
            errors.append("%s excerpt VA %#x outside PT_LOAD" % (label, va))
            continue
        if actual != raw:
            errors.append("%s excerpt bytes mismatch at %#x" % (label, va))
        checked += 1
    if checked == 0:
        errors.append("%s excerpt has no instruction lines" % label)


def check_packet(packet_dir, binary_path):
    """Verify the packet's semantic records against a binary.

    Returns a list of error strings; empty means ALL CHECKS PASSED.
    The caller/callee censuses are verified by the packet's own
    verify.py (which runs the .text byte scans); this checker
    verifies the recorded branch/call encodings, the carve SHAs, the
    padding, the FDE lines, every excerpt line's bytes, and the
    manifest.
    """
    errors = []
    records_path = os.path.join(packet_dir, "records.json")
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
        if _rel_target(elf, site, branch["length"]) != want:
            errors.append("branch %s target mismatch" % branch["site"])
    for call in rec["calls"]:
        site = int(call["site"], 16)
        want = int(call["target"], 16)
        if _rel_target(elf, site, 5) != want:
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
    for name in ("window", "callee"):
        _check_excerpt_bytes(
            elf, os.path.join(packet_dir, "%s.objdump.txt" % name),
            errors, name)
    manifest_path = os.path.join(packet_dir, "MANIFEST.sha256")
    try:
        with open(manifest_path) as f:
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
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("packet_dir")
    ap.add_argument("binary")
    args = ap.parse_args(argv)
    errors = check_packet(args.packet_dir, args.binary)
    if errors:
        for err in errors:
            print("FAIL: %s" % err)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
