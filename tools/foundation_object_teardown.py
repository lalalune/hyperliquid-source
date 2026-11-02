#!/usr/bin/env python3
"""RE-001: object teardown (function 0x514bfe0, node #94).

The target function is a null-safe teardown of a 0x2e0-byte object.
Read directly from the bytes in
research/work-items/RE-001-object-teardown-94/window.objdump.txt:

    if object is None: return with no delete call
    # string at +0x1a8 first, then string at +0x48; each string is
    # (pointer at +S, union at +S+0x10):
    for S in (0x1a8, 0x48):
        if pointer != object_address + S + 0x10:  # heap, not SSO
            delete(pointer, (union + 1) mod 2**64)
    delete(object, 0x2e0)  # tail jump: never returns on this path

The model below takes the string fields as its input: a ``Str``
carries the pointer value, the union value, and the string's offset
within the object, and the inline-buffer address is computed from
the offset (object base + offset + 0x10).  The delete calls are
recorded in order, including the final sized self-delete, so tests
can prove the disposal order and the SSO arms exactly.

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
FUNC_START = 0x514BFE0
FUNC_END = 0x514C041
FUNC_SHA256 = "b697d8a0b87360ceb90f4b43472e6a5fe758663eaeb5fa90498bf4d9f83383db"
FUNC_PADDING = 15
PLT_START = 0x5660440
PLT_END = 0x5660450
PLT_SHA256 = "3135a1370758dd60ff15c438e109b906388691df95912baf85ccbd9132155e45"
OBJECT_SIZE = 0x2E0
STRING_OFFSETS = (0x1A8, 0x48)
MASK64 = (1 << 64) - 1


class Str:
    """One embedded SSO string field, by object offset.

    ``pointer`` is the qword at +offset, ``union`` the qword at
    +offset+0x10 (capacity when heap, inline bytes when short).
    """

    __slots__ = ("offset", "pointer", "union")

    def __init__(self, offset, pointer, union):
        self.offset = offset
        self.pointer = pointer & MASK64
        self.union = union & MASK64


def teardown(obj, strings):
    """Teardown ``obj`` (None = null input) with ``strings`` in order.

    Returns ``(returned, deletes)`` where ``deletes`` is the ordered
    list of ``(pointer, size)`` delete calls.  ``returned`` is True
    only for the null input, which returns without any delete; the
    non-null path tail-jumps to delete and never returns, so it
    reports ``returned`` False with the self-delete last.
    """
    deletes = []
    if obj is None:
        return True, deletes
    for s in strings:
        inline = (obj + s.offset + 0x10) & MASK64
        if s.pointer != inline:
            deletes.append((s.pointer, (s.union + 1) & MASK64))
    deletes.append((obj, OBJECT_SIZE))
    return False, deletes


# ---------------------------------------------------------------------------
# Packet checker (used by tests/test_foundation_object_teardown.py)
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
    The caller census is verified by the packet's own verify.py (which
    runs a full disassembly scan); this checker verifies the recorded
    branch/call/tail-jump encodings, the carve SHAs, the padding, the
    FDE line, the PLT relocation line, every excerpt line's bytes,
    and the manifest.
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
    func = rec["function"]
    start = int(func["start_va"], 16)
    end = int(func["end_va_exclusive"], 16)
    body = elf.read(start, end - start)
    if len(body) != func["bytes"]:
        errors.append("function byte count mismatch")
    if hashlib.sha256(body).hexdigest() != func["sha256"]:
        errors.append("function SHA mismatch")
    pad = elf.read(end, func["padding_bytes"])
    if pad != b"\xcc" * func["padding_bytes"]:
        errors.append("function padding is not int3")
    plt = rec["plt_stub"]
    ps = int(plt["start_va"], 16)
    pe = int(plt["end_va_exclusive"], 16)
    pbody = elf.read(ps, pe - ps)
    if len(pbody) != plt["bytes"]:
        errors.append("PLT stub byte count mismatch")
    if hashlib.sha256(pbody).hexdigest() != plt["sha256"]:
        errors.append("PLT stub SHA mismatch")
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
    tail = rec["tail_jump"]
    if _rel_target(elf, int(tail["site"], 16), 5) != int(tail["target"], 16):
        errors.append("tail jump %s target mismatch" % tail["site"])
    try:
        with open(os.path.join(packet_dir, "frames.txt")) as f:
            frames = f.read()
    except OSError as exc:
        errors.append("cannot read frames.txt: %s" % exc)
        frames = ""
    if "pc=%016x..%016x" % (start, end) not in frames:
        errors.append("function FDE line missing from frames.txt")
    try:
        with open(os.path.join(packet_dir, "relocations.txt")) as f:
            relocs = f.read()
    except OSError as exc:
        errors.append("cannot read relocations.txt: %s" % exc)
        relocs = ""
    if plt["got_slot"][2:] not in relocs or "_ZdlPvm" not in relocs:
        errors.append("PLT GOT relocation line missing from relocations.txt")
    _check_excerpt_bytes(elf, os.path.join(packet_dir, "window.objdump.txt"),
                         errors, "window")
    _check_excerpt_bytes(elf, os.path.join(packet_dir, "plt.objdump.txt"),
                         errors, "plt")
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
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--packet-dir", default=os.path.join(
        os.path.dirname(__file__), "..", "research", "work-items",
        "RE-001-object-teardown-94"))
    ap.add_argument("--binary", default=os.path.join(
        "artifacts", "node", "94", "hl-node"))
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
