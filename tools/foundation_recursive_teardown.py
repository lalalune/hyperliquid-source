#!/usr/bin/env python3
"""RE-001: recursive chain teardown (function 0x514bf60, node #94).

The target function tears down a 0x60-byte node chain.  Read directly
from the bytes in research/work-items/RE-001-recursive-teardown-94/window.objdump.txt:

    teardown(node):                     # rdi = node or null
        if node is null: return         # je at 0x514bf63 to the ret
        cur = node
        while cur is not null:          # loop head 0x514bf70/0x514bf73
            teardown([cur + 0x18])      # child first, recursive call
            nxt = [cur + 0x10]          # next sibling, saved BEFORE
                                        # any disposal (0x514bf84)
            dispose(cur + 0x40 string)  # pointer +0x40, buffer +0x50
            dispose(cur + 0x20 string)  # pointer +0x20, buffer +0x30
            delete(cur, 0x60)           # sized operator delete
            cur = nxt                   # jne at 0x514bfc4 back to
                                        # 0x514bf70, which reloads rbx
                                        # from rbp on every iteration

    dispose(string):                    # per string, pointer P and
                                        # buffer field B (capacity
                                        # when heap-allocated)
        if P == node + buffer_offset:   # inline (SSO): nothing freed
            pass
        else:
            delete(P, B + 1 mod 2**64)  # via PLT 0x5660440 (_ZdlPvm)

The first entry bypasses the sibling reload via the jmp at 0x514bf6e
because rbx already holds the input object; every later iteration
passes through the mov at 0x514bf70, so the saved sibling pointer is
reloaded on every iteration (this is the loop-head reading the
preceding nested-teardown item corrected after review: an
instruction after the loop head still executes on every iteration
when the loop-back target precedes it).

The +0x00 and +0x08 qwords of a node are never read by this
function and are not modelled.  The string layout is read as the
SSO shape (pointer, unread length, capacity-or-inline-buffer)
because the disposal test compares the pointer against the inline
buffer address and the delete size is the buffer field + 1; no
source-level type name is claimed.  The function has no endbr64 and
no stack canary; rbp and rbx are pushed and popped in balance.

The model below takes the already-resolved structure as its input:
a ``Node`` holds its child, its next sibling, and its two strings
as ``StringField`` values (a pointer label, whether the string is
heap-allocated, and its capacity field).  The delete log records
every operator-delete call in byte order.  ``check_packet`` verifies
a packet directory against a node #94 binary; it returns a list of
error strings (empty = pass).  The caller census is verified by the
packet's own verify.py, not here.
"""

import hashlib
import json
import os
import re
import struct
import sys

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
FUNC_START = 0x514BF60
FUNC_END = 0x514BFD1
PLT_START = 0x5660440
NODE_SIZE = 0x60
MASK64 = (1 << 64) - 1


class StringField:
    """One string slot: pointer label, heap flag, capacity field.

    ``heap`` is True exactly when the pointer differs from the
    node's inline-buffer address (the je at 0x514bf8b / 0x514bfa5
    skips the delete on equality); ``capacity`` is the buffer
    field's value, used only on the heap arm as capacity + 1.
    """

    __slots__ = ("pointer", "heap", "capacity")

    def __init__(self, pointer, heap=False, capacity=0):
        self.pointer = pointer
        self.heap = heap
        self.capacity = capacity & MASK64


class Node:
    """One 0x60-byte chain node, after the loop's loads."""

    __slots__ = ("label", "child", "next_sibling", "string1", "string2")

    def __init__(self, label, child=None, next_sibling=None,
                 string1=None, string2=None):
        self.label = label
        self.child = child
        self.next_sibling = next_sibling
        self.string1 = string1 if string1 is not None else StringField(None)
        self.string2 = string2 if string2 is not None else StringField(None)


def _dispose(field, deletes):
    if field.pointer is None or not field.heap:
        return
    deletes.append(("string", field.pointer,
                    (field.capacity + 1) & MASK64))


def _walk(node, deletes):
    cur = node
    while cur is not None:
        _walk(cur.child, deletes)
        nxt = cur.next_sibling  # saved before any disposal, as in bytes
        _dispose(cur.string2, deletes)  # +0x40 string first
        _dispose(cur.string1, deletes)  # then the +0x20 string
        deletes.append(("node", cur.label, NODE_SIZE))
        cur = nxt


def teardown(root):
    """Tear down ``root``; return the delete log in byte order.

    A null root logs nothing.  Each entry is ("string", pointer,
    size) for a heap string disposal or ("node", label, 0x60) for a
    node delete.  Disposal order per node is: child subtree, second
    string, first string, the node itself; siblings follow in chain
    order.
    """
    deletes = []
    if root is not None:
        _walk(root, deletes)
    return deletes


# ---------------------------------------------------------------------------
# Packet checker (used by tests/test_foundation_recursive_teardown.py)
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
    This checker verifies the recorded branch/call encodings, the
    carve SHAs, the padding, the FDE line, every excerpt line's
    bytes, and the manifest.  The caller census is verified by the
    packet's own verify.py.
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
    plt = rec["plt_delete"]
    ps = int(plt["start_va"], 16)
    pbody = elf.read(ps, plt["bytes"])
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
    try:
        with open(os.path.join(packet_dir, "frames.txt")) as f:
            frames = f.read()
    except OSError as exc:
        errors.append("cannot read frames.txt: %s" % exc)
        frames = ""
    want = "pc=%016x..%016x" % (start, end)
    if want not in frames:
        errors.append("function FDE line missing from frames.txt")
    for name in ("window", "plt", "callers"):
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
