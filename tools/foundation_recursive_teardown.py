#!/usr/bin/env python3
"""RE-001: recursive teardown (function 0x514be80, node #94).

The target function tears down a chain of 0x48-byte nodes. Read
directly from the bytes in
research/work-items/RE-001-recursive-teardown-94/window.objdump.txt:

- A null input returns immediately (test rdi, rdi; je to the ret
  at 0x514bed8); nothing is freed.
- Otherwise, for each node in the chain, in order:
  1. Recursively call this same function on the link at node + 0x18
     (the recursive call at 0x514be97; a null link returns at once,
     so the recursion always terminates at the leaves).
  2. Save the next link from node + 0x10 (loaded at 0x514bea4,
     before any free below, so the walk survives the node's own
     delete).
  3. Dispose the string at node + 0x20: if the string pointer at
     node + 0x20 equals node + 0x30 (the inline-buffer address),
     nothing is freed; otherwise operator delete is called with
     (pointer, capacity + 1 mod 2**64), where capacity is the qword
     at node + 0x30 -- the same capacity-plus-terminator size the
     neighbouring string disposals use.
  4. Delete the node itself with size 0x48 (call at 0x514bec2).
  5. Advance to the saved next link; stop when it is null.
- The function returns void, preserves rbp and rbx, and keeps the
  stack balanced (push rbp/rbx, sub rsp 8, restored before ret).
  It has no stack canary.

The model below takes the post-deref values as its input: a node is
a ``Node`` whose ``child`` and ``next`` links are already resolved,
whose string is described by (inline, capacity), and whose identity
is a label used only to order the recorded free events. The walk,
the recursion, the string disposal test, and the node deletes are
simulated; the raw field loads themselves are recorded in
records.json and verified against the raw excerpts by
:func:`check_packet`, because the model has no memory image. No
role is claimed for the qwords at node + 0x0 or node + 0x8, which
the function never reads, and no source-level type name is claimed
for the node or for either link.

Stdlib only. ``check_packet`` verifies a packet directory against a
node #94 binary; it returns a list of error strings (empty = pass).
"""

import hashlib
import json
import os
import re
import struct
import sys

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
FUNC_START = 0x514BE80
FUNC_END = 0x514BED9
NODE_SIZE = 0x48
MASK64 = (1 << 64) - 1

# (address, length, target) for every branch/call in the function,
# re-derived from the raw encodings, not from objdump's annotations.
BRANCHES = [
    (0x514BE83, 2, 0x514BED8),  # je: null input -> ret
    (0x514BE8E, 2, 0x514BE93),  # jmp: first iteration skips the mov
    (0x514BEAB, 2, 0x514BEBA),  # je: inline string -> skip buffer free
    (0x514BECA, 2, 0x514BE90),  # jne: next link -> loop
]
CALLS = [
    (0x514BE97, 0x514BE80),  # recursive call on [node + 0x18]
    (0x514BEB5, 0x5660440),  # operator delete: string buffer
    (0x514BEC2, 0x5660440),  # operator delete: node, size 0x48
]

_EXCERPT_LINE = re.compile(
    r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(.*)$")


class Node:
    """One 0x48-byte node, with links already resolved.

    ``child`` is the node at +0x18, ``next`` the node at +0x10.
    ``str_inline`` is True when the string pointer at +0x20 equals
    the node's own +0x30 address; then no buffer delete runs and
    ``str_capacity`` is unread. Otherwise the buffer delete runs
    with size ``str_capacity + 1`` mod 2**64.
    """

    __slots__ = ("label", "child", "next", "str_inline", "str_capacity")

    def __init__(self, label, child=None, next=None,
                 str_inline=True, str_capacity=0):
        self.label = label
        self.child = child
        self.next = next
        self.str_inline = str_inline
        self.str_capacity = str_capacity


def teardown(node, events=None):
    """Simulate the function; return the ordered free events.

    Each event is ("free_string", label, size) or
    ("free_node", label, 0x48). A null input yields no events.
    """
    if events is None:
        events = []
    cur = node
    while cur is not None:
        nxt = cur.next  # saved before any free, as at 0x514bea4
        if cur.child is not None:
            teardown(cur.child, events)
        if not cur.str_inline:
            events.append(("free_string", cur.label,
                           (cur.str_capacity + 1) & MASK64))
        events.append(("free_node", cur.label, NODE_SIZE))
        cur = nxt
    return events


class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping only."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from(
            "<HH", data, 0x36)
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

    def text_scan(self, opcode, target):
        """All .text sites where an opcode rel32 lands on target."""
        (e_shoff,) = struct.unpack_from("<Q", self.data, 0x28)
        (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            "<HHH", self.data, 0x3A)
        str_off = e_shoff + e_shstrndx * e_shentsize
        (shstr_off,) = struct.unpack_from("<Q", self.data, str_off + 0x18)
        text = None
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            (name_idx, _type, _flags, addr, offset, size) = \
                struct.unpack_from("<IIQQQQ", self.data, off)
            end = self.data.index(b"\x00", shstr_off + name_idx)
            if self.data[shstr_off + name_idx:end] == b".text":
                text = (addr, offset, size)
                break
        if text is None:
            raise ValueError(".text section not found")
        addr, offset, size = text
        seg = self.data[offset:offset + size]
        hits = []
        for i in range(len(seg) - 4):
            if seg[i] != opcode:
                continue
            (disp,) = struct.unpack_from("<i", seg, i + 1)
            if addr + i + 5 + disp == target:
                hits.append(addr + i)
        return hits


def _rel_target(elf, site, length):
    raw = elf.read(site, length)
    if length == 2:
        (disp,) = struct.unpack_from("<b", raw, 1)
    elif length == 5:
        (disp,) = struct.unpack_from("<i", raw, 1)
    else:
        raise ValueError("unsupported branch length %d" % length)
    return site + length + disp


def check_packet(packet_dir, binary_path):
    """Verify the packet against the binary; [] means pass."""
    errors = []
    try:
        with open(os.path.join(packet_dir, "records.json")) as f:
            rec = json.load(f)
    except (OSError, ValueError) as exc:
        return ["cannot read records.json: %s" % exc]
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        return ["cannot read binary: %s" % exc]
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        errors.append("target digest mismatch")
    elf = Elf(data)
    func = rec["function"]
    blob = elf.read(int(func["start_va"], 16),
                    int(func["end_va_exclusive"], 16)
                    - int(func["start_va"], 16))
    if hashlib.sha256(blob).hexdigest() != func["sha256"]:
        errors.append("function SHA mismatch")
    if len(blob) != func["bytes"]:
        errors.append("function byte count mismatch")
    pad = elf.read(int(func["end_va_exclusive"], 16),
                   func["padding_bytes"])
    if pad != b"\xcc" * func["padding_bytes"]:
        errors.append("padding is not int3")
    for site, length, want in BRANCHES:
        if _rel_target(elf, site, length) != want:
            errors.append("branch %#x target mismatch" % site)
    for site, want in CALLS:
        if _rel_target(elf, site, 5) != want:
            errors.append("call %#x target mismatch" % site)
    try:
        census = rec["caller_census"]
        for opcode, key in ((0xE8, "direct_sites"),
                            (0xE9, "tail_jump_sites")):
            found = set(elf.text_scan(opcode, FUNC_START))
            want = set(int(s, 16) for s in census[key])
            if opcode == 0xE8:
                want.add(0x514BE97)  # the recursive self-call
            if found != want:
                errors.append("caller %s census mismatch: found %s, "
                              "want %s" % (key, sorted(hex(v) for v in found),
                                           sorted(hex(v) for v in want)))
    except ValueError as exc:
        errors.append("census scan failed: %s" % exc)
    try:
        with open(os.path.join(packet_dir, "window.objdump.txt")) as f:
            excerpt = f.read()
    except OSError as exc:
        return errors + ["cannot read window.objdump.txt: %s" % exc]
    checked = 0
    for line in excerpt.splitlines():
        m = _EXCERPT_LINE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if not (FUNC_START <= addr < FUNC_END + func["padding_bytes"]):
            continue
        raw = bytes(int(b, 16) for b in m.group(2).split())
        if elf.read(addr, len(raw)) != raw:
            errors.append("excerpt bytes mismatch at %#x" % addr)
        checked += 1
    if checked == 0:
        errors.append("no excerpt lines checked")
    try:
        with open(os.path.join(packet_dir, "frames.txt")) as f:
            frames = f.read()
    except OSError as exc:
        return errors + ["cannot read frames.txt: %s" % exc]
    want = "pc=%016x..%016x" % (FUNC_START, FUNC_END)
    if want not in frames:
        errors.append("function FDE line missing from frames.txt")
    try:
        with open(os.path.join(packet_dir, "MANIFEST.sha256")) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                digest, name = line.split(None, 1)
                with open(os.path.join(packet_dir, name.strip()),
                          "rb") as pf:
                    actual = hashlib.sha256(pf.read()).hexdigest()
                if actual != digest:
                    errors.append("MANIFEST mismatch for %s" % name)
    except OSError as exc:
        errors.append("cannot verify MANIFEST: %s" % exc)
    return errors


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary",
                    default=os.path.join("artifacts", "node", "94",
                                         "hl-node"))
    ap.add_argument("--packet",
                    default=os.path.join("research", "work-items",
                                         "RE-001-recursive-teardown-94"))
    args = ap.parse_args(argv)
    errors = check_packet(args.packet, args.binary)
    if errors:
        for err in errors:
            print("FAIL: %s" % err)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
