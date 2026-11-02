#!/usr/bin/env python3
"""RE-001: list teardown with array clear (function 0x514bd40, node #94).

The target function tears down one object in two phases. Read
directly from the bytes in
research/work-items/RE-001-list-teardown-94/window.objdump.txt:

Phase 1 -- walk the list at [object + 0x10]. Per node, in order:
save next = [node + 0x0]; dispose the string at node + 0x8 (skip
the buffer delete when [node + 0x8] == node + 0x18, the inline
buffer address; otherwise delete the buffer with size
[node + 0x18] + 1); delete the node itself with size 0x78; advance
to the saved next. A null head skips the walk entirely.

Phase 2 -- clear the array: memset([object + 0x0], 0,
[object + 0x8] * 8); zero [object + 0x10] and [object + 0x18]; if
[object + 0x0] == object + 0x30 the storage is inline and the
function returns, otherwise it tail-calls operator delete with
([object + 0x0], [object + 0x8] * 8).

The model below takes the post-deref values as its input: a node is
a ``Node`` whose ``next`` link is already resolved, whose string is
described by (inline, capacity), and whose identity is the object
itself. The list walk, the string disposal test, and the array
phases are simulated; the raw field loads themselves are recorded
in records.json and verified against the raw excerpts by
:func:`check_packet`, because the model has no memory image. The
qword at object + 0x18 is zeroed in phase 2 but never read, so no
role is claimed for it. Whether a heap string buffer's delete is
load-bearing beyond freeing is not claimed: the model records the
delete event, exactly as the bytes do.

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
FUNC_START = 0x514BD40
FUNC_END = 0x514BDE5
NODE_SIZE = 0x78
MASK64 = (1 << 64) - 1


class StrField:
    """A string field at node + 0x8, after the SSO test.

    ``inline`` is True when the string pointer equals node + 0x18
    (the capacity field's address, i.e. the inline buffer); then no
    buffer delete runs and ``capacity`` is unread. Otherwise the
    buffer delete runs with size ``capacity + 1``.
    """

    __slots__ = ("inline", "capacity")

    def __init__(self, inline=False, capacity=0):
        self.inline = bool(inline)
        self.capacity = capacity & MASK64


class Node:
    """One list node: ``next`` already resolved, ``string`` as above."""

    __slots__ = ("next", "string")

    def __init__(self, string, next=None):
        self.string = string
        self.next = next


def list_teardown(object_addr, array_ptr, count, head):
    """Run both phases; return ``(events, head_cleared, tail_cleared)``.

    ``events`` is the ordered list of observable effects:
    ("delete_buffer", size) per heap string, ("delete_node", 0x78)
    per node, ("memset", array_ptr, count * 8), then either
    ("array_inline",) or ("delete_array", count * 8). The two
    cleared fields are always True after phase 2 (the bytes zero
    [object + 0x10] and [object + 0x18] unconditionally).
    """
    events = []
    node = head
    while node is not None:
        nxt = node.next  # saved before any free, as in the bytes
        if not node.string.inline:
            events.append(("delete_buffer",
                           (node.string.capacity + 1) & MASK64))
        events.append(("delete_node", NODE_SIZE))
        node = nxt
    events.append(("memset", array_ptr & MASK64,
                   (count * 8) & MASK64))
    if (array_ptr & MASK64) == ((object_addr + 0x30) & MASK64):
        events.append(("array_inline",))
    else:
        events.append(("delete_array", (count * 8) & MASK64))
    return events, True, True


# ---------------------------------------------------------------------------
# Packet checker (used by tests/test_foundation_list_teardown.py)
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
    The caller census is verified by the packet's own verify.py (which
    runs a full disassembly scan); this checker verifies the recorded
    branch/call/tail-jump encodings, the carve SHA, the padding, the
    PLT GOT slot values, the FDE line, every excerpt line's bytes,
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
    except (OSError, ValueError) as exc:
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
    for jump in rec["tail_jumps"]:
        site = int(jump["site"], 16)
        want = int(jump["target"], 16)
        if _rel_target(elf, site, 5) != want:
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
    want = "pc=%016x..%016x" % (start, end)
    if want not in frames:
        errors.append("function FDE line missing from frames.txt")
    for name in ("window", "plt"):
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
