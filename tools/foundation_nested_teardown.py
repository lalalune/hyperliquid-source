#!/usr/bin/env python3
"""RE-001: nested teardown (function 0x514bee0, node #94).

The target function tears down a 0x58-byte node and, nested inside
it, a list of 0x30-byte items. Read directly from the bytes in
research/work-items/RE-001-nested-teardown-94/window.objdump.txt
(and the callee excerpt callee.objdump.txt):

- A null input returns immediately (test rdi, rdi; je to the ret
  at 0x514bf50); nothing is pushed, nothing is freed.
- Otherwise the frame pushes r12, rbp, rbx; rbp and r12 both start
  as the input node. The loop body, in order, is:
  1. Recursively call this same function on the link at
     [current + 0x18] (call at 0x514bef3; a null link returns at
     once, so the recursion always terminates at the leaves).
  2. Load the items head from [first + 0x38] -- where "first" is
     the r12 register, which the loop body never updates (see the
     quirk note below) -- and save the next link from
     [current + 0x10] (loaded at 0x514befd, before any free below,
     so the walk survives the frees).
  3. Walk the items list: for each item, first tear down the
     item's own +0x18 chain through the callee at 0x514b690
     (call at 0x514bf14; that callee is claimed in-tree by
     research/work-items/RE-001-recursive-destructor-94, and is
     reused here, not re-claimed: per item it destroys
     [item + 0x18] recursively, deletes the item with size 0x30,
     and advances to [item + 0x10]), then delete the item itself
     with size 0x30 (call at 0x514bf25) and advance to the saved
     [item + 0x10]. A null items head skips the walk (je at
     0x514bf04 to 0x514bf2f).
  4. Delete the node in r12 with size 0x58 (call at 0x514bf37).
  5. Advance to the saved next link; stop when it is null
     (jne at 0x514bf3f back to 0x514beec).
- The function returns void, preserves r12, rbp and rbx, and keeps
  the stack balanced (pushes restored at 0x514bf41..0x514bf43
  before ret at 0x514bf45). It has no stack canary.

QUIRK -- READ THIS BEFORE REUSING THE MODEL: the loop body updates
rbp (the current node) at 0x514befd but never updates r12 (the
node whose items list is read at 0x514bef8 and which is deleted
at 0x514bf37). So, literally, on every iteration after the first:

- the items head is re-read from the FIRST node's +0x38 slot,
  which by then has already been deleted (a freed-slot read);
- the FIRST node is deleted again with size 0x58 (a repeat free);
- the items walked in the first iteration are walked again, so
  their +0x18 chains are torn down again and the items are freed
  again;
- the subsequent nodes themselves (second, third, ...) are never
  deleted by this loop -- only their +0x18 subtrees are torn down
  (step 1 runs for each of them).

Whether any real execution ever presents a +0x10 chain longer than
one node is NOT established by this packet, and no claim is made
that the multi-node path is safe: with a non-clearing allocator
the freed slots still hold their old values, so the re-walk
follows the same pointers, but the repeat frees are repeat frees.
The model below reproduces the register flow faithfully, marking
freed-slot reads and repeat frees explicitly, instead of
smoothing the loop into the "sane" version (which would delete
each node once and read each node's own items). For a single-node
chain the quirk never triggers and the behavior is the clean one:
child subtree, then items, then the node itself, each exactly
once.

The model takes the post-deref values as its input: a node is an
``OuterNode`` whose ``child`` and ``next`` links are already
resolved and whose items list is a chain of ``ItemNode`` objects
with their own ``child``/``next`` links resolved. The walk, the
recursion, the callee rule and the node deletes are simulated;
the raw field loads themselves are recorded in records.json and
verified against the raw excerpts by :func:`check_packet`,
because the model has no memory image. No role is claimed for the
qwords at node + 0x0 or node + 0x8, which the function never
reads, and no source-level type name is claimed for the node, the
items, or either link. The callee at 0x514b690 is not re-claimed
here; its rule is restated only so the inner walk is complete.

Stdlib only. ``check_packet`` verifies a packet directory against
a node #94 binary; it returns a list of error strings (empty =
pass).
"""

import hashlib
import json
import os
import re
import struct
import sys

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
FUNC_START = 0x514BEE0
FUNC_END = 0x514BF51
CALLEE_START = 0x514B690
CALLEE_END = 0x514B6C1
OUTER_SIZE = 0x58
ITEM_SIZE = 0x30
MASK64 = (1 << 64) - 1

# (address, length, target) for every branch/call in the function,
# re-derived from the raw encodings, not from objdump's annotations.
BRANCHES = [
    (0x514BEE3, 2, 0x514BF50),  # je: null input -> ret (no frame)
    (0x514BF04, 2, 0x514BF2F),  # je: null items head -> skip walk
    (0x514BF2D, 2, 0x514BF10),  # jne: next item -> inner loop
    (0x514BF3F, 2, 0x514BEEC),  # jne: next outer link -> outer loop
]
CALLS = [
    (0x514BEF3, 0x514BEE0),  # recursive call on [current + 0x18]
    (0x514BF14, 0x514B690),  # callee on [item + 0x18]
    (0x514BF25, 0x5660440),  # operator delete: item, size 0x30
    (0x514BF37, 0x5660440),  # operator delete: first node, 0x58
]
CALLEE_BRANCHES = [
    (0x514B693, 2, 0x514B6C0),  # je: null input -> ret (no frame)
    (0x514B6B6, 2, 0x514B699),  # jne: next item -> callee loop
]
CALLEE_CALLS = [
    (0x514B69D, 0x514B690),  # recursive call on [item + 0x18]
    (0x514B6AE, 0x5660440),  # operator delete: item, size 0x30
]

_EXCERPT_LINE = re.compile(
    r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(.*)$")


class ItemNode:
    """One 0x30-byte item, with links already resolved.

    ``child`` is the node at +0x18, ``next`` the node at +0x10.
    """

    __slots__ = ("label", "child", "next")

    def __init__(self, label, child=None, next=None):
        self.label = label
        self.child = child
        self.next = next


class OuterNode:
    """One 0x58-byte node, with links already resolved.

    ``child`` is the node at +0x18, ``next`` the node at +0x10,
    ``items`` the head of the +0x38 items list (or None).
    """

    __slots__ = ("label", "child", "next", "items")

    def __init__(self, label, child=None, next=None, items=None):
        self.label = label
        self.child = child
        self.next = next
        self.items = items


def _teardown_item(item, events, freed):
    """The 0x514b690 rule, as reused by the inner walk.

    For each item in the +0x10 chain, in order: recursively tear
    down the +0x18 link, delete the item with size 0x30, advance
    to the saved [item + 0x10]. A null head yields no events.
    ``freed`` is the set of labels already deleted by the caller;
    reads and frees of such labels are marked, not hidden.
    """
    cur = item
    while cur is not None:
        nxt = cur.next
        if cur.label in freed:
            events.append(("read_freed", cur.label, "+0x10/+0x18"))
        if cur.child is not None:
            _teardown_item(cur.child, events, freed)
        if cur.label in freed:
            events.append(("free_again", "item", cur.label, ITEM_SIZE))
        else:
            events.append(("free", "item", cur.label, ITEM_SIZE))
            freed.add(cur.label)
        cur = nxt


def teardown(node, events=None, freed=None):
    """Simulate 0x514bee0 faithfully, including the r12 quirk.

    Each event is ("free", kind, label, size), ("free_again",
    kind, label, size) for a repeat free of an already-deleted
    label, or ("read_freed", label, field) for a field read from
    an already-deleted node. A null input yields no events. The
    returned list is the ordered observable effect sequence; the
    quirk markers are part of the claim, not noise: for a
    single-node chain no marker ever appears.
    """
    if events is None:
        events = []
    if freed is None:
        freed = set()
    if node is None:
        return events
    first = node
    cur = node
    while cur is not None:
        # Step 1: recurse on [current + 0x18] (self-call).
        if cur.child is not None:
            teardown(cur.child, events, freed)
        # Step 2: items head from [first + 0x38] (r12, invariant),
        # next link saved from [current + 0x10] (rbp, advancing).
        if first.label in freed:
            events.append(("read_freed", first.label, "+0x38"))
        items = first.items
        nxt = cur.next
        # Step 3: inner walk over the items list.
        item = items
        while item is not None:
            item_nxt = item.next
            if item.label in freed:
                events.append(("read_freed", item.label, "+0x10/+0x18"))
            if item.child is not None:
                _teardown_item(item.child, events, freed)
            if item.label in freed:
                events.append(("free_again", "item", item.label,
                               ITEM_SIZE))
            else:
                events.append(("free", "item", item.label, ITEM_SIZE))
                freed.add(item.label)
            item = item_nxt
        # Step 4: delete the node in r12 (always the first node).
        if first.label in freed:
            events.append(("free_again", "outer", first.label,
                           OUTER_SIZE))
        else:
            events.append(("free", "outer", first.label, OUTER_SIZE))
            freed.add(first.label)
        # Step 5: advance to the saved next link.
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

    def carve(self, start, end):
        return self.data[self.va_to_offset(start):self.va_to_offset(end)]

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

    def branch_target(self, site, length):
        off = self.va_to_offset(site)
        if length == 2:
            (rel,) = struct.unpack_from("<b", self.data, off + 1)
        elif length == 5:
            (rel,) = struct.unpack_from("<i", self.data, off + 1)
        else:
            raise ValueError("unsupported branch length %d" % length)
        return site + length + rel


def _excerpt_bytes(path):
    """Map excerpt address -> raw bytes from the objdump text."""
    out = {}
    with open(path) as f:
        for line in f:
            m = _EXCERPT_LINE.match(line.rstrip("\n"))
            if m:
                addr = int(m.group(1), 16)
                out[addr] = bytes(int(b, 16)
                                  for b in m.group(2).split())
    return out


def check_packet(packet_dir, binary_path):
    """Verify the packet's records against the binary.

    Returns a list of error strings (empty = pass).
    """
    errors = []
    with open(os.path.join(packet_dir, "records.json")) as f:
        records = json.load(f)
    with open(binary_path, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        errors.append("target digest mismatch")
        return errors
    elf = Elf(data)
    func = records["function"]
    carved = elf.carve(FUNC_START, FUNC_END)
    if hashlib.sha256(carved).hexdigest() != func["sha256"]:
        errors.append("function carve SHA mismatch")
    if len(carved) != func["bytes"]:
        errors.append("function byte length mismatch")
    pad = elf.carve(FUNC_END, int(records["next_fde_start"], 16))
    if pad != b"\xcc" * func["padding_bytes"]:
        errors.append("int3 padding mismatch")
    callee = records["callee"]
    carved_c = elf.carve(CALLEE_START, CALLEE_END)
    if hashlib.sha256(carved_c).hexdigest() != callee["sha256"]:
        errors.append("callee carve SHA mismatch")
    pad_c = elf.carve(CALLEE_END, int(callee["next_fde_start"], 16))
    if pad_c != b"\xcc" * callee["padding_bytes"]:
        errors.append("callee int3 padding mismatch")
    for site, length, target in BRANCHES:
        if elf.branch_target(site, length) != target:
            errors.append("branch at %#x does not reach %#x"
                          % (site, target))
    for site, target in CALLS:
        if elf.branch_target(site, 5) != target:
            errors.append("call at %#x does not reach %#x"
                          % (site, target))
    for site, length, target in CALLEE_BRANCHES:
        if elf.branch_target(site, length) != target:
            errors.append("callee branch at %#x does not reach %#x"
                          % (site, target))
    for site, target in CALLEE_CALLS:
        if elf.branch_target(site, 5) != target:
            errors.append("callee call at %#x does not reach %#x"
                          % (site, target))
    # Caller census: a full .text scan (section-header mapping,
    # as in the sibling packets) must find exactly the recorded
    # direct sites plus the recursive self-call site, and no tail
    # jumps at all.
    census = records["caller_census"]
    for opcode, key, extra in (
            (0xE8, "direct_sites",
             [int(census["self_call_site"], 16)]),
            (0xE9, "tail_jump_sites", [])):
        found = set(elf.text_scan(opcode, FUNC_START))
        want = set(int(s, 16) for s in census[key]) | set(extra)
        if found != want:
            errors.append("caller %s census mismatch: found %s, "
                          "want %s" % (key,
                                       sorted(hex(v) for v in found),
                                       sorted(hex(v) for v in want)))
    # Every excerpt line's bytes must match the binary.
    for name in ("window.objdump.txt", "callee.objdump.txt"):
        for addr, raw in _excerpt_bytes(
                os.path.join(packet_dir, name)).items():
            if elf.carve(addr, addr + len(raw)) != raw:
                errors.append("excerpt %s line %#x bytes mismatch"
                              % (name, addr))
                break
    # FDE lines must be present in frames.txt.
    with open(os.path.join(packet_dir, "frames.txt")) as f:
        frames = f.read()
    for start, end in ((FUNC_START, FUNC_END),
                       (CALLEE_START, CALLEE_END)):
        if "pc=%016x..%016x" % (start, end) not in frames:
            errors.append("FDE line missing for %#x" % start)
    # Manifest hashes must match the shipped packet files.
    manifest = {}
    with open(os.path.join(packet_dir, "MANIFEST.sha256")) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2:
                manifest[parts[1]] = parts[0]
    for name, digest in manifest.items():
        path = os.path.join(packet_dir, name)
        if not os.path.exists(path):
            errors.append("manifest file missing: %s" % name)
            continue
        with open(path, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != digest:
                errors.append("manifest hash mismatch: %s" % name)
    return errors


if __name__ == "__main__":
    print("teardown model import OK; run the tests for behavior")
