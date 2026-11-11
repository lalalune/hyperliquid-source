#!/usr/bin/env python3
"""Claim anchors for `CompactionJobStats::Reset` 0x61bd590..0x61bd60f.

One anchor per instruction, each carrying its byte span and the recovered claim.
`verify.py` re-decodes every anchor's bytes with Capstone (exactly one instruction,
the same length, the same mnemonic family) and matches the anchor text against the
committed excerpt, so an anchor span is a real instruction boundary and the claims
cannot drift from the artifact.

Run `python3 semantics.py` to rewrite `semantics.tsv`.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

PACKET = Path(__file__).resolve().parent
START = 0x61BD590
END = 0x61BD60F

# (address, byte length, instruction text as the excerpt prints it, claim)
ANCHORS = [
    (0x61BD590, 4, "endbr64",
     "CET entry pad; no register or memory effect."),
    (0x61BD594, 2, "xor %eax,%eax",
     "eax = 0 - the source of the `mov %ax,0x48(%rdi)` two-byte store."),
    (0x61BD596, 4, "pxor %xmm0,%xmm0",
     "xmm0 = 0 - one 128-bit zero register reused by all twelve `movups` stores."),
    (0x61BD59A, 8, "movq $0x0,0x40(%rdi)",
     "the 8-byte word at +0x40 is cleared."),
    (0x61BD5A2, 4, "mov %ax,0x48(%rdi)",
     "the 2-byte word at +0x48 is cleared; it is deliberately narrower than the "
     "`movups` strides, so the field at +0x4a is not touched."),
    (0x61BD5A6, 7, "mov 0xc0(%rdi),%rax",
     "rax = the pointer stored at +0xc0 - the data pointer of the first "
     "`std::string` member. This is the first of the body's two argument-dependent "
     "addresses: the write targets depend on the object's own contents."),
    (0x61BD5AD, 11, "movq $0x0,0xc8(%rdi)",
     "the 8-byte word at +0xc8 is cleared - the string's *size* field; the pointer "
     "at +0xc0 and the capacity at +0xd0 are preserved, which is `std::string::clear()`."),
    (0x61BD5B8, 3, "movups %xmm0,(%rdi)",
     "the 16 bytes at +0x00 are cleared (xmm0 is zero; `movups` has no disp because "
     "the displacement is 0)."),
    (0x61BD5BB, 4, "movups %xmm0,0x10(%rdi)",
     "the 16 bytes at +0x10 are cleared."),
    (0x61BD5BF, 4, "movups %xmm0,0x20(%rdi)",
     "the 16 bytes at +0x20 are cleared."),
    (0x61BD5C3, 4, "movups %xmm0,0x30(%rdi)",
     "the 16 bytes at +0x30 are cleared."),
    (0x61BD5C7, 4, "movups %xmm0,0x50(%rdi)",
     "the 16 bytes at +0x50 are cleared - the first field after the two-byte store, "
     "confirming +0x4a..+0x4f is skipped on purpose."),
    (0x61BD5CB, 4, "movups %xmm0,0x60(%rdi)",
     "the 16 bytes at +0x60 are cleared."),
    (0x61BD5CF, 4, "movups %xmm0,0x70(%rdi)",
     "the 16 bytes at +0x70 are cleared."),
    (0x61BD5D3, 7, "movups %xmm0,0x80(%rdi)",
     "the 16 bytes at +0x80 are cleared."),
    (0x61BD5DA, 7, "movups %xmm0,0x90(%rdi)",
     "the 16 bytes at +0x90 are cleared."),
    (0x61BD5E1, 7, "movups %xmm0,0xa0(%rdi)",
     "the 16 bytes at +0xa0 are cleared."),
    (0x61BD5E8, 7, "movups %xmm0,0xb0(%rdi)",
     "the 16 bytes at +0xb0 are cleared - the last field before the first string."),
    (0x61BD5EF, 3, "movb $0x0,(%rax)",
     "the first byte of the first string's buffer is set to NUL. The buffer is the "
     "one the object pointed at, so `clear()` leaves a terminated empty string; the "
     "buffer itself, at whatever address, is not part of the object."),
    (0x61BD5F2, 7, "mov 0xe0(%rdi),%rax",
     "rax = the pointer stored at +0xe0 - the second `std::string`'s data pointer."),
    (0x61BD5F9, 11, "movq $0x0,0xe8(%rdi)",
     "the 8-byte size word at +0xe8 is cleared; +0xe0 and +0xf0 are preserved."),
    (0x61BD604, 3, "movb $0x0,(%rax)",
     "NUL at the start of the second string's buffer."),
    (0x61BD607, 7, "movups %xmm0,0x100(%rdi)",
     "the last 16-byte field at +0x100 is cleared. The window ends at +0x10f, so "
     "the object's tail beyond +0x110 is not touched."),
    (0x61BD60E, 1, "ret",
     "return; there is no return value - the method's result is the mutation."),
]


def normalized(text):
    return " ".join(text.split())


def claim_anchors():
    return ANCHORS


def check(excerpt_text):
    """Re-decode each anchor from the artifact; return the number of anchors."""
    root = PACKET.parents[2]            # PACKET = <root>/research/work-items/<packet>
    binary = root / "artifacts" / "node" / "115" / "hl-node"
    data = binary.read_bytes()
    segs = []
    for line in subprocess.check_output(["readelf", "-lW", str(binary)]).decode().splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            segs.append((int(p[2], 16), int(p[1], 16), int(p[4], 16)))

    def off(va):
        for v, o, f in segs:
            if v <= va < v + f:
                return o + (va - v)
        raise AssertionError(f"{va:#x} not in a LOAD segment")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    lines = {}
    for line in excerpt_text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$", line)
        if m:
            lines[int(m.group(1), 16)] = normalized(m.group(2))
    n = 0
    for a, size, text, _ in claim_anchors():
        raw = data[off(a):off(a) + size]
        decoded = list(md.disasm(raw, a))
        assert len(decoded) == 1, f"{a:#x}: {len(decoded)} instructions in {size} bytes"
        ins = decoded[0]
        assert ins.size == size, f"{a:#x}: capstone size {ins.size} vs anchor {size}"
        mn = normalized(text).split()[0]
        # objdump prints a store of an 8-byte immediate as `movq $0x0,mem` but
        # a 4-byte one as `mov $0x0,mem`; Capstone reports both as `mov`.
        same = {"movzbl": "movzx", "movzwl": "movzx", "movzbq": "movzx",
                "movsbl": "movsx", "movslq": "movsxd", "sal": "shl",
                "movabs": "mov", "movq": "mov", "movl": "mov",
                "movw": "mov", "movb": "mov"}.get(mn, mn)
        assert ins.mnemonic.startswith("nop") or ins.mnemonic == same, \
            f"{a:#x}: capstone {ins.mnemonic} vs anchor {mn}"
        assert a in lines, f"{a:#x} missing from the excerpt"
        assert lines[a] == normalized(text), \
            f"{a:#x}: excerpt {lines[a]!r} vs anchor {normalized(text)!r}"
        n += 1
    # the anchors are contiguous and cover the whole window
    assert ANCHORS[0][0] == START and ANCHORS[-1][0] + ANCHORS[-1][1] == END
    for (a, size, _, _), (b, _, _, _) in zip(ANCHORS, ANCHORS[1:]):
        assert a + size == b, f"gap or overlap at {a:#x}"
    return n


def main():
    rows = ["address\tsize\tinstruction\tclaim"]
    for a, size, text, claim in claim_anchors():
        rows.append(f"{a:#x}\t{size}\t{normalized(text)}\t{claim}")
    (PACKET / "semantics.tsv").write_text("\n".join(rows) + "\n")
    print(f"wrote semantics.tsv ({len(ANCHORS)} anchors, "
          f"{sum(s for _, s, _, _ in ANCHORS)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
