#!/usr/bin/env python3
"""Claim anchors for `CompactionPicker::AreFilesInCompaction` 0x5d9a390..0x5d9a3cf.

One anchor per instruction, each carrying its byte span and the recovered claim.
`verify.py` re-decodes every anchor's bytes with Capstone (one instruction, the
same length, the same mnemonic) and matches the anchor text against the committed
excerpt, so an anchor span is a real instruction boundary and the claims cannot
drift from the artifact.

Run `python3 semantics.py` to rewrite `semantics.tsv`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
START = 0x5D9A390
END = 0x5D9A3CF

# (address, byte length, instruction text as the excerpt prints it, claim)
ANCHORS = [
    (0x5D9A390, 4, "endbr64",
     "CET entry pad; no register or memory effect."),
    (0x5D9A394, 4, "mov 0x8(%rsi),%rax",
     "rax = files.end - the second 8-byte field of the vector header in rsi."),
    (0x5D9A398, 3, "mov (%rsi),%rcx",
     "rcx = files.begin - the first field; the header itself is not read again."),
    (0x5D9A39B, 3, "mov %rax,%rsi",
     "the end pointer moves into rsi because rsi is about to be turned into the count."),
    (0x5D9A39E, 3, "sub %rcx,%rsi",
     "rsi = end - begin, i.e. the vector's byte size."),
    (0x5D9A3A1, 4, "sar $0x3,%rsi",
     "rsi = n = byte size / 8 = the element count. A signed shift; see the "
     "precondition in the model (end >= begin, so the count is non-negative)."),
    (0x5D9A3A5, 3, "cmp %rcx,%rax",
     "compare end with begin to answer the empty vector from the header alone."),
    (0x5D9A3A8, 2, "je 5d9a3cb",
     "end == begin: jump to the empty answer (edx = 0) without touching an element."),
    (0x5D9A3AA, 2, "xor %eax,%eax",
     "i = 0 - the loop counter starts at the low 32 bits and zeroes rax."),
    (0x5D9A3AC, 2, "jmp 5d9a3b9",
     "enter the loop at the element load: a rotated do-while, so the increment and "
     "the bound test live at the back edge."),
    (0x5D9A3AE, 2, "xchg %ax,%ax",
     "a 2-byte padding nop; it is the loop's alignment and has no effect."),
    (0x5D9A3B0, 4, "add $0x1,%rax",
     "i += 1 - the back edge, reached only when the current element is not flagged."),
    (0x5D9A3B4, 3, "cmp %rsi,%rax",
     "compare i with n."),
    (0x5D9A3B7, 2, "jae 5d9a3c8",
     "unsigned i >= n: leave the loop through the shared exit with the last flag "
     "byte (0, since the loop only continues past a zero flag) in edx."),
    (0x5D9A3B9, 4, "mov (%rcx,%rax,8),%rdx",
     "rdx = files[i] - the element pointer; the scale 8 is an addressing-mode "
     "property, not a second multiply of the pre-scaled count."),
    (0x5D9A3BD, 7, "movzbl 0xb4(%rdx),%edx",
     "edx = zero-extended byte at +0xb4 of the element - the being_compacted flag "
     "of FileMetaData in this build."),
    (0x5D9A3C4, 2, "test %dl,%dl",
     "the only test of the flag; the byte value itself is what gets returned."),
    (0x5D9A3C6, 2, "je 5d9a3b0",
     "flag == 0: keep walking."),
    (0x5D9A3C8, 2, "mov %edx,%eax",
     "the shared exit: whatever is in edx becomes the returned byte (the flag, or 0)."),
    (0x5D9A3CA, 1, "ret",
     "return; the value leaves in al/eax, zero-extended by the movzbl above."),
    (0x5D9A3CB, 2, "xor %edx,%edx",
     "the empty-vector path: edx = 0 so the shared exit answers false."),
    (0x5D9A3CD, 2, "jmp 5d9a3c8",
     "join the shared exit - one return site serves both the empty and the "
     "not-found cases."),
]


def normalized(text):
    return " ".join(text.split())


def claim_anchors():
    """(address, size, text, claim) rows, validated for contiguity and coverage."""
    addrs = [a for a, _, _, _ in ANCHORS]
    sizes = [s for _, s, _, _ in ANCHORS]
    assert addrs[0] == START and addrs[-1] + sizes[-1] == END, "anchors miss the window"
    for (a, s, _, _), b in zip(ANCHORS, addrs[1:]):
        assert a + s == b, f"gap or overlap at {a:#x}"
    assert sum(sizes) == END - START, sum(sizes)
    return ANCHORS


def check(excerpt_text):
    """Every anchor must be that one instruction, as the excerpt prints it."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    import subprocess

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
        # objdump spells some nops differently from Capstone; compare the mnemonic
        # family, not the spelling, and compare the operand text verbatim.
        mn = normalized(text).split()[0]
        # Capstone folds the AT&T size/zx suffixes into the base mnemonic.
        same = {"movzbl": "movzx", "movzwl": "movzx", "movzbq": "movzx",
                "movsbl": "movsx", "movslq": "movsxd", "sal": "shl",
                "cltq": "cdqe", "cqto": "cqo"}.get(mn, mn)
        assert ins.mnemonic.startswith("nop") or ins.mnemonic in ("endbr64", same), \
            f"{a:#x}: capstone {ins.mnemonic} vs anchor {mn}"
        assert a in lines, f"{a:#x} missing from the excerpt"
        assert lines[a] == normalized(text), \
            f"{a:#x}: excerpt {lines[a]!r} vs anchor {normalized(text)!r}"
        n += 1
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
