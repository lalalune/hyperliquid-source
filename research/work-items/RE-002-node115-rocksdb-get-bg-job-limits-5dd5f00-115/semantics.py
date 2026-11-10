#!/usr/bin/env python3
"""Claim anchors for `GetBGJobLimits` 0x5dd5f00 (node #115).

Every instruction of the 91-byte window is one claim: the bytes are read from
the artifact, the mnemonic text from the committed objdump excerpt, and
`verify.py` re-decodes each row from the artifact independently.

Run `python3 semantics.py --write` to regenerate `semantics.tsv`.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-get-bg-job-limits-5dd5f00-115")
START = 0x5DD5F00
END = 0x5DD5F5B

#: (claim, va, size, note) - one row per instruction, in address order
ANCHORS = (
    ("function entry", 0x5DD5F00, 4,
     "the FDE begins exactly here and the body opens with an endbr64 CET "
     "landing pad; seven int3 bytes sit immediately below the entry, so this is "
     "a real function start"),
    ("the flush argument is tested for positivity", 0x5DD5F04, 2,
     "test %edi,%edi sets the flags the cmovg below reads"),
    ("the default flush count is one", 0x5DD5F06, 5,
     "mov $0x1,%eax seeds the clamped value"),
    ("a positive flush count keeps its value", 0x5DD5F0B, 3,
     "cmovg %edi,%eax: eax = flushes when flushes > 0, otherwise the seeded 1"),
    ("the kDefault sentinel is -1", 0x5DD5F0E, 3,
     "cmp $0xffffffff,%edi compares the flush argument with -1"),
    ("the derivation is entered only for kDefault flushes", 0x5DD5F11, 2,
     "je 0x5dd5f38 splits the flow; the same path is re-entered from 0x5dd5f40"),
    ("the compaction argument is tested for positivity", 0x5DD5F13, 2,
     "test %esi,%esi"),
    ("the default compaction count is one", 0x5DD5F15, 5, "mov $0x1,%edx"),
    ("a positive compaction count keeps its value", 0x5DD5F1A, 3,
     "cmovg %esi,%edx"),
    ("the fourth argument is the multi-db flag", 0x5DD5F1D, 2,
     "test %cl,%cl: a byte argument, so the ABI passes it in the low byte of "
     "the fourth register"),
    ("the forced compaction count is one", 0x5DD5F1F, 5, "mov $0x1,%ecx"),
    ("the flush count is zero-extended, not recomputed", 0x5DD5F24, 2,
     "mov %eax,%eax: a 32-bit self-move that zero-extends eax into rax and, "
     "like every mov, leaves the flags alone - the cmove below still sees the "
     "multi-db flag from 0x5dd5f1d"),
    ("a single-db deployment is forced to one compaction", 0x5DD5F26, 3,
     "cmove %ecx,%edx: when multi_db is false edx becomes 1 whatever the rules "
     "above produced"),
    ("the second field is placed in the high dword", 0x5DD5F29, 4,
     "shl $0x20,%rdx moves the compaction count to bits 63..32"),
    ("the return packs both fields into one register", 0x5DD5F2D, 3,
     "or %rdx,%rax: rax[31:0] = flushes and rax[63:32] = compactions - the "
     "psABI packing of std::pair<int,int> into a single INTEGER eightbyte"),
    ("the packed pair is returned", 0x5DD5F30, 1, "ret"),
    ("padding after the return", 0x5DD5F31, 7,
     "nopl 0x0(%rax): a 7-byte padding nop, so the fast path cannot fall "
     "through into the derivation branch"),
    ("the derived flush count starts at one", 0x5DD5F38, 5, "mov $0x1,%eax"),
    ("both counts must be kDefault to derive", 0x5DD5F3D, 3,
     "cmp $0xffffffff,%esi: an explicit compaction count is required too"),
    ("an explicit compaction count skips the derivation", 0x5DD5F40, 2,
     "jne 0x5dd5f13 rejoins the explicit path, where flushes is already 1"),
    ("the job budget feeds the split", 0x5DD5F42, 2, "mov %edx,%esi"),
    ("a quarter of the budget becomes flushes", 0x5DD5F44, 3,
     "sar $0x2,%esi: an arithmetic shift, i.e. division by 4 rounding toward "
     "minus infinity"),
    ("the quarter only applies above seven jobs", 0x5DD5F47, 3,
     "cmp $0x7,%edx: at most seven jobs keeps a single flush"),
    ("the derived flush count is selected", 0x5DD5F4A, 3,
     "cmovg %esi,%eax: flushes = jobs/4 when jobs > 7, else 1"),
    ("the fallback compaction count is one", 0x5DD5F4D, 5, "mov $0x1,%esi"),
    ("the rest of the budget becomes compactions", 0x5DD5F52, 2,
     "sub %eax,%edx: edx = jobs - flushes"),
    ("the remainder is tested", 0x5DD5F54, 2, "test %edx,%edx"),
    ("a non-positive remainder becomes one compaction", 0x5DD5F56, 3,
     "cmovle %esi,%edx: a signed compare, so a remainder that wrapped negative "
     "is clamped to 1"),
    ("the derived compactions still obey the multi-db rule", 0x5DD5F59, 2,
     "jmp 0x5dd5f1d: the derived pair rejoins the multi-db test"),
)


def _stream(path=None):
    sys.path.insert(0, str(ROOT))
    from tools.rocksdb_get_bg_job_limits_5dd5f00_115 import instruction_stream
    return instruction_stream(path)


def instruction_text(path=None):
    """{va: 'mnemonic op_str'} straight from the decoded instruction stream."""
    return {i.addr: (i.mnemonic + (" " + i.op_str if i.op_str else "")).strip()
            for i in _stream(path)}



def window_bytes(path=None):
    """The 91 artifact bytes of the window, keyed by virtual address."""
    import hashlib
    import subprocess

    binary = ROOT / "artifacts" / "node" / "115" / "hl-node"
    data = binary.read_bytes()
    segs = []
    for line in subprocess.check_output(["readelf", "-lW", str(binary)]).decode().splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            segs.append((int(p[2], 16), int(p[1], 16), int(p[4], 16)))
    off = None
    for v, o, f in segs:
        if v <= START < v + f:
            off = o + (START - v)
    assert off is not None
    body = data[off:off + (END - START)]
    return {START + k: body[k:k + 1] for k in range(len(body))}, hashlib.sha256(body).hexdigest()


def rows(path=None):
    text = instruction_text(path)
    body, _ = window_bytes(path)
    sizes = {i.addr: len(i.raw) for i in _stream(path)}
    out = []
    for claim, va, size, note in ANCHORS:
        assert sizes[va] == size, (
            f"anchor {claim!r} at {va:#x} declares {size} bytes but the "
            f"instruction is {sizes[va]}")

        raw = b"".join(body[va + k] for k in range(size))
        out.append({
            "claim": claim,
            "va": va,
            "size": size,
            "bytes": raw.hex(),
            "instruction": text[va],
            "note": note,
        })
    return out


def write(path=None):
    cols = ("claim", "va", "size", "bytes", "instruction", "note")
    lines = ["\t".join(cols)]
    for r in rows(path):
        lines.append("\t".join([r["claim"], f"{r['va']:#x}", str(r["size"]),
                                r["bytes"], r["instruction"], r["note"]]))
    (PACKET / "semantics.tsv").write_text("\n".join(lines) + "\n")
    return len(lines) - 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--write" in argv:
        n = write()
        print(f"semantics.tsv: {n} claim anchors")
    else:
        for r in rows():
            print(f"{r['va']:#x} {r['bytes']:<20} {r['instruction']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
