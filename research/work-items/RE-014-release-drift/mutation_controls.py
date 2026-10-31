#!/usr/bin/env python3
"""RE-014 mutation controls: assemble tiny x86-64 functions, mutate one thing, check the class.

Each case disassembles the assembled bytes with a pure-Python AT&T decoder covering
the instruction subset used here (no objdump). Runs the same fingerprint and
classify code as tools/release_drift.py. Exits non-zero on any unexpected class;
uses no assert so it holds under python -O.
"""
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from release_drift import classify, fingerprint

BASE = 0x1000
PLT = (0x900, 0x980)


def call(at, target):
    return b"\xe8" + struct.pack("<i", target - (at + 5))


def layout(b_at=0x1030, constant=0x2a, push=b"\x55", a_call=None, extra=False):
    """C calls A, A calls B. Returns (code bytes, [(start, end)])."""
    c = call(0x1000, 0x1010) + b"\xc3"
    a = push + b"\xb8" + struct.pack("<I", constant) + call(0x1016, b_at if a_call is None else a_call) + b"\x5d\xc3"
    b = b"\xb8\x07\x00\x00\x00\xc3"
    code = bytearray(b"\xcc" * 0x80)
    for at, body in ((0x1000, c), (0x1010, a), (b_at, b)):
        code[at - BASE : at - BASE + len(body)] = body
    spans = [(0x1000, 0x1000 + len(c)), (0x1010, 0x1010 + len(a)), (b_at, b_at + len(b))]
    if extra:
        code[0x1070 - BASE : 0x1070 - BASE + 4] = b"\x48\x31\xc0\xc3"
        spans.append((0x1070, 0x1074))
    return bytes(code), spans


def _imm_hex(value):
    """GNU objdump style: lowercase hex without unnecessary leading zeros."""
    return f"{value:#x}"


def disassemble_att(code, base=BASE):
    """Linear-sweep AT&T lines matching GNU objdump for the RE-014 mutation opcode subset.

    Emits `    <va>:\\t<text>` lines. Covers: push/pop %rbp/%rbx, ret, int3,
    mov $imm32,%eax, call rel32, xor %rax,%rax. Unknown bytes raise ValueError
    (fail closed) rather than silently skipping.
    """
    lines = []
    i = 0
    n = len(code)
    while i < n:
        va = base + i
        b0 = code[i]
        if b0 == 0xCC:
            text, size = "int3", 1
        elif b0 == 0xC3:
            text, size = "ret", 1
        elif b0 == 0x55:
            text, size = "push   %rbp", 1
        elif b0 == 0x53:
            text, size = "push   %rbx", 1
        elif b0 == 0x5D:
            text, size = "pop    %rbp", 1
        elif b0 == 0xE8 and i + 5 <= n:
            rel = struct.unpack_from("<i", code, i + 1)[0]
            target = va + 5 + rel
            text, size = f"call   {_imm_hex(target)}", 5
        elif b0 == 0xB8 and i + 5 <= n:
            imm = struct.unpack_from("<I", code, i + 1)[0]
            text, size = f"mov    ${_imm_hex(imm)},%eax", 5
        elif b0 == 0x48 and i + 3 <= n and code[i + 1] == 0x31 and code[i + 2] == 0xC0:
            text, size = "xor    %rax,%rax", 3
        else:
            raise ValueError(f"unsupported opcode at {va:#x}: {code[i:i+8].hex()}")
        lines.append(f"    {va:x}:\t{text}")
        i += size
    return lines


def rows(code, spans):
    out = disassemble_att(code, BASE)
    return fingerprint(spans, lambda s, e: code[s - BASE : e - BASE], out, PLT)


def classes(old=None, **mutation):
    table = classify(rows(*layout(**(old or {}))), rows(*layout(**mutation)))
    return {(r[3] or "115:" + r[5]): r[0] for r in table}


# (name, mutation of #115 side, expected class per #94 start or #115-only start)
CASES = [
    ("unchanged", {}, {"0x1000": "identical", "0x1010": "identical", "0x1030": "identical"}),
    ("callee moved", {"b_at": 0x1040}, {"0x1000": "identical", "0x1010": "moved_only", "0x1030": "identical"}),
    ("constant changed", {"constant": 0x2B}, {"0x1000": "identical", "0x1010": "changed", "0x1030": "identical"}),
    # Both constants lie inside the code's address range; a PIE constant must still be compared.
    (
        "in-image-range constant changed",
        {"old": {"constant": 0x1048}, "constant": 0x1050},
        {"0x1000": "identical", "0x1010": "changed", "0x1030": "identical"},
    ),
    ("instruction changed", {"push": b"\x53"}, {"0x1000": "identical", "0x1010": "changed", "0x1030": "identical"}),
    (
        "call retargeted to non-FDE code",
        {"a_call": 0x1060},
        {"0x1000": "identical", "0x1010": "changed", "0x1030": "identical"},
    ),
    ("call retargeted to PLT", {"a_call": 0x910}, {"0x1000": "identical", "0x1010": "changed", "0x1030": "identical"}),
    (
        "function added",
        {"extra": True},
        {"0x1000": "identical", "0x1010": "identical", "0x1030": "identical", "115:0x1070": "unmatched_115"},
    ),
]


def main():
    failures = []
    for name, mutation, expected in CASES:
        got = classes(**mutation)
        status = "ok" if got == expected else "FAIL"
        print(f"{status}\t{name}\t{got}")
        if got != expected:
            failures.append(name)
    if failures:
        raise SystemExit(f"mutation controls failed: {failures}")


if __name__ == "__main__":
    main()
