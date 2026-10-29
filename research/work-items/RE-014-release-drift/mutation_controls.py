#!/usr/bin/env python3
"""RE-014 mutation controls: assemble tiny x86-64 functions, mutate one thing, check the class.

Each case disassembles real bytes with GNU objdump and runs the same fingerprint and
classify code as tools/release_drift.py. Exits non-zero on any unexpected class;
uses no assert so it holds under python -O.
"""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'tools'))
from release_drift import classify, fingerprint

BASE = 0x1000
PLT = (0x900, 0x980)


def call(at, target):
    return b'\xe8' + struct.pack('<i', target - (at + 5))


def layout(b_at=0x1030, constant=0x2a, push=b'\x55', a_call=None, extra=False):
    """C calls A, A calls B. Returns (code bytes, [(start, end)])."""
    c = call(0x1000, 0x1010) + b'\xc3'
    a = push + b'\xb8' + struct.pack('<I', constant) + call(0x1016, b_at if a_call is None else a_call) + b'\x5d\xc3'
    b = b'\xb8\x07\x00\x00\x00\xc3'
    code = bytearray(b'\xcc' * 0x80)
    for at, body in ((0x1000, c), (0x1010, a), (b_at, b)):
        code[at - BASE:at - BASE + len(body)] = body
    spans = [(0x1000, 0x1000 + len(c)), (0x1010, 0x1010 + len(a)), (b_at, b_at + len(b))]
    if extra:
        code[0x1070 - BASE:0x1070 - BASE + 4] = b'\x48\x31\xc0\xc3'
        spans.append((0x1070, 0x1074))
    return bytes(code), spans


def rows(code, spans):
    with tempfile.NamedTemporaryFile(suffix='.bin') as handle:
        handle.write(code)
        handle.flush()
        out = subprocess.run(['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-w', '--no-show-raw-insn',
                              f'--adjust-vma={BASE:#x}', handle.name], capture_output=True, text=True, check=True,
                             env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}).stdout
    return fingerprint(spans, lambda s, e: code[s - BASE:e - BASE], out.splitlines(), PLT)


def classes(old=None, **mutation):
    table = classify(rows(*layout(**(old or {}))), rows(*layout(**mutation)))
    return {(r[3] or '115:' + r[5]): r[0] for r in table}


# (name, mutation of #115 side, expected class per #94 start or #115-only start)
CASES = [
    ('unchanged', {}, {'0x1000': 'identical', '0x1010': 'identical', '0x1030': 'identical'}),
    ('callee moved', {'b_at': 0x1040}, {'0x1000': 'identical', '0x1010': 'moved_only', '0x1030': 'identical'}),
    ('constant changed', {'constant': 0x2b}, {'0x1000': 'identical', '0x1010': 'changed', '0x1030': 'identical'}),
    # Both constants lie inside the code's address range; a PIE constant must still be compared.
    ('in-image-range constant changed', {'old': {'constant': 0x1048}, 'constant': 0x1050},
     {'0x1000': 'identical', '0x1010': 'changed', '0x1030': 'identical'}),
    ('instruction changed', {'push': b'\x53'}, {'0x1000': 'identical', '0x1010': 'changed', '0x1030': 'identical'}),
    ('call retargeted to non-FDE code', {'a_call': 0x1060},
     {'0x1000': 'identical', '0x1010': 'changed', '0x1030': 'identical'}),
    ('call retargeted to PLT', {'a_call': 0x910}, {'0x1000': 'identical', '0x1010': 'changed', '0x1030': 'identical'}),
    ('function added', {'extra': True},
     {'0x1000': 'identical', '0x1010': 'identical', '0x1030': 'identical', '115:0x1070': 'unmatched_115'}),
]


def main():
    failures = []
    for name, mutation, expected in CASES:
        got = classes(**mutation)
        status = 'ok' if got == expected else 'FAIL'
        print(f'{status}\t{name}\t{got}')
        if got != expected:
            failures.append(name)
    if failures:
        raise SystemExit(f'mutation controls failed: {failures}')


if __name__ == '__main__':
    main()
