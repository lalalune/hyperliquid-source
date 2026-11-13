#!/usr/bin/env python3
"""Bind the node #115 abci digest check in the two step wrappers (46th stage).

Continues #6019 and #6021. The step wrapper 0x5a04e40 (layout A, #6006) and
its twin 0x5a06600 (layout B) compare 32-byte digests and panic with
"computed abci digest at height=... does not match quorum value ...". This
tool binds:

1. the compare: each wrapper walks a slice of 0x68-byte entries (+0x0 a
   u64 key, +0x48..+0x68 32 bytes), looks the key up in the engine value's
   map at +0x400 and, only when the key is present, compares the 32 bytes
   with pcmpeqb; a mismatch jumps to the panic block;
2. what fills the map: inside each step, a 32-byte value from 0x548dad0 (A)
   or 0x548d8c0 (B) is inserted with the height through 0x5a03fa0, which
   trims the map once it holds 0x33 (51) entries; the step computes it only
   when height % box +0x39c8 (A) / +0x4538 (B, the #5970 divisor) is 0 or
   when bpl is set; 0x548dad0 records into an observer through slot
   0x64e1010 (-> 0x1547530);
3. the bookkeeping: the wrapper stores (1, max entry key) at engine value
   +0x10/+0x18 and, when that tag is set, keeps only map keys above it
   (0x4de5ad0) before calling the step.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (RELATIVE, SHA256, TARGET, direct_calls, fixed, frame, read_va,
                                 relative_relocations, rip_target, text)

PACKET = ROOT / 'research/work-items/RE-008-abci-digest-check-115'

WRAPPER_A, WRAPPER_B = 0x5a04e40, 0x5a06600
STEP_A = 0x5a07ec0
DIGEST_A, DIGEST_B = 0x548dad0, 0x548d8c0
INSERT = 0x5a03fa0
PANIC_TEMPLATE = 0x44c993
RECORD_SLOT, RECORD = 0x64e1010, 0x1547530
COMPARE = bytes.fromhex('f3410f6f5548660f74d0f3410f6f4558')

FIXED = {
    # wrapper A: map at engine value +0x400, compare loop over 0x68-byte entries
    0x5a05cc8: '498dac2400040000',      # lea rbp, [r12+0x400]
    0x5a05d07: 'f3410f6f5548',          # movdqu xmm2, [r13+0x48]
    0x5a05d0d: '660f74d0',              # pcmpeqb xmm2, xmm0
    0x5a05d11: 'f3410f6f4558',          # movdqu xmm0, [r13+0x58]
    0x5a05d23: '3dffff0000',            # cmp eax, 0xffff
    0x5a05d2e: '4983c568',              # add r13, 0x68
    0x5a05d4b: '48b80000000000000080',  # movabs rax, 0x8000000000000000 (map mode)
    0x5a05dfb: 'a801',                  # test al, 1 (key not found -> next entry)
    # wrapper A: max key into engine value +0x10/+0x18, then trim below it
    0x5a05c0a: '49894c2410',            # mov [r12+0x10], rcx
    0x5a05c0f: '4989542418',            # mov [r12+0x18], rdx
    0x5a05ea1: '41807c241000',          # cmp byte [r12+0x10], 0
    0x5a05ead: '498b442418',            # mov rax, [r12+0x18]
    0x5a05eb2: '48ffc0',                # inc rax
    # wrapper B: same compare
    0x5a074f6: '498daf00040000',        # lea rbp, [r15+0x400]
    0x5a07527: 'f3410f6f5548',
    0x5a07531: 'f3410f6f4558',
    0x5a07543: '3dffff0000',
    0x5a0754e: '4983c568',
    # steps: divisor and insert target
    0x5a07f85: '488b8ec8390000',        # mov rcx, [rsi+0x39c8]   (A)
    0x5a07fd3: '498dbe00040000',        # lea rdi, [r14+0x400]
    0x5a087e5: '488b8e38450000',        # mov rcx, [rsi+0x4538]   (B)
    0x5a08833: '498dbe00040000',
    # insert: trim once the map holds 0x33 entries
    0x5a03fbd: '488b5318',              # mov rdx, [rbx+0x18]
    0x5a03fc1: '4883fa33',              # cmp rdx, 0x33
}
REFERENCES = (
    (0x5a05d28, b'\x0f\x85', 6, 0x5a060ec),       # mismatch -> panic block (A)
    (0x5a07548, b'\x0f\x85', 6, 0x5a0793f),       # mismatch -> panic block (B)
    (0x5a061ff, b'\x48\x8d\x3d', 7, PANIC_TEMPLATE),
    (0x5a07a54, b'\x48\x8d\x3d', 7, PANIC_TEMPLATE),
    (0x5a05df6, b'\xe8', 5, 0x57f8bb0),           # second map mode lookup
    (0x5a05ee3, b'\xe8', 5, 0x4de5ad0),           # keep keys above the max
    (0x5a05fc9, b'\xe8', 5, STEP_A),
    (0x5a07fce, b'\xe8', 5, DIGEST_A),
    (0x5a07fe5, b'\xe8', 5, INSERT),
    (0x5a0882e, b'\xe8', 5, DIGEST_B),
    (0x5a08845, b'\xe8', 5, INSERT),
    (0x548dbb6, b'\xff\x15', 6, RECORD_SLOT),
)
STRINGS = {
    0x44c994: b'computed abci digest',
    0x44c9b9: b'does not match quorum value',
}


def lea_refs(data, target):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if i + 7 <= len(code) and base + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == target:
            out.append(base + i)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    if relative_relocations(data).get(RECORD_SLOT) != RECORD:
        raise ValueError('record slot changed')

    base, code = text(data)
    compares = [base + m.start() for m in re.finditer(re.escape(COMPARE), code)]
    if compares != [0x5a05d07, 0x5a07527]:
        raise ValueError('compare census changed')
    owners = [hex(frame(fdes, v)) for v in compares]
    if owners != [hex(WRAPPER_A), hex(WRAPPER_B)]:
        raise ValueError('compare owners changed')
    inserts = direct_calls(data, INSERT)
    if inserts != [0x5a07fe5, 0x5a08845]:
        raise ValueError('insert census changed')
    panics = lea_refs(data, PANIC_TEMPLATE)
    panic_frames = [hex(frame(fdes, v)) for v in panics]

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'compare': {
            'sites': [hex(v) for v in compares],
            'wrappers': owners,
            'entry': '0x68 bytes; +0x0 u64 key (looked up), +0x48..+0x68 32 bytes compared',
            'map': 'engine value +0x400; two modes: B-tree when +0x400 == 0x8000000000000000 '
                   '(root +0x408, height +0x410), else 0x28-byte ring entries via 0x57f8bb0 '
                   '(len +0x418)',
            'missing_key': 'skip the entry (no compare)',
            'mismatch': 'jne to the panic block; template %s "computed abci digest ... does not '
                        'match quorum value"' % hex(PANIC_TEMPLATE),
        },
        'map_fill': {
            'insert_fn': hex(INSERT),
            'insert_calls': [hex(v) for v in inserts],
            'value_fn': {'A': hex(DIGEST_A), 'B': hex(DIGEST_B)},
            'condition': 'height % box divisor == 0 (A +0x39c8, B +0x4538) or bpl set',
            'trim_at_len': 0x33,
            'value_fn_records': 'call [rip+%s] -> %s (observer record)' % (hex(RECORD_SLOT), hex(RECORD)),
        },
        'bookkeeping': {
            'max_key': 'wrapper A stores (tag, max entry key) at engine value +0x10/+0x18',
            'trim': 'when tag set, keep map keys >= max + 1 (saturating) via 0x4de5ad0, before the step',
        },
        'panic_template_refs': {'sites': [hex(v) for v in panics], 'functions': panic_frames},
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print('compares=%s inserts=%s' % (result['compare']['sites'], result['map_fill']['insert_calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
