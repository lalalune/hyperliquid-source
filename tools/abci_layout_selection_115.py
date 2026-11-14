#!/usr/bin/env python3
"""Bind which node #115 code reaches abci box layout A and layout B (37th stage).

Continues #6006: layout A is the 0x42c8-byte box, layout B the 0x4e38-byte box
that 0x548ce30 builds by inserting the 0xb70-byte output-setter result at
+0x7c0. Paired functions differ only by +0xb70 box displacements: steps
0x5a07ec0 (A) / 0x5a08720 (B), dispatchers 0x538cd30 (A) / 0x5397b50 (B).
This tool binds:

1. both pollers (0x2aeaef0, 0x2cb6500) call 0x5a6bfb0 through slot 0x64e7440
   in the same way: rdi = the caller's box, rsi = a copy of the 0xb70-byte
   setter result, edx = poller byte +0x2a1a, loaded from poller +0xb00;
2. inside 0x5a6bfb0, with no branch between them on the path shown here:
   - the B path: allocate 0x42c8, copy, copy the 0xb70 setter result, call
     0x548ce30, store the new box at engine value +0x450 and call the B step
     0x5a08720 directly (0x5a6c16a);
   - the A path: store the caller's box (rbx = rdi) at +0x420 of a struct,
     copy 0x438 bytes of it, set +0x431 = 1 only when edx is non-zero, and
     call 0x5a08f80, which reads +0x420 as the box, copies +0x431 into engine
     value +0x46d and calls the A step 0x5a07ec0 (0x5a0901f);
3. the other step callers: A step from 0x5a04e40, reached from 0x56185e0,
   which 0x5443930 and 0x59ec200 call (the node.rs:659 visor_abci_state
   writers of #6004, which read the freeze height at layout A's +0x10e8);
   B step from 0x5a06600, reached from 0x56186c0, which 0x4fcb590 calls;
4. the two dispatcher instruction pairs left open by #6006 (add reg, 0xb9b in
   A; add reg, 0x7c0 in B) only set rcx for the twin callees 0x5490540 /
   0x54905d0. The twins are 142 bytes each, differ only in RIP-relative
   displacements that name the same slots, and overwrite ecx at +0x20 before
   any read, so the differing value is never used.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, read_va

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-layout-selection-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SELECT = 0x5a6bfb0
SELECT_SLOT = 0x64e7440
A_WRAP = 0x5a08f80
A_STEP, B_STEP = 0x5a07ec0, 0x5a08720
INSERT = 0x548ce30
TWINS = (0x5490540, 0x54905d0)
TWIN_LEN = 0x8e

FIXED = {
    # pollers: identical slot calls
    0x2aec3e0: '410fb694241a2a0000',    # movzx edx, byte [r12+0x2a1a]
    0x2aec3e9: '4889ef',                # mov rdi, rbp
    0x2aec3ec: '4c89f6',                # mov rsi, r14
    0x2cb7a00: '410fb694241a2a0000',
    0x2cb7a09: '4889ef',
    0x2cb7a0c: '4c89f6',
    0x2aebfa6: '0fb683000b0000',        # movzx eax, byte [rbx+0xb00]
    0x2aebfdc: '88831a2a0000',          # mov [rbx+0x2a1a], al
    0x2cb75c6: '0fb683000b0000',
    # 0x5a6bfb0: arguments
    0x5a6c01b: '89d5',                  # mov ebp, edx
    0x5a6c01d: '4989f6',                # mov r14, rsi   (setter result)
    0x5a6c020: '4889fb',                # mov rbx, rdi   (caller's box)
    # B path
    0x5a6c05d: 'bfc8420000',            # mov edi, 0x42c8
    0x5a6c096: 'ba700b0000',            # mov edx, 0xb70
    0x5a6c09e: '4c89f6',                # mov rsi, r14
    0x5a6c0af: '4989c6',                # mov r14, rax   (new box)
    0x5a6c10a: '4c89b42490160000',      # mov [rsp+0x1690], r14  (value +0x450)
    0x5a6c167: '4c89f6',                # mov rsi, r14 (value at rsp+0x1240)
    # A path
    0x5a6c39c: '48899c2460160000',      # mov [rsp+0x1660], rbx  (+0x420)
    0x5a6c5c3: '488dbc2408550000',      # lea rdi, [rsp+0x5508]
    0x5a6c5cb: '488db42440120000',      # lea rsi, [rsp+0x1240]
    0x5a6c5d3: 'ba38040000',            # mov edx, 0x438
    0x5a6c5db: '4084ed',                # test bpl, bpl
    0x5a6c5de: '7408',                  # je +8
    0x5a6c5e0: 'c684243959000001',      # mov byte [rsp+0x5939], 1  (+0x431)
    0x5a6c5f0: '488db42408550000',      # lea rsi, [rsp+0x5508]
    0x5a08f92: '4c8bb620040000',        # mov r14, [rsi+0x420]
    0x5a08fa8: '0fb6ae31040000',        # movzx ebp, byte [rsi+0x431]
    0x5a0900c: '4088ac247d040000',      # mov [rsp+0x47d], bpl   (value +0x46d)
    0x5a0901c: '4c89f6',                # mov rsi, r14
    # dispatcher pairs and the twins' first use of ecx
    0x5395f86: '4881c39b0b0000',        # add rbx, 0xb9b
    0x53a0da6: '4881c3c0070000',        # add rbx, 0x7c0
    0x5396821: '4881c59b0b0000',        # add rbp, 0xb9b
    0x53a1641: '4881c5c0070000',        # add rbp, 0x7c0
    0x5490560: '89e9',                  # mov ecx, ebp
    0x54905f0: '89e9',
}
CALLS = {
    # (call site, kind, target)
    0x2aec3ef: ('slot', SELECT_SLOT),
    0x2cb7a0f: ('slot', SELECT_SLOT),
    0x5a6c0aa: ('rel', INSERT),
    0x5a6c16a: ('rel', B_STEP),
    0x5a6c5f8: ('rel', A_WRAP),
    0x5a0901f: ('rel', A_STEP),
    0x5395f97: ('rel', TWINS[0]),
    0x5396836: ('rel', TWINS[0]),
    0x53a0db7: ('rel', TWINS[1]),
    0x53a1656: ('rel', TWINS[1]),
}
CENSUS = {
    A_STEP: [0x5a05fc9, 0x5a0901f],
    B_STEP: [0x5a077e1, 0x5a6c16a],
    A_WRAP: [0x5a6c5f8],
    INSERT: [0x5a6c0aa],
    0x5a04e40: [0x5618630],
    0x5a06600: [0x5618710],
    0x56185e0: [0x54439ad, 0x59ec2a8],
    0x56186c0: [0x4fcb795],
    TWINS[0]: [0x5395f97, 0x5396836],
    TWINS[1]: [0x53a0db7, 0x53a1656],
}


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def call_target(data, va, kind):
    if kind == 'slot':
        raw = read_va(data, va, 6)
        if raw[:2] != b'\xff\x15':
            raise ValueError(f'call at {va:#x} changed')
        return va + 6 + struct.unpack_from('<i', raw, 2)[0]
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def twin_diff(data):
    """Byte offsets where the twins differ; each must sit in a RIP disp32 naming one address."""
    a, b = TWINS
    ra, rb = read_va(data, a, TWIN_LEN), read_va(data, b, TWIN_LEN)
    diffs = [i for i in range(TWIN_LEN) if ra[i] != rb[i]]
    # disp32 fields: call [rip+x] at +0x22, call [rip+x] at +0x4a, call [rip+x] at +0x72
    fields = []
    for ins in (0x22, 0x4a, 0x72):
        da = a + ins + 6 + struct.unpack_from('<i', ra, ins + 2)[0]
        db = b + ins + 6 + struct.unpack_from('<i', rb, ins + 2)[0]
        if ra[ins:ins + 2] != b'\xff\x15' or rb[ins:ins + 2] != b'\xff\x15' or da != db:
            raise ValueError('twin slot call changed')
        fields.append((ins + 2, da))
    covered = {o for start, _ in fields for o in range(start, start + 4)}
    if not diffs or any(i not in covered for i in diffs):
        raise ValueError('twin bytes differ outside RIP displacements')
    # no read of rcx/ecx/cl before the write at +0x20: the bytes before it are
    # the five pushes, the frame and three register moves that do not name rcx
    if ra[:0x20] != rb[:0x20] or ra[0x20:0x22] != b'\x89\xe9':
        raise ValueError('twin prologue changed')
    if ra[:0x20] != bytes.fromhex('554157415641545348' '81ec90010000' '89d5' '4889f3' '4989fe' '4889e7' '4c89f6' '4889da'):
        raise ValueError('twin prologue changed')
    return diffs, fields


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, (kind, target) in CALLS.items():
        if call_target(data, va, kind) != target:
            raise ValueError(f'call at {va:#x} changed')
    if relative_relocations(data).get(SELECT_SLOT) != SELECT:
        raise ValueError('slot 0x64e7440 no longer names 0x5a6bfb0')
    census = {}
    for target, expect in CENSUS.items():
        got = sorted(direct_calls(data, target))
        if got != expect:
            raise ValueError(f'call census of {target:#x} changed: {[hex(v) for v in got]}')
        census[hex(target)] = [hex(v) for v in got]
    starts = {f['start']: f['end'] for f in fdes}
    if starts.get(SELECT) != 0x5a6c8ec or starts.get(A_WRAP) != 0x5a090c2:
        raise ValueError('FDE extents changed')
    if not (SELECT <= 0x5a6c16a < 0x5a6c5f8 < 0x5a6c8ec):
        raise ValueError('step call order changed')
    diffs, fields = twin_diff(data)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'pollers': {
            'calls': ['0x2aec3ef (in 0x2aeaef0)', '0x2cb7a0f (in 0x2cb6500)'],
            'slot': hex(SELECT_SLOT) + ' -> ' + hex(SELECT),
            'arguments': 'rdi = rbp (caller box), rsi = copy of the 0xb70 setter result, '
                         'edx = byte [r12+0x2a1a]',
            'byte_0x2a1a_source': 'poller +0xb00 (0x2aebfa6 -> 0x2aebfdc; 0x2cb75c6)',
        },
        'select_0x5a6bfb0': {
            'fde': [hex(SELECT), '0x5a6c8ec'],
            'b_path': '0x42c8 alloc, copy, 0xb70 setter copy, 0x548ce30 (0x5a6c0aa) -> box at value +0x450 '
                      '(0x5a6c10a), B step 0x5a08720 (0x5a6c16a)',
            'a_path': 'caller box rbx at +0x420 (0x5a6c39c), 0x438-byte copy, +0x431 = 1 if edx != 0 '
                      '(0x5a6c5db..0x5a6c5e0), 0x5a08f80 (0x5a6c5f8) reads +0x420 / +0x431 '
                      '(0x5a08f92, 0x5a08fa8), value +0x46d = flag (0x5a0900c), A step 0x5a07ec0 (0x5a0901f)',
            'order': 'B step call precedes the A wrapper call; both in one function',
        },
        'step_callers': census,
        'twin_callees': {
            'pair': [hex(v) for v in TWINS],
            'length': TWIN_LEN,
            'differing_byte_offsets': diffs,
            'rip_fields': [[hex(o), hex(t)] for o, t in fields],
            'rcx_first_use': '+0x20 mov ecx, ebp (write) in both',
            'dispatcher_args': {'A': ['0x5395f86 add rbx,0xb9b', '0x5396821 add rbp,0xb9b'],
                                'B': ['0x53a0da6 add rbx,0x7c0', '0x53a1641 add rbp,0x7c0']},
        },
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
    print('twin diffs', result['twin_callees']['differing_byte_offsets'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
