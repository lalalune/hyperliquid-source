#!/usr/bin/env python3
"""Bind the node #115 global extra-flush byte and the mempool_txs record (tenth stage).

Continues the line-writer packets. The ninth stage found that the second task
spawned by 0x5a81ed0 (poll 0x5a82670) calls the line write 0x4e3eaa0 once,
at 0x5a88864, with a record at rsp+0x1420, and that the write flushes again
when the writer flush byte (+0xaa) and the global byte 0x64ffe50 are both
set. This tool binds:

1. the global byte 0x64ffe50 (.bss, zero at load): its only GOT slot
   0x64e0f88; 101 slot loads in .text, 100 of them `movzx eax, byte [rax]`
   reads and one `mov byte [rsi], 1` write at 0x51cf3e7;
2. the writer 0x51cf360 (slot 0x64e7428, two calls): it stores 1 only when
   argument byte +0x20 is not zero; argument bytes +0x21 and +0x22 both set
   reach the panic text "cannot set both batch_by_block and
   stream_with_block_info" (0x91fd5f);
3. the poll path to the write: a two-word value is stored at future +0x190
   / +0x198 and copied to +0x2d60 / +0x2d68; a zero first word branches to
   0x5a8869d, which loads r15 = [future+0x2d68];
4. the record: tx_hash (+0x10..+0x30) is the 32-byte output of a 200-byte
   sponge state with +0xd0 = 0x88 and +0xd8 = 1, updated (slot 0x64e0148)
   with the bytes [r15+0x18] / [r15+0x20] and finalized (slot 0x64e0150);
   signed_actions (+0x0 pointer, +0x8 length) is the Ok payload (tag word
   0x1a2) of decoder slot 0x64e87f0 over the same bytes, freed as
   capacity * 0x168 bytes.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-mempool-txs-record-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

GLOBAL, GLOBAL_SLOT = 0x64ffe50, 0x64e0f88
SETTER, SETTER_SLOT = 0x51cf360, 0x64e7428
POLL = 0x5a82670
SLOTS = {GLOBAL_SLOT: GLOBAL, SETTER_SLOT: SETTER, 0x64e0148: 0x5cda910,
         0x64e0150: 0x5cdad40, 0x64e87f0: 0x36abb10}
PANIC = (0x91fd5f, b'cannot set both batch_by_block and stream_with_block_info')

FIXED = {
    # setter: argument byte +0x20 gates the only store
    0x51cf3da: '807e2000',              # cmp byte [rsi+0x20], 0
    0x51cf3de: '740a',                  # je 0x51cf3ea                  (skip store)
    0x51cf3e7: 'c60601',                # mov byte [rsi], 1             (rsi = global)
    0x51cf3cd: '0fb65621',              # movzx edx, byte [rsi+0x21]
    0x51cf3d1: '0fb64e22',              # movzx ecx, byte [rsi+0x22]
    0x51cf3ef: '84d2',                  # test dl, dl
    0x51cf3f1: '0f84b5000000',          # je 0x51cf4ac
    0x51cf3f9: '84c9',                  # test cl, cl
    0x51cf3fb: '0f85b9160000',          # jne 0x51d0aba                 (both set -> panic)
    0x51d0ac8: 'be73000000',            # mov esi, 0x73
    # poll: message pair stored, zero first word selects the write path
    0x5a8707c: '4183fc01',              # cmp r12d, 1
    0x5a87080: '0f85c9010000',          # jne 0x5a8724f
    0x5a87261: '48898b90010000',        # mov [rbx+0x190], rcx
    0x5a87268: '48898398010000',        # mov [rbx+0x198], rax
    0x5a8727f: '488983602d0000',        # mov [rbx+0x2d60], rax
    0x5a8728d: '488983682d0000',        # mov [rbx+0x2d68], rax
    0x5a8729b: '4885c0',                # test rax, rax
    0x5a8729e: '0f84f9130000',          # je 0x5a8869d
    0x5a886a4: '4c8bbb682d0000',        # mov r15, [rbx+0x2d68]
    0x5a886b3: '498b7718',              # mov rsi, [r15+0x18]           (bytes)
    0x5a886b7: '498b5720',              # mov rdx, [r15+0x20]           (length)
    # sponge parameters and tx_hash
    0x5a88746: '48c784249006000088000000',  # mov qword [rsp+0x690], 0x88
    0x5a88752: '66c78424980600000100',      # mov word [rsp+0x698], 1
    0x5a8875c: '488dbc24c0050000',      # lea rdi, [rsp+0x5c0]
    0x5a88788: '488db42410230000',      # lea rsi, [rsp+0x2310]
    0x5a88790: 'ba20000000',            # mov edx, 0x20
    # signed_actions
    0x5a887d6: '498b7718',              # mov rsi, [r15+0x18]
    0x5a887da: '498b5720',              # mov rdx, [r15+0x20]
    0x5a887ec: '6681bc24c0050000a201',  # cmp word [rsp+0x5c0], 0x1a2
    0x5a88810: '4c8ba424d0050000',      # mov r12, [rsp+0x5d0]          (pointer)
    0x5a88818: '488b8424d8050000',      # mov rax, [rsp+0x5d8]          (length)
    0x5a88832: 'f30f7f8c2440140000',    # movdqu [rsp+0x1440], xmm1     (hash hi)
    0x5a8883b: 'f30f7f842430140000',    # movdqu [rsp+0x1430], xmm0     (hash lo)
    0x5a88844: '4c89a42420140000',      # mov [rsp+0x1420], r12
    0x5a8884c: '4889842428140000',      # mov [rsp+0x1428], rax
    0x5a8885c: '488d942420140000',      # lea rdx, [rsp+0x1420]         (record)
    0x5a8887a: '4969f668010000',        # imul rsi, r14, 0x168
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x51cf3e0, b'\x48\x8b\x35', 7, GLOBAL_SLOT),
    (0x51d0aba, b'\x48\x8d\x3d', 7, PANIC[0]),
    (0x2aec025, b'\xff\x15', 6, SETTER_SLOT),
    (0x2cb7645, b'\xff\x15', 6, SETTER_SLOT),
    (0x4e3ec36, b'\x48\x8b\x05', 7, GLOBAL_SLOT),
    (0x5a88764, b'\xff\x15', 6, 0x64e0148),
    (0x5a88798, b'\xff\x15', 6, 0x64e0150),
    (0x5a887e6, b'\xff\x15', 6, 0x64e87f0),
    (0x5a88864, b'\xe8', 5, 0x4e3eaa0),
)
def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def slot_calls(data, slot):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
            out.append(base + i)
    return out


def frame_starts(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start'], ordered[i]['end']
    return frame




def slot_loads(data, slot):
    """`mov r64, [rip+disp32]` loads of a GOT slot, with the 3 bytes after each."""
    base, code = text(data)
    out = []
    for m in re.finditer(rb'[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if i + 10 <= len(code) and base + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == slot:
            out.append((base + i, code[i + 7:i + 10]))
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    into_global = sorted(k for k, v in rel.items() if GLOBAL <= v < GLOBAL + 8)
    if into_global != [GLOBAL_SLOT]:
        raise ValueError('global slot census changed')
    bss = next(s for s in sections(data) if s['name'] == '.bss')
    if not bss['address'] <= GLOBAL < bss['address'] + bss['size']:
        raise ValueError('global left .bss')
    if read_va(data, PANIC[0], len(PANIC[1])) != PANIC[1]:
        raise ValueError('panic text changed')

    frame = frame_starts(fdes)
    loads = slot_loads(data, GLOBAL_SLOT)
    reads = [va for va, nxt in loads if nxt == b'\x0f\xb6\x00']
    writes = [va for va, nxt in loads if nxt[:2] == b'\xc6\x06']
    if len(reads) + len(writes) != len(loads) or [frame(v)[0] for v in writes] != [SETTER]:
        raise ValueError('global access census changed')
    setter_calls = slot_calls(data, SETTER_SLOT)
    if frame(0x5a88864)[0] != POLL or frame(0x5a8724f)[0] != POLL:
        raise ValueError('poll extent changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'global_byte': {
            'address': hex(GLOBAL) + ' (.bss, zero at load)',
            'got_slot': hex(GLOBAL_SLOT),
            'slot_loads': len(loads),
            'reads_movzx_byte': len(reads),
            'read_functions': len({frame(v) for v in reads}),
            'writes': [hex(v) + ' slot load, ' + hex(v + 7) + ' mov byte [rsi], 1' for v in writes],
        },
        'setter': {
            'fn': hex(SETTER),
            'slot': hex(SETTER_SLOT),
            'calls': [hex(v) for v in setter_calls],
            'store_condition': 'argument byte +0x20 != 0 (0x51cf3da)',
            'both_flags_panic': 'argument bytes +0x21 and +0x22 both set -> %s %r (len 0x73 passed)'
                                % (hex(PANIC[0]), PANIC[1].decode()),
        },
        'poll_path': {
            'fn': hex(POLL),
            'store': 'r12d != 1 -> pair (rcx, rax) to future +0x190/+0x198, copied to +0x2d60/+0x2d68',
            'select': '+0x2d60 == 0 -> 0x5a8869d, r15 = [future+0x2d68]',
            'input': 'bytes [r15+0x18], length [r15+0x20]',
        },
        'record': {
            'address': 'rsp+0x1420, passed at 0x5a8885c to 0x4e3eaa0',
            'tx_hash': '+0x10..+0x30 = 32-byte finalize (slot 0x64e0150 -> 0x5cdad40) of a 200-byte sponge '
                       'state at rsp+0x5c0 with +0xd0 = 0x88 and +0xd8 = 1, updated with the input '
                       '(slot 0x64e0148 -> 0x5cda910)',
            'signed_actions': '+0x0 pointer, +0x8 length from the Ok payload (tag word 0x1a2) of slot '
                              '0x64e87f0 -> 0x36abb10 over the same input; freed as capacity * 0x168',
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
    g = result['global_byte']
    print(f"loads={g['slot_loads']} reads={g['reads_movzx_byte']} writes={len(g['writes'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
