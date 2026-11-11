#!/usr/bin/env python3
"""Bind the first stage of the node #115 shared value observer at 0x1547530.

The block-step recorder (RE-008) and 67 other call sites reach this routine
through slot 0x64e1010 with (state, count, Location, value). This tool binds
the observer window from entry to the running-maximum store, and the
12-byte wall-clock tuple provider it calls first.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

OBSERVER = 0x1547530
OBSERVER_END = 0x1548ba3
WINDOW_END = 0x15478e8  # the instruction after the running-maximum store at 0x15478e0
EPILOGUE = 0x154866c
OVERFLOW_PANIC = 0x1548a0b
OBSERVER_SLOT = 0x64e1010

PROVIDER = 0x1629690
PROVIDER_END = 0x1629795
PROVIDER_WINDOW_END = 0x162974f  # after the third output store
PROVIDER_SLOT = 0x64e0990
CLOCK = 0x5c842e0
DIFFERENCE = 0x5c84210
DATE_SLOT = 0x64dfff0
DATE_HELPER = 0x1628f50

DEQUE_GROW_SLOT = 0x64e0ea0
DEQUE_GROW = 0x152e190
VEC_GROW_SLOT = 0x64e0080
VEC_GROW = 0x14ca9a0

U64_HI = 0x451210
U64_BIAS = 0x450170
TWO_POW_64 = 0x459090

# (va, opcode prefix, instruction length, expected target)
REFERENCES = (
    (0x1547544, b'\x0f\x84', 6, EPILOGUE),
    (0x1547559, b'\xff\x15', 6, PROVIDER_SLOT),
    (0x15475cb, b'\x0f\x80', 6, OVERFLOW_PANIC),
    (0x15475e1, b'\x66\x0f\x62\x05', 8, U64_HI),
    (0x15475e9, b'\x66\x0f\x5c\x05', 8, U64_BIAS),
    (0x1547705, b'\xf2\x0f\x10\x0d', 8, TWO_POW_64),
    (0x154777f, b'\xff\x15', 6, DEQUE_GROW_SLOT),
    (0x154784a, b'\xf2\x0f\x10\x05', 8, TWO_POW_64),
    (0x15478b5, b'\xff\x15', 6, VEC_GROW_SLOT),
    (0x162969f, b'\xe8', 5, CLOCK),
    (0x16296cb, b'\xe8', 5, DIFFERENCE),
    (0x1629732, b'\xff\x15', 6, DATE_SLOT),
)

SLOTS = {
    OBSERVER_SLOT: OBSERVER,
    PROVIDER_SLOT: PROVIDER,
    DATE_SLOT: DATE_HELPER,
    DEQUE_GROW_SLOT: DEQUE_GROW,
    VEC_GROW_SLOT: VEC_GROW,
}

# Exact non-reference instructions this packet reads (observer window).
FIXED = {
    0x1547541: '4885f6',                    # test rsi, rsi          (count == 0 returns)
    0x154754a: '4989f6',                    # mov r14, rsi           (count)
    0x154754d: '4889fb',                    # mov rbx, rdi           (state)
    0x1547550: 'f20f11442410',              # movsd [rsp+0x10], xmm0 (value)
    0x1547556: '4889e7',                    # mov rdi, rsp           (tuple out)
    0x154755f: '8b3c24',                    # mov edi, [rsp]         (tuple dword 0)
    0x1547562: '39bb40020000',              # cmp [rbx+0x240], edi
    0x1547568: '7447',                      # je 0x15475b1
    0x154756a: '0f57c0',                    # xorps xmm0, xmm0
    0x154756d: '0f118300020000',            # movups [rbx+0x200], xmm0
    0x1547574: '48c7831002000000000000',    # mov qword [rbx+0x210], 0
    0x1547586: '48c7435800000000',          # mov qword [rbx+0x58], 0
    0x154758e: '48c7435000000000',          # mov qword [rbx+0x50], 0
    0x1547596: '89bb40020000',              # mov [rbx+0x240], edi
    0x154759c: '488b0424',                  # mov rax, [rsp]
    0x15475a0: '48898344020000',            # mov [rbx+0x244], rax
    0x15475a7: '8b442408',                  # mov eax, [rsp+8]
    0x15475ab: '89834c020000',              # mov [rbx+0x24c], eax
    0x15475b1: '80bb5c02000001',            # cmp byte [rbx+0x25c], 1
    0x15475b8: '751c',                      # jne 0x15475d6
    0x15475ba: 'b932000000',                # mov ecx, 50
    0x15475c2: '48f7e1',                    # mul rcx
    0x15475dc: '66490f6ec6',                # movq xmm0, r14         (count as u64 -> f64)
    0x15475fd: 'f20f59e3',                  # mulsd xmm4, xmm3       (w = count * value)
    0x1547658: 'f20f108310020000',          # movsd xmm0, [rbx+0x210]
    0x1547660: 'f20f58c4',                  # addsd xmm0, xmm4
    0x154770d: '488b8b00020000',            # mov rcx, [rbx+0x200]
    0x1547714: '4c01f1',                    # add rcx, r14
    0x1547721: '480f42f2',                  # cmovb rsi, rdx (-1)
    0x1547729: '4889b300020000',            # mov [rbx+0x200], rsi
    0x1547730: '488b8b08020000',            # mov rcx, [rbx+0x208]
    0x1547737: '48ffc1',                    # inc rcx
    0x154773a: '480f44ca',                  # cmove rcx, rdx (-1)
    0x154773e: '48898b08020000',            # mov [rbx+0x208], rcx
    0x1547745: '48b9000000000000f07f',      # mov rcx, 0x7ff0000000000000
    0x154774f: '4839c8',                    # cmp rax, rcx
    0x1547752: '7404',                      # je 0x1547758 (infinite sum keeps 2^64)
    0x1547758: 'f20f118b10020000',          # movsd [rbx+0x210], xmm1
    0x1547760: '4c8ba3f8010000',            # mov r12, [rbx+0x1f8]   (sample limit)
    0x1547767: '488b4340',                  # mov rax, [rbx+0x40]    (deque capacity)
    0x154776b: '488b4b58',                  # mov rcx, [rbx+0x58]    (deque length)
    0x154776f: '4839c1',                    # cmp rcx, rax
    0x1547776: '488d7b40',                  # lea rdi, [rbx+0x40]
    0x15477a5: '488b5348',                  # mov rdx, [rbx+0x48]    (deque buffer)
    0x15477a9: '488b7350',                  # mov rsi, [rbx+0x50]    (deque head)
    0x15477ad: '48ffce',                    # dec rsi
    0x15477b0: '4801f0',                    # add rax, rsi
    0x15477b3: '480f43c6',                  # cmovae rax, rsi
    0x15477b7: '48894350',                  # mov [rbx+0x50], rax
    0x15477bb: '48ffc1',                    # inc rcx
    0x15477be: '48894b58',                  # mov [rbx+0x58], rcx
    0x15477c2: 'f20f111cc2',                # movsd [rdx+rax*8], xmm3 (raw value)
    0x15477c7: '4c396358',                  # cmp [rbx+0x58], r12
    0x15477cb: '7604',                      # jbe 0x15477d1
    0x15477cd: '4c896358',                  # mov [rbx+0x58], r12
    0x15477d1: 'f20f58a388000000',          # addsd xmm4, [rbx+0x88]
    0x1547852: '4c037378',                  # add r14, [rbx+0x78]
    0x1547860: '480f42d1',                  # cmovb rdx, rcx (-1)
    0x1547868: '48895378',                  # mov [rbx+0x78], rdx
    0x154786c: '4c8b7370',                  # mov r14, [rbx+0x70]    (vector length)
    0x1547870: '488b9380000000',            # mov rdx, [rbx+0x80]
    0x1547877: '48ffc2',                    # inc rdx
    0x154787a: '480f44d1',                  # cmove rdx, rcx (-1)
    0x154787e: '48899380000000',            # mov [rbx+0x80], rdx
    0x154788f: '4839c8',                    # cmp rax, rcx
    0x1547892: '7404',                      # je 0x1547898
    0x1547898: 'f20f118388000000',          # movsd [rbx+0x88], xmm0
    0x15478a0: '4c3bb3f8010000',            # cmp r14, [rbx+0x1f8]
    0x15478a7: '732b',                      # jae 0x15478d4 (full vector skips the push)
    0x15478a9: '4c3b7360',                  # cmp r14, [rbx+0x60]    (vector capacity)
    0x15478b1: '488d7b60',                  # lea rdi, [rbx+0x60]
    0x15478c3: '488b4368',                  # mov rax, [rbx+0x68]    (vector buffer)
    0x15478c7: 'f2420f111cf0',              # movsd [rax+r14*8], xmm3 (raw value)
    0x15478cd: '49ffc6',                    # inc r14
    0x15478d0: '4c897370',                  # mov [rbx+0x70], r14
    0x15478d4: 'f20f108390000000',          # movsd xmm0, [rbx+0x90]
    0x15478dc: 'f20f5fc3',                  # maxsd xmm0, xmm3
    0x15478e0: 'f20f118390000000',          # movsd [rbx+0x90], xmm0
}

# Provider window: CLOCK(0), difference from (0, 0), days and seconds of day, date helper, three stores.
PROVIDER_FIXED = {
    0x162969a: '4889fb',          # mov rbx, rdi (output)
    0x162969d: '31ff',            # xor edi, edi (clock id 0)
    0x16296a4: '4889442418',      # mov [rsp+0x18], rax
    0x16296a9: '89542420',        # mov [rsp+0x20], edx
    0x16296ad: '48c744242800000000',  # mov qword [rsp+0x28], 0
    0x16296b6: 'c744243000000000',    # mov dword [rsp+0x30], 0
    0x16296fd: '4869c280510100',  # imul rax, rdx, 86400
    0x162972a: '81c23bf90a00',    # add edx, 719163
    0x1629730: '89d7',            # mov edi, edx
    0x1629738: '85c0',            # test eax, eax
    0x1629746: '8903',            # mov [rbx], eax        (dword +0: date helper result)
    0x1629748: '44897b04',        # mov [rbx+4], r15d     (dword +4: seconds of day)
    0x162974c: '896b08',          # mov [rbx+8], ebp      (dword +8: nanoseconds)
}


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return off, data[off:off + size]


def rip_target(data, va, prefix, length):
    _, raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2)[1] != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def relocations(data):
    rows = []
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        rows.extend(struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]))
    return rows


def frame(fdes, va):
    rows = [(f['start'], f['end']) for f in fdes if f['start'] <= va < f['end']]
    if len(rows) != 1:
        raise ValueError(f'expected one FDE at {va:#x}')
    return rows[0]


def text_census(data, target, slot):
    """Direct E8/E9 rel32 calls to `target`, and FF15/FF25 rip-relative uses of `slot`, in .text."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    raw = data[text['offset']:text['offset'] + text['size']]
    direct, through_slot = [], []
    for opcode, width, dest, out in ((b'\xe8', 5, target, direct), (b'\xe9', 5, target, direct),
                                     (b'\xff\x15', 6, slot, through_slot),
                                     (b'\xff\x25', 6, slot, through_slot)):
        start = 0
        while True:
            index = raw.find(opcode, start)
            if index < 0 or index + width > len(raw):
                break
            start = index + 1
            site = text['address'] + index
            if site + width + struct.unpack_from('<i', raw, index + len(opcode))[0] == dest:
                out.append((site, opcode.hex()))
    return sorted(direct), sorted(through_slot)


def f64(data, va):
    return struct.unpack('<d', read_va(data, va, 8)[1])[0]


def bind(data, fdes):
    if frame(fdes, OBSERVER) != (OBSERVER, OBSERVER_END):
        raise ValueError('observer FDE changed')
    if frame(fdes, PROVIDER) != (PROVIDER, PROVIDER_END):
        raise ValueError('provider FDE changed')
    for va, prefix, length, expect in REFERENCES:
        if rip_target(data, va, prefix, length) != expect:
            raise ValueError(f'reference at {va:#x} changed')
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, expect in PROVIDER_FIXED.items():
        fixed(data, va, expect)
    relocs = relocations(data)
    for slot, target in SLOTS.items():
        rows = [(info, addend) for va, info, addend in relocs if va == slot]
        if rows != [(8, target)]:
            raise ValueError(f'slot {slot:#x} relocation changed')
    if f64(data, TWO_POW_64) != 2.0 ** 64:
        raise ValueError('saturation constant changed')
    direct, through_slot = text_census(data, OBSERVER, OBSERVER_SLOT)
    relative = [va for va, info, addend in relocs if info & 0xffffffff == 8 and addend == OBSERVER]
    if direct or relative != [OBSERVER_SLOT]:
        raise ValueError('observer reference census changed')
    if (0x5b2a24c, 'ff15') not in through_slot:
        raise ValueError('block-step recorder no longer calls the observer')
    if len(through_slot) != 68 or any(op != 'ff15' for _, op in through_slot):
        raise ValueError('observer slot call census changed')
    _, window = read_va(data, OBSERVER, WINDOW_END - OBSERVER)
    _, pwindow = read_va(data, PROVIDER, PROVIDER_WINDOW_END - PROVIDER)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'observer': {
            'fde': {'start_va': hex(OBSERVER), 'end_va': hex(OBSERVER_END)},
            'window': {'start_va': hex(OBSERVER), 'end_va': hex(WINDOW_END),
                       'bytes': len(window), 'sha256': hashlib.sha256(window).hexdigest()},
            'entry': {'rdi': 'state (rbx)', 'rsi': 'count (r14)', 'xmm0': 'value (rsp+0x10)',
                      'rdx': 'Location: not read or saved before the call at 0x1547559'},
            'count_zero': {'test_va': '0x1547541', 'jump_to_epilogue_va': hex(EPILOGUE)},
            'tuple_call': {'va': '0x1547559', 'slot_va': hex(PROVIDER_SLOT), 'target_va': hex(PROVIDER),
                           'out': 'rsp'},
            'rollover': {'compare': 'dword [rbx+0x240] vs tuple dword +0',
                         'on_difference': ['zero 24 bytes at +0x200 (count, calls, sum)',
                                           'deque length +0x58 = 0', 'deque head +0x50 = 0',
                                           'store tuple at +0x240 (dword 0), +0x244 (bytes 0..7), +0x24c (dword 8)']},
            'count_multiplier': {'flag': 'byte [rbx+0x25c] == 1', 'factor': 50,
                                 'overflow_jump_va': hex(OVERFLOW_PANIC)},
            'weighted_value': 'w = f64(count as u64) * value; negative, infinite or NaN w becomes 0.0; +-0 kept',
            'daily': {'count': '+0x200 += count (saturating)', 'calls': '+0x208 += 1 (saturating)',
                      'sum': '+0x210 += w; an infinite sum is stored as 2^64',
                      'samples': 'deque cap +0x40, buf +0x48, head +0x50, len +0x58: push_front(value), '
                                 'grow via slot %s -> %s when full, then len = min(len, [+0x1f8])'
                                 % (hex(DEQUE_GROW_SLOT), hex(DEQUE_GROW))},
            'lifetime': {'count': '+0x78 += count (saturating)', 'calls': '+0x80 += 1 (saturating)',
                         'sum': '+0x88 += w; an infinite sum is stored as 2^64',
                         'samples': 'vector cap +0x60, buf +0x68, len +0x70: push(value) only while '
                                    'len < [+0x1f8]; grow via slot %s -> %s'
                                    % (hex(VEC_GROW_SLOT), hex(VEC_GROW)),
                         'max': '+0x90 = maxsd(+0x90, value)'},
            'saturation_constant': {'va': hex(TWO_POW_64), 'value': f64(data, TWO_POW_64)},
        },
        'provider': {
            'fde': {'start_va': hex(PROVIDER), 'end_va': hex(PROVIDER_END)},
            'window': {'start_va': hex(PROVIDER), 'end_va': hex(PROVIDER_WINDOW_END),
                       'bytes': len(pwindow), 'sha256': hashlib.sha256(pwindow).hexdigest()},
            'clock': {'helper_va': hex(CLOCK), 'edi': 0},
            'difference': {'helper_va': hex(DIFFERENCE), 'from': '(0, 0)'},
            'split': 'seconds / 86400 -> days; seconds mod 86400 -> seconds of day',
            'date_call': {'va': '0x1629732', 'slot_va': hex(DATE_SLOT), 'target_va': hex(DATE_HELPER),
                          'edi': 'days + 719163', 'zero_result': 'leaves this window'},
            'output': {'+0': 'date helper result (dword)', '+4': 'seconds of day (dword)',
                       '+8': 'nanoseconds (dword)'},
        },
        'census': {
            'observer_direct_calls': len(direct),
            'observer_relative_relocations': [hex(v) for v in relative],
            'observer_slot_calls': len(through_slot),
            'observer_slot_jumps': 0,
            'recorder_site_va': '0x5b2a24c',
            'encodings': 'E8/E9 rel32 to the observer; FF15/FF25 rip-relative through the slot, in .text; '
                         'R_X86_64_RELATIVE addends',
            'slot_call_sites': [hex(v) for v, _ in through_slot],
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
    print(f"{result['observer']['fde']['start_va']} slot_calls={result['census']['observer_slot_calls']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
