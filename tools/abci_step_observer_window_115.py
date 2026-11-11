#!/usr/bin/env python3
"""Bind the node #115 shared value observer's 30-second window (second stage).

Continues the first-stage packet for the observer at 0x1547530 (slot 0x64e1010).
This tool binds three things:

1. the observer window 0x15478e8..0x1547b9c: the deadline test on the window
   start at +0x228, the take-and-reset of the +0x60..+0x90 bucket, and the
   mean of the bucket that was taken;
2. the constructor 0x1548bb0 (slot 0x64e1020) that sets the window length
   +0x220, the sample limit +0x1f8, the x50 flag +0x25c and the window start;
3. the five constructor call sites that set the x50 flag to 1.

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
PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-window-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

OBSERVER = 0x1547530
OBSERVER_END = 0x1548ba3
OBSERVER_SLOT = 0x64e1010
WINDOW_START = 0x15478e8   # first instruction after the first-stage running-maximum store
WINDOW_END = 0x1547b9c     # merge point after the mean test
ROLLOVER = 0x1547a83
DEADLINE_MAX = 0x1547a3d
MEAN_PRESENT = 0x1547dc1
EPILOGUE = 0x154866c

CTOR = 0x1548bb0
CTOR_END = 0x1548f3d
CTOR_SLOT = 0x64e1020
CTOR_WINDOW_END = 0x1548e6f   # after the constructor's ret

PROVIDER_SLOT = 0x64e0990
PROVIDER = 0x1629690
SECONDS_SLOT = 0x64e0f70      # called with the f64 window length in xmm0
SECONDS = 0x15ed960
TIME_ADD_SLOT = 0x64e0f78     # called with (out, &(seconds of day, nanoseconds)) and the split duration
TIME_ADD = 0x162a9a0
DAYS_SLOT = 0x64e0aa0         # called with (start date, carried days)
DAYS = 0x16290d0

MAX_TUPLE = 0x4679d0          # three dwords used when the deadline cannot be built
EPSILON = 0x458fa0            # -1e-15
U64_HI = 0x451210
U64_BIAS = 0x450170

WINDOW_SECONDS_BITS = 0x403e000000000000   # 30.0
SAMPLE_LIMIT = 0x7d0                       # 2000
FIELD_238 = 0x3e8                          # 1000

# (va, opcode prefix, instruction length, expected target)
REFERENCES = (
    (0x15478fa, b'\x0f\x84', 6, ROLLOVER),          # start date 0 -> roll over now
    (0x154792a, b'\xff\x15', 6, SECONDS_SLOT),
    (0x1547988, b'\xff\x15', 6, TIME_ADD_SLOT),
    (0x15479b0, b'\x0f\x86', 6, DEADLINE_MAX),
    (0x1547a01, b'\xff\x15', 6, DAYS_SLOT),
    (0x1547a48, b'\x4c\x8d\x35', 7, MAX_TUPLE),
    (0x1547a4f, b'\x48\x8d\x05', 7, MAX_TUPLE + 8),
    (0x1547a56, b'\x48\x8d\x0d', 7, MAX_TUPLE + 4),
    (0x1547a76, b'\xe9', 5, EPILOGUE),
    (0x1547a7d, b'\x0f\x84', 6, EPILOGUE),
    (0x1547afa, b'\x0f\x84', 6, WINDOW_END),        # empty bucket: no mean
    (0x1547b15, b'\x0f\x8f', 6, WINDOW_END),        # non-finite sum: no mean
    (0x1547b1b, b'\x66\x0f\x2e\x15', 8, EPSILON),
    (0x1547b34, b'\x66\x0f\x62\x0d', 8, U64_HI),
    (0x1547b3c, b'\x66\x0f\x5c\x0d', 8, U64_BIAS),
    (0x1547b50, b'\xf2\x0f\x10\x0d', 8, EPSILON),
    (0x1547b96, b'\x0f\x8e', 6, MEAN_PRESENT),
    (0x1548bd7, b'\xff\x15', 6, PROVIDER_SLOT),     # constructor reads the clock tuple
)

SLOTS = {
    OBSERVER_SLOT: OBSERVER,
    CTOR_SLOT: CTOR,
    PROVIDER_SLOT: PROVIDER,
    SECONDS_SLOT: SECONDS,
    TIME_ADD_SLOT: TIME_ADD,
    DAYS_SLOT: DAYS,
}

# Exact non-reference instructions this packet reads in the observer window.
OBSERVER_FIXED = {
    0x15478e8: '448b6c2404',                # mov r13d, [rsp+4]       (now: seconds of day)
    0x15478ed: '448b642408',                # mov r12d, [rsp+8]       (now: nanoseconds)
    0x15478f2: '8bab28020000',              # mov ebp, [rbx+0x228]    (window start date)
    0x15478f8: '85ed',                      # test ebp, ebp
    0x1547900: '897c2410',                  # mov [rsp+0x10], edi     (now: date)
    0x1547904: 'f20f108320020000',          # movsd xmm0, [rbx+0x220] (window length, f64 seconds)
    0x154790c: '488b832c020000',            # mov rax, [rbx+0x22c]    (start seconds, nanoseconds)
    0x1547913: '89ac2480000000',            # mov [rsp+0x80], ebp
    0x1547922: '4889842484000000',          # mov [rsp+0x84], rax
    0x1547932: 'b900ca9a3b',                # mov ecx, 1000000000
    0x1547937: '48f7e1',                    # mul rcx
    0x1547946: '48b8ffffffffffffff7f',      # mov rax, i64::MAX
    0x1547950: '4839c1',                    # cmp rcx, rax
    0x1547953: '480f43c8',                  # cmovae rcx, rax
    0x1547957: '4885d2',                    # test rdx, rdx
    0x154795a: '480f45c8',                  # cmovne rcx, rax         (saturate total nanoseconds)
    0x154795e: '48bab394d626e80b2e11',      # mov rdx, 1e9 reciprocal
    0x154796e: '48c1ea1a',                  # shr rdx, 26
    0x1547972: '69c200ca9a3b',              # imul eax, edx, 1000000000
    0x1547996: '48b908ac1c5a643bdfff',      # carried-seconds range test 1
    0x15479a0: '4801c1',
    0x15479a3: '48ba105839b4c876beff',
    0x15479ad: '4839d1',
    0x15479b6: '48b9000000004057ffff',      # carried-seconds range test 2
    0x15479c3: '48ba81aefeff7faefeff',
    0x15479cd: '4839d1',
    0x15479d0: '726b',                      # jb DEADLINE_MAX
    0x15479e5: '48b9572951cea0c84518',      # 86400 reciprocal
    0x15479f9: '48c1ea0d',                  # shr rdx, 13
    0x15479ff: '89ef',                      # mov edi, ebp            (start date)
    0x1547a07: '85c0',                      # test eax, eax
    0x1547a09: '7432',                      # je DEADLINE_MAX         (date add failed)
    0x1547a2f: '8b7c2410',                  # mov edi, [rsp+0x10]     (now: date)
    0x1547a33: '41393e',                    # cmp [r14], edi          (deadline date vs now date)
    0x1547a36: '0f9cc2',                    # setl dl
    0x1547a39: '742e',                      # je 0x1547a69
    0x1547a3d: 'c78424d800000000000000',    # mov dword [rsp+0xd8], 0
    0x1547a69: '443929',                    # cmp [rcx], r13d         (deadline seconds vs now)
    0x1547a6c: '0f92c2',                    # setb dl
    0x1547a71: '443920',                    # cmp [rax], r12d         (deadline nanoseconds vs now)
    0x1547a74: '720d',                      # jb ROLLOVER
    0x1547a7b: '84d2',                      # test dl, dl
    0x1547a83: '488d4370',                  # lea rax, [rbx+0x70]
    0x1547a87: '89bb28020000',              # mov [rbx+0x228], edi    (new window start: date)
    0x1547a8d: '4489ab2c020000',            # mov [rbx+0x22c], r13d   (seconds of day)
    0x1547a94: '4489a330020000',            # mov [rbx+0x230], r12d   (nanoseconds)
    0x1547a9b: '4c8b7360',                  # take vector capacity +0x60
    0x1547a9f: '488b7b68',                  # take vector buffer +0x68
    0x1547aa3: '4c8b7b70',                  # take vector length +0x70
    0x1547aa7: '488b6b78',                  # take count +0x78
    0x1547aab: '488bb380000000',            # take calls +0x80
    0x1547ab2: 'f30f7e9388000000',          # take sum +0x88
    0x1547aba: 'f20f108390000000',          # take maximum +0x90
    0x1547ac8: '48c7436000000000',          # +0x60 = 0
    0x1547ad0: '48c7436808000000',          # +0x68 = 8 (empty vector)
    0x1547ad8: '660f57c0',                  # xorpd xmm0, xmm0
    0x1547adc: '660f114010',                # +0x80..+0x8f = 0
    0x1547ae1: '660f1100',                  # +0x70..+0x7f = 0
    0x1547ae5: '48c7402000000000',          # +0x90 = 0
    0x1547aed: '48baffffffffffffef7f',      # f64::MAX bits
    0x1547af7: '4885ed',                    # test rbp, rbp (count)
    0x1547b0f: '4821c8',                    # and rax, rcx (abs bits of sum)
    0x1547b12: '4839d0',                    # cmp rax, rdx
    0x1547b23: '770a',                      # ja: sum > -1e-15
    0x1547b29: '660f2ec2',                  # ucomisd xmm0(0.0), xmm2(sum)
    0x1547b2d: '776d',                      # ja WINDOW_END: sum <= -1e-15 and 0 > sum: no mean
    0x1547b44: '660f28c1',                  # f64(count as u64)
    0x1547b48: '660f15c1',
    0x1547b4c: 'f20f58c1',
    0x1547b58: 'f20fc2ca01',                # cmpltsd xmm1(-1e-15), xmm2(sum)
    0x1547b67: 'f20fc2d301',                # cmpltsd xmm2(sum), xmm3(0.0)
    0x1547b6c: '660f54d1',                  # andpd: -1e-15 < sum < 0
    0x1547b75: '41f6c001',
    0x1547b79: '7506',                      # tiny negative sum: numerator stays 0.0
    0x1547b7b: 'f20f105c2430',              # numerator = sum
    0x1547b81: 'f20f5ed8',                  # divsd: mean = numerator / count
    0x1547b93: '4839d0',                    # finite mean -> MEAN_PRESENT
}

CTOR_FIXED = {
    0x1548bc1: '4889cb',                    # mov rbx, rcx            (name length)
    0x1548bc4: '4989d4',                    # mov r12, rdx            (name pointer)
    0x1548bc7: 'f20f11442410',              # movsd [rsp+0x10], xmm0
    0x1548bcd: '89f5',                      # mov ebp, esi            (flag byte)
    0x1548bcf: '4989fe',                    # mov r14, rdi            (state)
    0x1548bd2: '488d7c2404',                # lea rdi, [rsp+4]        (clock tuple out)
    0x1548c09: '448b6c2404',                # mov r13d, [rsp+4]       (tuple date)
    0x1548c0e: '488b442408',                # mov rax, [rsp+8]        (seconds, nanoseconds)
    0x1548c13: '4889442420',
    0x1548c46: '44896c241c',
    0x1548d2b: '49895e28',                  # +0x28 = length
    0x1548d2f: '4d897e30',                  # +0x30 = copied buffer
    0x1548d33: '49895e38',                  # +0x38 = length
    0x1548d3e: '660f57c0',                  # xorpd xmm0, xmm0
    0x1548d42: '66410f118600020000',        # +0x200..+0x20f = 0
    0x1548d4b: '49c7861002000000000000',    # +0x210 = 0
    0x1548d56: '49c786f8010000d0070000',    # +0x1f8 = 2000
    0x1548d61: '49c7464000000000',          # +0x40 = 0
    0x1548d69: '49c7464808000000',          # +0x48 = 8
    0x1548d71: '66410f114650',              # +0x50..+0x5f = 0
    0x1548d77: '49c7466000000000',          # +0x60 = 0
    0x1548d7f: '49c7466808000000',          # +0x68 = 8
    0x1548d87: '66410f114670',              # +0x70..+0x7f = 0
    0x1548d8d: '66410f118680000000',        # +0x80..+0x8f = 0
    0x1548d96: '49c7869000000000000000',    # +0x90 = 0
    0x1548ddb: '4188ae5d020000',            # +0x25d = flag byte (esi)
    0x1548de2: '48b80000000000003e40',      # mov rax, 30.0
    0x1548dec: '49898620020000',            # +0x220 = 30.0
    0x1548df3: '8b44241c',
    0x1548df7: '41898628020000',            # +0x228 = tuple date
    0x1548dfe: '488b442420',
    0x1548e03: '4989862c020000',            # +0x22c = tuple seconds, nanoseconds
    0x1548e0a: '41c6865c02000000',          # +0x25c = 0
    0x1548e12: '49c70600000000',            # +0x0 = 0
    0x1548e30: '49c78638020000e8030000',    # +0x238 = 1000
    0x1548e52: '49c7461000000000',          # +0x10 = 0
    0x1548e5a: '4c89f0',                    # return state
    0x1548e6e: 'c3',
}

# Constructor call sites followed by a +0x25c = 1 store through the register
# that held rdi (a callee-saved register, so the constructed state).
# (rdi setup va, rdi setup bytes, call va, store va, store bytes, +0 store, +8 store)
FLAG_SETTERS = (
    (0x16eeea7, '4c89f7', 0x16eeeaf, 0x16eeeca, '41c6865c02000001',
     (0x16eeeb5, '49c70601000000'), (0x16eeebc, '48b8000000000000e03f', 0x16eeec6, '49894608')),
    (0x2503457, '4c89f7', 0x250345f, 0x250347a, '41c6865c02000001',
     (0x2503465, '49c70601000000'), (0x250346c, '48b8000000000000e03f', 0x2503476, '49894608')),
    (0x47716b7, '4c89f7', 0x47716bf, 0x47716da, '41c6865c02000001',
     (0x47716c5, '49c70601000000'), (0x47716cc, '48b8000000000000e03f', 0x47716d6, '49894608')),
    (0x4772906, '4889ef', 0x4772914, 0x477292d, 'c6855c02000001',
     (0x477291a, '48c7450001000000'), (0x4772922, 'f20f10442420', 0x4772928, 'f20f114508')),
    (0x5ab2557, '4c89f7', 0x5ab255f, 0x5ab257a, '41c6865c02000001',
     (0x5ab2565, '49c70601000000'), (0x5ab256c, '48b8000000000000e03f', 0x5ab2576, '49894608')),
)
OTHER_FLAG_STORES = (0x47832e9, 0x47849a8)   # +0x25c = 0 after indirect calls; base not traced


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


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def census(data, target, slot):
    """Direct E8/E9 rel32 to `target`; FF15/FF25 rip-relative through `slot`; in .text."""
    base, raw = text(data)
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
            site = base + index
            if site + width + struct.unpack_from('<i', raw, index + len(opcode))[0] == dest:
                out.append((site, opcode.hex()))
    return sorted(direct), sorted(through_slot)


def byte_stores(data, disp):
    """`mov byte [reg+disp32], imm8` (C6 /0) and `mov byte [reg+disp32], r8` (88), optional REX, in .text."""
    base, raw = text(data)
    pattern = struct.pack('<I', disp)
    sites = []
    start = 0
    while True:
        index = raw.find(pattern, start)
        if index < 0:
            break
        start = index + 1
        if index < 2:
            continue
        opcode, modrm = raw[index - 2], raw[index - 1]
        if modrm >> 6 != 2 or modrm & 7 == 4:
            continue
        if opcode == 0xc6 and (modrm >> 3) & 7 == 0:
            begin = index - 2
        elif opcode == 0x88:
            begin = index - 2
        else:
            continue
        if begin and raw[begin - 1] in (0x40, 0x41, 0x44, 0x45):
            begin -= 1
        sites.append(base + begin)
    return sorted(set(sites))


def range_tests():
    mask = (1 << 64) - 1
    signed = lambda v: v - (1 << 64) if v >> 63 else v
    a1, b1 = 0xffdf3b645a1cac08, 0xffbe76c8b4395810
    a2, b2 = 0xffff574000000000, 0xfffeae7ffffeae81
    return {
        'test_1': {'add': hex(a1), 'jbe_bound': hex(b1),
                   'kept_open_interval': [signed((b1 - a1 + 1) & mask) - 1, signed(-a1 & mask)]},
        'test_2': {'add': hex(a2), 'jb_bound': hex(b2),
                   'kept_half_open_interval': [signed((b2 - a2) & mask), signed(-a2 & mask)]},
    }


def bind(data, fdes):
    if frame(fdes, OBSERVER) != (OBSERVER, OBSERVER_END):
        raise ValueError('observer FDE changed')
    if frame(fdes, CTOR) != (CTOR, CTOR_END):
        raise ValueError('constructor FDE changed')
    for va, prefix, length, expect in REFERENCES:
        if rip_target(data, va, prefix, length) != expect:
            raise ValueError(f'reference at {va:#x} changed')
    for va, expect in {**OBSERVER_FIXED, **CTOR_FIXED}.items():
        fixed(data, va, expect)
    relocs = relocations(data)
    for slot, target in SLOTS.items():
        rows = [(info, addend) for va, info, addend in relocs if va == slot]
        if rows != [(8, target)]:
            raise ValueError(f'slot {slot:#x} relocation changed')
    max_tuple = struct.unpack('<3I', read_va(data, MAX_TUPLE, 12)[1])
    if max_tuple != (2147473118, 86399, 999999999):
        raise ValueError('deadline maximum tuple changed')
    epsilon = struct.unpack('<d', read_va(data, EPSILON, 8)[1])[0]
    if epsilon != -1e-15:
        raise ValueError('mean epsilon changed')
    window_seconds = struct.unpack('<d', struct.pack('<Q', WINDOW_SECONDS_BITS))[0]

    direct, ctor_calls = census(data, CTOR, CTOR_SLOT)
    ctor_relative = [va for va, info, addend in relocs if info & 0xffffffff == 8 and addend == CTOR]
    if direct or ctor_relative != [CTOR_SLOT] or len(ctor_calls) != 35 \
            or any(op != 'ff15' for _, op in ctor_calls):
        raise ValueError('constructor reference census changed')
    call_sites = {va for va, _ in ctor_calls}
    setters = []
    for rdi_va, rdi_bytes, call_va, store_va, store_bytes, zero, eight in FLAG_SETTERS:
        if call_va not in call_sites:
            raise ValueError(f'{call_va:#x} is no longer a constructor call')
        fixed(data, rdi_va, rdi_bytes)
        fixed(data, store_va, store_bytes)
        fixed(data, zero[0], zero[1])
        fixed(data, eight[0], eight[1])
        fixed(data, eight[2], eight[3])
        base = 'rbp' if rdi_bytes == '4889ef' else 'r14'
        constant = eight[1].startswith('48b8')
        setters.append({'rdi_from': base, 'rdi_va': hex(rdi_va), 'call_va': hex(call_va),
                        'flag_store_va': hex(store_va), 'flag': 1,
                        'field_0': {'va': hex(zero[0]), 'value': 1},
                        'field_8': {'va': hex(eight[2]),
                                    'value': 0.5 if constant else 'f64 from the caller stack'}})
    stores = byte_stores(data, 0x25c)
    expected = sorted([0x1548e0a] + [s[3] for s in FLAG_SETTERS] + list(OTHER_FLAG_STORES))
    if stores != expected:
        raise ValueError('byte-store census of +0x25c changed')

    _, window = read_va(data, WINDOW_START, WINDOW_END - WINDOW_START)
    _, cwindow = read_va(data, CTOR, CTOR_WINDOW_END - CTOR)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'observer_window': {
            'fde': {'start_va': hex(OBSERVER), 'end_va': hex(OBSERVER_END)},
            'window': {'start_va': hex(WINDOW_START), 'end_va': hex(WINDOW_END),
                       'bytes': len(window), 'sha256': hashlib.sha256(window).hexdigest()},
            'no_start': 'dword [+0x228] == 0 jumps straight to the rollover at %s' % hex(ROLLOVER),
            'deadline': {
                'length': 'f64 [+0x220] passed in xmm0 to slot %s -> %s; result (rax, edx) is '
                          'combined as rax * 1e9 + edx, saturating at i64::MAX, then split '
                          'back into seconds and nanoseconds' % (hex(SECONDS_SLOT), hex(SECONDS)),
                'time_add': 'slot %s -> %s with the start (seconds of day +0x22c, nanoseconds '
                            '+0x230) and the split length; it returns a time and carried seconds'
                            % (hex(TIME_ADD_SLOT), hex(TIME_ADD)),
                'range_tests': range_tests(),
                'days_add': 'carried seconds / 86400 and the start date +0x228 to slot %s -> %s; '
                            'a zero result fails' % (hex(DAYS_SLOT), hex(DAYS)),
                'on_failure': {'va': hex(DEADLINE_MAX), 'tuple_va': hex(MAX_TUPLE),
                               'tuple': list(max_tuple)},
            },
            'compare': 'roll over only when (now date, seconds, nanoseconds) is strictly greater '
                       'than the deadline; date compared signed (setl), the others unsigned',
            'rollover': {
                'new_start': 'now tuple to +0x228 (date), +0x22c (seconds), +0x230 (nanoseconds)',
                'taken': {'vector': '+0x60 capacity, +0x68 buffer, +0x70 length',
                          'count': '+0x78', 'calls': '+0x80', 'sum': '+0x88', 'max': '+0x90'},
                'reset': '+0x60 = 0, +0x68 = 8 (empty vector), +0x70..+0x97 = 0',
            },
            'mean': {
                'none_when': ['count +0x78 == 0', 'sum is not finite',
                              'sum <= -1e-15 (negative)', 'mean is not finite'],
                'value': 'numerator / f64(count as u64); numerator is 0.0 when -1e-15 < sum < 0, '
                         'otherwise the sum',
                'epsilon': {'va': hex(EPSILON), 'value': epsilon},
                'present_jump_va': hex(MEAN_PRESENT),
            },
        },
        'constructor': {
            'fde': {'start_va': hex(CTOR), 'end_va': hex(CTOR_END)},
            'window': {'start_va': hex(CTOR), 'end_va': hex(CTOR_WINDOW_END),
                       'bytes': len(cwindow), 'sha256': hashlib.sha256(cwindow).hexdigest()},
            'arguments': {'rdi': 'state (returned in rax)', 'esi': 'byte stored at +0x25d',
                          'rdx': 'name pointer', 'rcx': 'name length', 'xmm0': 'f64 (scaled, then +0x218)'},
            'initial': {
                '+0x220': {'bits': hex(WINDOW_SECONDS_BITS), 'value': window_seconds},
                '+0x1f8': SAMPLE_LIMIT,
                '+0x25c': 0,
                '+0x238': FIELD_238,
                '+0x228/+0x22c': 'clock tuple from slot %s -> %s (window start = construction time)'
                                 % (hex(PROVIDER_SLOT), hex(PROVIDER)),
                'zeroed': ['+0x0', '+0x10', '+0x40', '+0x50..+0x5f', '+0x60', '+0x70..+0x97',
                           '+0x200..+0x217'],
                'empty_buffers': {'+0x48': 8, '+0x68': 8},
                'name': '+0x28 = length, +0x30 = copied buffer, +0x38 = length',
            },
            'slot': {'va': hex(CTOR_SLOT), 'relative_relocations': [hex(v) for v in ctor_relative],
                     'direct_calls': len(direct), 'slot_calls': len(ctor_calls),
                     'slot_call_sites': [hex(v) for v, _ in ctor_calls]},
        },
        'flag_25c': {
            'byte_store_census': [hex(v) for v in stores],
            'encodings': 'C6 /0 and 88 with mod=10 and disp32 0x25c, optional REX, in .text',
            'constructor_store': '0x1548e0a (value 0)',
            'set_to_1_after_constructor': setters,
            'not_attributed': [hex(v) for v in OTHER_FLAG_STORES],
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
    print(f"{result['constructor']['fde']['start_va']} ctor_calls={result['constructor']['slot']['slot_calls']} "
          f"flag_setters={len(result['flag_25c']['set_to_1_after_constructor'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
